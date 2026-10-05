// journal_inspect dump|verify|stats|schema (06 §11).
//
//   journal_inspect dump   <dir> [--from I] [--to I] [--pads]   one line per record
//   journal_inspect verify <dir>                                recovery verdict (read-only)
//   journal_inspect stats  <dir>                                per-type counts and sizes
//   journal_inspect schema                                      the record/segment format
//
// <dir> is a journal day directory (journal/<day>/). Nothing is ever written: verify
// runs recovery in report-only mode. Exit status: 0 ok, 1 corruption or invalid
// records, 2 usage or I/O error.
#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>

#include "journal/describe.h"
#include "journal/posix_segment_dir.h"
#include "journal/reader.h"
#include "journal/recovery.h"

namespace {

using namespace lle::journal;

int usage() {
  std::fprintf(stderr,
               "usage: journal_inspect dump <dir> [--from I] [--to I] [--pads]\n"
               "       journal_inspect verify <dir>\n"
               "       journal_inspect stats <dir>\n"
               "       journal_inspect schema\n");
  return 2;
}

bool open_dir(const char* path, PosixSegmentDir& out) {
  auto d = PosixSegmentDir::open(path, false, PosixDeviceOptions{.read_only = true});
  if (!d) {
    std::fprintf(stderr, "journal_inspect: %s\n", d.error().c_str());
    return false;
  }
  out = std::move(*d);
  return true;
}

int dump(PosixSegmentDir& dir, int argc, char** argv) {
  ReadOptions o;
  for (int i = 0; i < argc; ++i) {
    const std::string_view a(argv[i]);
    if (a == "--from" && i + 1 < argc) {
      o.from_index = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--to" && i + 1 < argc) {
      o.to_index = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--pads") {
      o.include_pads = true;
    } else {
      return usage();
    }
  }
  std::uint64_t bad = 0;
  const ReadSummary s = read_journal(dir, o, [&](const RecordView& r, const RecordLocation& loc) {
    const std::string line = describe(r, loc.sealer->content_of(r.data()));
    if (line.find("<") != std::string::npos && r.type() != RecordType::Pad) ++bad;
    std::printf("%s\n", line.c_str());
    return true;
  });
  std::printf("# %" PRIu64 " records, last index %" PRIu64 ", stopped: %s\n", s.delivered, s.chain.last_index,
              std::string(to_string(s.stop)).c_str());
  return s.stop == ReadStop::IoError ? 2 : (bad != 0 ? 1 : 0);
}

int verify(PosixSegmentDir& dir) {
  RecoveryOptions o;
  o.repair = false;
  const RecoveryResult r = recover(dir, o);
  std::printf("status:      %s\n", std::string(to_string(r.status)).c_str());
  std::printf("detail:      %s\n", r.detail.c_str());
  std::printf("day:         %u\n", r.day);
  std::printf("records:     %" PRIu64 " (index %" PRIu64 "..%" PRIu64 ")\n", r.records, r.first_index,
              r.chain.last_index);
  std::printf("chain head:  %08x  last ts %" PRId64 "  epoch %u\n", r.chain.last_crc, r.chain.last_ts, r.chain.epoch);
  for (const auto& sgm : r.segments) {
    std::printf("segment:     %s  first %" PRIu64 "  epoch %u  records %" PRIu64 "  data end %" PRIu64 "/%" PRIu64
                "\n",
                std::string(dir.name(sgm.handle)).c_str(), sgm.header.first_index, sgm.header.epoch, sgm.records,
                sgm.data_end, sgm.header.segment_bytes);
  }
  if (r.status == RecoveryStatus::Ok) {
    std::printf("tail:        offset %" PRIu64 "%s, %" PRIu64 " sealed records in the in-flight window\n",
                r.tail_offset, r.torn_tail ? " (torn: recovery would truncate here)" : " (clean)",
                r.discarded_records);
  }
  std::printf("spares:      %zu clean, %zu to recycle; %zu ignored files\n", r.spares.size(), r.dirty_spares.size(),
              r.ignored.size());
  // Payloads must decode in canonical form.
  std::uint64_t bad = 0;
  (void)read_journal(dir, ReadOptions{}, [&](const RecordView& rec, const RecordLocation& loc) {
    if (describe(rec, loc.sealer->content_of(rec.data())).find("<") != std::string::npos) {
      if (++bad <= 10) std::printf("bad payload: index %" PRIu64 "\n", rec.index());
    }
    return true;
  });
  std::printf("payloads:    %" PRIu64 " invalid\n", bad);
  if (r.status == RecoveryStatus::IoError) return 2;
  return (r.status == RecoveryStatus::Corruption || bad != 0) ? 1 : 0;
}

int stats(PosixSegmentDir& dir) {
  struct Row {
    std::uint64_t n = 0;
    std::uint64_t bytes = 0;
    std::uint32_t min = std::numeric_limits<std::uint32_t>::max();
    std::uint32_t max = 0;
  };
  std::array<Row, kMaxRecordType + 1> rows{};
  lle::Nanos first_ts = 0, last_ts = 0;
  ReadOptions o;
  o.include_pads = true;
  const ReadSummary s = read_journal(dir, o, [&](const RecordView& r, const RecordLocation&) {
    Row& row = rows[r.type_raw()];
    ++row.n;
    row.bytes += r.len();
    row.min = std::min(row.min, r.len());
    row.max = std::max(row.max, r.len());
    if (r.type() != RecordType::Pad) {
      if (first_ts == 0) first_ts = r.ts_ns();
      last_ts = r.ts_ns();
    }
    return true;
  });
  std::printf("%-14s %12s %14s %8s %8s %8s\n", "type", "records", "bytes", "min", "avg", "max");
  std::uint64_t total = 0, total_bytes = 0;
  for (std::uint16_t t = kMinRecordType; t <= kMaxRecordType; ++t) {
    const Row& row = rows[t];
    if (row.n == 0) continue;
    total += row.n;
    total_bytes += row.bytes;
    std::printf("%-14s %12" PRIu64 " %14" PRIu64 " %8u %8" PRIu64 " %8u\n",
                std::string(to_string(static_cast<RecordType>(t))).c_str(), row.n, row.bytes, row.min,
                row.bytes / row.n, row.max);
  }
  std::printf("%-14s %12" PRIu64 " %14" PRIu64 "\n", "total", total, total_bytes);
  std::printf("segments %zu, last index %" PRIu64 ", span %.3f s, stopped: %s\n", s.segments, s.chain.last_index,
              static_cast<double>(last_ts - first_ts) / 1e9, std::string(to_string(s.stop)).c_str());
  return s.stop == ReadStop::IoError ? 2 : 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return usage();
  const std::string_view cmd(argv[1]);
  if (cmd == "schema") {
    std::fwrite(schema_text().data(), 1, schema_text().size(), stdout);
    return 0;
  }
  if (argc < 3) return usage();
  PosixSegmentDir dir;
  if (!open_dir(argv[2], dir)) return 2;
  if (cmd == "dump") return dump(dir, argc - 3, argv + 3);
  if (cmd == "verify") return verify(dir);
  if (cmd == "stats") return stats(dir);
  return usage();
}
