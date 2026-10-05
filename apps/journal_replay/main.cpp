// journal_replay <journal-dir> [--from I] [--to I] [--snapshot-dir D] [--print]
//                [--emit ITCH_FILE] [--emit-ouch OUCH_FILE]
// (06 §11). Walks the valid journal prefix through a replay sink (journal/replay.h).
//
// The sink validates and counts: every payload must decode in canonical form and
// the stamping invariants (strictly increasing ts_ns, monotonic epoch) must hold.
//
// --emit / --emit-ouch also run the matching engine over the records (Engine::apply
// on each RecordView through engine/journal_adapter.h) and write its output:
//   ITCH: NASDAQ BinaryFILE framing ([u16 BE length][message], ended by a zero-length
//         record), readable by itch_validate, itch_census and the other itch tools;
//   OUCH: [u32 BE session id][u16 BE length][message] per outbound message.
// With --snapshot-dir the engine starts from the snapshot it selects (the newest
// valid one at or below --to, 06 §7 step 4: engine section checked against the
// header) and the ITCH file starts after its S(P). The summary prints S(P) and the
// final engine state hash (compare with a live node's).
// Exit status: 0 ok, 1 invalid records, 2 usage or I/O error.
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>

#include "common/endian.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "journal/describe.h"
#include "journal/posix_segment_dir.h"
#include "journal/replay.h"
#include "snapshot/engine_section.h"
#include "snapshot/reader.h"

namespace {

using namespace lle::journal;

// Engine output to files (see the header comment for the framing).
class EmitSink {
 public:
  bool open(const std::string& itch_path, const std::string& ouch_path) {
    if (!itch_path.empty() && (itch_ = std::fopen(itch_path.c_str(), "wb")) == nullptr) return false;
    if (!ouch_path.empty() && (ouch_ = std::fopen(ouch_path.c_str(), "wb")) == nullptr) return false;
    return true;
  }
  ~EmitSink() {
    if (itch_ != nullptr) {
      const std::byte end[2] = {};
      (void)std::fwrite(end, 1, 2, itch_);  // end of session (BinaryFILE)
      (void)std::fclose(itch_);
    }
    if (ouch_ != nullptr) (void)std::fclose(ouch_);
  }
  void itch(std::uint64_t, std::span<const std::byte> b) {
    ++itch_msgs_;
    if (itch_ == nullptr) return;
    std::byte len[2];
    lle::store_be16(len, static_cast<std::uint16_t>(b.size()));
    ok_ = ok_ && std::fwrite(len, 1, 2, itch_) == 2 && std::fwrite(b.data(), 1, b.size(), itch_) == b.size();
  }
  void ouch(std::uint64_t, std::uint32_t session, std::span<const std::byte> b) {
    ++ouch_msgs_;
    if (ouch_ == nullptr) return;
    std::byte head[6];
    lle::store_be32(head, session);
    lle::store_be16(head + 4, static_cast<std::uint16_t>(b.size()));
    ok_ = ok_ && std::fwrite(head, 1, 6, ouch_) == 6 && std::fwrite(b.data(), 1, b.size(), ouch_) == b.size();
  }
  void audit(std::uint64_t, const lle::engine::AuditEvent&) { ++audits_; }
  [[nodiscard]] bool ok() const { return ok_; }
  std::uint64_t itch_msgs_ = 0, ouch_msgs_ = 0, audits_ = 0;

 private:
  std::FILE* itch_ = nullptr;
  std::FILE* ouch_ = nullptr;
  bool ok_ = true;
};

// Validates every record; optionally prints it and feeds it to the engine.
class CheckingSink {
 public:
  explicit CheckingSink(bool print, lle::engine::Engine* engine = nullptr, EmitSink* emit = nullptr)
      : print_(print), engine_(engine), emit_(emit) {}

  bool on_record(const RecordView& r) {
    if (engine_ != nullptr) engine_->apply(lle::engine::to_input(r), *emit_);
    const std::string line = describe(r, r.content());
    if (line.find('<') != std::string::npos) ++bad_payloads_;
    if (seen_ && (r.ts_ns() <= last_ts_ || r.epoch() < last_epoch_)) ++bad_stamps_;
    seen_ = true;
    last_ts_ = r.ts_ns();
    last_epoch_ = r.epoch();
    if (print_) std::printf("%s\n", line.c_str());
    return true;
  }

  [[nodiscard]] std::uint64_t bad_payloads() const { return bad_payloads_; }
  [[nodiscard]] std::uint64_t bad_stamps() const { return bad_stamps_; }

 private:
  bool print_;
  lle::engine::Engine* engine_;
  EmitSink* emit_;
  bool seen_ = false;
  lle::Nanos last_ts_ = 0;
  std::uint32_t last_epoch_ = 0;
  std::uint64_t bad_payloads_ = 0;
  std::uint64_t bad_stamps_ = 0;
};
static_assert(ReplaySink<CheckingSink>);

int usage() {
  std::fprintf(stderr,
               "usage: journal_replay <journal-dir> [--from I] [--to I] [--snapshot-dir D] [--print]\n"
               "                      [--emit ITCH_FILE] [--emit-ouch OUCH_FILE]\n");
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return usage();
  ReplayRange range;
  std::string snap_dir, emit_itch, emit_ouch;
  bool print = false;
  for (int i = 2; i < argc; ++i) {
    const std::string_view a(argv[i]);
    if (a == "--from" && i + 1 < argc) {
      range.from = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--to" && i + 1 < argc) {
      range.to = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--snapshot-dir" && i + 1 < argc) {
      snap_dir = argv[++i];
    } else if (a == "--print") {
      print = true;
    } else if (a == "--emit" && i + 1 < argc) {
      emit_itch = argv[++i];
    } else if (a == "--emit-ouch" && i + 1 < argc) {
      emit_ouch = argv[++i];
    } else {
      return usage();
    }
  }
  auto dir = PosixSegmentDir::open(argv[1], false, PosixDeviceOptions{.read_only = true});
  if (!dir) {
    std::fprintf(stderr, "journal_replay: %s\n", dir.error().c_str());
    return 2;
  }
  const bool emit = !emit_itch.empty() || !emit_ouch.empty();
  lle::engine::Engine engine;
  EmitSink out;
  if (emit && !out.open(emit_itch, emit_ouch)) {
    std::fprintf(stderr, "journal_replay: cannot create the output files\n");
    return 2;
  }
  if (!snap_dir.empty()) {
    const auto snap = lle::snap::find_latest(snap_dir, range.to);
    if (snap) {
      std::printf("snapshot: %s (index %" PRIu64 ", S(P) %" PRIu64 ", state hash %016" PRIx64 ")\n",
                  snap->path.c_str(), snap->meta.index, snap->meta.mold_seq, snap->meta.state_hash);
      range.from = std::max(range.from, snap->meta.index + 1);
      if (emit) {
        auto mapped = lle::snap::MappedSnapshot::open(snap->path);
        if (!mapped) {
          std::fprintf(stderr, "journal_replay: %s\n", std::string(lle::snap::to_string(mapped.error())).c_str());
          return 2;
        }
        if (const auto ok = lle::snap::load_engine(mapped->reader(), engine); !ok) {
          std::fprintf(stderr, "journal_replay: snapshot engine section: %s\n",
                       std::string(lle::snap::to_string(ok.error())).c_str());
          return 2;
        }
        if (range.from != snap->meta.index + 1) {
          std::fprintf(stderr, "journal_replay: --from must not skip records after the snapshot\n");
          return 2;
        }
      }
    } else {
      std::printf("snapshot: none at or below index %" PRIu64 "; replaying from the start of the day\n", range.to);
    }
  }
  if (emit && range.from != 1 && engine.date() == 0) {
    std::fprintf(stderr, "journal_replay: --emit replays from index 1 or from a snapshot\n");
    return 2;
  }
  CheckingSink sink(print, emit ? &engine : nullptr, emit ? &out : nullptr);
  const ReplayStats st = replay(*dir, range, sink);
  std::printf("replayed %" PRIu64 " records (index %" PRIu64 "..%" PRIu64 "), stopped: %s\n", st.records,
              st.first_index, st.last_index, std::string(to_string(st.stop)).c_str());
  for (std::uint16_t t = kMinRecordType; t <= kMaxRecordType; ++t) {
    if (st.by_type[t] != 0) {
      std::printf("  %-14s %" PRIu64 "\n", std::string(to_string(static_cast<RecordType>(t))).c_str(), st.by_type[t]);
    }
  }
  std::printf("invalid payloads: %" PRIu64 ", stamping violations: %" PRIu64 "\n", sink.bad_payloads(),
              sink.bad_stamps());
  if (emit) {
    std::printf("engine: S(P) %" PRIu64 " (%" PRIu64 " ITCH written), OUCH %" PRIu64 ", audits %" PRIu64
                ", live orders %zu, state hash %016" PRIx64 "\n",
                engine.itch_count(), out.itch_msgs_, out.ouch_msgs_, out.audits_, engine.live_orders(),
                engine.state_hash());
    if (!out.ok()) {
      std::fprintf(stderr, "journal_replay: writing the output failed\n");
      return 2;
    }
  }
  if (st.stop == ReadStop::IoError) return 2;
  return sink.bad_payloads() + sink.bad_stamps() != 0 ? 1 : 0;
}
