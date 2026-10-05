// itch_roundtrip: full-file decode -> encode -> memcmp over every BinaryFILE
// record (03-protocols §9 "Full-day round trip"). Pass criterion: 0 framing
// errors, 0 length mismatches, 0 unknown types, 0 byte differences.
//
//   itch_roundtrip [--max-records N] [--buffer-mb N] FILE...
//
// FILE may be plain or gzip (detected by magic bytes), or "-" for stdin.
// Exit status 0 iff every file passes.
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "proto/itch50/binary_file.h"
#include "proto/itch50/itch50.h"

namespace {

using lle::itch50::BinaryFileReader;
using lle::itch50::DecodeStatus;
using lle::itch50::Record;
using lle::itch50::RecordStatus;
using ull = unsigned long long;

struct Totals {
  std::uint64_t records = 0, messages = 0, end_of_session = 0, framing_errors = 0, io_errors = 0;
  std::uint64_t unknown_types = 0, length_mismatches = 0, roundtrip_diffs = 0;
  std::array<std::uint64_t, 256> per_type{};
};

void print_hex(const char* label, const std::byte* p, std::size_t n) {
  std::printf("    %s:", label);
  for (std::size_t i = 0; i < n; ++i) std::printf(" %02x", static_cast<unsigned>(p[i]));
  std::printf("\n");
}

bool run_file(const std::string& path, std::uint64_t max_records, std::size_t buffer_bytes) {
  BinaryFileReader reader;
  if (auto ok = reader.open(path, buffer_bytes); !ok) {
    std::printf("file: %s\n  ERROR %s\nRESULT FAIL\n", path.c_str(), ok.error().c_str());
    return false;
  }
  std::printf("file: %s (%s)\n", path.c_str(), reader.compressed() ? "gzip" : "plain");
  std::fflush(stdout);
  const auto t0 = std::chrono::steady_clock::now();

  Totals t;
  std::array<std::byte, lle::itch50::kMaxMsgLen> out{};
  constexpr std::uint64_t kMaxDiffReports = 10;
  bool done = false;
  while (!done && t.records < max_records) {
    const Record rec = reader.next();
    switch (rec.status) {
      case RecordStatus::Message: {
        ++t.records;
        ++t.messages;
        const auto type = static_cast<unsigned char>(rec.data[0]);
        ++t.per_type[type];
        const DecodeStatus st = lle::itch50::visit(rec.data, [&](auto v) {
          const std::size_t n = lle::itch50::encode(out, v.to_struct());
          if (n != rec.data.size() || std::memcmp(out.data(), rec.data.data(), n) != 0) [[unlikely]] {
            if (++t.roundtrip_diffs <= kMaxDiffReports) {
              std::printf("  DIFF record %llu type %c\n", static_cast<ull>(t.records), static_cast<char>(type));
              print_hex("in ", rec.data.data(), rec.data.size());
              print_hex("out", out.data(), n);
            }
          }
        });
        if (st == DecodeStatus::UnknownType) [[unlikely]] {
          if (++t.unknown_types <= kMaxDiffReports)
            std::printf("  UNKNOWN type 0x%02x at record %llu\n", type, static_cast<ull>(t.records));
        } else if (st == DecodeStatus::BadLength) [[unlikely]] {
          if (++t.length_mismatches <= kMaxDiffReports)
            std::printf("  LENGTH %zu for type %c (want %u) at record %llu\n", rec.data.size(), static_cast<char>(type),
                        unsigned{lle::itch50::kMsgLen[type]}, static_cast<ull>(t.records));
        }
        break;
      }
      case RecordStatus::EndOfSession:
        ++t.records;
        ++t.end_of_session;
        break;
      case RecordStatus::EndOfFile:
        done = true;
        break;
      case RecordStatus::Truncated:
        ++t.framing_errors;
        std::printf("  FRAMING truncated record (%zu trailing bytes) after record %llu\n", rec.data.size(),
                    static_cast<ull>(t.records));
        done = true;
        break;
      case RecordStatus::IoError:
        ++t.io_errors;
        std::printf("  IO ERROR after record %llu: %s\n", static_cast<ull>(t.records), reader.error().c_str());
        done = true;
        break;
    }
  }
  const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

  std::printf("  records %llu  messages %llu  end_of_session %llu  bytes(incl 2B prefix) %llu\n",
              static_cast<ull>(t.records), static_cast<ull>(t.messages), static_cast<ull>(t.end_of_session),
              static_cast<ull>(reader.bytes_consumed()));
  std::printf("  framing_errors %llu  io_errors %llu  unknown_types %llu  length_mismatches %llu  roundtrip_diffs %llu\n",
              static_cast<ull>(t.framing_errors), static_cast<ull>(t.io_errors), static_cast<ull>(t.unknown_types),
              static_cast<ull>(t.length_mismatches), static_cast<ull>(t.roundtrip_diffs));
  std::printf("  per-type counts:\n");
  for (unsigned c = 0; c < 256; ++c) {
    if (t.per_type[c] == 0) continue;
    const auto name = lle::itch50::message_name(static_cast<char>(c));
    std::printf("    %c %-26.*s %12llu\n", static_cast<char>(c), static_cast<int>(name.size()), name.data(),
                static_cast<ull>(t.per_type[c]));
  }
  std::printf("  elapsed %.1f s (%.2f M records/s, %.0f MB/s decompressed)\n", secs,
              secs > 0 ? static_cast<double>(t.records) / secs / 1e6 : 0.0,
              secs > 0 ? static_cast<double>(reader.bytes_consumed()) / secs / 1e6 : 0.0);
  const bool pass = t.framing_errors == 0 && t.io_errors == 0 && t.unknown_types == 0 && t.length_mismatches == 0 &&
                    t.roundtrip_diffs == 0;
  std::printf("RESULT %s\n", pass ? "PASS" : "FAIL");
  std::fflush(stdout);
  return pass;
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t max_records = UINT64_MAX;
  std::size_t buffer_bytes = BinaryFileReader::kDefaultBufferBytes;
  std::vector<std::string> files;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--max-records" && i + 1 < argc) {
      max_records = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--buffer-mb" && i + 1 < argc) {
      buffer_bytes = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10)) << 20;
    } else if (a == "-h" || a == "--help") {
      std::printf("usage: itch_roundtrip [--max-records N] [--buffer-mb N] FILE...\n");
      return 0;
    } else {
      files.push_back(a);
    }
  }
  if (files.empty()) {
    std::fprintf(stderr, "usage: itch_roundtrip [--max-records N] [--buffer-mb N] FILE...\n");
    return 2;
  }
  bool all = true;
  for (const auto& f : files) all = run_file(f, max_records, buffer_bytes) && all;
  return all ? 0 : 1;
}
