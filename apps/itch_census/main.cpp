// itch_census: per-type counts, bytes, timestamp checks, system events, burst
// maxima (1 ms / 100 ms / 1 s), hourly counts and observed enumerations of a
// BinaryFILE ITCH 5.0 stream (03-protocols §3, P-03). The report reproduces
// the research analyzer's format so it can be diffed against
// docs/plan/research/data/01302019.stats.txt.
//
//   itch_census [--coverage] [--max-records N] FILE
#include <cstdio>
#include <cstdlib>
#include <string>

#include "proto/itch50/binary_file.h"
#include "proto/itch50/census.h"

int main(int argc, char** argv) {
  using lle::itch50::RecordStatus;
  bool coverage = false;
  std::uint64_t max_records = UINT64_MAX;
  std::string path;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--coverage") {
      coverage = true;
    } else if (a == "--max-records" && i + 1 < argc) {
      max_records = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "-h" || a == "--help") {
      std::printf("usage: itch_census [--coverage] [--max-records N] FILE\n");
      return 0;
    } else {
      path = a;
    }
  }
  if (path.empty()) {
    std::fprintf(stderr, "usage: itch_census [--coverage] [--max-records N] FILE\n");
    return 2;
  }
  lle::itch50::BinaryFileReader reader;
  if (auto ok = reader.open(path); !ok) {
    std::fprintf(stderr, "itch_census: %s\n", ok.error().c_str());
    return 2;
  }
  lle::itch50::Census census;
  std::uint64_t records = 0;
  int rc = 0;
  for (; records < max_records; ++records) {
    const lle::itch50::Record r = reader.next();
    if (r.status == RecordStatus::Message || r.status == RecordStatus::EndOfSession) {
      census.add(r.data);
      continue;
    }
    if (r.status == RecordStatus::Truncated) {
      std::fprintf(stderr, "TRUNCATED at msg %llu (%zu trailing bytes)\n", static_cast<unsigned long long>(records),
                   r.data.size());
      rc = 1;
    } else if (r.status == RecordStatus::IoError) {
      std::fprintf(stderr, "itch_census: read error after %llu records: %s\n",
                   static_cast<unsigned long long>(records), reader.error().c_str());
      rc = 1;
    }
    break;
  }
  census.print_report(stdout);
  if (coverage) {
    std::printf("\n");
    census.print_coverage(stdout);
  }
  return rc;
}
