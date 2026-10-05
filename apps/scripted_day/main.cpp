// scripted_day: runs a trading day from a script through the real sequencer
// into the engine, deterministically and in-process (admin/day_runner.h for
// the script format), writes the ITCH output as a BinaryFILE and prints a
// summary. The T03 halt and IPO days are in apps/scripted_day/days/.
//
//   scripted_day SCRIPT [--itch OUT.itch]
//
// Exit status: 0 ok, 1 an ITCH message failed strict validation, 2 usage or script error.
#include <cinttypes>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

#include "admin/day_runner.h"

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: scripted_day SCRIPT [--itch OUT.itch]\n");
    return 2;
  }
  std::string out;
  for (int i = 2; i < argc; ++i) {
    if (std::string_view(argv[i]) == "--itch" && i + 1 < argc) {
      out = argv[++i];
    } else {
      std::fprintf(stderr, "scripted_day: unknown option %s\n", argv[i]);
      return 2;
    }
  }
  std::ifstream f(argv[1]);
  if (!f) {
    std::fprintf(stderr, "scripted_day: cannot read %s\n", argv[1]);
    return 2;
  }
  const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  const auto r = lle::admin::run_day(text);
  if (!r) {
    std::fprintf(stderr, "scripted_day: %s\n", r.error().c_str());
    return 2;
  }
  if (!out.empty() && !lle::admin::write_binary_file(out, r->itch)) {
    std::fprintf(stderr, "scripted_day: cannot write %s\n", out.c_str());
    return 2;
  }
  std::printf("records %" PRIu64 " (timers %" PRIu64 "), ITCH %zu, OUCH %" PRIu64 ", audits %" PRIu64
              ", live orders %" PRIu64 ", state hash %016" PRIx64 "\n",
              r->records, r->timers, r->itch.size(), r->ouch, r->audits, r->live_orders, r->state_hash);
  std::printf("ITCH by type:");
  for (const auto& [t, n] : r->itch_types) std::printf(" %c=%" PRIu64, t, n);
  std::printf("\nOUCH liquidity flags:");
  for (const auto& [t, n] : r->liquidity) std::printf(" %c=%" PRIu64, t, n);
  std::printf("\nstrict validator failures: %" PRIu64 "\n", r->invalid_itch);
  return r->invalid_itch == 0 ? 0 : 1;
}
