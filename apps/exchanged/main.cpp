// exchanged: one exchange node (07 §3, WP N-03).
//
//   exchanged --config FILE        run the node described by FILE
//   exchanged --hash-password PASS [--salt HEX]
//                                  print a credential for a [sessions] entry
//   exchanged --check-config FILE  parse FILE and print the derived tables
//
// SIGINT / SIGTERM stop the node gracefully: every sequenced record is made durable
// and the output log flushed. Exit status: 0 clean stop, 1 bad arguments or config,
// 2 start-up failure, 3 deposed (replication), 4 fatal I/O error.
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "env/entropy.h"
#include "exchanged/config.h"
#include "exchanged/node.h"
#include "exchanged/restart_guard.h"
#include "gateway/credentials.h"

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

int usage() {
  std::fprintf(stderr,
               "usage: exchanged --config FILE\n"
               "       exchanged --hash-password PASS [--salt HEX]\n"
               "       exchanged --check-config FILE\n");
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string_view> a(argv + 1, argv + argc);
  if (a.size() >= 2 && a[0] == "--hash-password") {
    std::vector<std::uint8_t> salt;
    if (a.size() >= 4 && a[2] == "--salt") {
      auto s = lle::gw::from_hex(a[3]);
      if (!s || s->empty() || s->size() > 32) return usage();
      salt = *s;
    } else {
      lle::env::ProdRng rng;
      for (int i = 0; i < 2; ++i) {
        const std::uint64_t v = rng.next_u64();
        for (int b = 0; b < 8; ++b) salt.push_back(static_cast<std::uint8_t>(v >> (8 * b)));
      }
    }
    std::printf("%s\n", lle::gw::Credential::make(a[1], salt).text().c_str());
    return 0;
  }
  if (a.size() == 2 && a[0] == "--check-config") {
    auto cfg = lle::exch::load_config(std::string(a[1]));
    if (!cfg) {
      std::fprintf(stderr, "exchanged: %s\n", cfg.error().c_str());
      return 1;
    }
    std::printf("node %s id %u, day %u: %zu symbols, %zu accounts, %zu sessions, %zu risk limits, %zu schedule entries\n",
                cfg->name.c_str(), cfg->node_id, cfg->date, cfg->symbols.size(), cfg->accounts.size(),
                cfg->sessions.size(), cfg->risk.size(), cfg->schedule_table().size());
    return 0;
  }
  if (a.size() != 2 || a[0] != "--config") return usage();
  auto cfg = lle::exch::load_config(std::string(a[1]));
  if (!cfg) {
    std::fprintf(stderr, "exchanged: %s\n", cfg.error().c_str());
    return 1;
  }
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::signal(SIGPIPE, SIG_IGN);
  setvbuf(stdout, nullptr, _IOLBF, 0);
  lle::exch::Node node(std::move(*cfg));
  node.set_stop_flag(&g_stop);
  if (auto r = node.start(); !r) {
    std::fprintf(stderr, "exchanged: %s\n", r.error().c_str());
    return node.restart_loop_refused() ? lle::exch::kExitRestartLoop : 2;
  }
  const int code = node.run(g_stop);
  std::printf("exchanged: stopped (%d)\n", code);
  return code;
}
