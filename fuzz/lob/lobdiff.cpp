// lobdiff: seeded random-walk differential fuzzer for the ITCH book builder
// (04-order-book §8, T14).
//
//   lobdiff --variant=<name|all> --seed-start S --seeds N --ops-per-seed M
//           [--full-check-every 65536] [--jobs J] [--ledger fuzz/ledger/runs.jsonl]
//           [--seed-timeout 600] [--verbose] [--list]
//
// Every seed draws a swarm configuration (gen.hpp), builds a fresh variant
// book and a fresh RefBook, and applies M generated operations (plus the
// end-of-day drain when the swarm enables it) to both, comparing result
// codes, per-operation BBO events and the running stream digest after every
// operation, and the final-books digest plus both invariant checkers every
// --full-check-every operations and at the end of the seed. An "op" counted
// in the ledger is one operation applied to both books and compared
// (R4b §5.6); a diverging seed counts its ops up to the divergence.
//
// With --jobs J the seed range is split into J contiguous slices run in
// forked worker processes; each worker gets its own ledger record.
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "book/variants.h"
#include "common/hash.h"
#include "diff.hpp"
#include "gen.hpp"
#include "provenance.hpp"

namespace {

using lle::lobfuzz::DiffPair;
using lle::lobfuzz::json_escape;
using lle::lobfuzz::Provenance;
using lle::lobfuzz::provenance;
using lle::lobfuzz::Gen;
using lle::lobfuzz::Op;

struct Args {
  std::string variant = "all";
  std::uint64_t seed_start = 1;
  std::uint64_t seeds = 16;
  std::uint64_t ops_per_seed = 100'000;
  std::uint64_t full_every = 65'536;
  unsigned jobs = 1;
  std::string ledger;
  unsigned seed_timeout_s = 600;  // a hung seed kills its process (SIGALRM) instead of stalling the run
  bool verbose = false;
};

struct Stats {
  std::uint64_t ops = 0;
  std::uint64_t full_checks = 0;
  std::uint64_t divergences = 0;
  std::uint64_t seeds_done = 0;
  std::uint64_t events = 0;
  char first_divergence[512] = {};
};

template <class V>
void run_seed_body(const Args& a, std::uint64_t seed, Stats& st);

template <class V>
void run_seed(const Args& a, std::uint64_t seed, Stats& st) {
  ::alarm(a.seed_timeout_s);
  run_seed_body<V>(a, seed, st);
  ::alarm(0);
}

template <class V>
void run_seed_body(const Args& a, std::uint64_t seed, Stats& st) {
  Gen gen(seed);
  DiffPair<V> pair(lle::lobfuzz::book_config_for(gen.swarm()));
  if (a.verbose) std::fprintf(stderr, "[%s] seed %llu: %s\n", V::kName.data(), static_cast<unsigned long long>(seed),
                              gen.swarm().describe().c_str());
  std::string why;
  std::uint64_t n = 0;
  auto diverge = [&](const Op* op, const char* where) {
    ++st.divergences;
    char buf[512];
    std::snprintf(buf, sizeof buf, "variant %s seed %llu op %llu (%s): %s%s%s", V::kName.data(),
                  static_cast<unsigned long long>(seed), static_cast<unsigned long long>(n), where, why.c_str(),
                  op != nullptr ? " | " : "", op != nullptr ? lle::lobfuzz::to_string(*op).c_str() : "");
    std::fprintf(stderr, "DIVERGENCE %s\n  swarm: %s\n", buf, gen.swarm().describe().c_str());
    if (st.first_divergence[0] == '\0') std::snprintf(st.first_divergence, sizeof st.first_divergence, "%s", buf);
  };
  auto step = [&](const Op& op) {
    ++n;
    ++st.ops;
    if (!pair.step(op, &why)) {
      diverge(&op, "step");
      return false;
    }
    if (n % a.full_every == 0) {
      ++st.full_checks;
      if (!pair.full_check(&why)) {
        diverge(&op, "full check");
        return false;
      }
    }
    return true;
  };
  for (std::uint64_t i = 0; i < a.ops_per_seed; ++i) {
    if (!step(gen.next())) return;
  }
  if (gen.swarm().drain) {
    Op op;
    while (gen.next_drain(op)) {
      if (!step(op)) return;
    }
    if (pair.book().live_orders() != 0) {
      why = "book not empty after drain";
      diverge(nullptr, "drain");
      return;
    }
  }
  ++st.full_checks;
  if (!pair.full_check(&why)) {
    diverge(nullptr, "final check");
    return;
  }
  st.events += pair.ref().event_count();
  ++st.seeds_done;
}

template <class V>
Stats run_range(const Args& a, std::uint64_t first, std::uint64_t count) {
  Stats st;
  for (std::uint64_t s = first; s < first + count; ++s) run_seed<V>(a, s, st);
  return st;
}

void append_ledger(const Args& a, const Provenance& pv, std::string_view variant, unsigned worker, std::uint64_t first,
                   std::uint64_t count, const Stats& st, double wall_s) {
  if (a.ledger.empty()) return;
  if (!pv.fresh) {
    std::fprintf(stderr, "%s: not writing the ledger: %s is newer than this binary (rebuild first)\n", "lobdiff",
                 pv.stale_file.c_str());
    return;
  }
  std::filesystem::create_directories(std::filesystem::path(a.ledger).parent_path());
  FILE* f = std::fopen(a.ledger.c_str(), "a");
  if (f == nullptr) {
    std::fprintf(stderr, "lobdiff: cannot open ledger %s\n", a.ledger.c_str());
    return;
  }
  char run_id[96];
  std::snprintf(run_id, sizeof run_id, "lobdiff-%s-%d-%u-%llu", pv.date.c_str(), static_cast<int>(::getpid()), worker,
                static_cast<unsigned long long>(first));
  std::fprintf(f,
               "{\"run_id\":\"%s\",\"harness\":\"lobdiff\",\"mode\":\"itch\",\"sha\":\"%s\",\"dirty\":%s,"
               "\"tree\":\"%s\",\"build\":\"%s\",\"variant\":\"%s\",\"seed_start\":%llu,\"seeds\":%llu,"
               "\"ops_per_seed\":%llu,\"full_check_every\":%llu,\"ops\":%llu,\"full_checks\":%llu,"
               "\"bbo_events\":%llu,\"divergences\":%llu,\"wall_s\":%.3f,\"host\":\"%s\",\"date\":\"%s\"%s%s%s}\n",
               run_id, json_escape(pv.sha).c_str(), pv.dirty ? "true" : "false", pv.tree.c_str(),
               json_escape(pv.build).c_str(), json_escape(variant).c_str(), static_cast<unsigned long long>(first),
               static_cast<unsigned long long>(count), static_cast<unsigned long long>(a.ops_per_seed),
               static_cast<unsigned long long>(a.full_every), static_cast<unsigned long long>(st.ops),
               static_cast<unsigned long long>(st.full_checks), static_cast<unsigned long long>(st.events),
               static_cast<unsigned long long>(st.divergences), wall_s, json_escape(pv.host).c_str(), pv.date.c_str(),
               st.divergences != 0 ? ",\"first_divergence\":\"" : "",
               st.divergences != 0 ? json_escape(st.first_divergence).c_str() : "", st.divergences != 0 ? "\"" : "");
  std::fclose(f);
}

template <class V>
std::uint64_t run_variant(const Args& a, const Provenance& pv) {
  const unsigned jobs = static_cast<unsigned>(std::min<std::uint64_t>(a.jobs, a.seeds == 0 ? 1 : a.seeds));
  const auto t0 = std::chrono::steady_clock::now();
  Stats total;
  std::uint64_t divergences = 0;
  if (jobs <= 1) {
    total = run_range<V>(a, a.seed_start, a.seeds);
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    append_ledger(a, pv, V::kName, 0, a.seed_start, a.seeds, total, wall);
    divergences = total.divergences;
  } else {
    struct Worker {
      pid_t pid;
      int fd;
      std::uint64_t first, count;
    };
    std::vector<Worker> ws;
    std::uint64_t next = a.seed_start;
    for (unsigned j = 0; j < jobs; ++j) {
      const std::uint64_t count = a.seeds / jobs + (j < a.seeds % jobs ? 1 : 0);
      int fds[2];
      if (::pipe(fds) != 0) {
        std::perror("pipe");
        std::exit(2);
      }
      const pid_t pid = ::fork();
      if (pid == 0) {
        ::close(fds[0]);
        const Stats st = run_range<V>(a, next, count);
        const char* p = reinterpret_cast<const char*>(&st);
        std::size_t left = sizeof st;
        while (left > 0) {
          const ssize_t w = ::write(fds[1], p, left);
          if (w <= 0) break;
          p += w;
          left -= static_cast<std::size_t>(w);
        }
        ::_exit(0);
      }
      ::close(fds[1]);
      ws.push_back(Worker{pid, fds[0], next, count});
      next += count;
    }
    unsigned idx = 0;
    for (const Worker& w : ws) {
      Stats st;
      char* p = reinterpret_cast<char*>(&st);
      std::size_t left = sizeof st;
      bool ok = true;
      while (left > 0) {
        const ssize_t r = ::read(w.fd, p, left);
        if (r <= 0) {
          ok = false;
          break;
        }
        p += r;
        left -= static_cast<std::size_t>(r);
      }
      ::close(w.fd);
      int status = 0;
      ::waitpid(w.pid, &status, 0);
      if (!ok || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "lobdiff: worker %u (seeds %llu..+%llu) crashed\n", idx,
                     static_cast<unsigned long long>(w.first), static_cast<unsigned long long>(w.count));
        st = Stats{};
        st.divergences = 1;
        std::snprintf(st.first_divergence, sizeof st.first_divergence, "worker crashed (status %d)", status);
      }
      const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
      append_ledger(a, pv, V::kName, idx, w.first, w.count, st, wall);
      total.ops += st.ops;
      total.full_checks += st.full_checks;
      total.divergences += st.divergences;
      total.seeds_done += st.seeds_done;
      total.events += st.events;
      ++idx;
    }
    divergences = total.divergences;
  }
  const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("%-14s seeds %llu..%llu  ops %llu  full_checks %llu  bbo_events %llu  divergences %llu  wall %.2fs  (%.2fM ops/s)\n",
              V::kName.data(), static_cast<unsigned long long>(a.seed_start),
              static_cast<unsigned long long>(a.seed_start + a.seeds - 1), static_cast<unsigned long long>(total.ops),
              static_cast<unsigned long long>(total.full_checks), static_cast<unsigned long long>(total.events),
              static_cast<unsigned long long>(divergences), wall, wall > 0 ? static_cast<double>(total.ops) / wall / 1e6 : 0.0);
  std::fflush(stdout);
  return divergences;
}

bool parse(int argc, char** argv, Args& a) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    std::string val;
    const auto eq = arg.find('=');
    auto take = [&](const char* name) -> bool {
      if (arg == name) {
        if (i + 1 >= argc) return false;
        val = argv[++i];
        return true;
      }
      if (eq != std::string::npos && arg.substr(0, eq) == name) {
        val = arg.substr(eq + 1);
        return true;
      }
      return false;
    };
    if (take("--variant")) {
      a.variant = val;
    } else if (take("--seed-start")) {
      a.seed_start = std::strtoull(val.c_str(), nullptr, 0);
    } else if (take("--seeds")) {
      a.seeds = std::strtoull(val.c_str(), nullptr, 0);
    } else if (take("--ops-per-seed")) {
      a.ops_per_seed = std::strtoull(val.c_str(), nullptr, 0);
    } else if (take("--full-check-every")) {
      a.full_every = std::max<std::uint64_t>(1, std::strtoull(val.c_str(), nullptr, 0));
    } else if (take("--jobs")) {
      a.jobs = static_cast<unsigned>(std::max<unsigned long>(1, std::strtoul(val.c_str(), nullptr, 0)));
    } else if (take("--ledger")) {
      a.ledger = val;
    } else if (take("--seed-timeout")) {
      a.seed_timeout_s = static_cast<unsigned>(std::strtoul(val.c_str(), nullptr, 0));
    } else if (arg == "--verbose") {
      a.verbose = true;
    } else if (arg == "--list") {
      lle::book::for_each_variant([]<class V>() { std::printf("%-14s %s\n", V::kName.data(), V::kDesc.data()); });
      std::exit(0);
    } else {
      std::fprintf(stderr, "lobdiff: unknown argument %s\n", argv[i]);
      return false;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  if (!parse(argc, argv, a)) {
    std::fprintf(stderr,
                 "usage: lobdiff --variant=<name|all> --seed-start S --seeds N --ops-per-seed M "
                 "[--full-check-every K] [--jobs J] [--ledger FILE] [--seed-timeout S] [--verbose] [--list]\n");
    return 2;
  }
  const Provenance pv = provenance();
  std::uint64_t divergences = 0;
  if (a.variant == "all") {
    lle::book::for_each_variant([&]<class V>() { divergences += run_variant<V>(a, pv); });
  } else if (!lle::book::visit_variant(a.variant, [&]<class V>() { divergences += run_variant<V>(a, pv); })) {
    std::fprintf(stderr, "lobdiff: unknown variant '%s' (try --list)\n", a.variant.c_str());
    return 2;
  }
  return divergences == 0 ? 0 : 1;
}
