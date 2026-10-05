// crossdiff: CrossCalculator vs the brute force on random books
// (05-matching-engine §5 "Validation", E-08: >= 10^8 cases).
//
//   crossdiff --seed-start S --seeds N --cases-per-seed M [--jobs J] [--ledger PATH]
//
// Each seed draws a swarm of book shapes (order count, price spread, tick
// width, market, imbalance-only and cross-order mixes, windows, references,
// cross kinds) and compares the full CrossResult of the two implementations
// for every case. A case counts as one "op" in the ledger (harness crossdiff).
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "common/prng.h"
#include "cross_bruteforce.hpp"
#include "engine/cross.h"
#include "ledger.hpp"

namespace {

using namespace lle::engine;
using lle::PxE4;
using lle::Qty;
using namespace lle::engine::harness;

struct Args {
  std::uint64_t seed_start = 1, seeds = 10, cases = 100'000;
  unsigned jobs = 1;
  std::string ledger;
};

struct Stats {
  std::uint64_t ops = 0, divergences = 0, valid = 0, volume = 0;
  char first[256] = {};
};

void run_seed(const Args& a, std::uint64_t seed, Stats& st) {
  lle::Prng rng(seed);
  const std::uint64_t max_n = 1 + rng.below(rng.chance(1, 4) ? 200 : 30);
  const std::int64_t spread = 1 + static_cast<std::int64_t>(rng.below(40));
  const PxE4 step = rng.chance(1, 3) ? 1 : (rng.chance(1, 2) ? 50 : 100);
  const std::uint64_t p_market = rng.below(20), p_io = rng.below(20), p_cross = rng.below(100), p_zero = rng.below(10);
  CrossCalculator calc;
  std::vector<CrossInterest> v;
  for (std::uint64_t k = 0; k < a.cases; ++k) {
    v.clear();
    const std::uint64_t n = rng.below(max_n + 1);
    const PxE4 base = 100'000;
    for (std::uint64_t i = 0; i < n; ++i) {
      CrossInterest c;
      c.buy = rng.chance(1, 2);
      c.market = rng.below(100) < p_market;
      c.px = base + rng.range(-spread, spread) * step;
      c.qty = rng.below(100) < p_zero ? 0 : static_cast<Qty>(1 + rng.below(rng.chance(1, 4) ? 999'999 : 1'000));
      c.imbalance_only = !c.market && rng.below(100) < p_io;
      c.cross_order = !c.imbalance_only && rng.below(100) < p_cross;
      v.push_back(c);
    }
    CrossParams p;
    p.kind = static_cast<CrossKind>("OCH"[rng.below(3)]);
    p.ref = rng.chance(1, 5) ? 0 : base + rng.range(-spread, spread) * step + (rng.chance(1, 4) ? step / 2 : 0);
    if (rng.chance(1, 2)) {
      p.lo = base + rng.range(-spread, spread / 2 + 1) * step;
      p.hi = p.lo + rng.range(0, spread) * step;
      if (p.lo < 1) p.lo = 1;
      p.hard = rng.chance(1, 3);
    }
    const CrossResult x = calc.compute(v, p);
    const CrossResult y = ref::brute_cross(v, p);
    ++st.ops;
    st.valid += x.valid ? 1 : 0;
    st.volume += x.volume > 0 ? 1 : 0;
    if (!(x == y)) {
      ++st.divergences;
      if (st.first[0] == '\0')
        std::snprintf(st.first, sizeof st.first, "seed %llu case %llu: price %lld/%lld volume %llu/%llu",
                      static_cast<unsigned long long>(seed), static_cast<unsigned long long>(k),
                      static_cast<long long>(x.price), static_cast<long long>(y.price),
                      static_cast<unsigned long long>(x.volume), static_cast<unsigned long long>(y.volume));
      return;
    }
  }
}

Stats run_range(const Args& a, std::uint64_t first, std::uint64_t count) {
  Stats st;
  for (std::uint64_t s = first; s < first + count; ++s) run_seed(a, s, st);
  return st;
}

void append(const Args& a, const Provenance& pv, unsigned worker, std::uint64_t first, std::uint64_t count,
            const Stats& st, double wall) {
  if (a.ledger.empty()) return;
  std::filesystem::create_directories(std::filesystem::path(a.ledger).parent_path());
  FILE* f = std::fopen(a.ledger.c_str(), "a");
  if (f == nullptr) return;
  std::fprintf(f,
               "{\"run_id\":\"crossdiff-%s-%d-%u-%llu\",\"harness\":\"crossdiff\",\"book\":\"engine\",\"sha\":\"%s\","
               "\"dirty\":%s,\"tree\":\"%s\",\"build\":\"%s\",\"variant\":\"cross\",\"seed_start\":%llu,\"seeds\":%llu,"
               "\"cases_per_seed\":%llu,\"ops\":%llu,\"with_volume\":%llu,\"divergences\":%llu,\"wall_s\":%.3f,"
               "\"host\":\"%s\",\"date\":\"%s\"%s%s%s}\n",
               pv.date.c_str(), static_cast<int>(::getpid()), worker, static_cast<unsigned long long>(first),
               json_escape(pv.sha).c_str(), pv.dirty ? "true" : "false", pv.tree.c_str(), json_escape(pv.build).c_str(),
               static_cast<unsigned long long>(first), static_cast<unsigned long long>(count),
               static_cast<unsigned long long>(a.cases), static_cast<unsigned long long>(st.ops),
               static_cast<unsigned long long>(st.volume), static_cast<unsigned long long>(st.divergences), wall,
               json_escape(pv.host).c_str(), pv.date.c_str(), st.divergences ? ",\"first_divergence\":\"" : "",
               st.divergences ? json_escape(st.first).c_str() : "", st.divergences ? "\"" : "");
  std::fclose(f);
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  for (int i = 1; i + 1 < argc; i += 2) {
    const std::string k = argv[i];
    const char* v = argv[i + 1];
    if (k == "--seed-start") a.seed_start = std::strtoull(v, nullptr, 0);
    else if (k == "--seeds") a.seeds = std::strtoull(v, nullptr, 0);
    else if (k == "--cases-per-seed") a.cases = std::strtoull(v, nullptr, 0);
    else if (k == "--jobs") a.jobs = static_cast<unsigned>(std::max<unsigned long>(1, std::strtoul(v, nullptr, 0)));
    else if (k == "--ledger") a.ledger = v;
    else {
      std::fprintf(stderr, "crossdiff: unknown argument %s\n", k.c_str());
      return 2;
    }
  }
  const Provenance pv = provenance();
  const auto t0 = std::chrono::steady_clock::now();
  const unsigned jobs = static_cast<unsigned>(std::min<std::uint64_t>(a.jobs, std::max<std::uint64_t>(a.seeds, 1)));
  struct W {
    pid_t pid;
    int fd;
    std::uint64_t first, count;
  };
  std::vector<W> ws;
  std::uint64_t next = a.seed_start;
  for (unsigned j = 0; j < jobs; ++j) {
    const std::uint64_t count = a.seeds / jobs + (j < a.seeds % jobs ? 1 : 0);
    int fds[2];
    if (::pipe(fds) != 0) return 2;
    const pid_t pid = ::fork();
    if (pid == 0) {
      ::close(fds[0]);
      const Stats st = run_range(a, next, count);
      if (::write(fds[1], &st, sizeof st) != static_cast<ssize_t>(sizeof st)) ::_exit(3);
      ::_exit(0);
    }
    ::close(fds[1]);
    ws.push_back(W{pid, fds[0], next, count});
    next += count;
  }
  Stats total;
  unsigned idx = 0;
  for (const W& w : ws) {
    Stats st;
    const bool ok = ::read(w.fd, &st, sizeof st) == static_cast<ssize_t>(sizeof st);
    ::close(w.fd);
    int status = 0;
    ::waitpid(w.pid, &status, 0);
    if (!ok || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      st = Stats{};
      st.divergences = 1;
      std::snprintf(st.first, sizeof st.first, "worker crashed (status %d)", status);
    }
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    append(a, pv, idx++, w.first, w.count, st, wall);
    total.ops += st.ops;
    total.valid += st.valid;
    total.volume += st.volume;
    total.divergences += st.divergences;
    if (st.divergences) std::fprintf(stderr, "crossdiff: DIVERGENCE %s\n", st.first);
  }
  const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("crossdiff seeds %llu..%llu  cases %llu  with volume %llu  divergences %llu  wall %.2fs\n",
              static_cast<unsigned long long>(a.seed_start), static_cast<unsigned long long>(a.seed_start + a.seeds - 1),
              static_cast<unsigned long long>(total.ops), static_cast<unsigned long long>(total.volume),
              static_cast<unsigned long long>(total.divergences), wall);
  return total.divergences == 0 ? 0 : 1;
}
