// Utcp.LossReorderSeeds (07 §2.4): many randomized client/server sessions over a lossy,
// reordering, duplicating, corrupting in-memory link. Every session must deliver both
// byte streams exactly and in order, never deadlock, and tear down (graceful close or
// abort) with every connection slot reclaimed.
//
// UTCP_SEEDS and UTCP_SEED0 (default 1) select the seed range. The default count is
// 10,000 in optimized builds and 1,000 in Debug/sanitizer builds (CI time budget); the
// 100,000-seed release run is recorded in docs/verification/network.md.
#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "session_driver.h"

namespace lle::net::utcp::test {
namespace {

std::uint64_t env_u64(const char* name, std::uint64_t def) {
  const char* v = std::getenv(name);
  return v != nullptr ? std::strtoull(v, nullptr, 10) : def;
}

#if defined(NDEBUG) && !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
constexpr std::uint64_t kDefaultSeeds = 10000;
#else
constexpr std::uint64_t kDefaultSeeds = 1000;
#endif

TEST(Utcp, LossReorderSeeds) {
  const std::uint64_t n = env_u64("UTCP_SEEDS", kDefaultSeeds);
  const std::uint64_t seed0 = env_u64("UTCP_SEED0", 1);
  std::vector<std::string> failures;
  SessionResult total;
  std::uint64_t aborts = 0;
  std::uint64_t lossy = 0;
  for (std::uint64_t seed = seed0; seed < seed0 + n; ++seed) {
    const SessionParams p = random_params(seed);
    SessionDriver d(p);
    const SessionResult r = d.run();
    if (!r.ok) {
      failures.push_back(r.error);
      if (failures.size() >= 10) break;
      continue;
    }
    aborts += p.abort_mode ? 1u : 0u;
    lossy += p.imp.loss_ppm != 0 ? 1u : 0u;
    total.bytes_c2s += r.bytes_c2s;
    total.bytes_s2c += r.bytes_s2c;
    total.retransmits += r.retransmits;
    total.rto_expiries += r.rto_expiries;
    total.fast_retransmits += r.fast_retransmits;
    total.zero_window_probes += r.zero_window_probes;
    total.ooo_dropped += r.ooo_dropped;
    total.link.sent += r.link.sent;
    total.link.lost += r.link.lost;
    total.link.duplicated += r.link.duplicated;
    total.link.reordered += r.link.reordered;
    total.link.corrupted += r.link.corrupted;
  }
  std::printf(
      "utcp random sessions: %llu seeds from %llu, %zu failures; %llu aborted, %llu lossy; bytes c2s %llu s2c %llu; "
      "frames %llu (lost %llu dup %llu reordered %llu corrupted %llu); retransmitted segs %llu, RTOs %llu, fast "
      "retransmits %llu, zero-window probes %llu, out-of-order dropped %llu\n",
      static_cast<unsigned long long>(n), static_cast<unsigned long long>(seed0), failures.size(),
      static_cast<unsigned long long>(aborts), static_cast<unsigned long long>(lossy),
      static_cast<unsigned long long>(total.bytes_c2s), static_cast<unsigned long long>(total.bytes_s2c),
      static_cast<unsigned long long>(total.link.sent), static_cast<unsigned long long>(total.link.lost),
      static_cast<unsigned long long>(total.link.duplicated), static_cast<unsigned long long>(total.link.reordered),
      static_cast<unsigned long long>(total.link.corrupted), static_cast<unsigned long long>(total.retransmits),
      static_cast<unsigned long long>(total.rto_expiries), static_cast<unsigned long long>(total.fast_retransmits),
      static_cast<unsigned long long>(total.zero_window_probes), static_cast<unsigned long long>(total.ooo_dropped));
  for (const auto& f : failures) ADD_FAILURE() << f;
  EXPECT_GT(total.zero_window_probes, 0u);
  EXPECT_GT(total.fast_retransmits, 0u);
  EXPECT_GT(total.rto_expiries, 0u);
}

// A clean link with large transfers in both directions (throughput path, no loss).
TEST(Utcp, CleanBulkBothWays) {
  SessionParams p;
  p.seed = 42;
  p.imp.delay = 20'000;
  p.client_bytes = 3'000'000;
  p.server_bytes = 3'000'000;
  p.max_write = 4096;
  SessionDriver d(p);
  const SessionResult r = d.run();
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.bytes_c2s, 3'000'000u);
  EXPECT_EQ(r.bytes_s2c, 3'000'000u);
  EXPECT_EQ(r.retransmits, 0u);
}

// Heavy loss and reordering on large transfers.
TEST(Utcp, HeavyLossBulk) {
  SessionParams p;
  p.seed = 7;
  p.imp.delay = 100'000;
  p.imp.loss_ppm = 100'000;
  p.imp.reorder_ppm = 200'000;
  p.imp.reorder_delay = 1'000'000;
  p.imp.dup_ppm = 50'000;
  p.client_conn.min_rto = 5'000'000;
  p.server_conn.min_rto = 5'000'000;
  p.client_conn.max_retransmits = 30;
  p.server_conn.max_retransmits = 30;
  p.client_bytes = 500'000;
  p.server_bytes = 300'000;
  p.max_write = 3000;
  SessionDriver d(p);
  const SessionResult r = d.run();
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_GT(r.retransmits, 0u);
}

}  // namespace
}  // namespace lle::net::utcp::test
