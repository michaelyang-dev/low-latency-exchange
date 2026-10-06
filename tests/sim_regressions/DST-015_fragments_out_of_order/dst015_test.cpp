// DST-015 regression test (scripted, seed-independent): a replica must reassemble a
// record that came in fragments whatever order the fragments arrive in. Found by
// `exsim --world=exchange_ha` (O-LIVE) once the world ran production's 1 Hz clock; see
// sim/ledger/bugs.yaml.
//
// An APPEND carries whole records up to the datagram limit (1,400 bytes), or one
// fragment of a larger record. The data plane loses, duplicates and reorders datagrams
// (the network of plan 10 §6). At the found tree the receiver took a record's fragments
// only in order: one that arrived ahead of its predecessor counted as a gap, and offset
// 0 started the record over. With the 1 Hz clock the day's schedule is about 0.9 MB of
// config records near the 32 KiB limit, some 24 fragments each. Under the simulator's
// delay jitter almost no burst of 24 arrived in order, so a joiner catching up from the
// start of the day stalled at the first of them for the rest of the day: no JOIN, and
// the primary ran without a partner.
#include <gtest/gtest.h>

#include <cstdint>
#include <utility>
#include <vector>

#include "../../unit/repl/repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kA = 0;
constexpr NodeId kB = 1;

// Every datagram A sends B is held and handed over newest first, once per step: a record
// cut into fragments always arrives backwards.
TEST(DST015, ARecordInFragmentsIsReassembledFromAnyOrder) {
  Cluster c;
  c.sequence(kA, 2);
  c.run(2 * kMs);
  ASSERT_EQ(c.host(kB).log, c.host(kA).log);
  std::vector<Bytes> held;
  c.data_filter = [&](int dir, const Bytes& b) {
    if (dir != 0) return true;
    held.push_back(b);
    return false;
  };
  c.host(kA).sequence_big(1, 30'000);  // about 23 fragments
  c.sequence(kA, 2);
  for (int i = 0; i < 2'000 && c.host(kB).log != c.host(kA).log; ++i) {
    c.step(50 * kUs);
    while (!held.empty()) {
      const Bytes b = std::move(held.back());
      held.pop_back();
      if (c.n[kB].up && c.n[kB].rep) c.rep(kB).on_peer(b, c.now);
    }
  }
  EXPECT_EQ(c.host(kB).log.size(), c.host(kA).log.size())
      << "B stopped at the record that came in fragments: they never arrived in order";
  EXPECT_TRUE(c.host(kB).log == c.host(kA).log) << "B's records differ from A's";
}

}  // namespace
}  // namespace lle::repl::test
