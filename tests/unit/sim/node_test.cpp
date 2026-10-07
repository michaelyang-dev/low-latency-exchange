#include <gtest/gtest.h>

#include <vector>

#include "sim/dist.h"
#include "sim/node.h"
#include "sim/world.h"
#include "test_util.h"

namespace lle::sim {
namespace {

struct Tally {
  int boots = 0;
  int restarts = 0;
  int destroyed = 0;
  std::vector<Nanos> polls;
  Node* crash_me = nullptr;
};

struct App : Process {
  struct Stage {
    App* app;
    bool poll() {
      app->t.polls.push_back(app->w.now());
      if (app->t.crash_me != nullptr && app->t.polls.size() == 3) app->t.crash_me->request_crash();
      return false;
    }
  };
  App(Node& n, Tally& tally) : w(n.world()), t(tally), stage{this} { n.add_stage(stage, "app"); }
  ~App() override { ++t.destroyed; }
  World& w;
  Tally& t;
  Stage stage;
};

Node& make(World& w, Tally& t, NodeOptions o = {}) {
  Node& n = w.add_node("n", o);
  n.set_boot([&t](Node& nd, BootReason why) {
    (why == BootReason::Initial ? t.boots : t.restarts)++;
    nd.emplace_process<App>(nd, t);
  });
  return n;
}

TEST(Node, BootCreatesProcessAndRegistersStages) {
  Tally t;  // outlives w: the processes w destroys count into it
  World w(1, base_fault_config());
  Node& n = make(w, t);
  n.boot();
  EXPECT_TRUE(n.alive());
  EXPECT_EQ(t.boots, 1);
  EXPECT_EQ(w.scheduler().stage_count(n.id()), 1u);
  test::run_for(w, kMs);
  EXPECT_GT(t.polls.size(), 5u);
}

TEST(Node, CrashDropsMemoryAndRestartRunsRecovery) {
  Tally t;  // outlives w: the processes w destroys count into it
  World w(2, base_fault_config());
  Node& n = make(w, t);
  n.boot();
  test::run_for(w, kMs);
  n.crash(CrashKind::Process);
  EXPECT_FALSE(n.alive());
  EXPECT_EQ(t.destroyed, 1);
  EXPECT_EQ(n.process(), nullptr);
  EXPECT_EQ(w.scheduler().stage_count(n.id()), 0u);
  const std::size_t polls = t.polls.size();
  const Nanos crashed_at = w.now();
  n.restart_after(50 * kMs);
  test::run_for(w, 49 * kMs);
  EXPECT_EQ(t.polls.size(), polls);  // dead: never polled
  test::run_for(w, 2 * kMs);
  EXPECT_TRUE(n.alive());
  EXPECT_EQ(t.restarts, 1);
  EXPECT_EQ(n.incarnation(), 1u);
  test::run_for(w, kMs);
  ASSERT_GT(t.polls.size(), polls);
  EXPECT_GE(t.polls[polls], crashed_at + 50 * kMs);
  EXPECT_EQ(w.stats().crashes_process, 1u);
  EXPECT_EQ(w.stats().restarts, 1u);
}

TEST(Node, PauseFreezesPollingForItsDuration) {
  Tally t;  // outlives w: the processes w destroys count into it
  World w(3, base_fault_config());
  Node& n = make(w, t);
  n.boot();
  test::run_for(w, kMs);
  const Nanos start = w.now();
  n.pause(200 * kMs);
  EXPECT_TRUE(n.paused());
  const std::size_t before = t.polls.size();
  test::run_for(w, 199 * kMs);
  EXPECT_EQ(t.polls.size(), before);
  test::run_for(w, 2 * kMs);
  EXPECT_FALSE(n.paused());
  ASSERT_GT(t.polls.size(), before);
  EXPECT_GE(t.polls[before], start + 200 * kMs);
  EXPECT_EQ(t.destroyed, 0);  // memory intact
}

TEST(Node, ProcessAbortIsDeferredAndSupervisorRestarts) {
  Tally t;  // outlives w: the processes w destroys count into it
  World w(4, base_fault_config());
  Node& n = make(w, t);
  t.crash_me = &n;
  n.boot();
  test::run_until(w, [&] { return !n.alive(); }, kSec);
  EXPECT_EQ(t.polls.size(), 3u);  // crashed right after the third poll returned
  EXPECT_EQ(t.destroyed, 1);
  t.crash_me = nullptr;
  const Nanos at = w.now();
  test::run_until(w, [&] { return n.alive(); }, kSec);
  EXPECT_GE(w.now() - at, 10 * kMs);
  EXPECT_LE(w.now() - at, 100 * kMs);
  EXPECT_EQ(t.restarts, 1);
}

TEST(Node, HealRestartsCrashedAndResumesPausedNodes) {
  Tally ta, tb;  // outlive w: the processes w destroys count into them
  World w(5, base_fault_config());
  Node& a = make(w, ta);
  Node& b = make(w, tb);
  a.boot();
  b.boot();
  a.crash(CrashKind::Host);
  b.pause(10 * kSec);
  w.heal();
  test::run_for(w, 5 * kMs);
  EXPECT_TRUE(a.alive());
  EXPECT_FALSE(b.paused());
  EXPECT_EQ(ta.restarts, 1);
}

TEST(Node, CohostGoesDownWithItsHostAndBootsWithIt) {
  Tally th, tc;  // outlive w: the processes w destroys count into them
  World w(7, base_fault_config());
  Node& host = make(w, th);
  Node& co = make(w, tc);
  host.add_cohost(co);
  EXPECT_EQ(co.host(), &host);
  EXPECT_EQ(host.host(), nullptr);
  host.boot();
  co.boot();
  test::run_for(w, kMs);
  // The host's process crashes alone: the cohost runs on.
  host.crash(CrashKind::Process);
  EXPECT_TRUE(co.alive());
  host.restart_after(5 * kMs);
  test::run_for(w, 10 * kMs);
  EXPECT_TRUE(host.alive());
  EXPECT_EQ(tc.destroyed, 0);
  // So does the cohost's: the host runs on.
  co.crash(CrashKind::Process);
  EXPECT_TRUE(host.alive());
  // A power loss takes both down. The restart the cohost had pending waits for the host,
  // and it boots when the host does.
  co.restart_after(2 * kMs);
  host.crash(CrashKind::Host);
  EXPECT_FALSE(co.alive());
  test::run_for(w, 20 * kMs);
  EXPECT_FALSE(co.alive());
  EXPECT_EQ(tc.restarts, 0);
  host.restart_after(kMs);
  test::run_for(w, 5 * kMs);
  EXPECT_TRUE(host.alive());
  EXPECT_TRUE(co.alive());
  EXPECT_EQ(tc.restarts, 1);
  EXPECT_EQ(co.host_crashes(), 0u);  // its own disk is untouched; the host's took the power loss
  EXPECT_EQ(host.host_crashes(), 1u);
  EXPECT_EQ(w.stats().crashes_host, 1u);  // the cohost's stop is not a fault of its own
}

TEST(Node, WorkloadStreamsDifferPerIncarnation) {
  Tally t;  // outlives w: the processes w destroys count into it
  World w(6, base_fault_config());
  Node& n = make(w, t);
  n.boot();
  const std::uint64_t first = n.rng(0).next_u64();
  EXPECT_EQ(first, n.rng(0).next_u64());
  n.crash(CrashKind::Process);
  n.restart_after(1);
  test::run_for(w, kMs);
  EXPECT_NE(first, n.rng(0).next_u64());
}

}  // namespace
}  // namespace lle::sim
