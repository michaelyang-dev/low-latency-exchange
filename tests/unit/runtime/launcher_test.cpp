#include "runtime/launcher.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "concurrent/spsc_ring.h"
#include "concurrent/wait.h"
#include "runtime/pinning.h"
#include "runtime/stage.h"

namespace lle::rt {
namespace {

TEST(CoreMap, ParsesConfigSection) {
  auto m = CoreMap::parse("[cores]\n gw0=8 gw1=9 seq=10  # sequencer\n md=11,eng=12;log=0\n");
  ASSERT_TRUE(m.has_value()) << m.error();
  EXPECT_EQ(m->size(), 6u);
  EXPECT_EQ(m->cpu_for("gw0"), 8);
  EXPECT_EQ(m->cpu_for("seq"), 10);
  EXPECT_EQ(m->cpu_for("log"), 0);
  EXPECT_FALSE(m->cpu_for("nope").has_value());
  EXPECT_EQ(m->entries().front().first, "gw0");  // insertion order kept
}

TEST(CoreMap, RejectsMalformed) {
  EXPECT_FALSE(CoreMap::parse("gw0").has_value());
  EXPECT_FALSE(CoreMap::parse("=3").has_value());
  EXPECT_FALSE(CoreMap::parse("gw0=").has_value());
  EXPECT_FALSE(CoreMap::parse("gw0=-1").has_value());
  EXPECT_FALSE(CoreMap::parse("gw0=x").has_value());
  EXPECT_FALSE(CoreMap::parse("gw0=99999").has_value());
  EXPECT_FALSE(CoreMap::parse("g w=1").has_value());
  EXPECT_FALSE(CoreMap::parse("a=1 a=2").has_value());
  EXPECT_FALSE(CoreMap::parse("[cores").has_value());
  EXPECT_FALSE(CoreMap::parse("bad/name=1").has_value());
  auto empty = CoreMap::parse("  # nothing\n[cores]\n");
  ASSERT_TRUE(empty.has_value());
  EXPECT_EQ(empty->size(), 0u);
}

TEST(CoreMap, SetReplaces) {
  CoreMap m;
  m.set("a", 1);
  m.set("b", 2);
  m.set("a", 3);
  EXPECT_EQ(m.size(), 2u);
  EXPECT_EQ(m.cpu_for("a"), 3);
}

// A two-stage pipeline over an SpscRing: the producer stage emits 0..n-1, the consumer
// stage sums them. Both run on launcher threads.
struct Pipe {
  conc::SpscRing<std::uint64_t, 64> q;
};

struct ProducerStage {
  Pipe* pipe;
  std::uint64_t n;
  std::uint64_t next = 0;
  bool poll() {
    if (next == n || !pipe->q.try_push(next)) return false;
    ++next;
    return true;
  }
};

struct ConsumerStage {
  Pipe* pipe;
  std::atomic<std::uint64_t> count{0};
  std::uint64_t sum = 0;
  bool poll() {
    std::uint64_t v = 0;
    if (!pipe->q.try_pop(v)) return false;
    sum += v;
    count.store(count.load(std::memory_order_relaxed) + 1, std::memory_order_release);
    return true;
  }
};

struct NameProbe {
  std::string seen;
  std::atomic<bool> done{false};
  bool poll() {
    if (!done.load(std::memory_order_relaxed)) {
      seen = current_thread_name();
      done.store(true, std::memory_order_release);
    }
    return false;
  }
};

TEST(Launcher, RunsPipelineUntilStop) {
  auto pipe = std::make_unique<Pipe>();
  constexpr std::uint64_t kN = 100'000;
  ProducerStage prod{pipe.get(), kN};
  ConsumerStage cons{pipe.get()};
  Launcher l(*CoreMap::parse("prod=0 cons=1"), LaunchOptions{});
  l.add("prod", prod);
  l.add("cons", cons);
  EXPECT_EQ(l.stage_count(), 2u);
  ASSERT_TRUE(l.start().has_value());
  EXPECT_TRUE(l.running());
  conc::spin_until([&] { return cons.count.load(std::memory_order_acquire) == kN; }, conc::Backoff{});
  l.request_stop();
  l.join();
  EXPECT_FALSE(l.running());
  EXPECT_EQ(cons.sum, kN * (kN - 1) / 2);
  const auto reps = l.reports();
  ASSERT_EQ(reps.size(), 2u);
  EXPECT_EQ(reps[0].name, "prod");
  EXPECT_EQ(reps[0].cpu, 0);
  EXPECT_EQ(reps[1].cpu, 1);
  EXPECT_EQ(reps[0].busy_polls, kN);
  EXPECT_EQ(reps[1].busy_polls, kN);
  EXPECT_GE(reps[0].polls, reps[0].busy_polls);
#if defined(__linux__)
  // Pinning works where the CPUs exist and the cpuset allows them.
  if (online_cpus() >= 2) EXPECT_EQ(reps[0].pin, PinStatus::Ok);
#else
  EXPECT_EQ(reps[0].pin, PinStatus::Unsupported);
#endif
}

TEST(Launcher, NamesThreadsAndPretouches) {
  NameProbe probe;
  std::vector<std::uint64_t> pool(1 << 16, 7);
  Launcher l(CoreMap{}, LaunchOptions{.idle = IdlePolicy::Backoff});
  l.add("probe-stage", probe);
  l.add_pretouch("probe-stage", pool.data(), pool.size() * sizeof(std::uint64_t));
  ASSERT_TRUE(l.start().has_value());
  conc::spin_until([&] { return probe.done.load(std::memory_order_acquire); }, conc::Backoff{});
  l.request_stop();
  l.join();
  EXPECT_EQ(probe.seen, "probe-stage");
  EXPECT_EQ(pool.front(), 7u);  // pre-touch does not change contents
  EXPECT_EQ(pool.back(), 7u);
  EXPECT_EQ(l.reports()[0].pin, PinStatus::NotRequested);
}

TEST(Launcher, IdlePoliciesAllStop) {
  for (const IdlePolicy p : {IdlePolicy::Spin, IdlePolicy::SpinPause, IdlePolicy::Backoff}) {
    NameProbe probe;
    Launcher l(CoreMap{}, LaunchOptions{.idle = p});
    l.add("idle", probe);
    ASSERT_TRUE(l.start().has_value());
    conc::spin_until([&] { return probe.done.load(std::memory_order_acquire); }, conc::Backoff{});
    l.request_stop();
    l.join();
    EXPECT_GE(l.reports()[0].polls, 1u);
    EXPECT_EQ(l.reports()[0].busy_polls, 0u);
  }
}

TEST(Launcher, RejectsBadConfigurations) {
  NameProbe a, b;
  {
    Launcher l;
    l.add("x", a);
    l.add("x", b);
    EXPECT_FALSE(l.start().has_value());  // duplicate stage names
  }
  {
    Launcher l(CoreMap{}, LaunchOptions{.require_core_map_entry = true});
    l.add("x", a);
    EXPECT_FALSE(l.start().has_value());  // no CPU for x
  }
  {
    Launcher l;
    l.add("x", a);
    ASSERT_TRUE(l.start().has_value());
    EXPECT_FALSE(l.start().has_value());  // already started
  }  // destructor stops and joins
}

TEST(Launcher, RequirePinningFailsCleanlyWhereUnsupported) {
  NameProbe a;
  Launcher l(*CoreMap::parse("x=0"), LaunchOptions{.require_pinning = true});
  l.add("x", a);
  const auto r = l.start();
#if defined(__linux__)
  if (r.has_value()) {
    l.request_stop();
    l.join();
  }
#else
  ASSERT_FALSE(r.has_value());
  EXPECT_NE(r.error().find("not pinned"), std::string::npos);
  EXPECT_FALSE(a.done.load());  // the barrier never released the stage
  EXPECT_FALSE(l.running());
#endif
}

TEST(Pinning, Helpers) {
  EXPECT_GE(online_cpus(), 1u);
  EXPECT_STREQ(to_string(PinStatus::Ok), "ok");
  EXPECT_STREQ(to_string(PinStatus::Unsupported), "unsupported");
  EXPECT_EQ(pin_current_thread(-1), PinStatus::Failed);
#if !defined(__linux__)
  EXPECT_EQ(pin_current_thread(0), PinStatus::Unsupported);
  EXPECT_EQ(lock_all_memory(), PinStatus::Unsupported);
  EXPECT_EQ(current_cpu(), -1);
#endif
  prefault(nullptr, 100);  // no-op
}

TEST(InlineRunnerRuntime, DrivesSameStagesOnOneThread) {
  auto pipe = std::make_unique<Pipe>();
  ProducerStage prod{pipe.get(), 1000};
  ConsumerStage cons{pipe.get()};
  InlineRunner runner(prod, cons);
  runner.run_until([&] { return cons.count.load() == 1000; });
  EXPECT_EQ(cons.sum, 1000u * 999u / 2);
}

}  // namespace
}  // namespace lle::rt
