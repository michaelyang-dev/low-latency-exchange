#include <gtest/gtest.h>

#include <set>
#include <string>

#include "sim/dist.h"
#include "sim/fault/buggify.h"
#include "sim/fault/buggify_registry.h"
#include "sim/fault/injector.h"
#include "sim/fault/probes.h"
#include "sim/fault/swarm.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/world.h"
#include "test_util.h"

namespace lle::sim {
namespace {

bool in_class(FaultClass c, std::uint32_t mask) { return (mask & class_bit(c)) != 0; }

TEST(Swarm, ValuesStayInRangeOrAtBase) {
  for (std::uint64_t seed = 1; seed <= 500; ++seed) {
    for (const Mode m : {Mode::Swarm, Mode::Lite}) {
      const FaultConfig f = draw_fault_config(seed, m, 0);
      for (std::size_t i = 0; i < kNumParams; ++i) {
        const ParamSpec& p = kSwarmParams[i];
        const std::int64_t hi = m == Mode::Lite ? p.lite_hi : p.hi;
        const std::int64_t v = f.v[i];
        ASSERT_TRUE(v == p.base || (v >= std::max<std::int64_t>(p.lo, p.shape == Shape::LogUniform ? 1 : p.lo) &&
                                    v <= hi))
            << p.name << "=" << v << " seed " << seed;
      }
    }
  }
}

TEST(Swarm, DisablingAClassLeavesEveryOtherDrawUnchanged) {
  const FaultClass classes[] = {FaultClass::Net, FaultClass::Disk, FaultClass::Crash, FaultClass::Clock,
                                FaultClass::Buggify};
  for (std::uint64_t seed = 1; seed <= 100; ++seed) {
    const FaultConfig all = draw_fault_config(seed, Mode::Swarm, 0);
    for (const FaultClass c : classes) {
      const FaultConfig off = draw_fault_config(seed, Mode::Swarm, class_bit(c));
      const std::uint32_t mask = expand_disable_mask(class_bit(c));
      for (std::size_t i = 0; i < kNumParams; ++i) {
        const ParamSpec& p = kSwarmParams[i];
        if (in_class(p.cls, mask)) {
          ASSERT_EQ(off.v[i], p.base) << p.name;
        } else {
          ASSERT_EQ(off.v[i], all.v[i]) << p.name << " changed when disabling " << fault_class_name(c);
        }
      }
    }
  }
}

TEST(Swarm, NoFaultsModeKeepsSchedulerDiversity) {
  const FaultConfig a = draw_fault_config(1, Mode::NoFaults, 0);
  const FaultConfig b = draw_fault_config(2, Mode::NoFaults, 0);
  for (std::size_t i = 0; i < kNumParams; ++i) {
    if (kSwarmParams[i].cls != FaultClass::Sched) EXPECT_EQ(a.v[i], kSwarmParams[i].base);
  }
  EXPECT_NE(a.digest(), b.digest());
  EXPECT_FALSE(a.enabled(FaultClass::Net));
}

TEST(Swarm, SwarmSometimesTurnsKnobsOff) {
  int off = 0;
  int on = 0;
  for (std::uint64_t seed = 1; seed <= 400; ++seed) {
    const FaultConfig f = draw_fault_config(seed, Mode::Swarm, 0);
    (f[Param::NetLossPpm] == 0 ? off : on)++;
  }
  EXPECT_GT(off, 50);  // off_ppm = 25%
  EXPECT_GT(on, 200);
}

TEST(Swarm, ParseDisableList) {
  EXPECT_EQ(parse_disable_list(""), 0u);
  EXPECT_EQ(parse_disable_list("-"), 0u);
  EXPECT_EQ(parse_disable_list("net,clock"), class_bit(FaultClass::Net) | class_bit(FaultClass::Clock));
  EXPECT_FALSE(parse_disable_list("net,bogus").has_value());
  EXPECT_FALSE(parse_disable_list("sched").has_value());
  EXPECT_EQ(format_disable_list(class_bit(FaultClass::Disk) | class_bit(FaultClass::Buggify)), "disk,buggify");
  EXPECT_EQ(expand_disable_mask(class_bit(FaultClass::Net)),
            class_bit(FaultClass::Net) | class_bit(FaultClass::Partition));
  EXPECT_EQ(expand_disable_mask(class_bit(FaultClass::Crash)),
            class_bit(FaultClass::Crash) | class_bit(FaultClass::Pause));
  EXPECT_EQ(parse_mode("lite"), Mode::Lite);
  EXPECT_FALSE(parse_mode("x").has_value());
}

TEST(Buggify, FoundationDbRates) {
  BuggifyRegistry reg(77, true, 250'000, 250'000);
  int active = 0;
  const int sites = 4000;
  for (int i = 0; i < sites; ++i) {
    active += reg.site("s" + std::to_string(i), "f.cpp", static_cast<unsigned>(i))->active ? 1 : 0;
  }
  EXPECT_NEAR(active, sites / 4, sites / 20);
  BuggifyRegistry one(1, true, 250'000, 250'000);
  one.force("x", "f.cpp", 1, true);
  BuggifySite* s = one.site("x", "f.cpp", 1);
  int fired = 0;
  for (int i = 0; i < 40'000; ++i) fired += one.eval(*s) ? 1 : 0;
  EXPECT_NEAR(fired, 10'000, 600);
  EXPECT_EQ(s->evals, 40'000u);
}

TEST(Buggify, ActivationDoesNotDependOnEvaluationOrder) {
  BuggifyRegistry a(5, true, 250'000, 250'000);
  BuggifyRegistry b(5, true, 250'000, 250'000);
  for (int i = 0; i < 100; ++i) (void)a.site("s" + std::to_string(i), "f", 0);
  for (int i = 99; i >= 0; --i) (void)b.site("s" + std::to_string(i), "f", 0);
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ(a.site("s" + std::to_string(i), "f", 0)->active, b.site("s" + std::to_string(i), "f", 0)->active);
  }
  BuggifyRegistry off(5, false, 250'000, 250'000);
  for (int i = 0; i < 100; ++i) EXPECT_FALSE(off.site("s" + std::to_string(i), "f", 0)->active);
}

bool evaluate_buggify_site() { return SIM_BUGGIFY("test.site"); }

#if defined(LLE_SIM) && LLE_SIM
TEST(Buggify, MacroFiresInSimBuilds) {
  FaultConfig f = base_fault_config();
  f.set(Param::BuggifyEnabled, 1);
  f.set(Param::BuggifyActivatePpm, 1'000'000);
  f.set(Param::BuggifyFirePpm, 1'000'000);
  World w(1, f);
  EXPECT_FALSE(evaluate_buggify_site());  // setup phase: code-level faults are off
  w.set_phase(Phase::Safety);
  EXPECT_TRUE(evaluate_buggify_site());
  EXPECT_EQ(w.buggify().fired(), 1u);
  w.set_phase(Phase::Heal);  // off again from the heal phase on (09 §5)
  EXPECT_FALSE(evaluate_buggify_site());
  EXPECT_EQ(w.buggify().fired(), 1u);
  {
    World other(2, base_fault_config());  // buggify disabled
    other.set_phase(Phase::Safety);
    EXPECT_FALSE(evaluate_buggify_site());
  }
}
#else
// Compiled out of production builds: the macro is the constant false.
static_assert(!SIM_BUGGIFY("compiled.out"));
TEST(Buggify, CompiledOutWithoutLleSim) {
  FaultConfig f = base_fault_config();
  f.set(Param::BuggifyEnabled, 1);
  f.set(Param::BuggifyActivatePpm, 1'000'000);
  f.set(Param::BuggifyFirePpm, 1'000'000);
  World w(1, f);
  EXPECT_FALSE(evaluate_buggify_site());
  EXPECT_EQ(w.buggify().fired(), 0u);
}
#endif

void hit_probe_macro() {
  SIM_PROBE("test.macro_probe");
  SIM_PROBE("test.macro_probe_rare", rare);
}

TEST(Probes, CountsStatusAndMustHitReport) {
  ProbeRegistry p;
  // The default manifest is loaded: plan 09 §8 probes, mostly pending.
  EXPECT_EQ(ProbeRegistry::status(*p.site("disk.ooo_persist_at_crash", true)), ProbeStatus::Missing);
  EXPECT_EQ(ProbeRegistry::status(*p.site("ha.halt_reopen_cross_spans_failover", false)), ProbeStatus::Pending);
  p.declare("t.a", false);
  p.declare("t.rare", true);
  auto missing = p.missing(false);
  EXPECT_NE(std::find(missing.begin(), missing.end(), "t.a"), missing.end());
  EXPECT_EQ(std::find(missing.begin(), missing.end(), "t.rare"), missing.end());
  missing = p.missing(true);
  EXPECT_NE(std::find(missing.begin(), missing.end(), "t.rare"), missing.end());
  p.hit("t.a");
  p.hit("t.a");
  p.hit("t.unlisted");
  EXPECT_EQ(p.hits("t.a"), 2u);
  EXPECT_EQ(ProbeRegistry::status(*p.site("t.a", false)), ProbeStatus::Ok);
  EXPECT_EQ(ProbeRegistry::status(*p.site("t.unlisted", false)), ProbeStatus::Unlisted);
  ProbeRegistry q;
  q.declare("t.a", false);
  q.merge(p);
  q.merge(p);
  EXPECT_EQ(q.hits("t.a"), 4u);
}

TEST(Probes, MacroCountsOnlyInSimBuilds) {
  World w(1, base_fault_config());
  hit_probe_macro();
  hit_probe_macro();
#if defined(LLE_SIM) && LLE_SIM
  EXPECT_EQ(w.probes().hits("test.macro_probe"), 2u);
  EXPECT_EQ(w.probes().hits("test.macro_probe_rare"), 2u);
  World w2(2, base_fault_config());
  hit_probe_macro();
  EXPECT_EQ(w2.probes().hits("test.macro_probe"), 1u);  // per-world counters
#else
  EXPECT_EQ(w.probes().hits("test.macro_probe"), 0u);
#endif
}

TEST(FaultSchedule, FormatParseRoundTrip) {
  FaultSchedule s;
  s.events.push_back(FaultEvent{10, FaultKind::Crash, 2, 1, 0, 500});
  s.events.push_back(FaultEvent{20, FaultKind::Partition, 1, 0b011, 0b100, 7000});
  s.events.push_back(FaultEvent{30, FaultKind::ClockStep, 0, static_cast<std::uint64_t>(-12345), 0, 0});
  const std::string text = s.format("wal");
  FaultSchedule back;
  ASSERT_TRUE(back.parse("# comment\n" + text + "other 1 0 0 0 0 0\n", "wal"));
  EXPECT_EQ(back.events, s.events);
  FaultSchedule bad;
  EXPECT_FALSE(bad.parse("wal 1 2 3\n", "wal"));
  EXPECT_FALSE(bad.parse("wal 1 9 0 0 0 0\n", "wal"));
}

FaultSchedule schedule_for(std::uint64_t seed, std::uint32_t disabled) {
  World w(seed, draw_fault_config(seed, Mode::Swarm, disabled));
  for (int i = 0; i < 4; ++i) w.add_node("n" + std::to_string(i));
  return w.injector().generate(0, 5 * kSec);
}

TEST(FaultInjector, GenerationIsPureAndAblationPreservesOtherClasses) {
  int compared = 0;
  for (std::uint64_t seed = 1; seed <= 50; ++seed) {
    const FaultSchedule a = schedule_for(seed, 0);
    EXPECT_EQ(a.events, schedule_for(seed, 0).events);
    const FaultSchedule no_net = schedule_for(seed, class_bit(FaultClass::Net));
    auto only = [](const FaultSchedule& s, FaultKind k) {
      std::vector<FaultEvent> out;
      for (const FaultEvent& e : s.events) {
        if (e.kind == k) out.push_back(e);
      }
      return out;
    };
    EXPECT_TRUE(only(no_net, FaultKind::Partition).empty());
    EXPECT_EQ(only(a, FaultKind::Crash), only(no_net, FaultKind::Crash));
    EXPECT_EQ(only(a, FaultKind::Pause), only(no_net, FaultKind::Pause));
    EXPECT_EQ(only(a, FaultKind::ClockStep), only(no_net, FaultKind::ClockStep));
    compared += static_cast<int>(only(a, FaultKind::Crash).size());
  }
  EXPECT_GT(compared, 0);
}

TEST(FaultInjector, EventsFireOnlyInSafetyPhase) {
  World w(1, base_fault_config());
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  a.boot();
  b.boot();
  FaultSchedule s;
  s.events.push_back(FaultEvent{1 * kMs, FaultKind::Pause, 1, 0, 0, 20 * kMs});
  s.events.push_back(FaultEvent{2 * kMs, FaultKind::Partition, 1, 0b01, 0b10, 5 * kMs});
  s.events.push_back(FaultEvent{3 * kMs, FaultKind::ClockStep, 0, static_cast<std::uint64_t>(kSec), 0, 0});
  s.events.push_back(FaultEvent{4 * kMs, FaultKind::Crash, 0, 1, 0, 10 * kMs});
  w.injector().install(s);
  w.set_phase(Phase::Safety);
  test::run_for(w, 4 * kMs);
  EXPECT_TRUE(b.paused());
  EXPECT_TRUE(w.net().blocked(0, 1));
  EXPECT_TRUE(w.net().blocked(1, 0));
  EXPECT_EQ(a.clock().steps_total_ns(), kSec);
  EXPECT_FALSE(a.alive());
  EXPECT_EQ(w.stats().crashes_host, 1u);
  test::run_for(w, 20 * kMs);
  EXPECT_TRUE(a.alive());  // restarted after 10 ms
  EXPECT_EQ(a.incarnation(), 1u);
  EXPECT_FALSE(b.paused());
  EXPECT_FALSE(w.net().blocked(0, 1));
  EXPECT_EQ(w.injector().fired(), 4u);

  // Outside the safety phase nothing fires.
  World w2(1, base_fault_config());
  Node& c = w2.add_node("c");
  c.boot();
  FaultSchedule s2;
  s2.events.push_back(FaultEvent{1 * kMs, FaultKind::Crash, 0, 0, 0, 0});
  w2.injector().install(s2);
  w2.set_phase(Phase::Heal);
  test::run_for(w2, 2 * kMs);
  EXPECT_TRUE(c.alive());
  EXPECT_EQ(w2.injector().skipped(), 1u);
}

}  // namespace
}  // namespace lle::sim
