// Failover classes of plan 10 §7 on localhost, each with a rejoin (10 §5; F8 has nobody to
// rejoin): ha_trial.h. The same trials run repeatedly under bench/failover/run_trials.py
// (exchange_failover_trial), also on the lab's hosts (--lab); the lab deployment's own
// pieces (configuration rendering and overrides, its shell commands) are checked here
// without a lab.
#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>

#include "ha_trial.h"

namespace lle::exch::test {
namespace {

class Failover : public ::testing::TestWithParam<std::string> {};

TEST_P(Failover, ExactlyOnceContinuousFeedAndIdenticalJournalsAfterRejoin) {
  std::string name = GetParam();
  for (char& c : name)
    if (c == '-') c = '_';
  const auto dir = fresh_dir("fo-" + name);
  const ScopedDir cleanup(dir);
  ha::TrialOptions o;
  o.dir = dir;
  o.seed = 1;
  const ha::TrialResult r = ha::run_trial(GetParam(), o);
  for (const std::string& v : r.violations) ADD_FAILURE() << v;
  std::printf("%s", r.json().c_str());
  EXPECT_TRUE(r.pass);
}

// The same classes with the replica on its own thread (repl_stage.h, split mode).
class FailoverSplit : public ::testing::TestWithParam<std::string> {};

TEST_P(FailoverSplit, ReplicaOnItsOwnThread) {
  std::string name = GetParam();
  for (char& c : name)
    if (c == '-') c = '_';
  const auto dir = fresh_dir("fos-" + name);
  const ScopedDir cleanup(dir);
  ha::TrialOptions o;
  o.dir = dir;
  o.seed = 2;
  o.repl_thread = true;
  const ha::TrialResult r = ha::run_trial(GetParam(), o);
  for (const std::string& v : r.violations) ADD_FAILURE() << v;
  std::printf("%s", r.json().c_str());
  EXPECT_TRUE(r.pass);
}

INSTANTIATE_TEST_SUITE_P(Split, FailoverSplit, ::testing::Values("F1", "F1-divergent", "F2", "F6", "F7-resume"),
                         [](const ::testing::TestParamInfo<std::string>& i) {
                           std::string n = i.param;
                           for (char& c : n)
                             if (c == '-') c = '_';
                           return n;
                         });

INSTANTIATE_TEST_SUITE_P(Classes, Failover,
                         ::testing::Values("F1", "F1-partial", "F1-divergent", "F2", "F6", "F7", "F7-resume", "F8", "F9"),
                         [](const ::testing::TestParamInfo<std::string>& i) {
                           std::string n = i.param;
                           for (char& c : n)
                             if (c == '-') c = '_';
                           return n;
                         });

// The prober (DELTA, an order or a cancel every 5 ms around the fault, on the backup's
// mirror connection): T_new and the first acknowledgement of a new-epoch order are
// measured, the probes' stream is exact and every probe order is answered once. (At this
// rate the backup's FORWARD window, 512, holds what it receives during the 1.5 s
// detection; a faster prober overflows it, see docs/verification/exchange.md.)
TEST(FailoverProbes, TakeoverMeasuresTNewAndTheFirstNewOrderAck) {
  const auto dir = fresh_dir("fo-probes");
  const ScopedDir cleanup(dir);
  ha::TrialOptions o;
  o.dir = dir;
  o.seed = 3;
  o.probe_us = 5'000;
  const ha::TrialResult r = ha::run_trial("F1", o);
  for (const std::string& v : r.violations) ADD_FAILURE() << v;
  EXPECT_TRUE(r.pass);
  EXPECT_GT(r.num.at("probes_sent"), 100);
  EXPECT_GT(r.num.at("probes_accepted"), 10);
  EXPECT_EQ(r.num.at("probes_unanswered"), 0);
  EXPECT_GT(r.num.at("new_epoch_first_itch_seq"), 1);
  ASSERT_TRUE(r.ms.contains("t_new"));
  ASSERT_TRUE(r.ms.contains("t_takeover"));
  EXPECT_GE(r.ms.at("t_new"), r.ms.at("t_takeover"));  // the new epoch's output is on or after B's first packet
  EXPECT_TRUE(r.ms.contains("t_first_new_order_ack"));
  EXPECT_TRUE(r.ms.contains("nlog_request_to_grant")) << "the survivor's nlog breakdown";
}

// A fast prober (every 100 us) on the backup's mirror connection through the takeover: its
// orders arrive while the backup is a candidate and right at the grant. The promoted
// backup re-injects its pending FORWARDs ahead of the input its gateway queued meanwhile
// (Sequencer::inject_ahead); behind it, all of them were ignored as resends (lower
// UserRefNums than a newer order already taken) and never answered: 513 orders in one run.
class FailoverFastProbes : public ::testing::TestWithParam<bool> {};

TEST_P(FailoverFastProbes, EveryOrderOnTheMirrorConnectionIsAnsweredOnce) {
  const auto dir = fresh_dir(GetParam() ? "fo-fastprobes-split" : "fo-fastprobes");
  const ScopedDir cleanup(dir);
  ha::TrialOptions o;
  o.dir = dir;
  o.seed = 3;
  o.probe_us = 100;
  o.repl_thread = GetParam();
  const ha::TrialResult r = ha::run_trial("F1", o);
  for (const std::string& v : r.violations) ADD_FAILURE() << v;
  EXPECT_TRUE(r.pass);
  EXPECT_EQ(r.num.at("probes_unanswered"), 0);
  EXPECT_GT(r.num.at("probes_accepted"), 1000);
}

INSTANTIATE_TEST_SUITE_P(Mode, FailoverFastProbes, ::testing::Values(false, true),
                         [](const ::testing::TestParamInfo<bool>& i) { return i.param ? "Split" : "Combined"; });

// Lab configurations (exchange_failover_trial --render-config): overrides replace a key in
// place, add one at the end of its section or a new section, and remove one with "-".
TEST(TrialConfig, OverridesReplaceAppendAndRemove) {
  const std::string base = "[node]\nname = x\nbackend = epoll\n[md]\nheartbeat_ms = 200\nttl = 1\n[symbols]\nAAPL prior=1\n";
  const std::string out = apply_overrides(base, {"node.backend = uring", "md.heartbeat_us = 20", "md.ttl = -",
                                                 "cores.seq = 10", "bogus line"});
  EXPECT_EQ(out,
            "[node]\nname = x\nbackend = uring\n[md]\nheartbeat_ms = 200\nheartbeat_us = 20\n[symbols]\nAAPL prior=1\n"
            "[cores]\nseq = 10\n");
}

// Both lab nodes render from one description, and exchanged accepts what was rendered.
TEST(TrialConfig, LabNodesRenderToConfigurationsTheNodeAccepts) {
  const auto dir = fresh_dir("fo-render");
  const ScopedDir cleanup(dir);
  const auto spec_path = dir / "lab.spec";
  std::ofstream(spec_path) << "lab.name = unit\nc.ip = 10.77.0.254\nwitness.listen = 10.77.0.254:7400\n"
                              "lines.a = 239.77.0.1:26477\nlines.b = 239.77.0.2:26478\n"
                              "common.override.0 = md.heartbeat_us = 20\ncommon.override.1 = md.multicast_if = eth0\n"
                              "node.A.ip = 10.77.0.1\nnode.A.repl = 10.78.0.1:7500\nnode.A.data_dir = /tmp/lle-unit-A\n"
                              "node.A.port.gw0 = 15000\nnode.A.port.gw1 = 15001\nnode.A.port.rerequest = 26479\n"
                              "node.A.port.control = 17000\nnode.A.port.admin = 17001\nnode.A.override.0 = cores.seq = 10\n"
                              "node.B.ip = 10.77.0.2\nnode.B.repl = 10.78.0.2:7500\nnode.B.data_dir = /tmp/lle-unit-B\n"
                              "node.B.port.gw0 = 15100\nnode.B.port.gw1 = 15101\nnode.B.port.rerequest = 26579\n"
                              "node.B.port.control = 17100\nnode.B.port.admin = 17101\n";
  std::string err;
  const auto lab = ha::LabSpec::load(spec_path.string(), &err);
  ASSERT_TRUE(lab.has_value()) << err;
  ha::TrialOptions o;
  for (int n : {0, 1}) {
    const std::string text = config_text(ha::lab_node(n, *lab, o));
    const std::string me = n == 0 ? "10.77.0.1" : "10.77.0.2", peer = n == 0 ? "10.78.0.2:7500" : "10.78.0.1:7500";
    EXPECT_NE(text.find("gw0 = " + me + (n == 0 ? ":15000" : ":15100")), std::string::npos) << text;
    EXPECT_NE(text.find("line_a = 239.77.0.1:26477"), std::string::npos) << text;
    EXPECT_NE(text.find("peer = " + peer), std::string::npos) << text;
    EXPECT_NE(text.find("witness = 10.77.0.254:7400"), std::string::npos) << text;
    EXPECT_NE(text.find("heartbeat_us = 20"), std::string::npos) << text;
    EXPECT_NE(text.find("DELTA"), std::string::npos) << "the prober's session";
    EXPECT_EQ(text.find("seq = 10") != std::string::npos, n == 0) << text;
    const auto conf = dir / (n == 0 ? "A.conf" : "B.conf");
    std::ofstream(conf) << text;
    int code = -1;
    const std::string out = run_capture({LLE_EXCHANGED, "--check-config", conf.string()}, &code);
    EXPECT_EQ(code, 0) << out << text;
  }
}

// The lab's commands run in their own process group and are cut off at their timeout.
TEST(TrialConfig, ShellCommandsReportTheirStatusAndTimeOut) {
  const auto dir = fresh_dir("fo-sh");
  const ScopedDir cleanup(dir);
  const ha::ShResult ok = ha::run_sh("echo hi; exit 3", std::chrono::milliseconds(5'000), dir);
  EXPECT_EQ(ok.code, 3);
  EXPECT_FALSE(ok.timed_out);
  EXPECT_EQ(ok.out, "hi\n");
  const auto t0 = std::chrono::steady_clock::now();
  const ha::ShResult slow = ha::run_sh("sleep 30 & sleep 30", std::chrono::milliseconds(300), dir);
  EXPECT_TRUE(slow.timed_out);
  EXPECT_EQ(slow.code, -1);
  EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(5));
}

}  // namespace
}  // namespace lle::exch::test
