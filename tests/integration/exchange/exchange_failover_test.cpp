// Failover classes of plan 10 §7 on localhost, each with a rejoin (10 §5): ha_trial.h.
// The same trials run repeatedly under bench/failover/run_trials.py (exchange_failover_trial).
#include <gtest/gtest.h>

#include <cstdio>

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

INSTANTIATE_TEST_SUITE_P(Split, FailoverSplit, ::testing::Values("F1", "F1-divergent", "F6", "F7-resume"),
                         [](const ::testing::TestParamInfo<std::string>& i) {
                           std::string n = i.param;
                           for (char& c : n)
                             if (c == '-') c = '_';
                           return n;
                         });

INSTANTIATE_TEST_SUITE_P(Classes, Failover, ::testing::Values("F1", "F1-partial", "F1-divergent", "F6", "F7", "F7-resume"),
                         [](const ::testing::TestParamInfo<std::string>& i) {
                           std::string n = i.param;
                           for (char& c : n)
                             if (c == '-') c = '_';
                           return n;
                         });

}  // namespace
}  // namespace lle::exch::test
