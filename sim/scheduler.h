#pragma once
// Seeded stage scheduler (09 §2, R4b §2.2).
//
// Every registered Stage (env-templated component thread body with
// `bool poll()`) is a recurring poll event. A poll that did work is followed by
// the next poll after a seeded CPU cost; an idle poll backs off exponentially
// from idle_min to idle_max, and any I/O arrival for the node wakes its idle
// stages. The policy (uniform jitter, PCT-style priorities, starve-one) and all
// costs come from the scheduler stream, so the interleaving of stages across
// nodes is a function of the seed.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "runtime/stage.h"
#include "sim/event.h"

namespace lle::sim {

class World;

enum class SchedPolicy : std::uint8_t { Uniform = 0, Pct = 1, StarveOne = 2 };

struct SchedConfig {
  SchedPolicy policy = SchedPolicy::Uniform;
  Nanos cpu_min_ns = 100;
  Nanos cpu_jitter_ns = 0;
  Nanos idle_min_ns = 1000;
  Nanos idle_max_ns = 100000;
  Nanos wake_jitter_ns = 0;
  Nanos pct_step_ns = 0;
  std::uint32_t pct_change_ppm = 0;
  std::int64_t starve_factor = 1;
};

class Scheduler {
 public:
  Scheduler(World& w, const SchedConfig& cfg, std::uint64_t seed);

  using PollFn = bool (*)(void*);
  std::uint32_t add_stage(NodeId node, void* obj, PollFn fn, std::string_view name);
  template <rt::StageLike S>
  std::uint32_t add_stage(NodeId node, S& s, std::string_view name) {
    return add_stage(node, &s, [](void* o) { return static_cast<S*>(o)->poll(); }, name);
  }

  // Cancels all stages of a node (crash) / suspends them (pause) / resumes.
  void remove_node(NodeId node);
  void suspend_node(NodeId node);
  void resume_node(NodeId node);
  // I/O arrived for the node: poll its idle stages soon.
  void wake(NodeId node);

  [[nodiscard]] const SchedConfig& config() const noexcept { return cfg_; }
  [[nodiscard]] std::uint64_t polls() const noexcept { return polls_; }
  [[nodiscard]] std::uint64_t busy_polls() const noexcept { return busy_polls_; }
  [[nodiscard]] std::size_t stage_count(NodeId node) const;
  [[nodiscard]] std::string_view stage_name(std::uint32_t slot) const { return slots_[slot].name; }

  static Dispatch on_event(void* ctx, const Event& ev);

 private:
  struct Slot {
    void* obj = nullptr;
    PollFn fn = nullptr;
    NodeId node = kNoNode;
    std::uint32_t gen = 0;
    Nanos next_at = 0;
    Nanos backoff = 0;
    std::uint32_t prio = 0;
    bool active = false;
    bool idle = false;
    bool suspended = false;
    bool starved = false;
    std::string name;
  };

  void arm(std::uint32_t slot, Nanos at);
  Nanos work_cost(Slot& s);
  Dispatch poll(const Event& ev);

  World& w_;
  SchedConfig cfg_;
  Prng rng_;
  HandlerId handler_;
  std::vector<Slot> slots_;
  std::vector<std::uint32_t> free_;
  std::vector<std::vector<std::uint32_t>> by_node_;
  std::uint64_t polls_ = 0;
  std::uint64_t busy_polls_ = 0;
  std::uint32_t starve_pick_ = 0;
};

}  // namespace lle::sim
