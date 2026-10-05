#include "sim/scheduler.h"

#include <algorithm>

#include "sim/dist.h"
#include "sim/world.h"

namespace lle::sim {

Scheduler::Scheduler(World& w, const SchedConfig& cfg, std::uint64_t seed) : w_(w), cfg_(cfg), rng_(seed) {
  if (cfg_.idle_min_ns < 1) cfg_.idle_min_ns = 1;
  if (cfg_.idle_max_ns < cfg_.idle_min_ns) cfg_.idle_max_ns = cfg_.idle_min_ns;
  if (cfg_.starve_factor < 1) cfg_.starve_factor = 1;
  handler_ = w.register_handler(this, &Scheduler::on_event, "sched");
  starve_pick_ = static_cast<std::uint32_t>(rng_.below(4));
}

std::uint32_t Scheduler::add_stage(NodeId node, void* obj, PollFn fn, std::string_view name) {
  std::uint32_t slot;
  if (!free_.empty()) {
    slot = free_.back();
    free_.pop_back();
  } else {
    slot = static_cast<std::uint32_t>(slots_.size());
    slots_.emplace_back();
  }
  Slot& s = slots_[slot];
  s.obj = obj;
  s.fn = fn;
  s.node = node;
  ++s.gen;
  s.active = true;
  s.idle = false;
  s.suspended = false;
  s.backoff = cfg_.idle_min_ns;
  s.name = std::string(name);
  s.prio = static_cast<std::uint32_t>(rng_.below(8));
  // Starve policy: a seeded quarter of the stages run starve_factor slower.
  s.starved = cfg_.policy == SchedPolicy::StarveOne && rng_.below(4) == starve_pick_;
  if (by_node_.size() <= node) by_node_.resize(static_cast<std::size_t>(node) + 1);
  by_node_[node].push_back(slot);
  arm(slot, w_.now() + 1 + uniform(rng_, 0, cfg_.wake_jitter_ns + cfg_.cpu_min_ns));
  return slot;
}

void Scheduler::arm(std::uint32_t slot, Nanos at) {
  Slot& s = slots_[slot];
  s.next_at = at;
  w_.schedule(at, handler_, 0, s.node, slot, s.gen, slot);
}

void Scheduler::remove_node(NodeId node) {
  if (node >= by_node_.size()) return;
  for (const std::uint32_t slot : by_node_[node]) {
    Slot& s = slots_[slot];
    s.active = false;
    ++s.gen;
    s.obj = nullptr;
    free_.push_back(slot);
  }
  by_node_[node].clear();
}

void Scheduler::suspend_node(NodeId node) {
  if (node >= by_node_.size()) return;
  for (const std::uint32_t slot : by_node_[node]) {
    Slot& s = slots_[slot];
    s.suspended = true;
    ++s.gen;
  }
}

void Scheduler::resume_node(NodeId node) {
  if (node >= by_node_.size()) return;
  for (const std::uint32_t slot : by_node_[node]) {
    Slot& s = slots_[slot];
    s.suspended = false;
    s.idle = false;
    s.backoff = cfg_.idle_min_ns;
    ++s.gen;
    arm(slot, w_.now() + 1 + uniform(rng_, 0, cfg_.wake_jitter_ns));
  }
}

void Scheduler::wake(NodeId node) {
  if (node >= by_node_.size()) return;
  for (const std::uint32_t slot : by_node_[node]) {
    Slot& s = slots_[slot];
    if (!s.active || s.suspended || !s.idle) continue;
    const Nanos at = w_.now() + 1 + uniform(rng_, 0, cfg_.wake_jitter_ns);
    if (at >= s.next_at) continue;
    ++s.gen;
    s.idle = false;
    s.backoff = cfg_.idle_min_ns;
    arm(slot, at);
  }
}

std::size_t Scheduler::stage_count(NodeId node) const {
  return node < by_node_.size() ? by_node_[node].size() : 0;
}

Nanos Scheduler::work_cost(Slot& s) {
  Nanos cost = cfg_.cpu_min_ns + uniform(rng_, 0, cfg_.cpu_jitter_ns);
  if (cfg_.policy == SchedPolicy::Pct) {
    // PCT-style: lower-priority stages are delayed more; priorities change at
    // seeded points so the "starved" stage moves around.
    cost += static_cast<Nanos>(s.prio) * cfg_.pct_step_ns;
    if (chance_ppm(rng_, cfg_.pct_change_ppm)) s.prio = static_cast<std::uint32_t>(rng_.below(8));
  } else if (s.starved) {
    cost *= cfg_.starve_factor;
  }
  return cost < 1 ? 1 : cost;
}

Dispatch Scheduler::poll(const Event& ev) {
  const auto slot = static_cast<std::uint32_t>(ev.a);
  if (slot >= slots_.size()) return {false, 0};
  {
    const Slot& s = slots_[slot];
    if (!s.active || s.suspended || s.gen != ev.b) return {false, 0};
  }
  ++polls_;
  void* obj = slots_[slot].obj;
  const PollFn fn = slots_[slot].fn;
  const std::uint32_t gen = slots_[slot].gen;
  const bool did = fn(obj);
  Slot& s = slots_[slot];  // re-fetch: the poll may have registered stages
  if (!s.active || s.suspended || s.gen != gen) return {true, did ? 1u : 0u};
  if (did) {
    ++busy_polls_;
    s.idle = false;
    s.backoff = cfg_.idle_min_ns;
    arm(slot, w_.now() + work_cost(s));
  } else {
    s.idle = true;
    const Nanos b = s.backoff;
    s.backoff = std::min(b * 2, cfg_.idle_max_ns);
    arm(slot, w_.now() + b);
  }
  return {true, did ? 1u : 0u};
}

Dispatch Scheduler::on_event(void* ctx, const Event& ev) { return static_cast<Scheduler*>(ctx)->poll(ev); }

}  // namespace lle::sim
