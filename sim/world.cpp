#include "sim/world.h"

#include <algorithm>
#include <limits>

#include "common/assert.h"
#include "common/hash.h"
#include "sim/disk.h"
#include "sim/dist.h"
#include "sim/fault/injector.h"
#include "sim/fault_atlas.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/scheduler.h"

namespace lle::sim {

namespace {

// The simulator is single-threaded by construction (01 §5): one current world.
World* g_current = nullptr;
std::uint64_t g_epoch = 0;

SchedConfig sched_config(const FaultConfig& f) {
  SchedConfig c;
  c.policy = static_cast<SchedPolicy>(std::clamp<std::int64_t>(f[Param::SchedPolicy], 0, 2));
  c.cpu_min_ns = f[Param::SchedCpuMinNs];
  c.cpu_jitter_ns = f[Param::SchedCpuJitterNs];
  c.idle_min_ns = f[Param::SchedIdleMinNs];
  c.idle_max_ns = f[Param::SchedIdleMaxNs];
  c.wake_jitter_ns = f[Param::SchedWakeJitterNs];
  c.pct_step_ns = f[Param::SchedPctStepNs];
  c.pct_change_ppm = static_cast<std::uint32_t>(f.u(Param::SchedPctChangePpm));
  c.starve_factor = f[Param::SchedStarveFactor];
  return c;
}

Dispatch node_event(void* ctx, const Event& ev) {
  auto* w = static_cast<World*>(ctx);
  Node& n = w->node(ev.node);
  if (ev.kind == 1) {
    n.on_restart(ev.a);
  } else {
    n.on_resume(ev.a);
  }
  return {true, ev.kind};
}

}  // namespace

std::string_view phase_name(Phase p) noexcept {
  switch (p) {
    case Phase::Setup:
      return "setup";
    case Phase::Safety:
      return "safety";
    case Phase::Heal:
      return "heal";
    case Phase::Convergence:
      return "convergence";
    case Phase::Done:
      return "done";
  }
  return "?";
}

World* World::current() noexcept { return g_current; }

World::World(std::uint64_t seed, const FaultConfig& faults)
    : seed_(seed),
      faults_(faults),
      trace_hash_(Fnv1a64::kOffset),
      epoch_(++g_epoch),
      buggify_(derive_seed(seed, Stream::Buggify), faults[Param::BuggifyEnabled] != 0,
               static_cast<std::uint32_t>(faults.u(Param::BuggifyActivatePpm)),
               static_cast<std::uint32_t>(faults.u(Param::BuggifyFirePpm))) {
  oracles_.set_event_index_source(&current_index_);
  o_live_ = oracles_.activate(kOLive);
  heap_.reserve(4096);
  handlers_.reserve(16);
  sched_ = std::make_unique<Scheduler>(*this, sched_config(faults_), derive_seed(seed, Stream::Scheduler));
  atlas_ = std::make_unique<FaultAtlas>(derive_seed(seed, Stream::Disk, 0xA71A5ull << 32),
                                        static_cast<std::uint32_t>(faults_.u(Param::DiskAtlasPpm)));
  net_ = std::make_unique<Network>(*this);
  injector_ = std::make_unique<FaultInjector>(*this);
  node_handler_ = register_handler(this, &node_event, "node");
  disk_handler_ = register_handler(this, &Disk::on_event, "disk");
  make_current();
}

World::~World() {
  // Processes first: their ports and file handles unregister from the network
  // and disks, which must still exist.
  nodes_.clear();
  injector_.reset();
  net_.reset();
  atlas_.reset();
  sched_.reset();
  if (g_current == this) g_current = nullptr;
}

void World::make_current() noexcept { g_current = this; }

HandlerId World::register_handler(void* ctx, HandlerFn fn, const char* name) {
  LLE_ASSERT(handlers_.size() < 0xFFFF, "too many event handlers");
  handlers_.push_back(HandlerEntry{ctx, fn, name});
  return static_cast<HandlerId>(handlers_.size() - 1);
}

void World::schedule(Nanos at, HandlerId h, std::uint16_t kind, NodeId node, std::uint64_t a, std::uint64_t b,
                     std::uint64_t digest) {
  LLE_ASSERT(at >= now_, "event scheduled in the past");
  heap_.push_back(Event{at, ++seq_, a, b, digest, node, h, kind});
  std::push_heap(heap_.begin(), heap_.end(), Later{});
}

Nanos World::next_event_time() const noexcept {
  return heap_.empty() ? std::numeric_limits<Nanos>::max() : heap_.front().at;
}

bool World::step() {
  if (heap_.empty()) return false;
  g_current = this;  // SIM_BUGGIFY / SIM_PROBE target, even if drivers interleave worlds
  std::pop_heap(heap_.begin(), heap_.end(), Later{});
  const Event ev = heap_.back();
  heap_.pop_back();
  LLE_ASSERT(ev.at >= now_, "virtual time went backwards");
  now_ = ev.at;
  current_index_ = events_ + 1;
  const HandlerEntry& h = handlers_[ev.handler];
  const Dispatch d = h.fn(h.ctx, ev);
  if (d.counted) {
    ++events_;
    Fnv1a64 f(trace_hash_);
    f.u(ev.handler);
    f.u(ev.kind);
    f.u(ev.node);
    f.u(ev.at);
    f.u(ev.digest);
    f.u(d.result);
    trace_hash_ = f.value();
    if (trace_ != nullptr) {
      std::fprintf(trace_, "%llu t=%lld %s/%u n=%d d=%016llx r=%llx h=%016llx\n",
                   static_cast<unsigned long long>(events_), static_cast<long long>(ev.at), h.name,
                   static_cast<unsigned>(ev.kind), ev.node == kNoNode ? -1 : static_cast<int>(ev.node),
                   static_cast<unsigned long long>(ev.digest), static_cast<unsigned long long>(d.result),
                   static_cast<unsigned long long>(trace_hash_));
    }
  }
  if (!deferred_crashes_.empty()) apply_deferred();
  return true;
}

void World::run_until_time(Nanos t) {
  while (!heap_.empty() && heap_.front().at <= t) step();
  advance_to(t);
}

Node& World::add_node(std::string name) { return add_node(std::move(name), NodeOptions{}); }

Node& World::add_node(std::string name, const NodeOptions& opts) {
  const auto id = static_cast<NodeId>(nodes_.size());
  LLE_ASSERT(id < 64, "fault masks support up to 64 nodes");
  net_->ensure_nodes(nodes_.size() + 1);
  nodes_.push_back(std::make_unique<Node>(*this, id, std::move(name), opts));
  nodes_.back()->disk().set_handler(disk_handler_);
  return *nodes_.back();
}

void World::defer_crash(NodeId node) { deferred_crashes_.push_back(node); }

void World::apply_deferred() {
  std::vector<NodeId> ids;
  ids.swap(deferred_crashes_);
  for (const NodeId id : ids) {
    Node& n = *nodes_[id];
    if (!n.alive_ || !n.crash_requested_) continue;
    n.crash(CrashKind::Process);
    // A supervisor restarts the aborted process shortly after.
    n.restart_after(uniform(n.supervisor_rng_, 10 * kMs, 100 * kMs));
  }
}

void World::heal() {
  phase_ = Phase::Heal;
  net_->heal_all();
  for (auto& n : nodes_) {
    if (!n->alive()) {
      n->restart_after(kMs);
    } else if (n->paused()) {
      n->resume();
    }
  }
  for (auto& hook : heal_hooks_) hook();
}

RunResult World::run(const PhasePlan& plan, const std::function<bool()>& converged) {
  make_current();
  RunResult r;
  const Nanos safety_end = now_ + plan.safety_ns;
  phase_ = Phase::Safety;
  while (!oracles_.failed()) {
    if (events_ >= plan.ticks_max) {
      r.truncated = true;
      break;
    }
    if (heap_.empty() || heap_.front().at >= safety_end) {
      advance_to(safety_end);
      break;
    }
    step();
  }

  if (!oracles_.failed() && !r.truncated) {
    heal();
    phase_ = Phase::Convergence;
    const Nanos deadline = now_ + plan.convergence_ns;
    Nanos next_check = now_;
    const auto is_converged = [&] { return !converged || converged(); };
    while (!oracles_.failed()) {
      if (now_ >= next_check) {
        if (is_converged()) {
          r.converged = true;
          break;
        }
        next_check = now_ + plan.check_interval_ns;
      }
      if (events_ >= plan.ticks_max) {
        r.truncated = true;
        break;
      }
      if (heap_.empty() || heap_.front().at > deadline) {
        advance_to(deadline);
        r.converged = is_converged();
        break;
      }
      step();
    }
    if (!r.converged && !r.truncated && !oracles_.failed()) {
      current_index_ = events_;
      oracles_.fail(o_live_, "no convergence within bound B after healing");
    }
    if (r.converged && !oracles_.failed()) {
      oracles_.pass(o_live_);
      current_index_ = events_;
      oracles_.run_final_checks();
    }
  }

  r.phase = phase_;
  phase_ = Phase::Done;
  stats_.buggify_fired = buggify_.fired();
  r.events = events_;
  r.trace_hash = trace_hash_;
  r.virtual_ns = now_;
  r.failed = oracles_.failed();
  if (r.failed) r.failure = oracles_.first_failure();
  return r;
}

}  // namespace lle::sim
