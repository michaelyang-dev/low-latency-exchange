#pragma once
// The discrete-event world (09 §1, §2, §5, §9).
//
// All nodes of a scenario run single-threaded inside one World. Virtual time
// only advances by popping the next event from a heap keyed by
// (virtual_ns, seq). Every counted event is folded into a 64-bit FNV-1a trace
// hash (type, node, virtual time, payload digest, outcome) so a re-run with the
// same seed at the same commit can be compared byte for byte.
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "sim/event.h"
#include "sim/fault/buggify_registry.h"
#include "sim/fault/probes.h"
#include "sim/fault/swarm.h"
#include "sim/oracles/registry.h"
#include "sim/rng.h"
#include "sim/stats.h"

namespace lle::sim {

class Node;
class Network;
class Scheduler;
class FaultInjector;
class FaultAtlas;
struct NodeOptions;

enum class Phase : std::uint8_t { Setup, Safety, Heal, Convergence, Done };
[[nodiscard]] std::string_view phase_name(Phase p) noexcept;

struct PhasePlan {
  Nanos safety_ns = 500'000'000;          // faults on, workload running
  Nanos convergence_ns = 30'000'000'000;  // bound B after healing (09 §5)
  std::uint64_t ticks_max = ~std::uint64_t{0};  // hard cap on counted events
  Nanos check_interval_ns = 1'000'000;    // how often converged() is evaluated
};

struct RunResult {
  std::uint64_t events = 0;
  std::uint64_t trace_hash = 0;
  Nanos virtual_ns = 0;
  Phase phase = Phase::Setup;
  bool converged = false;
  bool truncated = false;  // ticks_max reached; liveness and final checks skipped
  bool failed = false;
  Signature failure;
};

class World {
 public:
  World(std::uint64_t seed, const FaultConfig& faults);
  ~World();
  World(const World&) = delete;
  World& operator=(const World&) = delete;

  // --- identity, configuration, randomness ---
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }
  [[nodiscard]] const FaultConfig& faults() const noexcept { return faults_; }
  [[nodiscard]] Phase phase() const noexcept { return phase_; }
  // For tests and custom drivers that step() the world directly instead of
  // calling run(): e.g. set Phase::Safety so probabilistic faults apply.
  void set_phase(Phase p) noexcept { phase_ = p; }
  // Probabilistic faults (loss, EIO, stalls, ...) apply only in the safety
  // phase; the heal phase turns them off (09 §5).
  [[nodiscard]] bool faults_active() const noexcept { return phase_ == Phase::Safety; }
  [[nodiscard]] Rng stream(Stream s, std::uint64_t sub = 0) const noexcept { return make_rng(seed_, s, sub); }

  // --- time and events ---
  [[nodiscard]] Nanos now() const noexcept { return now_; }
  HandlerId register_handler(void* ctx, HandlerFn fn, const char* name);
  void schedule(Nanos at, HandlerId h, std::uint16_t kind, NodeId node, std::uint64_t a = 0, std::uint64_t b = 0,
                std::uint64_t digest = 0);
  // Pops and dispatches one event. Returns false if the heap is empty.
  bool step();
  // Dispatches every event due at or before t, then advances virtual time to
  // t (for tests and custom drivers; run() is the normal entry point).
  void run_until_time(Nanos t);
  [[nodiscard]] std::uint64_t events() const noexcept { return events_; }
  [[nodiscard]] std::uint64_t trace_hash() const noexcept { return trace_hash_; }
  // 1-based index of the event being dispatched (what signatures record).
  [[nodiscard]] std::uint64_t current_event_index() const noexcept { return current_index_; }
  [[nodiscard]] std::size_t pending_events() const noexcept { return heap_.size(); }
  [[nodiscard]] Nanos next_event_time() const noexcept;

  // --- nodes and subsystems ---
  Node& add_node(std::string name, const NodeOptions& opts);
  Node& add_node(std::string name);
  [[nodiscard]] Node& node(NodeId id) { return *nodes_[id]; }
  [[nodiscard]] const Node& node(NodeId id) const { return *nodes_[id]; }
  [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
  [[nodiscard]] Network& net() noexcept { return *net_; }
  [[nodiscard]] Scheduler& scheduler() noexcept { return *sched_; }
  [[nodiscard]] FaultInjector& injector() noexcept { return *injector_; }
  [[nodiscard]] FaultAtlas& atlas() noexcept { return *atlas_; }
  [[nodiscard]] FaultStats& stats() noexcept { return stats_; }
  [[nodiscard]] ProbeRegistry& probes() noexcept { return probes_; }
  [[nodiscard]] OracleRegistry& oracles() noexcept { return oracles_; }
  [[nodiscard]] BuggifyRegistry& buggify() noexcept { return buggify_; }

  // --- phases ---
  void on_heal(std::function<void()> fn) { heal_hooks_.push_back(std::move(fn)); }
  // Safety -> heal -> convergence within plan.convergence_ns -> final oracles.
  RunResult run(const PhasePlan& plan, const std::function<bool()>& converged);
  void heal();

  // Node crash requested from inside an event (e.g. a process aborting on
  // fsync EIO). Applied after the current event finishes.
  void defer_crash(NodeId node);

  // Writes one line per counted event (for bisecting divergences).
  void set_trace(std::FILE* f) noexcept { trace_ = f; }
  // Installs this world as the target of SIM_BUGGIFY / SIM_PROBE macros.
  void make_current() noexcept;
  [[nodiscard]] std::uint64_t epoch() const noexcept { return epoch_; }

  // Process-wide current world (sim is single-threaded); nullptr if none.
  static World* current() noexcept;

 private:
  struct HandlerEntry {
    void* ctx;
    HandlerFn fn;
    const char* name;
  };
  struct Later {
    bool operator()(const Event& x, const Event& y) const noexcept {
      return x.at != y.at ? x.at > y.at : x.seq > y.seq;
    }
  };

  void apply_deferred();
  void advance_to(Nanos t) noexcept {
    if (t > now_) now_ = t;
  }

  std::uint64_t seed_;
  FaultConfig faults_;
  Phase phase_ = Phase::Setup;
  Nanos now_ = 0;
  std::uint64_t seq_ = 0;
  std::uint64_t events_ = 0;
  std::uint64_t current_index_ = 0;
  std::uint64_t trace_hash_;
  std::uint64_t epoch_;
  std::FILE* trace_ = nullptr;

  std::vector<HandlerEntry> handlers_;
  std::vector<Event> heap_;
  std::vector<NodeId> deferred_crashes_;
  std::vector<std::function<void()>> heal_hooks_;

  FaultStats stats_;
  ProbeRegistry probes_;
  OracleRegistry oracles_;
  BuggifyRegistry buggify_;
  OracleId o_live_;

  std::unique_ptr<Scheduler> sched_;
  std::unique_ptr<FaultAtlas> atlas_;
  std::unique_ptr<Network> net_;
  std::unique_ptr<FaultInjector> injector_;
  std::vector<std::unique_ptr<Node>> nodes_;
  HandlerId node_handler_ = 0;
  HandlerId disk_handler_ = 0;

  friend class Node;
};

}  // namespace lle::sim
