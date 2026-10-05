#pragma once
// Simulated node: one process plus its persistent hardware (09 §2).
//
// The node owns what survives a crash: its disk, its clock and its identity.
// The process image (every object a boot function creates: components, ports,
// file handles, queues) is a Process subclass owned through one pointer, so a
// crash is "destroy the image": memory is gone, sockets are reset, file
// handles are closed. A restart calls the user's boot function again with
// BootReason::Restart, which runs the production recovery path against the
// simulated disk.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "runtime/stage.h"
#include "sim/clock.h"
#include "sim/disk.h"
#include "sim/event.h"
#include "sim/scheduler.h"
#include "sim/world.h"

namespace lle::sim {

struct NodeOptions {
  bool crashable = true;  // fault injector may kill it
  bool pausable = true;   // fault injector may SIGSTOP it
};

enum class CrashKind : std::uint8_t {
  Process,  // SIGKILL: memory lost, page cache survives
  Host,     // power loss: memory lost, unsynced disk data lost or torn
};
enum class BootReason : std::uint8_t { Initial, Restart };

// Base for process images. Virtual only for destruction (cold path).
class Process {
 public:
  virtual ~Process() = default;
};

class Node {
 public:
  using BootFn = std::function<void(Node&, BootReason)>;

  Node(World& w, NodeId id, std::string name, const NodeOptions& opts);
  ~Node();
  Node(const Node&) = delete;
  Node& operator=(const Node&) = delete;

  [[nodiscard]] NodeId id() const noexcept { return id_; }
  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  [[nodiscard]] std::uint32_t ip() const noexcept { return ip_; }
  [[nodiscard]] World& world() noexcept { return w_; }
  [[nodiscard]] Clock& clock() noexcept { return clock_; }
  [[nodiscard]] Disk& disk() noexcept { return disk_; }
  [[nodiscard]] bool alive() const noexcept { return alive_; }
  [[nodiscard]] bool paused() const noexcept { return paused_; }
  [[nodiscard]] bool crashable() const noexcept { return opts_.crashable; }
  [[nodiscard]] bool pausable() const noexcept { return opts_.pausable; }
  [[nodiscard]] std::uint32_t incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] std::uint64_t crashes() const noexcept { return crashes_; }

  // Workload stream for this node and incarnation (sub-stream `sub`).
  [[nodiscard]] Rng rng(std::uint64_t sub = 0) const noexcept;

  void set_boot(BootFn fn) { boot_ = std::move(fn); }
  void boot();  // initial start

  // Replaces the process image. Call from the boot function.
  template <class P, class... A>
  P& emplace_process(A&&... args) {
    static_assert(std::is_base_of_v<Process, P>, "process images derive from sim::Process");
    proc_.reset();
    auto p = std::make_unique<P>(std::forward<A>(args)...);
    P& ref = *p;
    proc_ = std::move(p);
    return ref;
  }
  [[nodiscard]] Process* process() noexcept { return proc_.get(); }

  // Registers a stage of the current process with the world's scheduler.
  template <rt::StageLike S>
  void add_stage(S& s, std::string_view stage_name) {
    w_.scheduler().add_stage(id_, s, stage_name);
  }

  // `injected` = false for harness actions (e.g. a verification power cut
  // after convergence) that must not count as fired faults.
  void crash(CrashKind kind, bool injected = true);
  void restart_after(Nanos delay);
  void pause(Nanos duration);
  void resume();
  // From inside the process (e.g. abort on fsync EIO): crash after the current
  // event, then a supervisor restarts it after a short seeded delay.
  void request_crash();

  // Node-level events (restart, resume), dispatched by the world.
  void on_restart(std::uint64_t gen);
  void on_resume(std::uint64_t gen);

 private:
  World& w_;
  NodeId id_;
  std::string name_;
  NodeOptions opts_;
  std::uint32_t ip_;
  Clock clock_;
  Disk disk_;
  Rng supervisor_rng_;
  BootFn boot_;
  std::unique_ptr<Process> proc_;
  bool alive_ = false;
  bool paused_ = false;
  bool crash_requested_ = false;
  std::uint32_t incarnation_ = 0;
  std::uint64_t restart_gen_ = 0;
  std::uint64_t pause_gen_ = 0;
  std::uint64_t crashes_ = 0;

  friend class World;
};

// First node gets 10.0.0.1, then 10.0.0.2, ...
[[nodiscard]] constexpr std::uint32_t node_ip(NodeId id) noexcept { return 0x0A00'0001u + id; }

}  // namespace lle::sim
