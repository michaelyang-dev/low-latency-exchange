#pragma once
// Stage launcher (08-concurrency-runtime §1): one thread per stage, each running its
// stage's poll() loop until stop. Startup per thread: set the thread name, pin to the
// core-map CPU, pre-touch the stage's registered memory, then wait at a startup
// barrier so every stage begins polling only after all are placed. Optionally
// mlockall() first. Stop is a flag every loop checks; join() waits for all threads.
//
// The launcher is cold-path code (startup/shutdown) and uses the type-erased StageRef;
// the per-iteration loop is one indirect call to poll() plus a relaxed load of the stop
// flag. Dev mode and the simulator use InlineRunner (runtime/stage.h) instead.
//
// macOS: pinning and mlockall are unsupported (runtime/pinning.h); threads are named
// and run unpinned. Use LaunchOptions::require_pinning on Linux production hosts.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "common/cache.h"
#include "runtime/pinning.h"
#include "runtime/stage.h"

namespace lle::rt {

// Stage name -> CPU id. Configuration text (08 §1):
//   [cores]
//   gw0=8 gw1=9 seq=10   # comments run to end of line
// Entries are separated by whitespace, commas or semicolons; bracketed section headers
// are skipped. Insertion order is kept (no unordered iteration).
class CoreMap {
 public:
  static std::expected<CoreMap, std::string> parse(std::string_view text);

  // Adds or replaces an entry.
  void set(std::string_view name, int cpu);
  std::optional<int> cpu_for(std::string_view name) const;
  std::size_t size() const noexcept { return entries_.size(); }
  const std::vector<std::pair<std::string, int>>& entries() const noexcept { return entries_; }

 private:
  std::vector<std::pair<std::string, int>> entries_;
};

enum class IdlePolicy : std::uint8_t {
  Spin,       // isolated cores: busy poll, no PAUSE
  SpinPause,  // busy poll with a relax hint
  Backoff,    // shared cores: PAUSE bursts, then yield (default for dev)
};

struct LaunchOptions {
  IdlePolicy idle = IdlePolicy::Backoff;
  bool lock_memory = false;             // mlockall(MCL_CURRENT|MCL_FUTURE) before start
  bool require_pinning = false;         // start() fails unless every mapped stage pinned
  bool require_core_map_entry = false;  // start() fails if a stage has no CPU
};

struct StageReport {
  std::string name;
  int cpu = -1;  // requested CPU, -1 if unmapped
  PinStatus pin = PinStatus::NotRequested;
  std::uint64_t polls = 0;       // poll() calls
  std::uint64_t busy_polls = 0;  // poll() calls that returned true
};

class Launcher {
 public:
  explicit Launcher(CoreMap cores = {}, LaunchOptions opts = {});
  ~Launcher();  // request_stop() + join()
  Launcher(const Launcher&) = delete;
  Launcher& operator=(const Launcher&) = delete;

  // Registers a stage before start(). The stage must outlive the launcher's threads.
  template <StageLike S>
  void add(std::string_view name, S& stage) {
    add(name, StageRef(stage));
  }
  void add(std::string_view name, StageRef stage);

  // Memory the named stage's thread pre-faults before the barrier (rings, pools).
  void add_pretouch(std::string_view stage, void* p, std::size_t bytes);

  // Starts every stage thread and releases them together once all are placed. On
  // failure no stage has polled and no thread is left running.
  std::expected<void, std::string> start();

  void request_stop() noexcept;
  void join();
  bool running() const noexcept { return started_ && !joined_; }
  bool stop_requested() const noexcept { return stop_.load(std::memory_order_relaxed); }

  std::size_t stage_count() const noexcept { return stages_.size(); }
  PinStatus memory_lock_status() const noexcept { return mlock_; }
  // Per-stage placement and counters; the counters are final after join().
  std::vector<StageReport> reports() const;

 private:
  struct Region {
    void* p;
    std::size_t bytes;
  };
  struct alignas(kFalseSharingBytes) Slot {
    explicit Slot(std::string n, StageRef s) : name(std::move(n)), stage(s) {}
    std::string name;
    StageRef stage;
    int cpu = -1;
    std::vector<Region> pretouch;
    PinStatus pin = PinStatus::NotRequested;  // written before the barrier
    std::uint64_t polls = 0;                  // written by the stage thread only
    std::uint64_t busy_polls = 0;
    std::thread thread;
  };
  enum class Phase : int { Starting, Running, Aborted };

  void thread_main(Slot& s);
  template <class Policy>
  void poll_loop(Slot& s, Policy policy);
  Slot* find(std::string_view name);

  CoreMap cores_;
  LaunchOptions opts_;
  std::vector<std::unique_ptr<Slot>> stages_;
  PinStatus mlock_ = PinStatus::NotRequested;
  bool started_ = false;
  bool joined_ = false;
  alignas(kFalseSharingBytes) std::atomic<std::size_t> ready_{0};
  alignas(kFalseSharingBytes) std::atomic<Phase> phase_{Phase::Starting};
  alignas(kFalseSharingBytes) std::atomic<bool> stop_{false};
};

}  // namespace lle::rt
