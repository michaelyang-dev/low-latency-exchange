#pragma once
// Thread placement helpers for the stage launcher (08-concurrency-runtime §1).
//
// Platform behavior:
//   - Linux: pthread_setaffinity_np pins, mlockall(MCL_CURRENT|MCL_FUTURE) locks
//     memory, sched_getcpu reports the current CPU, thread names are truncated to the
//     kernel's 15 characters.
//   - macOS: there is no thread-affinity API (thread_policy_set affinity tags are
//     scheduling hints that Apple silicon ignores), so pinning and mlockall report
//     Unsupported and runs there are functional only, never latency evidence. Thread
//     names work (63 characters).
// Cold path only (startup).
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace lle::rt {

enum class PinStatus : std::uint8_t {
  Ok,
  NotRequested,  // the stage has no core-map entry
  Unsupported,   // the platform cannot do it (macOS)
  Failed,        // the call failed (bad CPU id, cpuset, RLIMIT_MEMLOCK, ...)
};

const char* to_string(PinStatus s) noexcept;

// Pins the calling thread to one CPU.
PinStatus pin_current_thread(int cpu) noexcept;

// Names the calling thread (visible in top/htop/perf/lldb). Linux truncates to 15 chars.
bool set_current_thread_name(std::string_view name) noexcept;
std::string current_thread_name();

// mlockall(MCL_CURRENT | MCL_FUTURE): no page faults on the hot path after startup.
PinStatus lock_all_memory() noexcept;

// CPU the caller is running on, or -1 where the platform cannot tell.
int current_cpu() noexcept;

// Number of online CPUs (at least 1).
unsigned online_cpus() noexcept;

// Faults in every page of [p, p + bytes) for writing without changing its contents
// (pre-touch of pools and rings, 08 §1). Run it on the thread that will use the
// memory so first-touch NUMA placement puts it on that thread's node.
void prefault(void* p, std::size_t bytes) noexcept;

}  // namespace lle::rt
