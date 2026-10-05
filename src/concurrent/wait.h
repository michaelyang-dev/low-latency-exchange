#pragma once
// Wait policies (08-concurrency-runtime §1). Queues never wait; callers do, with a
// policy chosen per deployment:
//   - Spin:      isolated cores. Pure busy poll with no PAUSE: Intel PAUSE can cost
//                ~140 cycles on Skylake and later (R6 §D2.3), which is pure latency.
//   - SpinPause: busy poll with a CPU relax hint per failed poll (SMT siblings,
//                power); x86 PAUSE, arm64 ISB.
//   - Backoff:   shared cores (dev, CI): exponentially growing PAUSE bursts, then
//                std::this_thread::yield().
// A policy is any type with `void wait() noexcept` (called after each failed poll)
// and `void reset() noexcept` (called after useful work).
//
// Include allowlist (08 §7): <atomic>, <cstddef>, <cstdint>, <type_traits> only, so
// the yield lives out of line in wait.cpp.
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace lle::conc {

namespace detail {
void yield_thread() noexcept;  // std::this_thread::yield(), in wait.cpp
}  // namespace detail

// One spin-wait hint.
inline void cpu_relax() noexcept {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#elif defined(__aarch64__)
  // ISB stalls for roughly the latency PAUSE is meant to give; arm64 YIELD is a NOP on
  // most cores.
  __asm__ __volatile__("isb" ::: "memory");
#endif
}

struct Spin {
  void wait() noexcept {}
  void reset() noexcept {}
};

struct SpinPause {
  void wait() noexcept { cpu_relax(); }
  void reset() noexcept {}
};

class Backoff {
 public:
  // Bursts of 1, 2, 4, ... 2^max_exp PAUSEs; after that every wait() yields.
  constexpr explicit Backoff(std::uint32_t max_exp = 6) noexcept : max_exp_(max_exp < 20 ? max_exp : 20) {}

  void wait() noexcept {
    if (step_ <= max_exp_) {
      for (std::uint32_t i = 0, n = 1u << step_; i < n; ++i) cpu_relax();
      ++step_;
    } else {
      detail::yield_thread();
    }
  }
  void reset() noexcept { step_ = 0; }
  bool yielding() const noexcept { return step_ > max_exp_; }

 private:
  std::uint32_t max_exp_;
  std::uint32_t step_ = 0;
};

template <class P>
concept WaitPolicy = requires(P& p) {
  p.wait();
  p.reset();
};

// Polls `pred` until it returns true, calling policy.wait() after each failure.
// Returns the number of failed polls.
template <class Pred, WaitPolicy Policy = Backoff>
std::uint64_t spin_until(Pred&& pred, Policy policy = Policy{}) {
  std::uint64_t failed = 0;
  while (!pred()) {
    policy.wait();
    ++failed;
  }
  return failed;
}

// As spin_until, but gives up after `max_failed` failed polls. Returns pred's final value.
template <class Pred, WaitPolicy Policy = Backoff>
bool spin_until_for(Pred&& pred, std::uint64_t max_failed, Policy policy = Policy{}) {
  for (std::uint64_t failed = 0;; ++failed) {
    if (pred()) return true;
    if (failed == max_failed) return false;
    policy.wait();
  }
}

}  // namespace lle::conc
