#pragma once
// The input SCQs (OUCH, session events) have one consumer at a time (the documented
// MPSC contract; ADR-031 would rely on it). In split paired mode the consumer changes
// with the role: the sequencer while sequencing is allowed, the replica (FORWARD) while
// it is backup or candidate, handed over through Shared::split (repl_stage.h).
//
// Debug builds check the hand-over: each consumer holds the guard while it may pop, and
// a second holder fails an assertion. Release builds compile it out (an empty struct).
#include <atomic>
#include <cstdint>

#include "common/assert.h"

namespace lle::exch {

class ScqConsumerGuard {
 public:
  enum Who : std::uint8_t { kNone = 0, kSeq = 1, kRepl = 2 };
#if !defined(NDEBUG)
  void enter(Who who) noexcept {
    std::uint8_t expected = kNone;
    const bool mine = owner_.compare_exchange_strong(expected, who, std::memory_order_acq_rel) || expected == who;
    LLE_ASSERT(mine, "two consumers of the input SCQs at once (single-consumer contract)");
  }
  void exit(Who who) noexcept {
    std::uint8_t expected = who;
    (void)owner_.compare_exchange_strong(expected, kNone, std::memory_order_acq_rel);
  }

 private:
  std::atomic<std::uint8_t> owner_{kNone};
#else
  void enter(Who) noexcept {}
  void exit(Who) noexcept {}
#endif
};

class ScqConsumerScope {
 public:
  ScqConsumerScope(ScqConsumerGuard& g, ScqConsumerGuard::Who who) noexcept : g_(&g), who_(who) { g_->enter(who_); }
  ~ScqConsumerScope() { g_->exit(who_); }
  ScqConsumerScope(const ScqConsumerScope&) = delete;
  ScqConsumerScope& operator=(const ScqConsumerScope&) = delete;

 private:
  ScqConsumerGuard* g_;
  ScqConsumerGuard::Who who_;
};

}  // namespace lle::exch
