#pragma once
// The node clock (apps/exchanged/clock.h, NodeClock) on the simulated node's clock:
// env::ClockLike plus mode(), manual(), set_manual() and freeze(), which the seq stage
// and the start-up steps use (seq_stage.h, start_impl.h). Exchange time is the node's
// simulated realtime (with its drift and step faults) in Real mode; the work meters
// read tsc(), which is virtual time here.
#include <cstdint>

#include "common/types.h"
#include "exchanged/config.h"
#include "sim/clock.h"

namespace lle::sim::exch {

class SimNodeClock {
 public:
  explicit SimNodeClock(const Clock& c) noexcept : c_(&c) {}
  SimNodeClock(const SimNodeClock&) = delete;
  SimNodeClock& operator=(const SimNodeClock&) = delete;

  [[nodiscard]] Nanos now_mono() const noexcept { return c_->now_mono(); }
  [[nodiscard]] Nanos now_real() const noexcept { return frozen_ != 0 ? frozen_ : c_->now_real(); }
  [[nodiscard]] std::uint64_t tsc() const noexcept { return c_->tsc(); }

  [[nodiscard]] lle::exch::ClockMode mode() const noexcept { return lle::exch::ClockMode::Real; }
  [[nodiscard]] Nanos manual() const noexcept { return 0; }  // Real mode: never walked
  void set_manual(Nanos) noexcept {}
  // The day-start records are stamped at a fixed time (clock.h); 0 releases it.
  void freeze(Nanos t) noexcept { frozen_ = t; }

 private:
  const Clock* c_;
  Nanos frozen_ = 0;
};

}  // namespace lle::sim::exch
