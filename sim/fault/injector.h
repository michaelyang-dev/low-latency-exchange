#pragma once
// Discrete fault schedule for the safety phase (09 §4, §5).
//
// Crashes, pauses, partitions and clock steps are generated up front for the
// safety window, each class from its own stream, as Poisson processes with the
// swarm's mean interval. The schedule is a plain list, so exsim can write it
// out (--record-faults) and read a subset back (--replay); shrink.py runs ddmin
// over its lines. Per-packet and per-I/O faults (loss, EIO, stalls) are drawn
// inline by the network and disk instead and are ablated by class.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "common/types.h"
#include "sim/event.h"

namespace lle::sim {

class World;

enum class FaultKind : std::uint8_t { Crash = 0, Pause = 1, Partition = 2, ClockStep = 3 };

struct FaultEvent {
  Nanos at = 0;
  FaultKind kind = FaultKind::Crash;
  NodeId node = kNoNode;   // crash/pause/clock target; partition: 1 = symmetric
  std::uint64_t a = 0;     // crash: 1 = host crash; partition: group A mask; clock: delta (two's complement)
  std::uint64_t b = 0;     // partition: group B mask
  Nanos dur = 0;           // crash: restart delay; pause/partition: duration

  friend bool operator==(const FaultEvent&, const FaultEvent&) = default;
};

struct FaultSchedule {
  std::vector<FaultEvent> events;  // sorted by (at, generation order)

  // One event per line: "<at> <kind> <node> <a> <b> <dur>", '#' comments.
  [[nodiscard]] std::string format(std::string_view prefix = {}) const;
  // Parses lines produced by format(); lines whose first token differs from a
  // non-empty `prefix` are skipped. Returns false on a malformed line.
  bool parse(std::string_view text, std::string_view prefix = {});
};

[[nodiscard]] std::string_view fault_kind_name(FaultKind k) noexcept;

class FaultInjector {
 public:
  explicit FaultInjector(World& w);

  // Pure function of (seed, fault config, node set): the schedule for [start, end).
  [[nodiscard]] FaultSchedule generate(Nanos start, Nanos end) const;
  // Schedules every event as a world event; replaces any earlier schedule.
  void install(const FaultSchedule& s);
  [[nodiscard]] const FaultSchedule& installed() const noexcept { return schedule_; }
  // A world may veto a crash at fire time to stay inside the failure model
  // (e.g. never take down the last node that can make progress, 01 §9).
  // Vetoed crashes count as skipped.
  void set_crash_guard(std::function<bool(NodeId)> guard) { crash_guard_ = std::move(guard); }
  [[nodiscard]] std::uint64_t fired() const noexcept { return fired_; }
  [[nodiscard]] std::uint64_t skipped() const noexcept { return skipped_; }

  static Dispatch on_event(void* ctx, const Event& ev);

 private:
  Dispatch fire(const FaultEvent& f);

  World& w_;
  HandlerId handler_;
  FaultSchedule schedule_;
  std::function<bool(NodeId)> crash_guard_;
  std::uint64_t fired_ = 0;
  std::uint64_t skipped_ = 0;
};

}  // namespace lle::sim
