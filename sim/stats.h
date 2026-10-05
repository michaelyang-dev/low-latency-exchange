#pragma once
// Fault and traffic counters for one world run. T22 acceptance reads these:
// every fault class must fire >= 10^3 times across the nightly ensemble.
#include <cstdint>

namespace lle::sim {

// X(name, fault_class_label)
#define LLE_SIM_FAULT_STATS(X)              \
  X(net_sent, "traffic")                    \
  X(net_delivered, "traffic")               \
  X(net_loss, "loss")                       \
  X(net_dup, "duplication")                 \
  X(net_reorder, "reorder")                 \
  X(net_spike, "reorder")                   \
  X(net_partition_drop, "partition")        \
  X(net_rx_overflow, "loss")                \
  X(partitions, "partition")                \
  X(stream_segments, "traffic")             \
  X(stream_short_segments, "reorder")       \
  X(stream_stalls, "reorder")               \
  X(stream_resets, "partition")             \
  X(stream_refused, "traffic")              \
  X(crashes_process, "crash")               \
  X(crashes_host, "crash")                  \
  X(restarts, "crash")                      \
  X(pauses, "pause")                        \
  X(disk_writes, "traffic")                 \
  X(disk_syncs, "traffic")                  \
  X(disk_stalls, "disk_stall")              \
  X(disk_eio, "disk_error")                 \
  X(disk_torn, "disk_error")                \
  X(disk_lost_unsynced, "disk_error")       \
  X(disk_persisted_unsynced, "disk_error")  \
  X(disk_ooo_persist, "disk_error")         \
  X(disk_misdirect, "disk_error")           \
  X(disk_bitflip, "disk_error")             \
  X(clock_steps, "clock")                   \
  X(clock_drift_nodes, "clock")             \
  X(buggify_fired, "buggify")

struct FaultStats {
#define LLE_SIM_STAT_FIELD(name, cls) std::uint64_t name = 0;
  LLE_SIM_FAULT_STATS(LLE_SIM_STAT_FIELD)
#undef LLE_SIM_STAT_FIELD

  template <class F>
  void for_each(F&& f) const {
#define LLE_SIM_STAT_VISIT(name, cls) f(#name, cls, name);
    LLE_SIM_FAULT_STATS(LLE_SIM_STAT_VISIT)
#undef LLE_SIM_STAT_VISIT
  }

  FaultStats& operator+=(const FaultStats& o) noexcept {
#define LLE_SIM_STAT_ADD(name, cls) name += o.name;
    LLE_SIM_FAULT_STATS(LLE_SIM_STAT_ADD)
#undef LLE_SIM_STAT_ADD
    return *this;
  }
};

}  // namespace lle::sim
