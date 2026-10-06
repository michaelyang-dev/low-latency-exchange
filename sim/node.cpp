#include "sim/node.h"

#include <algorithm>

#include "common/assert.h"
#include "sim/dist.h"

namespace lle::sim {

namespace {

ClockParams clock_params(const World& w, NodeId id) {
  Rng r = w.stream(Stream::Clock, id);
  const FaultConfig& f = w.faults();
  ClockParams p;
  // Always three draws, whatever the configuration, so streams stay aligned.
  const std::int64_t off = uniform(r, -f[Param::ClockOffsetNs], f[Param::ClockOffsetNs]);
  const std::int64_t drift = uniform(r, -f[Param::ClockDriftPpb], f[Param::ClockDriftPpb]);
  const std::uint64_t tsc = r.next_u64() >> 8;
  p.offset_ns = off;
  p.drift_ppb = drift;
  p.tsc_base = tsc;
  return p;
}

DiskParams disk_params(const World& w, NodeId id) {
  const FaultConfig& f = w.faults();
  DiskParams p;
  p.write_min_ns = f[Param::DiskWriteMinNs];
  p.write_mean_ns = f[Param::DiskWriteMeanNs];
  p.sync_min_ns = f[Param::DiskSyncMinNs];
  p.sync_mean_ns = f[Param::DiskSyncMeanNs];
  p.stall_ppm = static_cast<std::uint32_t>(f.u(Param::DiskStallPpm));
  p.stall_max_ns = f[Param::DiskStallMaxNs];
  p.eio_write_ppm = static_cast<std::uint32_t>(f.u(Param::DiskEioWritePpm));
  p.eio_sync_ppm = static_cast<std::uint32_t>(f.u(Param::DiskEioSyncPpm));
  p.crash_keep_ppm = static_cast<std::uint32_t>(f.u(Param::DiskCrashKeepPpm));
  p.crash_torn_ppm = static_cast<std::uint32_t>(f.u(Param::DiskCrashTornPpm));
  // Per-disk tear granularity: a property of the device, drawn once.
  Rng r = w.stream(Stream::Disk, (std::uint64_t{1} << 32) | id);
  p.tear_bytes = chance_ppm(r, f.u(Param::DiskTear4kPpm)) ? 4096 : 512;
  p.misdirect_ppm = static_cast<std::uint32_t>(f.u(Param::DiskMisdirectPpm));
  p.bitflip_ppm = static_cast<std::uint32_t>(f.u(Param::DiskBitflipPpm));
  return p;
}

}  // namespace

Node::Node(World& w, NodeId id, std::string name, const NodeOptions& opts)
    : w_(w),
      id_(id),
      name_(std::move(name)),
      opts_(opts),
      ip_(node_ip(id)),
      clock_(w, clock_params(w, id)),
      disk_(w, id, disk_params(w, id), derive_seed(w.seed(), Stream::Disk, id)),
      supervisor_rng_(w.stream(Stream::Process, (std::uint64_t{2} << 32) | id)) {
  if (clock_.params().drift_ppb != 0 || clock_.params().offset_ns != 0) ++w_.stats().clock_drift_nodes;
}

Node::~Node() {
  // Tear the process down while the network and disk still exist.
  w_.scheduler().remove_node(id_);
  proc_.reset();
}

Rng Node::rng(std::uint64_t sub) const noexcept {
  return w_.stream(Stream::Workload, (static_cast<std::uint64_t>(id_) << 40) |
                                         (static_cast<std::uint64_t>(incarnation_) << 20) | (sub & 0xFFFFF));
}

void Node::boot() {
  LLE_ASSERT(!alive_, "node already running");
  alive_ = true;
  if (boot_) boot_(*this, incarnation_ == 0 ? BootReason::Initial : BootReason::Restart);
}

void Node::crash(CrashKind kind, bool injected) {
  if (!alive_) return;
  w_.scheduler().remove_node(id_);
  alive_ = false;
  paused_ = false;
  ++pause_gen_;
  ++restart_gen_;
  crash_requested_ = false;
  ++crashes_;
  proc_.reset();  // memory is gone: ports reset, file handles closed
  if (kind == CrashKind::Host) {
    ++host_crashes_;
    disk_.crash_host();
  }
  if (injected) ++(kind == CrashKind::Host ? w_.stats().crashes_host : w_.stats().crashes_process);
}

void Node::restart_after(Nanos delay) {
  ++restart_gen_;
  w_.schedule(w_.now() + std::max<Nanos>(delay, 1), w_.node_handler_, /*kind=*/1, id_, restart_gen_);
}

void Node::on_restart(std::uint64_t gen) {
  if (gen != restart_gen_ || alive_) return;
  if (disk_.inflight_total() > 0) {
    // A dying process's write syscalls complete (or fail) before it is gone,
    // so its successor never races them: retry once they have settled.
    w_.schedule(w_.now() + kMs, w_.node_handler_, /*kind=*/1, id_, restart_gen_);
    return;
  }
  ++incarnation_;
  ++w_.stats().restarts;
  boot();
}

void Node::pause(Nanos duration) {
  if (!alive_ || paused_) return;
  paused_ = true;
  ++pause_gen_;
  ++w_.stats().pauses;
  w_.scheduler().suspend_node(id_);
  w_.schedule(w_.now() + std::max<Nanos>(duration, 1), w_.node_handler_, /*kind=*/2, id_, pause_gen_);
}

void Node::resume() {
  if (!paused_) return;
  paused_ = false;
  ++pause_gen_;
  w_.scheduler().resume_node(id_);
}

void Node::on_resume(std::uint64_t gen) {
  if (gen != pause_gen_ || !paused_) return;
  resume();
}

void Node::request_crash() {
  if (!alive_ || crash_requested_) return;
  crash_requested_ = true;
  w_.defer_crash(id_);
}

}  // namespace lle::sim
