#include "sim/disk.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "common/assert.h"
#include "common/hash.h"
#include "sim/dist.h"
#include "sim/fault_atlas.h"
#include "sim/node.h"
#include "sim/scheduler.h"
#include "sim/world.h"

namespace lle::sim {

namespace {
constexpr std::uint16_t kWriteDone = 1;
constexpr std::uint16_t kSyncDone = 2;
}  // namespace

Disk::Disk(World& w, NodeId node, const DiskParams& p, std::uint64_t seed) : w_(w), node_(node), p_(p), rng_(seed) {
  if (p_.tear_bytes == 0) p_.tear_bytes = 512;
}

Disk::~Disk() = default;

std::uint32_t Disk::open(std::string_view name) {
  if (const auto it = by_name_.find(name); it != by_name_.end()) return it->second;
  auto f = std::make_unique<File>();
  f->name = std::string(name);
  f->key = FaultAtlas::file_key(name.data(), name.size());
  const auto idx = static_cast<std::uint32_t>(files_.size());
  files_.push_back(std::move(f));
  by_name_.emplace(std::string(name), idx);
  return idx;
}

bool Disk::exists(std::string_view name) const { return by_name_.find(name) != by_name_.end(); }

std::uint64_t Disk::size(std::uint32_t f) const { return files_[f]->cache.size(); }
std::uint64_t Disk::durable_size(std::uint32_t f) const { return files_[f]->durable.size(); }
std::uint64_t Disk::inflight(std::uint32_t f) const { return files_[f]->inflight.size(); }
std::uint64_t Disk::dirty(std::uint32_t f) const { return files_[f]->dirty.size(); }

std::uint64_t Disk::inflight_total() const {
  std::uint64_t n = 0;
  for (const auto& f : files_) n += f->inflight.size();
  return n;
}

void Disk::install(std::string_view name, std::span<const std::byte> bytes) {
  File& f = *files_[open(name)];
  LLE_ASSERT(f.inflight.empty() && f.dirty.empty(), "install() is for setup only");
  f.durable.assign(bytes.begin(), bytes.end());
  f.cache = f.durable;
}
std::span<const std::byte> Disk::durable_image(std::uint32_t f) const { return files_[f]->durable; }
std::span<const std::byte> Disk::cache_image(std::uint32_t f) const { return files_[f]->cache; }

std::size_t Disk::read(std::uint32_t fi, std::uint64_t off, std::span<std::byte> out) const {
  const File& f = *files_[fi];
  if (off >= f.cache.size()) return 0;
  const std::size_t n = std::min<std::size_t>(out.size(), static_cast<std::size_t>(f.cache.size() - off));
  std::memcpy(out.data(), f.cache.data() + off, n);
  return n;
}

std::uint32_t Disk::attach(std::uint32_t fi) {
  File& f = *files_[fi];
  LLE_ASSERT(!f.handle_open, "sim::Disk supports one open handle per file");
  f.handle_open = true;
  f.cq.clear();
  return f.handle_gen;
}

void Disk::detach(std::uint32_t fi, std::uint32_t gen) {
  File& f = *files_[fi];
  if (!f.handle_open || f.handle_gen != gen) return;
  f.handle_open = false;
  ++f.handle_gen;
  f.cq.clear();
}

bool Disk::handle_valid(std::uint32_t fi, std::uint32_t gen) const {
  const File& f = *files_[fi];
  return f.handle_open && f.handle_gen == gen;
}

RingQueue<env::DiskCompletion>& Disk::completions(std::uint32_t f) { return files_[f]->cq; }

std::uint32_t Disk::acquire(std::span<const std::byte> data) {
  std::uint32_t b;
  if (!free_bufs_.empty()) {
    b = free_bufs_.back();
    free_bufs_.pop_back();
  } else {
    b = static_cast<std::uint32_t>(bufs_.size());
    bufs_.emplace_back();
  }
  std::vector<std::byte>& v = bufs_[b];
  if (v.size() < data.size()) v.resize(data.size());
  if (!data.empty()) std::memcpy(v.data(), data.data(), data.size());
  return b;
}

Nanos Disk::latency(Nanos min, Nanos mean) {
  Nanos lat = min + exp_ns(rng_, mean);
  const bool stall = chance_ppm(rng_, p_.stall_ppm);
  const Nanos stall_ns = log_uniform(rng_, kMs, std::max(kMs, p_.stall_max_ns));
  if (stall && w_.faults_active()) {
    lat += stall_ns;
    ++w_.stats().disk_stalls;
    if (stall_ns > p_.heartbeat_ns) w_.probes().hit("disk.stall_longer_than_heartbeat");
  }
  return lat < 1 ? 1 : lat;
}

bool Disk::submit_write(std::uint32_t fi, std::uint64_t off, std::span<const std::byte> data, bool dsync,
                        std::uint64_t tag) {
  File& f = *files_[fi];
  if (f.inflight.size() >= p_.max_queue_depth) return false;
  Op op;
  op.seq = ++f.next_seq;
  op.off = off;
  op.len = data.size();
  op.buf = acquire(data);
  op.dsync = dsync;
  op.tag = tag;
  op.handle_gen = f.handle_gen;
  const Nanos lat = latency(p_.write_min_ns, p_.write_mean_ns);
  const bool eio = chance_ppm(rng_, p_.eio_write_ppm);
  op.eio = eio && w_.faults_active() && faults_allowed();
  f.inflight.push_back(op);
  Fnv1a64 h;
  h.bytes(data);
  h.u(off);
  w_.schedule(w_.now() + lat, handler_, kWriteDone, node_, fi | (static_cast<std::uint64_t>(f.crash_epoch) << 32),
              op.seq, h.value());
  ++w_.stats().disk_writes;
  return true;
}

bool Disk::submit_sync(std::uint32_t fi, std::uint64_t tag) {
  File& f = *files_[fi];
  if (f.inflight.size() >= p_.max_queue_depth) return false;
  Op op;
  op.seq = ++f.next_seq;
  op.is_sync = true;
  op.tag = tag;
  op.covers_done = f.done_counter;
  op.handle_gen = f.handle_gen;
  const Nanos lat = latency(p_.sync_min_ns, p_.sync_mean_ns);
  const bool eio = chance_ppm(rng_, p_.eio_sync_ppm);
  op.eio = eio && w_.faults_active() && faults_allowed();
  f.inflight.push_back(op);
  w_.schedule(w_.now() + lat, handler_, kSyncDone, node_, fi | (static_cast<std::uint64_t>(f.crash_epoch) << 32),
              op.seq, op.covers_done);
  ++w_.stats().disk_syncs;
  return true;
}

std::int32_t Disk::write_now(std::uint32_t fi, std::uint64_t off, std::span<const std::byte> data, bool dsync) {
  File& f = *files_[fi];
  const bool eio = chance_ppm(rng_, p_.eio_write_ppm);
  ++w_.stats().disk_writes;
  if (eio && w_.faults_active() && faults_allowed()) {
    fault_landed();
    ++w_.stats().disk_eio;
    return -kEio;
  }
  if (atlas_replicas_ > 1) {
    // Fault atlas, as for asynchronous completions: corruption only where
    // another replica keeps a clean copy. Drawn only on replicated disks, so
    // single-copy worlds keep their random streams.
    const bool mis = chance_ppm(rng_, p_.misdirect_ppm);
    const bool mis_up = rng_.below(2) == 0;
    const auto mis_k = static_cast<std::uint64_t>(uniform(rng_, 1, 8));
    const bool flip = chance_ppm(rng_, p_.bitflip_ppm);
    const std::uint64_t flip_at = rng_.next_u64();
    const auto flip_bit = static_cast<unsigned>(rng_.below(8));
    if (w_.faults_active() && !data.empty() &&
        w_.atlas().range_faulty(f.key, off, data.size(), atlas_replica_, atlas_replicas_)) {
      if (mis) {
        const std::uint64_t delta = mis_k * p_.tear_bytes;
        const bool can_down = off >= delta;
        const std::uint64_t target = mis_up || !can_down ? off + delta : off - delta;
        if (w_.atlas().range_faulty(f.key, target, data.size(), atlas_replica_, atlas_replicas_)) {
          off = target;
          ++w_.stats().disk_misdirect;
        }
      }
      if (flip) {
        now_scratch_.assign(data.begin(), data.end());
        now_scratch_[static_cast<std::size_t>(flip_at % data.size())] ^= static_cast<std::byte>(1u << flip_bit);
        data = now_scratch_;
        ++w_.stats().disk_bitflip;
      }
    }
  }
  write_image(f.cache, off, data);
  if (dsync) {
    write_image(f.durable, off, data);
  } else {
    f.dirty.push_back(Dirty{++f.next_seq, ++f.done_counter, off, data.size(), acquire(data), false});
  }
  return static_cast<std::int32_t>(data.size());
}

std::int32_t Disk::sync_now(std::uint32_t fi) {
  File& f = *files_[fi];
  const bool eio = chance_ppm(rng_, p_.eio_sync_ppm);
  ++w_.stats().disk_syncs;
  if (eio && w_.faults_active() && faults_allowed()) {
    fault_landed();
    for (Dirty& d : f.dirty) d.doomed = true;  // fsyncgate, as for asynchronous syncs
    ++w_.stats().disk_eio;
    return -kEio;
  }
  for (const Dirty& d : f.dirty) {
    if (!d.doomed) {
      write_image(f.durable, d.off, data_of(d.buf, d.len));
      release(d.buf);
    }
  }
  std::erase_if(f.dirty, [](const Dirty& d) { return !d.doomed; });
  return 0;
}

void Disk::resize(std::uint32_t fi, std::uint64_t n) {
  File& f = *files_[fi];
  f.cache.resize(static_cast<std::size_t>(n), std::byte{0});
  f.durable.resize(static_cast<std::size_t>(n), std::byte{0});
}

bool Disk::remove(std::string_view name) {
  const auto it = by_name_.find(name);
  if (it == by_name_.end()) return false;
  by_name_.erase(it);
  return true;
}

std::vector<std::string> Disk::list() const {
  std::vector<std::string> out;
  out.reserve(by_name_.size());
  for (const auto& [name, idx] : by_name_) out.push_back(name);
  return out;
}

bool Disk::rename(std::string_view from, std::string_view to) {
  const auto it = by_name_.find(from);
  if (it == by_name_.end()) return false;
  if (from == to) return true;
  const std::uint32_t idx = it->second;
  by_name_.erase(it);
  if (const auto old = by_name_.find(to); old != by_name_.end()) by_name_.erase(old);  // replaced
  by_name_.emplace(std::string(to), idx);
  files_[idx]->name = std::string(to);
  return true;
}

void Disk::write_image(std::vector<std::byte>& img, std::uint64_t off, std::span<const std::byte> data) {
  if (data.empty()) return;
  const std::uint64_t end = off + data.size();
  if (img.size() < end) img.resize(static_cast<std::size_t>(end), std::byte{0});
  std::memcpy(img.data() + off, data.data(), data.size());
}

Dispatch Disk::on_event(void* ctx, const Event& ev) {
  auto* w = static_cast<World*>(ctx);
  return w->node(ev.node).disk().handle(ev);
}

Dispatch Disk::handle(const Event& ev) {
  const auto fi = static_cast<std::uint32_t>(ev.a & 0xFFFF'FFFFu);
  const auto epoch = static_cast<std::uint32_t>(ev.a >> 32);
  File& f = *files_[fi];
  if (epoch != f.crash_epoch) return {false, 0};
  const auto it = std::find_if(f.inflight.begin(), f.inflight.end(), [&](const Op& o) { return o.seq == ev.b; });
  if (it == f.inflight.end()) return {false, 0};
  Op op = *it;
  f.inflight.erase(it);
  // A gated disk (set_fault_gate) re-checks at completion: an error drawn while failures
  // were allowed does not land once they are not (the other node failed meanwhile).
  if (op.eio && fault_gate_ && !fault_gate_()) op.eio = false;
  if (op.eio) fault_landed();

  std::int32_t result = 0;
  if (!op.is_sync) {
    if (op.eio) {
      result = -kEio;
      ++w_.stats().disk_eio;
      release(op.buf);
    } else {
      std::uint64_t off = op.off;
      const std::span<std::byte> data = data_of(op.buf, op.len);
      // Fault atlas: corruption only where another replica keeps a clean copy.
      // Draws are made unconditionally so the stream stays aligned.
      const bool mis = chance_ppm(rng_, p_.misdirect_ppm);
      const bool mis_up = rng_.below(2) == 0;
      const auto mis_k = static_cast<std::uint64_t>(uniform(rng_, 1, 8));
      const bool flip = chance_ppm(rng_, p_.bitflip_ppm);
      const std::uint64_t flip_at = rng_.next_u64();
      const auto flip_bit = static_cast<unsigned>(rng_.below(8));
      if (w_.faults_active() && !data.empty() &&
          w_.atlas().range_faulty(f.key, off, data.size(), atlas_replica_, atlas_replicas_)) {
        if (mis) {
          const std::uint64_t delta = mis_k * p_.tear_bytes;
          const bool can_down = off >= delta;
          const std::uint64_t target = mis_up || !can_down ? off + delta : off - delta;
          if (w_.atlas().range_faulty(f.key, target, data.size(), atlas_replica_, atlas_replicas_)) {
            off = target;
            ++w_.stats().disk_misdirect;
          }
        }
        if (flip) {
          data[static_cast<std::size_t>(flip_at % data.size())] ^= static_cast<std::byte>(1u << flip_bit);
          ++w_.stats().disk_bitflip;
        }
      }
      write_image(f.cache, off, data);
      if (op.dsync) {
        write_image(f.durable, off, data);
        release(op.buf);
      } else {
        f.dirty.push_back(Dirty{op.seq, ++f.done_counter, off, op.len, op.buf, false});
      }
      result = static_cast<std::int32_t>(op.len);
    }
  } else if (op.eio) {
    // fsyncgate: the covered pages are marked clean but never reach the disk.
    for (Dirty& d : f.dirty) {
      if (d.done_seq <= op.covers_done) d.doomed = true;
    }
    result = -kEio;
    ++w_.stats().disk_eio;
  } else {
    for (const Dirty& d : f.dirty) {
      if (d.done_seq <= op.covers_done && !d.doomed) {
        write_image(f.durable, d.off, data_of(d.buf, d.len));
        release(d.buf);
      }
    }
    std::erase_if(f.dirty, [&](const Dirty& d) { return d.done_seq <= op.covers_done && !d.doomed; });
  }

  if (f.handle_open && op.handle_gen == f.handle_gen) {
    f.cq.push(env::DiskCompletion{op.tag, result});
    w_.scheduler().wake(node_);
  }
  return {true, static_cast<std::uint32_t>(result)};
}

void Disk::crash_host() {
  for (auto& fp : files_) {
    File& f = *fp;
    if (!f.dirty.empty()) w_.probes().hit("disk.crash_between_write_and_fsync");
    bool lost_earlier = false;
    const std::uint64_t g = p_.tear_bytes;
    auto decide = [&](std::uint64_t off, std::uint64_t len, std::uint32_t buf, bool doomed) {
      const std::uint64_t r = rng_.below(kPpm);
      const std::byte* src = bufs_[buf].data();
      bool persisted_any = false;
      if (doomed || len == 0) {
        // Write-back already failed: these pages never reach the disk.
      } else if (r < p_.crash_keep_ppm) {
        write_image(f.durable, off, std::span<const std::byte>(src, static_cast<std::size_t>(len)));
        persisted_any = true;
        ++w_.stats().disk_persisted_unsynced;
      } else if (r < static_cast<std::uint64_t>(p_.crash_keep_ppm) + p_.crash_torn_ppm) {
        // Torn: each sector of the write independently made it or not.
        for (std::uint64_t s = off / g; s <= (off + len - 1) / g; ++s) {
          const std::uint64_t lo = std::max(off, s * g);
          const std::uint64_t hi = std::min(off + len, (s + 1) * g);
          if (rng_.below(2) == 0) {
            write_image(f.durable, lo, std::span<const std::byte>(src + (lo - off), static_cast<std::size_t>(hi - lo)));
            persisted_any = true;
          }
        }
        ++w_.stats().disk_torn;
      }
      if (!persisted_any) {
        ++w_.stats().disk_lost_unsynced;
        lost_earlier = true;
      } else if (lost_earlier) {
        ++w_.stats().disk_ooo_persist;
        w_.probes().hit("disk.ooo_persist_at_crash", /*rare=*/true);
      }
      release(buf);
    };
    for (const Dirty& d : f.dirty) decide(d.off, d.len, d.buf, d.doomed);
    for (const Op& op : f.inflight) {
      if (op.is_sync) continue;
      if (op.eio) {
        release(op.buf);
      } else {
        decide(op.off, op.len, op.buf, false);
      }
    }
    f.cache = f.durable;
    f.inflight.clear();
    f.dirty.clear();
    f.cq.clear();
    ++f.crash_epoch;
    if (f.handle_open) {
      f.handle_open = false;
      ++f.handle_gen;
    }
  }
}

DiskFile::DiskFile(Node& node, std::string_view name) : disk_(&node.disk()) {
  file_ = disk_->open(name);
  gen_ = disk_->attach(file_);
}

DiskFile::~DiskFile() { disk_->detach(file_, gen_); }

}  // namespace lle::sim
