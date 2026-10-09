#pragma once
// Simulated disk with AsyncFileNonDurable semantics (09 §3; FoundationDB
// AsyncFileNonDurable, TigerBeetle storage faults).
//
// Per file the disk keeps two images:
//   durable  what survives a host crash (power loss);
//   cache    what reads return: durable plus every completed write, the
//            kernel page cache.
// A write completes after a seeded latency (stall spikes 1 ms - 5 s, EIO with
// configurable probability) and lands in the cache as "dirty". A sync makes
// durable every dirty write that completed before the sync was submitted
// (fsync semantics); a failed sync dooms those writes (Linux "fsyncgate": the
// pages are marked clean but never reach the platter). Completions are
// independent, so they may arrive out of submission order, as with io_uring.
//
// Crash semantics:
//   process crash  memory is gone, the kernel keeps going: in-flight writes
//                  still complete into the cache, dirty data stays dirty.
//   host crash     every unsynced write (dirty or in flight) is independently
//                  lost, persisted, or torn at 512 B / 4 KiB sector granularity,
//                  so a later write may survive while an earlier one is lost.
//
// The Disk object belongs to the Node and survives crashes; DiskFile handles
// live in process memory.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "env/concepts.h"
#include "sim/event.h"
#include "sim/ring_queue.h"

namespace lle::sim {

class World;
class Node;
class FaultAtlas;

inline constexpr std::int32_t kEio = 5;  // errno EIO; completions carry -kEio

struct DiskParams {
  Nanos write_min_ns = 10'000;
  Nanos write_mean_ns = 0;
  Nanos sync_min_ns = 20'000;
  Nanos sync_mean_ns = 0;
  std::uint32_t stall_ppm = 0;
  Nanos stall_max_ns = 0;
  std::uint32_t eio_write_ppm = 0;
  std::uint32_t eio_sync_ppm = 0;
  std::uint32_t crash_keep_ppm = 0;  // unsynced write fully persists at host crash
  std::uint32_t crash_torn_ppm = 0;  // unsynced write partially persists (torn)
  std::uint32_t tear_bytes = 512;    // tear granularity: 512 or 4096
  std::uint32_t misdirect_ppm = 0;   // only inside fault-atlas areas
  std::uint32_t bitflip_ppm = 0;     // only inside fault-atlas areas
  Nanos heartbeat_ns = 100'000'000;  // stalls longer than this hit a must-hit probe
  std::uint32_t max_queue_depth = 256;
};

class Disk {
 public:
  Disk(World& w, NodeId node, const DiskParams& p, std::uint64_t seed);
  ~Disk();
  Disk(const Disk&) = delete;
  Disk& operator=(const Disk&) = delete;

  // Returns the persistent file index for `name`, creating an empty file.
  std::uint32_t open(std::string_view name);
  [[nodiscard]] bool exists(std::string_view name) const;
  [[nodiscard]] std::uint64_t size(std::uint32_t f) const;
  [[nodiscard]] std::uint64_t durable_size(std::uint32_t f) const;
  std::size_t read(std::uint32_t f, std::uint64_t off, std::span<std::byte> out) const;
  [[nodiscard]] std::span<const std::byte> durable_image(std::uint32_t f) const;
  [[nodiscard]] std::span<const std::byte> cache_image(std::uint32_t f) const;

  bool submit_write(std::uint32_t f, std::uint64_t off, std::span<const std::byte> data, bool dsync, std::uint64_t tag);
  bool submit_sync(std::uint32_t f, std::uint64_t tag);

  // Synchronous I/O for cold paths that block in a syscall (recovery repair,
  // segment preparation): applied at once, with the same EIO draws as
  // asynchronous I/O but no latency. A non-dsync write lands in the cache as
  // dirty; dsync makes it durable. Returns bytes written / 0, or -kEio.
  std::int32_t write_now(std::uint32_t f, std::uint64_t off, std::span<const std::byte> data, bool dsync);
  std::int32_t sync_now(std::uint32_t f);

  // Directory operations (immediately durable: a simplification, see dst.md).
  void resize(std::uint32_t f, std::uint64_t n);
  [[nodiscard]] std::vector<std::string> list() const;  // sorted names
  // Replaces `to` if it exists, as rename(2) does.
  bool rename(std::string_view from, std::string_view to);
  // Unlinks `name`; the file's index stays valid for handles still open.
  bool remove(std::string_view name);

  // Handle lifecycle: completions reach only the handle that submitted.
  std::uint32_t attach(std::uint32_t f);  // returns handle generation
  void detach(std::uint32_t f, std::uint32_t gen);
  [[nodiscard]] bool handle_valid(std::uint32_t f, std::uint32_t gen) const;
  RingQueue<env::DiskCompletion>& completions(std::uint32_t f);

  // Power loss: applies the crash semantics above to every file.
  void crash_host();

  // Fault-atlas membership: this disk holds replica `replica` of `replicas`.
  void set_atlas_replica(std::uint32_t replica, std::uint32_t replicas) noexcept {
    atlas_replica_ = replica;
    atlas_replicas_ = replicas;
  }
  // A bad region under some files (a world's dimension, outside the atlas): while faults
  // run, each write to a file whose name `filter` accepts (when it is opened) flips one
  // bit with probability `flip_ppm`. The draws come from `rng`, so the disk's other
  // faults keep their stream. Set before the files are opened.
  void set_corruption(std::function<bool(std::string_view)> filter, std::uint32_t flip_ppm, Prng rng) {
    corrupt_filter_ = std::move(filter);
    corrupt_ppm_ = flip_ppm;
    corrupt_rng_ = rng;
  }
  [[nodiscard]] const DiskParams& params() const noexcept { return p_; }
  // Opt-in gate on injected I/O errors (a world keeping its failures inside a failure
  // model): an EIO drawn while the gate says no is not applied. The draw itself is made
  // either way, so the disk's random stream does not depend on the gate. Unset: no gate.
  // `landed` (optional) is told when a gated error is delivered (the node is failing).
  void set_fault_gate(std::function<bool()> gate, std::function<void()> landed = {}) {
    fault_gate_ = std::move(gate);
    fault_landed_ = std::move(landed);
  }
  // Overrides the swarm-drawn parameters (tests, targeted scenarios).
  void set_params(const DiskParams& p) noexcept {
    p_ = p;
    if (p_.tear_bytes == 0) p_.tear_bytes = 512;
  }
  [[nodiscard]] std::uint64_t inflight(std::uint32_t f) const;
  [[nodiscard]] std::uint64_t inflight_total() const;
  // Setup only (before the node boots, e.g. `witnessd --init`): makes `bytes`
  // the durable and visible content of file `name`.
  void install(std::string_view name, std::span<const std::byte> bytes);
  [[nodiscard]] std::uint64_t dirty(std::uint32_t f) const;

  static Dispatch on_event(void* ctx, const Event& ev);
  [[nodiscard]] bool faults_allowed() const { return !fault_gate_ || fault_gate_(); }
  void fault_landed() const {
    if (fault_landed_) fault_landed_();
  }
  void set_handler(HandlerId h) noexcept { handler_ = h; }

 private:
  struct Op {
    std::uint64_t seq = 0;
    bool is_sync = false;
    bool dsync = false;
    bool eio = false;
    std::uint64_t off = 0;
    std::uint64_t len = 0;
    std::uint32_t buf = 0;  // write data, in the disk's buffer pool
    std::uint64_t tag = 0;
    std::uint64_t covers_done = 0;  // sync: dirty writes with done_seq <= this
    std::uint32_t handle_gen = 0;
  };
  struct Dirty {
    std::uint64_t seq = 0;
    std::uint64_t done_seq = 0;
    std::uint64_t off = 0;
    std::uint64_t len = 0;
    std::uint32_t buf = 0;
    bool doomed = false;
  };
  struct File {
    std::string name;
    std::uint64_t key = 0;
    bool corrupt = false;  // under a bad region (set_corruption)
    std::vector<std::byte> durable;
    std::vector<std::byte> cache;
    std::vector<Op> inflight;
    std::vector<Dirty> dirty;
    std::uint64_t next_seq = 0;
    std::uint64_t done_counter = 0;
    std::uint32_t crash_epoch = 0;
    std::uint32_t handle_gen = 0;
    bool handle_open = false;
    RingQueue<env::DiskCompletion> cq;
  };

  Dispatch handle(const Event& ev);
  Nanos latency(Nanos min, Nanos mean);
  void apply(File& f, std::uint64_t off, std::span<const std::byte> data, bool to_durable, bool allow_corrupt);
  static void write_image(std::vector<std::byte>& img, std::uint64_t off, std::span<const std::byte> data);
  // Write data lives in pooled buffers from submission until the write is
  // durable, failed, or resolved by a crash; buffers are reused, so steady
  // I/O does not allocate and memory is bounded by the unsynced data.
  std::uint32_t acquire(std::span<const std::byte> data);
  void release(std::uint32_t buf) { free_bufs_.push_back(buf); }
  std::span<std::byte> data_of(std::uint32_t buf, std::uint64_t len) {
    return {bufs_[buf].data(), static_cast<std::size_t>(len)};
  }

  World& w_;
  NodeId node_;
  DiskParams p_;
  Prng rng_;
  std::function<bool()> fault_gate_;
  std::function<void()> fault_landed_;
  HandlerId handler_ = 0;
  std::uint32_t atlas_replica_ = 0;
  std::uint32_t atlas_replicas_ = 1;
  std::vector<std::byte> now_scratch_;  // write_now: a corrupted copy of the data
  std::function<bool(std::string_view)> corrupt_filter_;
  std::uint32_t corrupt_ppm_ = 0;
  Prng corrupt_rng_;
  std::vector<std::unique_ptr<File>> files_;
  std::vector<std::vector<std::byte>> bufs_;
  std::vector<std::uint32_t> free_bufs_;
  std::map<std::string, std::uint32_t, std::less<>> by_name_;
};

// env::DiskFileLike handle. Lives in process memory; destroyed on crash.
class DiskFile {
 public:
  DiskFile(Node& node, std::string_view name);
  ~DiskFile();
  DiskFile(const DiskFile&) = delete;
  DiskFile& operator=(const DiskFile&) = delete;

  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) {
    return disk_->submit_write(file_, off, b, dsync, tag);
  }
  bool submit_sync(std::uint64_t tag) { return disk_->submit_sync(file_, tag); }

  template <class F>
  std::size_t poll(F&& cb) {
    if (!disk_->handle_valid(file_, gen_)) return 0;
    RingQueue<env::DiskCompletion>& cq = disk_->completions(file_);
    const std::size_t n = cq.size();
    for (std::size_t i = 0; i < n; ++i) {
      const env::DiskCompletion c = cq.front();
      cq.pop();
      cb(c);
    }
    return n;
  }

  // Synchronous read of the visible (cache) image, for recovery scans.
  std::size_t read(std::uint64_t off, std::span<std::byte> out) const { return disk_->read(file_, off, out); }
  [[nodiscard]] std::uint64_t size() const { return disk_->size(file_); }

 private:
  Disk* disk_;
  std::uint32_t file_;
  std::uint32_t gen_;
};

static_assert(env::DiskFileLike<DiskFile>);

}  // namespace lle::sim
