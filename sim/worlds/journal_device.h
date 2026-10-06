#pragma once
// SimJournalDevice / SimSegmentDir: the journal's device and directory
// concepts (src/journal/journal_device.h, segment_dir.h) over the simulated
// disk (09 S-03).
//
// The device mirrors PosixJournalDevice, the device the journal ships with:
// a dsync write is a pwrite into the page cache followed by fdatasync. Here
// they are two simulated I/Os with independent latencies, so a process killed
// between them leaves the bytes readable but not durable, a failed fdatasync
// dooms the pages (fsyncgate), and a host crash loses or tears whatever is
// not durable yet. Completions are reported in completion order (like
// io_uring), which is a superset of the posix device's in-order behaviour.
//
// Operations tagged journal::kSyncHelperTag come from the synchronous cold-path
// helpers (write_sync, sync_device: recovery repair, segment preparation),
// which spin on poll() and cannot let virtual time advance: they are applied
// at once through sim::Disk::write_now/sync_now, with the same EIO draws. A
// directory in at-once mode (SimSegmentDir::set_at_once) applies all of its
// devices' operations that way: a start-up step that drains a journal writer
// (exchanged's L2 restore) runs inside one event, as it spins in production.
//
// The device also hits the journal's must-hit probes (09 §8) that only the
// device can observe: the process dying between a record's pwrite and its
// fdatasync, and a journal write or sync outstanding longer than the
// heartbeat bound (DiskParams::heartbeat_ns).
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/assert.h"
#include "env/concepts.h"
#include "journal/journal_device.h"
#include "journal/segment_dir.h"
#include "sim/disk.h"
#include "sim/node.h"
#include "sim/ring_queue.h"
#include "sim/world.h"

namespace lle::sim::worlds {

// Optional observer of journal writes that became durable (a world's oracle, e.g. the
// Output Rule): [off, off + len) of file `fidx` is on the durable image now. Observing
// changes nothing the device does; worlds without one pass nullptr.
class JournalDurableObserver {
 public:
  virtual ~JournalDurableObserver() = default;
  virtual void on_durable(Disk& disk, std::uint32_t fidx, std::uint64_t off, std::uint32_t len) = 0;
};

class SimJournalDevice {
 public:
  static constexpr std::size_t kMaxOps = 64;  // like PosixJournalDevice's completion queue

  SimJournalDevice(Node& node, std::string_view name, JournalDurableObserver* obs = nullptr,
                   const bool* at_once = nullptr)
      : node_(&node), disk_(&node.disk()), file_(node, name), obs_(obs), at_once_(at_once) {
    fidx_ = disk_->open(name);
  }
  // Destroyed with the process image. Node::crash marks the node dead first,
  // so a dead node here means the process was killed, not torn down.
  ~SimJournalDevice() {
    const Phase ph = node_->world().phase();
    if (node_->alive() || (ph != Phase::Safety && ph != Phase::Heal)) return;
    for (const Op& op : ops_) {
      if (op.syncing && op.len != 0) {
        node_->world().probes().hit("journal.crash_between_write_and_fsync");
        return;
      }
    }
  }
  SimJournalDevice(const SimJournalDevice&) = delete;
  SimJournalDevice& operator=(const SimJournalDevice&) = delete;

  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) {
    if (in_flight() >= kMaxOps) return false;
    if (tag == journal::kSyncHelperTag || (at_once_ != nullptr && *at_once_)) {
      std::int32_t r = disk_->write_now(fidx_, off, b, false);
      if (r == static_cast<std::int32_t>(b.size()) && dsync) {
        const std::int32_t s = disk_->sync_now(fidx_);
        if (s != 0) r = s;
        if (s == 0 && obs_ != nullptr) obs_->on_durable(*disk_, fidx_, off, static_cast<std::uint32_t>(b.size()));
      }
      ready_.push(env::DiskCompletion{tag, r});
      return true;
    }
    const std::uint64_t itag = next_itag_++;
    if (!file_.submit_write(off, b, /*dsync=*/false, itag)) return false;  // the pwrite
    ops_.push_back(Op{tag, itag, static_cast<std::uint32_t>(b.size()), dsync, false, node_->world().now(), off});
    return true;
  }

  bool submit_sync(std::uint64_t tag) {
    if (in_flight() >= kMaxOps) return false;
    if (tag == journal::kSyncHelperTag || (at_once_ != nullptr && *at_once_)) {
      const std::int32_t r = disk_->sync_now(fidx_);
      if (r == 0 && obs_ != nullptr) obs_->on_durable(*disk_, fidx_, 0, 0);
      ready_.push(env::DiskCompletion{tag, r});
      return true;
    }
    const std::uint64_t itag = next_itag_++;
    if (!file_.submit_sync(itag)) return false;
    ops_.push_back(Op{tag, itag, 0, false, true, node_->world().now(), 0});
    return true;
  }

  template <class F>
  std::size_t poll(F&& cb) {
    file_.poll([&](const env::DiskCompletion& c) { advance(c); });
    const std::size_t n = ready_.size();
    for (std::size_t i = 0; i < n; ++i) {
      const env::DiskCompletion c = ready_.front();
      ready_.pop();
      cb(c);
    }
    return n;
  }

  std::int64_t read(std::uint64_t off, std::span<std::byte> out) {
    return static_cast<std::int64_t>(file_.read(off, out));
  }
  [[nodiscard]] std::uint64_t size() const { return file_.size(); }
  bool resize(std::uint64_t n) {
    disk_->resize(fidx_, n);
    return true;
  }
  [[nodiscard]] std::size_t in_flight() const { return ops_.size() + ready_.size(); }

 private:
  struct Op {
    std::uint64_t user_tag;
    std::uint64_t itag;
    std::uint32_t len;
    bool dsync;
    bool syncing;  // the fdatasync of a dsync write, or a plain sync
    Nanos submitted;
    std::uint64_t off;
  };

  void advance(const env::DiskCompletion& c) {
    for (std::size_t i = 0; i < ops_.size(); ++i) {
      Op& op = ops_[i];
      if (op.itag != c.tag) continue;
      if (!op.syncing && op.dsync && c.result == static_cast<std::int32_t>(op.len)) {
        // pwrite done; now fdatasync. A crash before it completes leaves the
        // bytes in the page cache only.
        const std::uint64_t itag = next_itag_++;
        if (file_.submit_sync(itag)) {
          op.itag = itag;
          op.syncing = true;
          return;
        }
        ready_.push(env::DiskCompletion{op.user_tag, -11});  // EAGAIN
      } else if (op.syncing && op.len != 0) {
        if (c.result >= 0 && obs_ != nullptr) obs_->on_durable(*disk_, fidx_, op.off, op.len);
        ready_.push(env::DiskCompletion{op.user_tag, c.result < 0 ? c.result : static_cast<std::int32_t>(op.len)});
      } else {
        if (op.syncing && c.result >= 0 && obs_ != nullptr) obs_->on_durable(*disk_, fidx_, 0, 0);
        ready_.push(env::DiskCompletion{op.user_tag, c.result});
      }
      if (node_->world().now() - op.submitted > disk_->params().heartbeat_ns)
        node_->world().probes().hit("journal.stall_longer_than_heartbeat");
      ops_.erase(ops_.begin() + static_cast<std::ptrdiff_t>(i));
      return;
    }
    LLE_UNREACHABLE("completion for an unknown simulated journal op");
  }

  Node* node_;
  Disk* disk_;
  DiskFile file_;
  JournalDurableObserver* obs_ = nullptr;
  const bool* at_once_ = nullptr;  // the directory's at-once mode
  std::uint32_t fidx_ = 0;
  std::vector<Op> ops_;
  RingQueue<env::DiskCompletion> ready_;
  std::uint64_t next_itag_ = 1;
};

static_assert(journal::JournalDeviceLike<SimJournalDevice>);

// Segment files under `prefix` on the node's disk. The listing is taken at
// construction (as PosixSegmentDir::open does), sorted by name.
class SimSegmentDir {
 public:
  using Device = SimJournalDevice;

  SimSegmentDir(Node& node, std::string prefix, JournalDurableObserver* obs = nullptr)
      : node_(&node), prefix_(std::move(prefix)), obs_(obs) {
    for (const std::string& n : node.disk().list()) {
      // As PosixSegmentDir::open: segment files only (*.seg), not e.g. the incarnation file.
      if (n.starts_with(prefix_) && n.ends_with(".seg")) {
        files_.push_back(Entry{n.substr(prefix_.size()), std::make_unique<Device>(node, n, obs_, &at_once_)});
      }
    }
  }

  SimSegmentDir(const SimSegmentDir&) = delete;  // the devices point at at_once_
  SimSegmentDir& operator=(const SimSegmentDir&) = delete;

  [[nodiscard]] std::size_t count() const noexcept { return files_.size(); }
  [[nodiscard]] Device& device(std::size_t i) noexcept { return *files_[i].dev; }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return files_[i].name; }

  std::optional<std::size_t> create(std::string_view name, std::uint64_t size) {
    const std::string full = prefix_ + std::string(name);
    if (node_->disk().exists(full)) return std::nullopt;  // O_CREAT | O_EXCL
    files_.push_back(Entry{std::string(name), std::make_unique<Device>(*node_, full, obs_, &at_once_)});
    files_.back().dev->resize(size);  // ftruncate
    return files_.size() - 1;
  }
  bool rename(std::size_t i, std::string_view name) {
    if (i >= files_.size()) return false;
    // As PosixSegmentDir: never clobber an existing file (a spare can already
    // carry a segment name when its assignment header did not persist).
    if (node_->disk().exists(prefix_ + std::string(name))) return false;
    if (!node_->disk().rename(prefix_ + files_[i].name, prefix_ + std::string(name))) return false;
    files_[i].name = std::string(name);
    return true;
  }
  bool sync_dir() noexcept { return true; }
  // At-once mode: every device's I/O is applied when submitted (see the header).
  void set_at_once(bool on) noexcept { at_once_ = on; }

 private:
  struct Entry {
    std::string name;
    std::unique_ptr<Device> dev;
  };
  Node* node_;
  std::string prefix_;
  JournalDurableObserver* obs_ = nullptr;
  bool at_once_ = false;  // devices hold a pointer to it: the directory does not move
  std::vector<Entry> files_;
};

static_assert(journal::SegmentDirLike<SimSegmentDir>);

}  // namespace lle::sim::worlds
