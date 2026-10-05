#pragma once
// The exchange node's storage on the simulated disk (09 S-03): the output-log file
// system bound to the node being built, the snapshot storage, and the io policies of
// the production recovery (apps/exchanged/recovery_impl.h) and of snapshotd's
// follower (apps/snapshotd/snapshotter.h).
//
// The disk namespace is flat: directories are name prefixes, created implicitly and
// durable at once (dst.md, fidelity limits). Snapshot files and sidecars are written
// synchronously (Disk::write_now / sync_now): published with the production sequence
// (temp, sync, rename), torn or lost by a host crash like any unsynced data.
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "engine/engine.h"
#include "journal/journal_device.h"
#include "journal/segment_dir.h"
#include "outlog/reader.h"
#include "outlog/repair.h"
#include "sim/disk.h"
#include "sim/exchange/sim_net.h"
#include "sim/node.h"
#include "sim/worlds/journal_device.h"
#include "snapshot/engine_section.h"
#include "snapshot/reader.h"
#include "snapshot/storage.h"
#include "snapshotd/out_digest.h"

namespace lle::sim::exch {

// The output log's storage (outlog/disk.h) on the node's disk, as worlds::SimOutlogFs
// (synchronous I/O through Disk::write_now / sync_now), except that a process that was
// killed writes nothing more: the writers flush their user-space buffers when they are
// destroyed, and a SIGKILLed process never gets there (Node::crash marks the node dead
// before it destroys the image).
class SimNodeOutlogFile {
 public:
  SimNodeOutlogFile() noexcept = default;
  SimNodeOutlogFile(Node& node, std::uint32_t fidx) noexcept : node_(&node), fidx_(fidx) {}
  SimNodeOutlogFile(SimNodeOutlogFile&& o) noexcept : node_(o.node_), fidx_(o.fidx_), n_(o.n_), done_(o.done_) {
    o.node_ = nullptr;
    o.n_ = 0;
  }
  SimNodeOutlogFile& operator=(SimNodeOutlogFile&& o) noexcept {
    node_ = o.node_;
    fidx_ = o.fidx_;
    n_ = o.n_;
    done_ = o.done_;
    o.node_ = nullptr;
    o.n_ = 0;
    return *this;
  }
  SimNodeOutlogFile(const SimNodeOutlogFile&) = delete;
  SimNodeOutlogFile& operator=(const SimNodeOutlogFile&) = delete;

  [[nodiscard]] bool valid() const noexcept { return node_ != nullptr; }

  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) {
    if (n_ == kQueue) return false;
    std::int32_t r = static_cast<std::int32_t>(b.size());
    if (node_->alive()) r = node_->disk().write_now(fidx_, off, b, dsync);
    done_[n_++] = env::DiskCompletion{tag, r < 0 ? -EIO : r};
    return true;
  }
  bool submit_sync(std::uint64_t tag) {
    if (n_ == kQueue) return false;
    const bool ok = !node_->alive() || node_->disk().sync_now(fidx_) >= 0;
    done_[n_++] = env::DiskCompletion{tag, ok ? 0 : -EIO};
    return true;
  }
  template <class F>
  std::size_t poll(F&& cb) {
    const std::size_t n = n_;
    for (std::size_t i = 0; i < n; ++i) cb(done_[i]);
    n_ = 0;
    return n;
  }
  std::size_t read(std::uint64_t off, std::span<std::byte> out) const { return node_->disk().read(fidx_, off, out); }
  [[nodiscard]] std::uint64_t size() const { return node_->disk().size(fidx_); }
  bool resize(std::uint64_t n) {
    if (node_->alive()) node_->disk().resize(fidx_, n);
    return true;
  }
  std::ptrdiff_t read_checked(std::uint64_t off, std::span<std::byte> out) const {
    return static_cast<std::ptrdiff_t>(node_->disk().read(fidx_, off, out));
  }
  [[nodiscard]] std::expected<std::uint64_t, int> size_checked() const { return node_->disk().size(fidx_); }

 private:
  static constexpr std::size_t kQueue = 4;
  Node* node_ = nullptr;
  std::uint32_t fidx_ = 0;
  std::size_t n_ = 0;
  std::array<env::DiskCompletion, kQueue> done_{};
};

class SimNodeOutlogFs {
 public:
  using File = SimNodeOutlogFile;
  explicit SimNodeOutlogFs(Node& node) noexcept : node_(&node) {}

  std::expected<File, int> open(const std::string& path, outlog::OpenMode mode) {
    Disk& d = node_->disk();
    const bool exists = d.exists(path);
    if (!exists && (mode == outlog::OpenMode::ReadOnly || mode == outlog::OpenMode::ReadWrite)) {
      return std::unexpected(ENOENT);
    }
    const std::uint32_t f = d.open(path);
    if (mode == outlog::OpenMode::CreateTruncate && node_->alive()) d.resize(f, 0);
    return File(*node_, f);
  }
  int rename(const std::string& from, const std::string& to) { return node_->disk().rename(from, to) ? 0 : ENOENT; }
  int remove(const std::string& path) { return node_->disk().remove(path) ? 0 : ENOENT; }
  int make_dirs(const std::string&) { return 0; }  // flat namespace
  bool lock_writer(File&) { return true; }         // one writer process per node

 private:
  Node* node_;
};

static_assert(outlog::OutlogFileLike<SimNodeOutlogFile>);
static_assert(outlog::OutlogFsLike<SimNodeOutlogFs>);

// The output-log file system of the node whose stages are being built: the stages'
// fallback readers (gateway replay, md re-requests, GLIMPSE) are default-constructed
// members (outlog::env_reader_t).
class SimBoundOutlogFs : public SimNodeOutlogFs {
 public:
  SimBoundOutlogFs() : SimNodeOutlogFs(NodeBinding::current()) {}
};
static_assert(outlog::OutlogFsLike<SimBoundOutlogFs>);

class SimSnapStorage final : public snap::Storage {
 public:
  explicit SimSnapStorage(Node& node) : disk_(&node.disk()) {}

  int create(const std::string& path) override {
    const std::uint32_t f = disk_->open(path);
    disk_->resize(f, 0);
    handles_.push_back(f);
    return static_cast<int>(handles_.size() - 1);
  }
  int write_at(int h, std::uint64_t off, std::span<const std::byte> data) override {
    return disk_->write_now(file(h), off, data, false) < 0 ? EIO : 0;
  }
  int sync(int h, bool) override { return disk_->sync_now(file(h)) < 0 ? EIO : 0; }
  int close(int) override { return 0; }
  int rename(const std::string& from, const std::string& to) override { return disk_->rename(from, to) ? 0 : ENOENT; }
  int sync_dir(const std::string&) override { return 0; }  // directory operations are durable at once
  int remove(const std::string& path) override { return disk_->remove(path) ? 0 : ENOENT; }
  std::vector<std::string> list(const std::string& dir) override {
    std::vector<std::string> out;
    const std::string prefix = dir + "/";
    for (const std::string& n : disk_->list()) {
      if (n.starts_with(prefix) && n.find('/', prefix.size()) == std::string::npos)
        out.push_back(n.substr(prefix.size()));
    }
    return out;
  }
  std::expected<std::vector<std::byte>, int> read_all(const std::string& path) override {
    if (!disk_->exists(path)) return std::unexpected(ENOENT);
    const std::uint32_t f = disk_->open(path);
    std::vector<std::byte> out(static_cast<std::size_t>(disk_->size(f)));
    if (disk_->read(f, 0, out) != out.size()) return std::unexpected(EIO);
    return out;
  }

 private:
  [[nodiscard]] std::uint32_t file(int h) const { return handles_[static_cast<std::size_t>(h)]; }
  Disk* disk_;
  std::vector<std::uint32_t> handles_;
};

// Snapshot lookups shared by recovery and the follower.
struct SimSnapLookup {
  snap::Storage* st = nullptr;
  std::optional<snap::SnapshotInfo> find_snapshot(const std::string& dir, std::uint64_t max_index) {
    return snap::find_latest(*st, dir, max_index);
  }
  std::expected<snap::LoadedSnapshot, snap::LoadError> open_snapshot(const std::string& path) {
    return snap::LoadedSnapshot::open(*st, path);
  }
  std::optional<snapd::OutDigests> read_sidecar(const std::string& path) {
    const auto b = st->read_all(path);
    if (!b) return std::nullopt;
    return snapd::decode_sidecar(*b);
  }
};

using Note = std::function<void(const std::string&)>;

// recovery_impl.h's Io on the simulated disk.
struct SimRecoveryIo : SimSnapLookup {
  using Reader = outlog::BasicOutlogReader<SimNodeOutlogFs>;
  Node* node = nullptr;
  Note note_fn;

  std::unique_ptr<Reader> make_reader() { return std::make_unique<Reader>(SimNodeOutlogFs(*node)); }
  bool truncate_outlog(const std::string& path, SeqNo keep) {
    SimNodeOutlogFs fs(*node);
    return outlog::truncate_to(fs, path, keep).has_value();
  }
  void note(const std::string& line) {
    if (note_fn) note_fn(line);
  }
};

// A journal directory opened read-only by another process (snapshotd, as
// PosixSegmentDir::open(..., read_only)): reads see what the writer wrote, durable or
// not (the page cache); nothing can be written. The listing is taken at open.
class SimReadOnlyJournalDevice {
 public:
  SimReadOnlyJournalDevice(Disk& disk, std::uint32_t fidx) noexcept : disk_(&disk), fidx_(fidx) {}
  bool submit_write(std::uint64_t, std::span<const std::byte>, bool, std::uint64_t) { return false; }
  bool submit_sync(std::uint64_t) { return false; }
  template <class F>
  std::size_t poll(F&&) {
    return 0;
  }
  std::int64_t read(std::uint64_t off, std::span<std::byte> out) {
    return static_cast<std::int64_t>(disk_->read(fidx_, off, out));
  }
  [[nodiscard]] std::uint64_t size() const { return disk_->size(fidx_); }
  bool resize(std::uint64_t) { return false; }
  [[nodiscard]] std::size_t in_flight() const { return 0; }

 private:
  Disk* disk_;
  std::uint32_t fidx_;
};
static_assert(journal::JournalDeviceLike<SimReadOnlyJournalDevice>);

class SimReadOnlySegmentDir {
 public:
  using Device = SimReadOnlyJournalDevice;
  SimReadOnlySegmentDir(Node& node, const std::string& prefix) {
    Disk& d = node.disk();
    for (const std::string& n : d.list()) {
      if (n.starts_with(prefix) && n.ends_with(".seg"))  // segment files only, as PosixSegmentDir
        files_.push_back(Entry{n.substr(prefix.size()), std::make_unique<Device>(d, d.open(n))});
    }
  }
  [[nodiscard]] std::size_t count() const noexcept { return files_.size(); }
  [[nodiscard]] Device& device(std::size_t i) noexcept { return *files_[i].dev; }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return files_[i].name; }
  std::optional<std::size_t> create(std::string_view, std::uint64_t) { return std::nullopt; }
  bool rename(std::size_t, std::string_view) { return false; }
  bool sync_dir() noexcept { return true; }

 private:
  struct Entry {
    std::string name;
    std::unique_ptr<Device> dev;
  };
  std::vector<Entry> files_;
};
static_assert(journal::SegmentDirLike<SimReadOnlySegmentDir>);

// snapshotter.h's Io on the simulated disk: the journal is read through a fresh
// read-only listing per open (as PosixSegmentDir::open), snapshots and sidecars are
// published through the snapshot storage.
struct SimSnapIo : SimSnapLookup {
  Node* node = nullptr;
  Note out_fn;
  // A snapshot was published: the engine as it was written and the record index.
  std::function<void(const engine::Engine&, std::uint64_t index)> written_fn;

  std::expected<SimReadOnlySegmentDir, std::string> open_journal(const std::string& path) {
    return SimReadOnlySegmentDir(*node, path);
  }
  std::expected<std::string, snap::Error> save_engine(const engine::Engine& e, const snap::EngineSnapshotIds& ids,
                                                      const std::string& dir) {
    auto r = snap::save_engine(*st, e, ids, dir);
    if (r && written_fn) written_fn(e, ids.index);
    return r;
  }
  // As snapd::write_sidecar: temp, sync, rename, sync of the directory.
  bool write_sidecar(const std::string& path, const snapd::OutDigests& d) {
    const std::vector<std::byte> b = snapd::encode_sidecar(d);
    const std::string tmp = path + ".tmp";
    const int h = st->create(tmp);
    if (h < 0) return false;
    const bool ok = st->write_at(h, 0, b) == 0 && st->sync(h, false) == 0;
    (void)st->close(h);
    if (!ok || st->rename(tmp, path) != 0) return false;
    const std::size_t slash = path.rfind('/');
    return st->sync_dir(slash == std::string::npos ? std::string(".") : path.substr(0, slash)) == 0;
  }
  std::vector<std::string> list(const std::string& dir) { return st->list(dir); }
  void remove(const std::string& path) { (void)st->remove(path); }
  void out(const std::string& line) {
    if (out_fn) out_fn(line);
  }
  void err(const std::string& line) {
    if (out_fn) out_fn(line);
  }
  void flush() {}
};

}  // namespace lle::sim::exch
