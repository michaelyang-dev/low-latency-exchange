#pragma once
// SimOutlogFs: the output log's storage concepts (src/outlog/disk.h) over the
// simulated disk (09 S-03), for the outlog world.
//
// The output log's I/O is synchronous (outlog::write_sync / sync_file), so
// every operation is applied at once through sim::Disk::write_now / sync_now:
// the same EIO draws as asynchronous I/O and no latency. A write lands in the
// page cache as dirty, where a host crash can lose it, tear it at sector
// granularity or persist it out of order. Directory operations are durable at
// once (dst.md, fidelity limits).
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include "env/concepts.h"
#include "outlog/disk.h"
#include "sim/disk.h"
#include "sim/node.h"

namespace lle::sim::worlds {

class SimOutlogFile {
 public:
  SimOutlogFile() noexcept = default;
  SimOutlogFile(Disk& disk, std::uint32_t fidx) noexcept : disk_(&disk), fidx_(fidx) {}
  SimOutlogFile(SimOutlogFile&& o) noexcept : disk_(o.disk_), fidx_(o.fidx_), n_(o.n_), done_(o.done_) {
    o.disk_ = nullptr;
    o.n_ = 0;
  }
  SimOutlogFile& operator=(SimOutlogFile&& o) noexcept {
    disk_ = o.disk_;
    fidx_ = o.fidx_;
    n_ = o.n_;
    done_ = o.done_;
    o.disk_ = nullptr;
    o.n_ = 0;
    return *this;
  }
  SimOutlogFile(const SimOutlogFile&) = delete;
  SimOutlogFile& operator=(const SimOutlogFile&) = delete;

  [[nodiscard]] bool valid() const noexcept { return disk_ != nullptr; }

  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) {
    if (n_ == kQueue) return false;
    const std::int32_t r = disk_->write_now(fidx_, off, b, dsync);
    done_[n_++] = env::DiskCompletion{tag, r < 0 ? -EIO : r};
    return true;
  }
  bool submit_sync(std::uint64_t tag) {
    if (n_ == kQueue) return false;
    done_[n_++] = env::DiskCompletion{tag, disk_->sync_now(fidx_) < 0 ? -EIO : 0};
    return true;
  }
  template <class F>
  std::size_t poll(F&& cb) {
    const std::size_t n = n_;
    for (std::size_t i = 0; i < n; ++i) cb(done_[i]);
    n_ = 0;
    return n;
  }
  std::size_t read(std::uint64_t off, std::span<std::byte> out) const { return disk_->read(fidx_, off, out); }
  [[nodiscard]] std::uint64_t size() const { return disk_->size(fidx_); }
  bool resize(std::uint64_t n) {
    disk_->resize(fidx_, n);
    return true;
  }
  std::ptrdiff_t read_checked(std::uint64_t off, std::span<std::byte> out) const {
    return static_cast<std::ptrdiff_t>(disk_->read(fidx_, off, out));
  }
  [[nodiscard]] std::expected<std::uint64_t, int> size_checked() const { return disk_->size(fidx_); }

 private:
  static constexpr std::size_t kQueue = 4;
  Disk* disk_ = nullptr;
  std::uint32_t fidx_ = 0;
  std::size_t n_ = 0;
  std::array<env::DiskCompletion, kQueue> done_{};
};

class SimOutlogFs {
 public:
  using File = SimOutlogFile;
  explicit SimOutlogFs(Node& node) noexcept : disk_(&node.disk()) {}

  std::expected<File, int> open(const std::string& path, outlog::OpenMode mode) {
    const bool exists = disk_->exists(path);
    if (!exists && (mode == outlog::OpenMode::ReadOnly || mode == outlog::OpenMode::ReadWrite)) {
      return std::unexpected(ENOENT);
    }
    const std::uint32_t f = disk_->open(path);
    if (mode == outlog::OpenMode::CreateTruncate) disk_->resize(f, 0);
    return File(*disk_, f);
  }
  int rename(const std::string& from, const std::string& to) { return disk_->rename(from, to) ? 0 : ENOENT; }
  int remove(const std::string& path) { return disk_->remove(path) ? 0 : ENOENT; }
  int make_dirs(const std::string&) { return 0; }  // flat namespace
  bool lock_writer(File&) { return true; }         // one writer process per node

 private:
  Disk* disk_;
};

static_assert(outlog::OutlogFileLike<SimOutlogFile>);
static_assert(outlog::OutlogFsLike<SimOutlogFs>);

}  // namespace lle::sim::worlds
