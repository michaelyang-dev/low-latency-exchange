#pragma once
// Journal devices (06 §6, R6 R10): the L3 writer, the segment preparer and recovery
// reach the disk only through a type modelling JournalDeviceLike, i.e. the
// asynchronous env::DiskFileLike interface (submit_write / submit_sync / poll) plus a
// few synchronous operations used on cold paths (preparation, recovery, tools).
//
//   PosixJournalDevice     pwrite + fdatasync (or F_FULLFSYNC on macOS, for durability
//                          tests only); operations complete inside submit_*, results
//                          are delivered by poll(). Dev, CI, tools.
//   IoUringJournalDevice   Linux only (io_uring_journal_device.h): IOPOLL, O_DIRECT,
//                          WRITE_FIXED + RWF_DSYNC on registered buffers.
//   MemJournalDevice       in-memory, with seeded completion order and crash semantics
//                          (mem_journal_device.h). Unit and property tests.
//   SimJournalDevice       the simulator's device (sim/, 09 S-03).
//
// Error policy (06 §6): any EIO, short write or fsync error is fatal for the writer.
// Devices report results faithfully and never retry an fsync: after a failed fsync the
// kernel may already have dropped the dirty pages (R6 D4.1).
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include "env/concepts.h"

namespace lle::journal {

template <class D>
concept JournalDeviceLike = env::DiskFileLike<D> && requires(D& d, const D& cd, std::uint64_t off, std::span<std::byte> out) {
  { d.read(off, out) } -> std::same_as<std::int64_t>;  // bytes read (short at EOF) or -errno
  { cd.size() } -> std::same_as<std::uint64_t>;
  { d.resize(off) } -> std::same_as<bool>;
  { cd.in_flight() } -> std::same_as<std::size_t>;  // submitted, completion not yet delivered
};

// Tag reserved for the synchronous helpers below.
inline constexpr std::uint64_t kSyncHelperTag = ~std::uint64_t{0};

// Submits one operation and polls until its completion arrives. Cold paths only, with
// nothing else in flight on the device. Returns the completion result (bytes written,
// 0 for a sync, or -errno; -1 if the submission itself was refused).
template <JournalDeviceLike D>
std::int32_t write_sync(D& d, std::uint64_t off, std::span<const std::byte> b, bool dsync = true) {
  if (!d.submit_write(off, b, dsync, kSyncHelperTag)) return -1;
  std::int32_t result = 0;
  bool done = false;
  while (!done) {
    d.poll([&](const env::DiskCompletion& c) {
      if (c.tag == kSyncHelperTag) {
        result = c.result;
        done = true;
      }
    });
  }
  return result;
}

template <JournalDeviceLike D>
std::int32_t sync_device(D& d) {
  if (!d.submit_sync(kSyncHelperTag)) return -1;
  std::int32_t result = 0;
  bool done = false;
  while (!done) {
    d.poll([&](const env::DiskCompletion& c) {
      if (c.tag == kSyncHelperTag) {
        result = c.result;
        done = true;
      }
    });
  }
  return result;
}

// Reads exactly out.size() bytes or fails.
template <JournalDeviceLike D>
bool read_exact(D& d, std::uint64_t off, std::span<std::byte> out) {
  return d.read(off, out) == static_cast<std::int64_t>(out.size());
}

// ---- PosixJournalDevice ------------------------------------------------------------

struct PosixDeviceOptions {
  bool create = false;      // O_CREAT (the file must not exist when exclusive is set)
  bool exclusive = false;   // O_EXCL
  bool read_only = false;
  bool direct = false;      // O_DIRECT on Linux, F_NOCACHE on macOS (a caching hint there)
  // macOS: fcntl(F_FULLFSYNC) instead of fsync. Plain fsync on macOS does not flush the
  // drive cache; F_FULLFSYNC does (~4.5 ms per call on the dev laptop, R6 D4.3). Use it
  // for durability tests only. Ignored elsewhere.
  bool full_fsync = false;
};

class PosixJournalDevice {
 public:
  static constexpr std::size_t kCompletionCapacity = 64;

  PosixJournalDevice() noexcept = default;
  ~PosixJournalDevice();
  PosixJournalDevice(PosixJournalDevice&& o) noexcept;
  PosixJournalDevice& operator=(PosixJournalDevice&& o) noexcept;
  PosixJournalDevice(const PosixJournalDevice&) = delete;
  PosixJournalDevice& operator=(const PosixJournalDevice&) = delete;

  // Returns the device or errno.
  static std::expected<PosixJournalDevice, int> open(const std::string& path, const PosixDeviceOptions& opts = {});

  // pwrite (then fdatasync / F_FULLFSYNC when dsync) happens here; the result is queued
  // for poll(). Returns false only if the completion queue is full.
  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept;
  bool submit_sync(std::uint64_t tag) noexcept;

  template <class F>
  std::size_t poll(F&& f) {
    std::size_t n = 0;
    while (head_ != tail_) {
      const env::DiskCompletion c = cq_[head_ % kCompletionCapacity];
      ++head_;
      ++n;
      f(c);
    }
    return n;
  }

  std::int64_t read(std::uint64_t off, std::span<std::byte> out) noexcept;
  [[nodiscard]] std::uint64_t size() const noexcept;
  bool resize(std::uint64_t n) noexcept;
  [[nodiscard]] std::size_t in_flight() const noexcept { return static_cast<std::size_t>(tail_ - head_); }
  [[nodiscard]] int fd() const noexcept { return fd_; }
  [[nodiscard]] bool is_open() const noexcept { return fd_ >= 0; }
  void close() noexcept;

 private:
  std::int32_t durable_sync() noexcept;  // 0 or -errno
  bool push(std::uint64_t tag, std::int32_t result) noexcept;

  int fd_ = -1;
  bool full_fsync_ = false;
  std::array<env::DiskCompletion, kCompletionCapacity> cq_{};
  std::uint64_t head_ = 0;
  std::uint64_t tail_ = 0;
};

static_assert(JournalDeviceLike<PosixJournalDevice>);

}  // namespace lle::journal
