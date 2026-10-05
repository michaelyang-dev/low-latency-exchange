#pragma once
// IoUringJournalDevice (06 §6): the production L3 write path. Linux only, built when
// liburing is found (LLE_HAVE_IO_URING; see src/journal/CMakeLists.txt).
//
//   - io_uring with SINGLE_ISSUER | DEFER_TASKRUN | IOPOLL on NVMe polled queues
//     (nvme.poll_queues=2): completions are reaped by the io stage, no interrupts;
//   - IORING_REGISTER_IOWQ_AFF pins any io-wq worker to the io CPU;
//   - IORING_REGISTER_BUFFERS with the writer's batch buffers (8 x 64 KiB, 4 KiB aligned);
//   - IORING_OP_WRITE_FIXED with RWF_DSYNC on an O_DIRECT fd, queue depth <= 4.
// fsync is not available on IOPOLL rings: submit_sync() runs fdatasync synchronously
// and queues its completion (the writer never needs it: every write is RWF_DSYNC).
// If IOPOLL (or DEFER_TASKRUN) is unavailable and `allow_fallback` is set, the ring is
// created without it (06 §15: interrupt-driven completion, IRQs pinned to the io CPU).
// IOPOLL support is probed at open by rewriting the file's last block with its own
// bytes: a device without polled queues accepts the ring setup but fails its writes.
#if defined(__linux__) && defined(LLE_HAVE_IO_URING)

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>

#include "env/concepts.h"
#include "journal/journal_device.h"

struct io_uring;

namespace lle::journal {

struct IoUringOptions {
  unsigned entries = 32;      // SQ size (>= queue depth + 1)
  bool iopoll = true;         // IORING_SETUP_IOPOLL (needs O_DIRECT and polled queues)
  bool defer_taskrun = true;  // IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN
  bool direct = true;         // O_DIRECT
  int iowq_cpu = -1;          // IORING_REGISTER_IOWQ_AFF target, -1: unset
  bool allow_fallback = true; // retry without IOPOLL / DEFER_TASKRUN if refused
};

class IoUringJournalDevice {
 public:
  static constexpr std::size_t kMaxRegistered = 16;
  static constexpr std::size_t kLocalCapacity = 16;

  IoUringJournalDevice() noexcept;
  ~IoUringJournalDevice();
  IoUringJournalDevice(IoUringJournalDevice&& o) noexcept;
  IoUringJournalDevice& operator=(IoUringJournalDevice&& o) noexcept;
  IoUringJournalDevice(const IoUringJournalDevice&) = delete;
  IoUringJournalDevice& operator=(const IoUringJournalDevice&) = delete;

  // Opens an existing (prepared) segment file. Returns the device or -errno.
  static std::expected<IoUringJournalDevice, int> open(const std::string& path, const IoUringOptions& opts = {});

  // IORING_REGISTER_BUFFERS; writes from inside a registered buffer use WRITE_FIXED.
  // False if refused; register_error() is then the -errno (-ENOMEM: the user's
  // RLIMIT_MEMLOCK, which every process of that user shares, is exhausted). Writes
  // from unregistered buffers still work (IORING_OP_WRITE).
  bool register_buffers(std::span<const std::span<std::byte>> bufs) noexcept;
  [[nodiscard]] int register_error() const noexcept { return register_error_; }

  // ---- env::DiskFileLike ---------------------------------------------------------
  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept;
  bool submit_sync(std::uint64_t tag) noexcept;

  template <class F>
  std::size_t poll(F&& f) {
    std::size_t n = 0;
    while (local_head_ != local_tail_) {
      const env::DiskCompletion c = local_[local_head_ % kLocalCapacity];
      ++local_head_;
      ++n;
      f(c);
    }
    if (in_ring_ == 0) return n;
    env::DiskCompletion batch[32];
    const std::size_t got = reap(batch, 32);
    for (std::size_t i = 0; i < got; ++i) f(batch[i]);
    return n + got;
  }

  // ---- synchronous extras (buffered fd; cold paths) ---------------------------------
  std::int64_t read(std::uint64_t off, std::span<std::byte> out) noexcept;
  [[nodiscard]] std::uint64_t size() const noexcept;
  bool resize(std::uint64_t n) noexcept;
  [[nodiscard]] std::size_t in_flight() const noexcept {
    return in_ring_ + static_cast<std::size_t>(local_tail_ - local_head_);
  }

  [[nodiscard]] bool iopoll_active() const noexcept { return iopoll_; }
  [[nodiscard]] bool defer_taskrun_active() const noexcept { return defer_; }
  [[nodiscard]] bool fixed_buffers() const noexcept { return n_registered_ != 0; }

 private:
  std::size_t reap(env::DiskCompletion* out, std::size_t max) noexcept;
  int registered_index(const std::byte* p, std::size_t n) const noexcept;
  void close() noexcept;

  struct Registered {
    const std::byte* base = nullptr;
    std::size_t len = 0;
  };

  std::unique_ptr<io_uring> ring_;
  bool ring_ok_ = false;
  int fd_ = -1;           // O_DIRECT, used by the ring
  int buffered_fd_ = -1;  // reads, size, resize, fdatasync
  bool iopoll_ = false;
  bool defer_ = false;
  std::size_t in_ring_ = 0;
  std::array<Registered, kMaxRegistered> registered_{};
  std::size_t n_registered_ = 0;
  int register_error_ = 0;
  std::array<env::DiskCompletion, kLocalCapacity> local_{};
  std::uint64_t local_head_ = 0;
  std::uint64_t local_tail_ = 0;
};

static_assert(JournalDeviceLike<IoUringJournalDevice>);

}  // namespace lle::journal

#endif  // __linux__ && LLE_HAVE_IO_URING
