#include "journal/io_uring_journal_device.h"

#if defined(__linux__) && defined(LLE_HAVE_IO_URING)

#include <fcntl.h>
#include <liburing.h>
#include <linux/fs.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <utility>

namespace lle::journal {

namespace {

int neg_errno() noexcept { return -errno; }

// Writes back the file's last block with its own contents through the ring and waits
// for the completion: devices without polled queues accept an IOPOLL ring but fail
// its writes with -EOPNOTSUPP, which would otherwise surface as a fatal journal error.
// Rewriting identical bytes is harmless whatever the segment holds.
int probe_write(io_uring* ring, int fd, int buffered_fd, bool iopoll) noexcept {
  struct stat st {};
  if (::fstat(buffered_fd, &st) != 0 || st.st_size < 4096) return 0;
  const off_t off = (st.st_size / 4096 - 1) * 4096;
  void* buf = std::aligned_alloc(4096, 4096);
  if (buf == nullptr) return -ENOMEM;
  int res = 0;
  if (::pread(buffered_fd, buf, 4096, off) != 4096) {
    res = neg_errno();
  } else if (io_uring_sqe* sqe = io_uring_get_sqe(ring); sqe == nullptr) {
    res = -EBUSY;
  } else {
    io_uring_prep_write(sqe, fd, buf, 4096, static_cast<__u64>(off));
    io_uring_sqe_set_data64(sqe, 0);
    res = io_uring_submit(ring);
    if (res >= 0) {
      io_uring_cqe* cqe = nullptr;
      res = iopoll ? 0 : io_uring_wait_cqe(ring, &cqe);
      while (iopoll && res == 0 && cqe == nullptr) {
        (void)io_uring_get_events(ring);
        res = io_uring_peek_cqe(ring, &cqe);
        if (res == -EAGAIN) res = 0;
      }
      if (res == 0 && cqe != nullptr) {
        res = cqe->res < 0 ? cqe->res : 0;
        io_uring_cqe_seen(ring, cqe);
      }
    }
  }
  std::free(buf);
  return res;
}

int try_init(io_uring* ring, unsigned entries, bool iopoll, bool defer) noexcept {
  io_uring_params p{};
  if (iopoll) p.flags |= IORING_SETUP_IOPOLL;
  if (defer) p.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
  return io_uring_queue_init_params(entries, ring, &p);
}

}  // namespace

IoUringJournalDevice::IoUringJournalDevice() noexcept = default;

IoUringJournalDevice::~IoUringJournalDevice() { close(); }

IoUringJournalDevice::IoUringJournalDevice(IoUringJournalDevice&& o) noexcept
    : ring_(std::move(o.ring_)), ring_ok_(o.ring_ok_), fd_(o.fd_), buffered_fd_(o.buffered_fd_), iopoll_(o.iopoll_),
      defer_(o.defer_), in_ring_(o.in_ring_), registered_(o.registered_), n_registered_(o.n_registered_), register_error_(o.register_error_),
      local_(o.local_), local_head_(o.local_head_), local_tail_(o.local_tail_) {
  o.ring_ok_ = false;
  o.fd_ = -1;
  o.buffered_fd_ = -1;
  o.in_ring_ = 0;
}

IoUringJournalDevice& IoUringJournalDevice::operator=(IoUringJournalDevice&& o) noexcept {
  if (this != &o) {
    close();
    ring_ = std::move(o.ring_);
    ring_ok_ = o.ring_ok_;
    fd_ = o.fd_;
    buffered_fd_ = o.buffered_fd_;
    iopoll_ = o.iopoll_;
    defer_ = o.defer_;
    in_ring_ = o.in_ring_;
    registered_ = o.registered_;
    n_registered_ = o.n_registered_;
    register_error_ = o.register_error_;
    local_ = o.local_;
    local_head_ = o.local_head_;
    local_tail_ = o.local_tail_;
    o.ring_ok_ = false;
    o.fd_ = -1;
    o.buffered_fd_ = -1;
    o.in_ring_ = 0;
  }
  return *this;
}

void IoUringJournalDevice::close() noexcept {
  if (ring_ok_ && ring_) io_uring_queue_exit(ring_.get());
  ring_ok_ = false;
  if (fd_ >= 0) ::close(fd_);
  if (buffered_fd_ >= 0) ::close(buffered_fd_);
  fd_ = -1;
  buffered_fd_ = -1;
}

std::expected<IoUringJournalDevice, int> IoUringJournalDevice::open(const std::string& path,
                                                                    const IoUringOptions& opts) {
  IoUringJournalDevice d;
  d.fd_ = ::open(path.c_str(), O_RDWR | O_CLOEXEC | (opts.direct ? O_DIRECT : 0));
  if (d.fd_ < 0) return std::unexpected(neg_errno());
  d.buffered_fd_ = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
  if (d.buffered_fd_ < 0) return std::unexpected(neg_errno());
  d.ring_ = std::make_unique<io_uring>();
  bool iopoll = opts.iopoll && opts.direct;
  bool defer = opts.defer_taskrun;
  int r = try_init(d.ring_.get(), opts.entries, iopoll, defer);
  if (r < 0 && opts.allow_fallback && defer) {  // DEFER_TASKRUN needs Linux 6.1
    defer = false;
    r = try_init(d.ring_.get(), opts.entries, iopoll, defer);
  }
  if (r < 0 && opts.allow_fallback && iopoll) {  // no polled queues for this device
    iopoll = false;
    r = try_init(d.ring_.get(), opts.entries, iopoll, opts.defer_taskrun);
    defer = opts.defer_taskrun;
    if (r < 0 && defer) {
      defer = false;
      r = try_init(d.ring_.get(), opts.entries, iopoll, defer);
    }
  }
  if (r < 0) return std::unexpected(r);
  d.ring_ok_ = true;
  if (iopoll && opts.allow_fallback && probe_write(d.ring_.get(), d.fd_, d.buffered_fd_, true) != 0) {
    io_uring_queue_exit(d.ring_.get());
    d.ring_ok_ = false;
    iopoll = false;
    defer = opts.defer_taskrun;
    r = try_init(d.ring_.get(), opts.entries, iopoll, defer);
    if (r < 0 && defer) {
      defer = false;
      r = try_init(d.ring_.get(), opts.entries, iopoll, defer);
    }
    if (r < 0) return std::unexpected(r);
    d.ring_ok_ = true;
  }
  d.iopoll_ = iopoll;
  d.defer_ = defer;
  if (opts.iowq_cpu >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(static_cast<unsigned>(opts.iowq_cpu), &set);
    const int a = io_uring_register_iowq_aff(d.ring_.get(), sizeof(set), &set);
    if (a < 0) return std::unexpected(a);
  }
  return d;
}

bool IoUringJournalDevice::register_buffers(std::span<const std::span<std::byte>> bufs) noexcept {
  if (!ring_ok_ || bufs.empty() || bufs.size() > kMaxRegistered || n_registered_ != 0) return false;
  iovec iov[kMaxRegistered];
  for (std::size_t i = 0; i < bufs.size(); ++i) {
    iov[i].iov_base = bufs[i].data();
    iov[i].iov_len = bufs[i].size();
  }
  if (const int r = io_uring_register_buffers(ring_.get(), iov, static_cast<unsigned>(bufs.size())); r < 0) {
    register_error_ = r;
    return false;
  }
  register_error_ = 0;
  for (std::size_t i = 0; i < bufs.size(); ++i) registered_[i] = Registered{bufs[i].data(), bufs[i].size()};
  n_registered_ = bufs.size();
  return true;
}

int IoUringJournalDevice::registered_index(const std::byte* p, std::size_t n) const noexcept {
  for (std::size_t i = 0; i < n_registered_; ++i) {
    const Registered& r = registered_[i];
    if (p >= r.base && p + n <= r.base + r.len) return static_cast<int>(i);
  }
  return -1;
}

bool IoUringJournalDevice::submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync,
                                        std::uint64_t tag) noexcept {
  if (!ring_ok_ || b.size() > static_cast<std::size_t>(INT32_MAX)) return false;
  io_uring_sqe* sqe = io_uring_get_sqe(ring_.get());
  if (sqe == nullptr) return false;
  const auto len = static_cast<unsigned>(b.size());
  const int idx = registered_index(b.data(), b.size());
  if (idx >= 0) {
    io_uring_prep_write_fixed(sqe, fd_, b.data(), len, off, idx);
  } else {
    io_uring_prep_write(sqe, fd_, b.data(), len, off);
  }
  // Per-write O_DSYNC (Linux 4.7): with an O_DIRECT overwrite of pre-zeroed space the
  // block layer uses FUA and skips the cache flush (R6 D4.1).
  if (dsync) sqe->rw_flags = RWF_DSYNC;
  io_uring_sqe_set_data64(sqe, tag);
  if (io_uring_submit(ring_.get()) < 0) return false;
  ++in_ring_;
  return true;
}

bool IoUringJournalDevice::submit_sync(std::uint64_t tag) noexcept {
  if (local_tail_ - local_head_ >= kLocalCapacity) return false;
  const int r = ::fdatasync(buffered_fd_) == 0 ? 0 : neg_errno();
  local_[local_tail_ % kLocalCapacity] = env::DiskCompletion{tag, r};
  ++local_tail_;
  return true;
}

std::size_t IoUringJournalDevice::reap(env::DiskCompletion* out, std::size_t max) noexcept {
  // IOPOLL completions are found only by entering the kernel with GETEVENTS, and
  // DEFER_TASKRUN runs completion work only then; both are reaped here, on the io stage.
  if (iopoll_ || defer_) (void)io_uring_get_events(ring_.get());
  std::size_t n = 0;
  unsigned head = 0;
  io_uring_cqe* cqe = nullptr;
  io_uring_for_each_cqe(ring_.get(), head, cqe) {
    if (n == max) break;
    out[n++] = env::DiskCompletion{io_uring_cqe_get_data64(cqe), cqe->res};
  }
  io_uring_cq_advance(ring_.get(), static_cast<unsigned>(n));
  in_ring_ -= n;
  return n;
}

std::int64_t IoUringJournalDevice::read(std::uint64_t off, std::span<std::byte> out) noexcept {
  std::size_t done = 0;
  while (done < out.size()) {
    const ssize_t r = ::pread(buffered_fd_, out.data() + done, out.size() - done, static_cast<off_t>(off + done));
    if (r < 0) {
      if (errno == EINTR) continue;
      return neg_errno();
    }
    if (r == 0) break;
    done += static_cast<std::size_t>(r);
  }
  return static_cast<std::int64_t>(done);
}

std::uint64_t IoUringJournalDevice::size() const noexcept {
  struct stat st {};
  if (buffered_fd_ < 0 || ::fstat(buffered_fd_, &st) != 0) return 0;
  return static_cast<std::uint64_t>(st.st_size);
}

bool IoUringJournalDevice::resize(std::uint64_t n) noexcept {
  return buffered_fd_ >= 0 && ::ftruncate(buffered_fd_, static_cast<off_t>(n)) == 0;
}

}  // namespace lle::journal

#endif  // __linux__ && LLE_HAVE_IO_URING
