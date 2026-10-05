#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <climits>

#include "journal/journal_device.h"

namespace lle::journal {

namespace {

std::int32_t neg_errno() noexcept { return -static_cast<std::int32_t>(errno); }

// The largest single pwrite/pread we issue; journal writes are <= 64 KiB, preparation
// chunks 1 MiB, so this only bounds pathological callers.
constexpr std::size_t kMaxIo = std::size_t{1} << 30;

}  // namespace

PosixJournalDevice::~PosixJournalDevice() { close(); }

PosixJournalDevice::PosixJournalDevice(PosixJournalDevice&& o) noexcept
    : fd_(o.fd_), full_fsync_(o.full_fsync_), cq_(o.cq_), head_(o.head_), tail_(o.tail_) {
  o.fd_ = -1;
  o.head_ = o.tail_ = 0;
}

PosixJournalDevice& PosixJournalDevice::operator=(PosixJournalDevice&& o) noexcept {
  if (this != &o) {
    close();
    fd_ = o.fd_;
    full_fsync_ = o.full_fsync_;
    cq_ = o.cq_;
    head_ = o.head_;
    tail_ = o.tail_;
    o.fd_ = -1;
    o.head_ = o.tail_ = 0;
  }
  return *this;
}

void PosixJournalDevice::close() noexcept {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
}

std::expected<PosixJournalDevice, int> PosixJournalDevice::open(const std::string& path, const PosixDeviceOptions& opts) {
  int flags = O_CLOEXEC | (opts.read_only ? O_RDONLY : O_RDWR);
  if (opts.create) flags |= O_CREAT;
  if (opts.exclusive) flags |= O_EXCL;
#if defined(__linux__)
  if (opts.direct) flags |= O_DIRECT;
#endif
  const int fd = ::open(path.c_str(), flags, 0644);
  if (fd < 0) return std::unexpected(errno);
#if defined(__APPLE__)
  if (opts.direct && ::fcntl(fd, F_NOCACHE, 1) != 0) {
    const int e = errno;
    ::close(fd);
    return std::unexpected(e);
  }
#endif
  PosixJournalDevice d;
  d.fd_ = fd;
  d.full_fsync_ = opts.full_fsync;
  return d;
}

std::int32_t PosixJournalDevice::durable_sync() noexcept {
#if defined(__APPLE__)
  if (full_fsync_) return ::fcntl(fd_, F_FULLFSYNC) == 0 ? 0 : neg_errno();
  return ::fsync(fd_) == 0 ? 0 : neg_errno();
#else
  return ::fdatasync(fd_) == 0 ? 0 : neg_errno();
#endif
}

bool PosixJournalDevice::push(std::uint64_t tag, std::int32_t result) noexcept {
  if (tail_ - head_ >= kCompletionCapacity) return false;
  cq_[tail_ % kCompletionCapacity] = env::DiskCompletion{tag, result};
  ++tail_;
  return true;
}

bool PosixJournalDevice::submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept {
  if (tail_ - head_ >= kCompletionCapacity) return false;
  if (fd_ < 0) return push(tag, -EBADF);
  if (b.size() > kMaxIo || b.size() > static_cast<std::size_t>(INT32_MAX)) return push(tag, -EINVAL);
  ssize_t w;
  do {
    w = ::pwrite(fd_, b.data(), b.size(), static_cast<off_t>(off));
  } while (w < 0 && errno == EINTR);
  if (w < 0) return push(tag, neg_errno());
  // A short write is reported as such; the writer treats it as fatal (06 §6).
  if (dsync && static_cast<std::size_t>(w) == b.size()) {
    const std::int32_t s = durable_sync();
    if (s != 0) return push(tag, s);
  }
  return push(tag, static_cast<std::int32_t>(w));
}

bool PosixJournalDevice::submit_sync(std::uint64_t tag) noexcept {
  if (tail_ - head_ >= kCompletionCapacity) return false;
  if (fd_ < 0) return push(tag, -EBADF);
  return push(tag, durable_sync());
}

std::int64_t PosixJournalDevice::read(std::uint64_t off, std::span<std::byte> out) noexcept {
  if (fd_ < 0) return -EBADF;
  std::size_t done = 0;
  while (done < out.size()) {
    const std::size_t want = out.size() - done < kMaxIo ? out.size() - done : kMaxIo;
    const ssize_t r = ::pread(fd_, out.data() + done, want, static_cast<off_t>(off + done));
    if (r < 0) {
      if (errno == EINTR) continue;
      return neg_errno();
    }
    if (r == 0) break;
    done += static_cast<std::size_t>(r);
  }
  return static_cast<std::int64_t>(done);
}

std::uint64_t PosixJournalDevice::size() const noexcept {
  struct stat st {};
  if (fd_ < 0 || ::fstat(fd_, &st) != 0) return 0;
  return static_cast<std::uint64_t>(st.st_size);
}

bool PosixJournalDevice::resize(std::uint64_t n) noexcept {
  return fd_ >= 0 && ::ftruncate(fd_, static_cast<off_t>(n)) == 0;
}

}  // namespace lle::journal
