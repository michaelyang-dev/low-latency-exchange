#include "outlog/posix_fs.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <system_error>

namespace lle::outlog {
namespace {

std::ptrdiff_t pread_full(int fd, std::byte* dst, std::size_t n, std::uint64_t off) noexcept {
  std::size_t got = 0;
  while (got < n) {
    const ssize_t r = ::pread(fd, dst + got, n - got, static_cast<off_t>(off + got));
    if (r > 0) {
      got += static_cast<std::size_t>(r);
    } else if (r == 0) {
      break;
    } else if (errno != EINTR) {
      return -errno;
    }
  }
  return static_cast<std::ptrdiff_t>(got);
}

// Writes all `n` bytes at `off`. Short writes are continued (they are progress,
// not errors); any failure returns its errno and is never retried.
int pwrite_full(int fd, const std::byte* src, std::size_t n, std::uint64_t off) noexcept {
  std::size_t done = 0;
  while (done < n) {
    const ssize_t r = ::pwrite(fd, src + done, n - done, static_cast<off_t>(off + done));
    if (r > 0) {
      done += static_cast<std::size_t>(r);
    } else if (r == 0) {
      return EIO;  // no progress and no error code: treat as a device failure
    } else if (errno != EINTR) {
      return errno;
    }
  }
  return 0;
}

int data_sync(int fd) noexcept {
#if defined(__APPLE__)
  return ::fsync(fd);
#else
  return ::fdatasync(fd);
#endif
}

}  // namespace

void PosixFile::reset() noexcept {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
  n_ = 0;
}

bool PosixFile::push(std::uint64_t tag, std::int32_t result) noexcept {
  if (n_ == kQueue) return false;
  done_[n_++] = env::DiskCompletion{tag, result};
  return true;
}

bool PosixFile::submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept {
  if (n_ == kQueue || b.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) return false;
  int err = pwrite_full(fd_, b.data(), b.size(), off);
  if (err == 0 && dsync && data_sync(fd_) != 0) err = errno;
  return push(tag, err == 0 ? static_cast<std::int32_t>(b.size()) : -err);
}

bool PosixFile::submit_sync(std::uint64_t tag) noexcept {
  if (n_ == kQueue) return false;
  return push(tag, data_sync(fd_) == 0 ? 0 : -errno);
}

std::size_t PosixFile::read(std::uint64_t off, std::span<std::byte> out) const noexcept {
  const std::ptrdiff_t r = read_checked(off, out);
  return r < 0 ? 0 : static_cast<std::size_t>(r);
}

std::uint64_t PosixFile::size() const noexcept { return size_checked().value_or(0); }

bool PosixFile::resize(std::uint64_t n) noexcept { return ::ftruncate(fd_, static_cast<off_t>(n)) == 0; }

std::ptrdiff_t PosixFile::read_checked(std::uint64_t off, std::span<std::byte> out) const noexcept {
  return pread_full(fd_, out.data(), out.size(), off);
}

std::expected<std::uint64_t, int> PosixFile::size_checked() const noexcept {
  struct stat st{};
  if (::fstat(fd_, &st) != 0) return std::unexpected(errno);
  return static_cast<std::uint64_t>(st.st_size);
}

std::expected<PosixFile, int> PosixFs::open(const std::string& path, OpenMode mode) {
  int flags = O_CLOEXEC;
  switch (mode) {
    case OpenMode::ReadOnly:
      flags |= O_RDONLY;
      break;
    case OpenMode::ReadWrite:
      flags |= O_RDWR;
      break;
    case OpenMode::ReadWriteCreate:
      flags |= O_RDWR | O_CREAT;
      break;
    case OpenMode::CreateTruncate:
      flags |= O_WRONLY | O_CREAT | O_TRUNC;
      break;
  }
  const int fd = ::open(path.c_str(), flags, 0644);
  if (fd < 0) return std::unexpected(errno);
  return PosixFile(fd);
}

int PosixFs::rename(const std::string& from, const std::string& to) {
  return std::rename(from.c_str(), to.c_str()) == 0 ? 0 : errno;
}

int PosixFs::remove(const std::string& path) { return ::unlink(path.c_str()) == 0 ? 0 : errno; }

int PosixFs::make_dirs(const std::string& dir) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  return ec ? (ec.value() != 0 ? ec.value() : EIO) : 0;
}

bool PosixFs::lock_writer(PosixFile& f) { return ::flock(f.fd(), LOCK_EX | LOCK_NB) == 0; }

}  // namespace lle::outlog
