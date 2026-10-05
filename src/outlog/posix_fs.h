#pragma once
// POSIX binding of the output log's storage (outlog/disk.h): plain files with
// pread/pwrite, fdatasync (fsync on macOS), ftruncate, rename and flock. Every
// operation completes inside submit, so poll() only hands back the result.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include "env/concepts.h"
#include "outlog/disk.h"

namespace lle::outlog {

class PosixFile {
 public:
  PosixFile() noexcept = default;
  explicit PosixFile(int fd) noexcept : fd_(fd) {}
  ~PosixFile() { reset(); }
  PosixFile(PosixFile&& o) noexcept : fd_(o.fd_), n_(o.n_), done_(o.done_) { o.fd_ = -1; o.n_ = 0; }
  PosixFile& operator=(PosixFile&& o) noexcept {
    if (this != &o) {
      reset();
      fd_ = o.fd_;
      n_ = o.n_;
      done_ = o.done_;
      o.fd_ = -1;
      o.n_ = 0;
    }
    return *this;
  }
  PosixFile(const PosixFile&) = delete;
  PosixFile& operator=(const PosixFile&) = delete;

  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  [[nodiscard]] int fd() const noexcept { return fd_; }
  void reset() noexcept;

  // env::DiskFileLike: the write or sync happens here; its result is queued.
  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept;
  bool submit_sync(std::uint64_t tag) noexcept;
  template <class F>
  std::size_t poll(F&& cb) {
    const std::size_t n = n_;
    for (std::size_t i = 0; i < n; ++i) cb(done_[i]);
    n_ = 0;
    return n;
  }
  // env::DiskFileReadLike (errors read as 0 bytes; the outlog uses the checked forms).
  std::size_t read(std::uint64_t off, std::span<std::byte> out) const noexcept;
  [[nodiscard]] std::uint64_t size() const noexcept;

  bool resize(std::uint64_t n) noexcept;
  std::ptrdiff_t read_checked(std::uint64_t off, std::span<std::byte> out) const noexcept;
  [[nodiscard]] std::expected<std::uint64_t, int> size_checked() const noexcept;

 private:
  static constexpr std::size_t kQueue = 4;
  bool push(std::uint64_t tag, std::int32_t result) noexcept;

  int fd_ = -1;
  std::size_t n_ = 0;
  std::array<env::DiskCompletion, kQueue> done_{};
};

struct PosixFs {
  using File = PosixFile;
  std::expected<PosixFile, int> open(const std::string& path, OpenMode mode);
  int rename(const std::string& from, const std::string& to);
  int remove(const std::string& path);
  int make_dirs(const std::string& dir);
  bool lock_writer(PosixFile& f);
};

static_assert(OutlogFileLike<PosixFile>);
static_assert(OutlogFsLike<PosixFs>);

}  // namespace lle::outlog
