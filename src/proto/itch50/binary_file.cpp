#include "proto/itch50/binary_file.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <cerrno>
#include <climits>
#include <cstring>
#include <utility>

namespace lle::itch50 {
namespace {

constexpr std::size_t kGzInputBytes = std::size_t{1} << 20;

std::string errno_text(const char* what, const std::string& path) {
  return std::string(what) + " '" + path + "': " + std::strerror(errno);
}

// Reads up to n bytes from fd, retrying on EINTR. Returns bytes, 0 at EOF, -1 on error.
std::ptrdiff_t read_fd(int fd, std::byte* dst, std::size_t n) noexcept {
  for (;;) {
    const ssize_t r = ::read(fd, dst, n);
    if (r >= 0) return r;
    if (errno != EINTR) return -1;
  }
}

// zlib inflate over our own compressed-input buffer so that gzip detection can
// look at bytes already read (works for pipes too) and so that concatenated
// gzip members (allowed by RFC 1952) are decoded back to back.
struct GzState {
  z_stream zs{};
  std::unique_ptr<std::byte[]> in;
  bool in_eof = false;
  bool member_done = false;
  bool inited = false;
  bool pending_error = false;  // error seen after some output was produced
};

}  // namespace

BinaryFileReader::BinaryFileReader() noexcept = default;

BinaryFileReader::~BinaryFileReader() { close(); }

void BinaryFileReader::close() noexcept {
  if (gz_ != nullptr) {
    auto* st = static_cast<GzState*>(gz_);
    if (st->inited) inflateEnd(&st->zs);
    delete st;
    gz_ = nullptr;
  }
  if (owns_fd_ && fd_ >= 0) ::close(fd_);
  fd_ = -1;
  owns_fd_ = false;
  kind_ = SourceKind::None;
  eof_ = false;
  failed_ = false;
  pos_ = end_ = 0;
  consumed_ = 0;
}

std::expected<void, std::string> BinaryFileReader::open(const std::string& path, std::size_t buffer_bytes) {
  close();
  error_.clear();
  cap_ = buffer_bytes < kMinBufferBytes ? kMinBufferBytes : buffer_bytes;
  if (cap_ > INT_MAX) cap_ = std::size_t{INT_MAX};
  buf_ = std::make_unique<std::byte[]>(cap_);

  if (path == "-") {
    fd_ = STDIN_FILENO;
    owns_fd_ = false;
  } else {
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) return std::unexpected(errno_text("cannot open", path));
    owns_fd_ = true;
  }

  // Read at least two bytes (or to EOF) to sniff the gzip magic.
  std::size_t have = 0;
  while (have < 2) {
    const std::ptrdiff_t r = read_fd(fd_, buf_.get() + have, cap_ - have);
    if (r < 0) {
      std::string e = errno_text("cannot read", path);
      close();
      return std::unexpected(std::move(e));
    }
    if (r == 0) {
      eof_ = true;
      break;
    }
    have += static_cast<std::size_t>(r);
  }

  const bool gzip = have >= 2 && buf_[0] == std::byte{0x1f} && buf_[1] == std::byte{0x8b};
  if (!gzip) {
    kind_ = SourceKind::Fd;
    pos_ = 0;
    end_ = have;
    return {};
  }

  auto* st = new GzState;
  gz_ = st;
  st->in = std::make_unique<std::byte[]>(have > kGzInputBytes ? have : kGzInputBytes);
  std::memcpy(st->in.get(), buf_.get(), have);
  st->zs.next_in = reinterpret_cast<Bytef*>(st->in.get());
  st->zs.avail_in = static_cast<uInt>(have);
  st->in_eof = eof_;
  if (inflateInit2(&st->zs, 15 + 16) != Z_OK) {  // 15-bit window, gzip wrapper only
    close();
    return std::unexpected("zlib inflateInit2 failed for '" + path + "'");
  }
  st->inited = true;
  kind_ = SourceKind::Gzip;
  eof_ = false;
  pos_ = end_ = 0;
  return {};
}

std::ptrdiff_t BinaryFileReader::read_source(std::byte* dst, std::size_t n) noexcept {
  if (kind_ == SourceKind::Fd) {
    const std::ptrdiff_t r = read_fd(fd_, dst, n);
    if (r < 0) error_ = std::string("read failed: ") + std::strerror(errno);
    return r;
  }
  auto* st = static_cast<GzState*>(gz_);
  if (st->pending_error) return -1;
  z_stream& zs = st->zs;
  if (n > UINT_MAX) n = UINT_MAX;
  zs.next_out = reinterpret_cast<Bytef*>(dst);
  zs.avail_out = static_cast<uInt>(n);
  // Bytes inflated so far are returned even when an error follows; the error
  // is then reported by the next call, so records before it stay readable.
  const auto fail = [&](std::string msg) -> std::ptrdiff_t {
    error_ = std::move(msg);
    const auto produced = static_cast<std::ptrdiff_t>(n - zs.avail_out);
    if (produced == 0) return -1;
    st->pending_error = true;
    return produced;
  };
  while (zs.avail_out > 0) {
    if (zs.avail_in == 0 && !st->in_eof) {
      const std::ptrdiff_t r = read_fd(fd_, st->in.get(), kGzInputBytes);
      if (r < 0) return fail(std::string("read failed: ") + std::strerror(errno));
      if (r == 0) {
        st->in_eof = true;
      } else {
        zs.next_in = reinterpret_cast<Bytef*>(st->in.get());
        zs.avail_in = static_cast<uInt>(r);
      }
    }
    if (zs.avail_in == 0 && st->in_eof) {
      if (!st->member_done) return fail("gzip stream truncated");
      break;  // clean end after the last member
    }
    if (st->member_done) {
      // More input after a complete member: the next gzip member starts here.
      if (inflateReset(&zs) != Z_OK) return fail("zlib inflateReset failed");
      st->member_done = false;
    }
    const int rc = inflate(&zs, Z_NO_FLUSH);
    if (rc == Z_STREAM_END) {
      st->member_done = true;
      continue;
    }
    if (rc == Z_OK) continue;
    if (rc == Z_BUF_ERROR && zs.avail_in == 0) continue;  // needs more input
    return fail(std::string("zlib inflate error: ") + (zs.msg != nullptr ? zs.msg : "unknown"));
  }
  return static_cast<std::ptrdiff_t>(n - zs.avail_out);
}

Record BinaryFileReader::next_slow() noexcept {
  if (kind_ == SourceKind::None) return {RecordStatus::IoError, {}};
  for (;;) {
    const std::size_t avail = end_ - pos_;
    if (avail >= 2) {
      const std::size_t len = load_be16(buf_.get() + pos_);
      if (avail >= 2 + len) {
        const std::span<const std::byte> msg(buf_.get() + pos_ + 2, len);
        pos_ += 2 + len;
        consumed_ += 2 + len;
        return {len == 0 ? RecordStatus::EndOfSession : RecordStatus::Message, msg};
      }
    }
    if (failed_) return {RecordStatus::IoError, {}};
    if (eof_) {
      if (avail == 0) return {RecordStatus::EndOfFile, {}};
      const std::span<const std::byte> part(buf_.get() + pos_, avail);
      pos_ = end_;
      consumed_ += avail;
      return {RecordStatus::Truncated, part};
    }
    if (pos_ > 0) {
      std::memmove(buf_.get(), buf_.get() + pos_, avail);
      pos_ = 0;
      end_ = avail;
    }
    const std::ptrdiff_t r = read_source(buf_.get() + end_, cap_ - end_);
    if (r < 0) {
      failed_ = true;
      return {RecordStatus::IoError, {}};
    }
    if (r == 0) eof_ = true;
    end_ += static_cast<std::size_t>(r);
  }
}

MappedFile::~MappedFile() { close(); }

void MappedFile::close() noexcept {
  if (p_ != nullptr) ::munmap(p_, n_);
  p_ = nullptr;
  n_ = 0;
}

std::expected<void, std::string> MappedFile::open(const std::string& path) {
  close();
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return std::unexpected(errno_text("cannot open", path));
  struct stat sb{};
  if (::fstat(fd, &sb) != 0) {
    std::string e = errno_text("cannot stat", path);
    ::close(fd);
    return std::unexpected(std::move(e));
  }
  const auto size = static_cast<std::size_t>(sb.st_size);
  if (size > 0) {
    void* p = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
      std::string e = errno_text("cannot mmap", path);
      ::close(fd);
      return std::unexpected(std::move(e));
    }
    ::madvise(p, size, MADV_SEQUENTIAL);
    p_ = p;
    n_ = size;
  }
  ::close(fd);
  return {};
}

}  // namespace lle::itch50
