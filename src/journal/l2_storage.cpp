#include "journal/l2_storage.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "common/crc32c.h"
#include "common/endian.h"
#include "journal/record.h"

namespace lle::journal {

namespace {

constexpr char kMagic[8] = {'L', 'L', 'E', 'L', '2', 'R', 'N', '1'};
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kCrcOff = 4092;

bool control_matches(const std::byte* c, const L2StorageOptions& o, std::uint64_t& nonce) {
  if (std::memcmp(c, kMagic, sizeof(kMagic)) != 0) return false;
  if (crc32c(c, kCrcOff) != load_le32(c + kCrcOff)) return false;
  if (load_le32(c + 8) != kVersion || load_le32(c + 12) != o.node || load_le32(c + 16) != o.day ||
      load_le32(c + 20) != o.epoch || load_le64(c + 24) != o.capacity || load_le64(c + 40) != o.control_bytes) {
    return false;
  }
  nonce = load_le64(c + 32);
  return usable_nonce(nonce);
}

void write_control(std::byte* c, const L2StorageOptions& o, std::uint64_t nonce) {
  std::memset(c, 0, 4096);
  std::memcpy(c, kMagic, sizeof(kMagic));
  store_le32(c + 8, kVersion);
  store_le32(c + 12, o.node);
  store_le32(c + 16, o.day);
  store_le32(c + 20, o.epoch);
  store_le64(c + 24, o.capacity);
  store_le64(c + 32, nonce);
  store_le64(c + 40, o.control_bytes);
  store_le32(c + kCrcOff, crc32c(c, kCrcOff));
}

std::string err(const char* what, const std::string& path) {
  return std::string(what) + " " + path + ": " + std::strerror(errno);
}

// Touches every page with a write of its own value: later appends never fault, and an
// existing ring's contents are unchanged.
void prefault(std::byte* p, std::size_t n) {
  const auto page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
  for (std::size_t i = 0; i < n; i += page) {
    volatile std::byte* b = p + i;
    *b = *b;
  }
}

}  // namespace

L2Storage::~L2Storage() { release(); }

L2Storage::L2Storage(L2Storage&& o) noexcept
    : map_(o.map_), map_bytes_(o.map_bytes_), fd_(o.fd_), data_(o.data_), capacity_(o.capacity_),
      nonce_(o.nonce_), reopened_(o.reopened_) {
  o.map_ = nullptr;
  o.fd_ = -1;
}

L2Storage& L2Storage::operator=(L2Storage&& o) noexcept {
  if (this != &o) {
    release();
    map_ = o.map_;
    map_bytes_ = o.map_bytes_;
    fd_ = o.fd_;
    data_ = o.data_;
    capacity_ = o.capacity_;
    nonce_ = o.nonce_;
    reopened_ = o.reopened_;
    o.map_ = nullptr;
    o.fd_ = -1;
  }
  return *this;
}

void L2Storage::release() noexcept {
  if (map_ != nullptr) ::munmap(map_, map_bytes_);
  if (fd_ >= 0) ::close(fd_);
  map_ = nullptr;
  fd_ = -1;
}

std::expected<L2Storage, std::string> L2Storage::open_with(const L2StorageOptions& opts, std::uint64_t (*gen)(void*),
                                                           void* ctx) {
  if (opts.capacity < 4096 || (opts.capacity & (opts.capacity - 1)) != 0) {
    return std::unexpected(std::string("L2 capacity must be a power of two >= 4096"));
  }
  if (opts.control_bytes < 4096 || opts.control_bytes % 4096 != 0) {
    return std::unexpected(std::string("L2 control block must be a multiple of 4096"));
  }
  L2Storage s;
  s.map_bytes_ = opts.control_bytes + opts.capacity;
  s.capacity_ = opts.capacity;
  int flags = MAP_SHARED;
  if (opts.path.empty()) {
    flags = MAP_PRIVATE | MAP_ANONYMOUS;
  } else {
    s.fd_ = ::open(opts.path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (s.fd_ < 0) return std::unexpected(err("open", opts.path));
    struct stat st {};
    if (::fstat(s.fd_, &st) != 0) return std::unexpected(err("fstat", opts.path));
    if (static_cast<std::size_t>(st.st_size) != s.map_bytes_) {
      // Wrong size: start over (a fresh file is all zeros).
      if (::ftruncate(s.fd_, 0) != 0 || ::ftruncate(s.fd_, static_cast<off_t>(s.map_bytes_)) != 0) {
        return std::unexpected(err("ftruncate", opts.path));
      }
    }
  }
#if defined(__linux__)
  if (opts.prefault) flags |= MAP_POPULATE;
#endif
  void* m = ::mmap(nullptr, s.map_bytes_, PROT_READ | PROT_WRITE, flags, s.fd_, 0);
  if (m == MAP_FAILED) return std::unexpected(err("mmap", opts.path.empty() ? "anonymous" : opts.path));
  s.map_ = m;
  auto* base = static_cast<std::byte*>(m);
  s.data_ = base + opts.control_bytes;
  if (opts.prefault) prefault(base, s.map_bytes_);

  std::uint64_t nonce = 0;
  if (!opts.path.empty() && control_matches(base, opts, nonce)) {
    s.nonce_ = nonce;
    s.reopened_ = true;
    return s;
  }
  do {
    nonce = gen(ctx);
  } while (!usable_nonce(nonce));
  write_control(base, opts, nonce);
  s.nonce_ = nonce;
  return s;
}

void L2Storage::renew_with(std::uint64_t (*gen)(void*), void* ctx) noexcept {
  std::uint64_t nonce = 0;
  do {
    nonce = gen(ctx);
  } while (!usable_nonce(nonce) || nonce == nonce_);
  // A process killed between the two stores leaves a control block that fails its crc:
  // the next open starts a new ring, which retires the old one as well.
  auto* c = static_cast<std::byte*>(map_);
  store_le64(c + 32, nonce);
  store_le32(c + kCrcOff, crc32c(c, kCrcOff));
  nonce_ = nonce;
}

}  // namespace lle::journal
