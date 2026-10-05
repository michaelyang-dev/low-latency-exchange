#include "input.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>
#include <vector>

#include "common/endian.h"
#include "proto/itch50/binary_file.h"

namespace lle::replay {
namespace {

constexpr std::size_t k2M = std::size_t{2} << 20;
[[maybe_unused]] constexpr std::size_t k1G = std::size_t{1} << 30;

std::size_t round_up(std::size_t n, std::size_t a) { return (n + a - 1) / a * a; }

void* map_anon(std::size_t len, int extra) {
  void* p = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | extra, -1, 0);
  return p == MAP_FAILED ? nullptr : p;
}

bool is_gzip(const std::string& path) {
  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) return false;
  unsigned char m[2] = {0, 0};
  const bool gz = ::read(fd, m, 2) == 2 && m[0] == 0x1f && m[1] == 0x8b;
  ::close(fd);
  return gz;
}

}  // namespace

bool parse_huge_policy(const std::string& s, HugePolicy& out) noexcept {
  if (s == "auto") out = HugePolicy::kAuto;
  else if (s == "1g") out = HugePolicy::k1G;
  else if (s == "2m") out = HugePolicy::k2M;
  else if (s == "thp") out = HugePolicy::kThp;
  else if (s == "none") out = HugePolicy::kNone;
  else return false;
  return true;
}

Input::~Input() {
  if (p_ != nullptr) munmap(p_, mapped_);
}

Input::Input(Input&& o) noexcept
    : p_(std::exchange(o.p_, nullptr)),
      n_(std::exchange(o.n_, 0)),
      mapped_(std::exchange(o.mapped_, 0)),
      pages_(std::move(o.pages_)),
      locked_(o.locked_) {}

Input& Input::operator=(Input&& o) noexcept {
  if (this != &o) {
    if (p_ != nullptr) munmap(p_, mapped_);
    p_ = std::exchange(o.p_, nullptr);
    n_ = std::exchange(o.n_, 0);
    mapped_ = std::exchange(o.mapped_, 0);
    pages_ = std::move(o.pages_);
    locked_ = o.locked_;
  }
  return *this;
}

std::expected<void, std::string> Input::allocate(std::size_t n, HugePolicy policy) {
  const std::size_t want = n == 0 ? 1 : n;
#if defined(__linux__)
  if (policy == HugePolicy::kAuto || policy == HugePolicy::k1G) {
    const std::size_t len = round_up(want, k1G);
    if (void* p = map_anon(len, MAP_HUGETLB | (30 << MAP_HUGE_SHIFT))) {
      p_ = static_cast<std::byte*>(p), mapped_ = len, pages_ = "1g";
    } else if (policy == HugePolicy::k1G) {
      return std::unexpected(std::string("1 GiB huge pages unavailable: ") + std::strerror(errno));
    }
  }
  if (p_ == nullptr && (policy == HugePolicy::kAuto || policy == HugePolicy::k2M)) {
    const std::size_t len = round_up(want, k2M);
    if (void* p = map_anon(len, MAP_HUGETLB | (21 << MAP_HUGE_SHIFT))) {
      p_ = static_cast<std::byte*>(p), mapped_ = len, pages_ = "2m";
    } else if (policy == HugePolicy::k2M) {
      return std::unexpected(std::string("2 MiB huge pages unavailable: ") + std::strerror(errno));
    }
  }
#endif
  if (p_ == nullptr && policy != HugePolicy::kNone) {
    // Transparent huge pages need 2 MiB alignment: over-map, then trim.
    const std::size_t len = round_up(want, k2M);
    if (void* raw = map_anon(len + k2M, 0)) {
      const auto base = reinterpret_cast<std::uintptr_t>(raw);
      const std::uintptr_t aligned = round_up(base, k2M);
      if (aligned != base) munmap(raw, aligned - base);
      const std::uintptr_t tail = aligned + len;
      const std::uintptr_t raw_end = base + len + k2M;
      if (raw_end != tail) munmap(reinterpret_cast<void*>(tail), raw_end - tail);
      p_ = reinterpret_cast<std::byte*>(aligned), mapped_ = len;
#if defined(MADV_HUGEPAGE)
      pages_ = madvise(p_, len, MADV_HUGEPAGE) == 0 ? "thp" : "4k";
#else
      pages_ = "4k";
#endif
    }
  }
  if (p_ == nullptr) {
    const std::size_t len = round_up(want, 4096);
    void* p = map_anon(len, 0);
    if (p == nullptr) return std::unexpected(std::string("mmap: ") + std::strerror(errno));
    p_ = static_cast<std::byte*>(p), mapped_ = len, pages_ = "4k";
  }
  n_ = n;
  return {};
}

std::expected<Input, std::string> Input::load(const std::string& path, std::uint64_t max_records,
                                              HugePolicy policy) {
  Input in;
  if (max_records == 0 && !is_gzip(path)) {
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return std::unexpected(path + ": " + std::strerror(errno));
    struct stat st{};
    if (fstat(fd, &st) != 0) {
      ::close(fd);
      return std::unexpected(path + ": fstat failed");
    }
    if (auto r = in.allocate(static_cast<std::size_t>(st.st_size), policy); !r) {
      ::close(fd);
      return std::unexpected(r.error());
    }
    std::size_t got = 0;
    while (got < in.n_) {
      const std::size_t chunk = std::min<std::size_t>(in.n_ - got, std::size_t{1} << 30);
      const ssize_t r = ::read(fd, in.p_ + got, chunk);
      if (r <= 0) {
        ::close(fd);
        return std::unexpected(path + ": short read");
      }
      got += static_cast<std::size_t>(r);
    }
    ::close(fd);
  } else {
    // Gzip input or a record prefix: stream the records and re-frame them.
    // Full-day gzip input works but needs twice the day's size in memory; the
    // benchmark protocol decompresses once to data/itch/*.bin instead.
    itch50::BinaryFileReader rd;
    if (auto r = rd.open(path); !r) return std::unexpected(r.error());
    std::vector<std::byte> buf;
    std::uint64_t kept = 0;
    for (;;) {
      if (max_records != 0 && kept == max_records) break;
      const itch50::Record rec = rd.next();
      if (rec.status == itch50::RecordStatus::EndOfFile) break;
      if (rec.status == itch50::RecordStatus::Truncated) return std::unexpected(path + ": truncated record");
      if (rec.status == itch50::RecordStatus::IoError) return std::unexpected(path + ": " + rd.error());
      std::byte len[2];
      store_be16(len, static_cast<std::uint16_t>(rec.data.size()));
      buf.insert(buf.end(), len, len + 2);
      buf.insert(buf.end(), rec.data.begin(), rec.data.end());
      if (rec.status == itch50::RecordStatus::Message) ++kept;
    }
    if (auto r = in.allocate(buf.size(), policy); !r) return std::unexpected(r.error());
    std::memcpy(in.p_, buf.data(), buf.size());
  }
  // Touch every page now (read() already did for plain input) and lock them,
  // so the timed region takes no faults on the input.
  in.locked_ = mlock(in.p_, in.mapped_) == 0;
  return in;
}

FrameScan scan_frames(const std::byte* p, std::size_t n) noexcept {
  FrameScan s;
  itch50::BinaryFileView v({p, n});
  for (;;) {
    const itch50::Record r = v.next();
    if (r.status == itch50::RecordStatus::Message) ++s.records;
    else if (r.status == itch50::RecordStatus::EndOfSession) ++s.end_of_session;
    else {
      s.truncated = r.status == itch50::RecordStatus::Truncated;
      return s;
    }
  }
}

}  // namespace lle::replay
