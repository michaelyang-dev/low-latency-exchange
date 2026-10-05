#pragma once
// Fault atlas (09 §3; TigerBeetle ClusterFaultAtlas).
//
// Misdirected writes and bit flips are only injected inside "faulty areas".
// Every file is divided into fixed-size areas; for a logical file replicated on
// N disks, the atlas marks each (file, area) faulty on a seeded subset of the
// replicas but never on all of them, so at least one valid copy of committed
// data always survives. Single-copy data (N <= 1) is never faulty. The atlas is
// stateless: a pure hash of (seed, file key, area, replica).
#include <cstdint>

#include "common/hash.h"

namespace lle::sim {

class FaultAtlas {
 public:
  static constexpr std::uint64_t kDefaultAreaBytes = 64 * 1024;

  FaultAtlas(std::uint64_t seed, std::uint32_t faulty_ppm, std::uint64_t area_bytes = kDefaultAreaBytes) noexcept
      : seed_(seed), faulty_ppm_(faulty_ppm), area_bytes_(area_bytes == 0 ? kDefaultAreaBytes : area_bytes) {}

  [[nodiscard]] bool faulty(std::uint64_t file_key, std::uint64_t area, std::uint32_t replica,
                            std::uint32_t replicas) const noexcept {
    if (replicas <= 1 || replica >= replicas || faulty_ppm_ == 0) return false;
    bool all = true;
    for (std::uint32_t r = 0; r < replicas; ++r) all = all && raw(file_key, area, r);
    if (all) {
      // Keep one replica clean: the last valid copy is never destroyed.
      const std::uint32_t spare = static_cast<std::uint32_t>(h(file_key, area, 0xFFFF'FFFFu) % replicas);
      if (replica == spare) return false;
    }
    return raw(file_key, area, replica);
  }

  // True if every area touched by [off, off + len) is faulty for the replica.
  [[nodiscard]] bool range_faulty(std::uint64_t file_key, std::uint64_t off, std::uint64_t len, std::uint32_t replica,
                                  std::uint32_t replicas) const noexcept {
    if (len == 0) return false;
    for (std::uint64_t a = off / area_bytes_; a <= (off + len - 1) / area_bytes_; ++a) {
      if (!faulty(file_key, a, replica, replicas)) return false;
    }
    return true;
  }

  [[nodiscard]] std::uint64_t area_bytes() const noexcept { return area_bytes_; }
  [[nodiscard]] std::uint32_t faulty_ppm() const noexcept { return faulty_ppm_; }

  [[nodiscard]] static std::uint64_t file_key(const char* name, std::size_t n) noexcept {
    Fnv1a64 f;
    f.bytes(name, n);
    return f.value();
  }

 private:
  [[nodiscard]] std::uint64_t h(std::uint64_t key, std::uint64_t area, std::uint32_t r) const noexcept {
    return mix64(seed_ ^ mix64(key ^ mix64(area * 0x9E3779B97F4A7C15ull + r)));
  }
  [[nodiscard]] bool raw(std::uint64_t key, std::uint64_t area, std::uint32_t r) const noexcept {
    return h(key, area, r) % 1'000'000 < faulty_ppm_;
  }

  std::uint64_t seed_;
  std::uint32_t faulty_ppm_;
  std::uint64_t area_bytes_;
};

}  // namespace lle::sim
