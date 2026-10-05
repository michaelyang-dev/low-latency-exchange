#pragma once
// L2Storage: the memory behind the L2 broadcast ring (06 §5).
//
//   - Production (Linux): a file on a dedicated hugetlbfs mount (/mnt/lle-huge, 2 MiB
//     or 1 GiB pages, checked by verify_env.sh), named per (node, day, epoch), so the
//     ring survives a process crash. Default tmpfs /dev/shm gives no huge pages, and a
//     regular-file mmap is not used in production (fdatasync write-protects mapped
//     pages, so later appends fault: R6 D4.1, experiment J1).
//   - macOS / tests: anonymous memory, or a regular file (restart tests).
//
// Layout: a control block of `control_bytes` (>= 4 KiB; the huge-page size on
// hugetlbfs so the file stays page-aligned), then `capacity` data bytes.
// Control block (little-endian):
//    0 char[8] "LLEL2RN1"   8 u32 version (1)   12 u32 node   16 u32 day   20 u32 epoch
//   24 u64 capacity   32 u64 nonce   40 u64 control_bytes   ... zeros   4092 u32 crc32c([0, 4092))
// A file whose control block is valid and matches (node, day, epoch, capacity) is
// reopened as is (restart: L2Ring::restore); anything else is reinitialized with a
// fresh nonce, so stale records from an older ring never validate.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>

#include "env/concepts.h"

namespace lle::journal {

struct L2StorageOptions {
  std::string path;                    // empty: anonymous memory
  std::size_t capacity = std::size_t{1} << 30;  // power of two
  std::size_t control_bytes = 4096;    // >= 4096; set to the huge-page size on hugetlbfs
  std::uint32_t node = 0;
  std::uint32_t day = 0;
  std::uint32_t epoch = 0;
  bool prefault = true;                // touch every page now, not on the append path
};

class L2Storage {
 public:
  L2Storage() noexcept = default;
  ~L2Storage();
  L2Storage(L2Storage&& o) noexcept;
  L2Storage& operator=(L2Storage&& o) noexcept;
  L2Storage(const L2Storage&) = delete;
  L2Storage& operator=(const L2Storage&) = delete;

  // `rng` draws the nonce, only when a new ring must be initialized.
  template <env::RngLike Rng>
  static std::expected<L2Storage, std::string> open(const L2StorageOptions& opts, Rng& rng) {
    return open_with(opts, [](void* ctx) { return static_cast<Rng*>(ctx)->next_u64(); }, &rng);
  }

  [[nodiscard]] std::byte* data() const noexcept { return data_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] std::uint64_t nonce() const noexcept { return nonce_; }
  // True if an existing ring with a valid control block was reopened (restart).
  [[nodiscard]] bool reopened() const noexcept { return reopened_; }

 private:
  static std::expected<L2Storage, std::string> open_with(const L2StorageOptions& opts, std::uint64_t (*gen)(void*),
                                                         void* ctx);
  void release() noexcept;

  void* map_ = nullptr;
  std::size_t map_bytes_ = 0;
  int fd_ = -1;
  std::byte* data_ = nullptr;
  std::size_t capacity_ = 0;
  std::uint64_t nonce_ = 0;
  bool reopened_ = false;
};

}  // namespace lle::journal
