#pragma once
// AF_XDP UMEM (07 §2.3): one packet-buffer area registered with the kernel, shared by
// every socket of a thread (XDP_SHARED_UMEM; across devices since 5.10, so the A- and
// B-line sockets share one area and one thread arbitrates them without copies).
//
// - 2 MiB hugepages when available (MAP_HUGETLB), else normal pages.
// - 4,096-byte chunks (aligned mode).
// - tx_metadata_len = 24 (sizeof(struct xsk_tx_metadata)) with XDP_UMEM_TX_METADATA_LEN
//   (6.11); retried without the flag (6.8-6.10 semantics) and then without TX metadata
//   on EINVAL (older kernels).
// - A LIFO frame allocator hands out chunk addresses; nothing allocates after create().
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <vector>

namespace lle::net::xsk {

struct Error {
  int err = 0;              // errno
  const char* what = "";    // the failing step
};

struct UmemConfig {
  std::uint32_t frame_count = 4096;
  std::uint32_t frame_size = 4096;
  std::uint32_t tx_metadata_len = 24;  // 0 disables TX metadata
  bool hugepages = true;               // try MAP_HUGETLB first
};

enum class TxMetadataSupport : std::uint8_t {
  None,          // registered without TX metadata
  WithoutFlag,   // 6.8-6.10: tx_metadata_len honoured without XDP_UMEM_TX_METADATA_LEN
  WithFlag,      // 6.11+: XDP_UMEM_TX_METADATA_LEN
};

class Umem {
 public:
  // Creates the area, an AF_XDP socket that owns the registration, and registers it.
  static std::expected<std::unique_ptr<Umem>, Error> create(const UmemConfig& cfg);
  ~Umem();
  Umem(const Umem&) = delete;
  Umem& operator=(const Umem&) = delete;

  [[nodiscard]] int fd() const noexcept { return fd_; }
  [[nodiscard]] std::byte* base() const noexcept { return base_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::uint32_t frame_size() const noexcept { return cfg_.frame_size; }
  [[nodiscard]] std::uint32_t frame_count() const noexcept { return cfg_.frame_count; }
  [[nodiscard]] bool hugepages() const noexcept { return huge_; }
  [[nodiscard]] std::uint32_t tx_metadata_len() const noexcept { return tx_meta_len_; }
  [[nodiscard]] TxMetadataSupport tx_metadata_support() const noexcept { return tx_meta_; }

  // Frame allocator (chunk base addresses, offsets into the area).
  bool alloc(std::uint64_t* addr) noexcept {
    if (free_count_ == 0) return false;
    *addr = free_[--free_count_];
    return true;
  }
  void release(std::uint64_t addr) noexcept { free_[free_count_++] = chunk_of(addr); }
  [[nodiscard]] std::size_t free_frames() const noexcept { return free_count_; }
  [[nodiscard]] std::uint64_t chunk_of(std::uint64_t addr) const noexcept { return addr & ~std::uint64_t{cfg_.frame_size - 1}; }

  // The first socket bound with this UMEM uses its fd (and the FILL/COMP rings set on it).
  bool claim_owner_fd() noexcept {
    const bool first = !owner_claimed_;
    owner_claimed_ = true;
    return first;
  }

 private:
  Umem() = default;
  UmemConfig cfg_{};
  int fd_ = -1;
  std::byte* base_ = nullptr;
  std::size_t size_ = 0;
  bool huge_ = false;
  bool owner_claimed_ = false;
  std::uint32_t tx_meta_len_ = 0;
  TxMetadataSupport tx_meta_ = TxMetadataSupport::None;
  std::vector<std::uint64_t> free_;
  std::size_t free_count_ = 0;
};

}  // namespace lle::net::xsk
