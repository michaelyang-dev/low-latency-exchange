#include "net/xsk/umem.h"

#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>

#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef XDP_UMEM_TX_METADATA_LEN
#define XDP_UMEM_TX_METADATA_LEN (1 << 2)
#endif

namespace lle::net::xsk {
namespace {

constexpr std::size_t kHugePage = 2u << 20;

// struct xdp_umem_reg up to and including tx_metadata_len (6.8+); older kernels accept
// the shorter prefix (optlen without the last field).
struct UmemReg {
  std::uint64_t addr;
  std::uint64_t len;
  std::uint32_t chunk_size;
  std::uint32_t headroom;
  std::uint32_t flags;
  std::uint32_t tx_metadata_len;
};
static_assert(sizeof(UmemReg) == 32);

}  // namespace

std::expected<std::unique_ptr<Umem>, Error> Umem::create(const UmemConfig& cfg) {
  if (cfg.frame_size < 2048 || (cfg.frame_size & (cfg.frame_size - 1)) != 0 || cfg.frame_count == 0) {
    return std::unexpected(Error{EINVAL, "umem config"});
  }
  std::unique_ptr<Umem> u(new Umem());
  u->cfg_ = cfg;
  const std::size_t want = std::size_t{cfg.frame_count} * cfg.frame_size;
  void* p = MAP_FAILED;
  if (cfg.hugepages) {
    const std::size_t len = (want + kHugePage - 1) & ~(kHugePage - 1);
    p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, -1, 0);
    if (p != MAP_FAILED) {
      u->size_ = len;
      u->huge_ = true;
    }
  }
  if (p == MAP_FAILED) {
    p = ::mmap(nullptr, want, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p == MAP_FAILED) return std::unexpected(Error{errno, "mmap umem"});
    u->size_ = want;
  }
  u->base_ = static_cast<std::byte*>(p);
  u->fd_ = ::socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
  if (u->fd_ < 0) return std::unexpected(Error{errno, "socket(AF_XDP)"});

  UmemReg reg{};
  reg.addr = reinterpret_cast<std::uintptr_t>(u->base_);
  reg.len = want;
  reg.chunk_size = cfg.frame_size;
  reg.headroom = 0;
  int rc = -1;
  if (cfg.tx_metadata_len != 0) {
    reg.flags = XDP_UMEM_TX_METADATA_LEN;
    reg.tx_metadata_len = cfg.tx_metadata_len;
    rc = ::setsockopt(u->fd_, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg));
    if (rc == 0) {
      u->tx_meta_ = TxMetadataSupport::WithFlag;
    } else if (errno == EINVAL) {
      reg.flags = 0;  // 6.8-6.10: the length alone requests TX metadata
      rc = ::setsockopt(u->fd_, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg));
      if (rc == 0) u->tx_meta_ = TxMetadataSupport::WithoutFlag;
    }
  }
  if (rc != 0) {
    reg.flags = 0;
    reg.tx_metadata_len = 0;
    rc = ::setsockopt(u->fd_, SOL_XDP, XDP_UMEM_REG, &reg, offsetof(UmemReg, tx_metadata_len));
    if (rc != 0) return std::unexpected(Error{errno, "XDP_UMEM_REG"});
    u->tx_meta_ = TxMetadataSupport::None;
  }
  u->tx_meta_len_ = u->tx_meta_ == TxMetadataSupport::None ? 0 : cfg.tx_metadata_len;
  u->free_.resize(cfg.frame_count);
  for (std::uint32_t i = 0; i < cfg.frame_count; ++i) {
    u->free_[i] = std::uint64_t{cfg.frame_count - 1 - i} * cfg.frame_size;
  }
  u->free_count_ = cfg.frame_count;
  return u;
}

Umem::~Umem() {
  if (fd_ >= 0) ::close(fd_);
  if (base_ != nullptr) ::munmap(base_, size_);
}

}  // namespace lle::net::xsk
