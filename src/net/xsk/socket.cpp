#include "net/xsk/socket.h"

#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <time.h>

#include <cerrno>

#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif

namespace lle::net::xsk {
namespace {

std::expected<RingMap, Error> map_ring(int fd, const xdp_ring_offset& off, std::uint32_t size, std::size_t entry,
                                       off_t pgoff, const char* what) {
  RingMap m;
  m.size = size;
  m.mmap_len = off.desc + std::size_t{size} * entry;
  void* p = ::mmap(nullptr, m.mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, pgoff);
  if (p == MAP_FAILED) return std::unexpected(Error{errno, what});
  auto* b = static_cast<std::byte*>(p);
  m.mmap_base = p;
  m.producer = reinterpret_cast<std::uint32_t*>(b + off.producer);
  m.consumer = reinterpret_cast<std::uint32_t*>(b + off.consumer);
  m.flags = reinterpret_cast<std::uint32_t*>(b + off.flags);
  m.desc = b + off.desc;
  return m;
}

bool set_int(int fd, int level, int opt, int v) { return ::setsockopt(fd, level, opt, &v, sizeof(v)) == 0; }

}  // namespace

std::expected<std::unique_ptr<XskSocket>, Error> XskSocket::create(Umem& umem, const XskConfig& cfg) {
  std::unique_ptr<XskSocket> s(new XskSocket(umem, cfg));
  s->tx_slots_.resize(umem.frame_count());  // startup: no allocation on the data path
  s->ifindex_ = static_cast<int>(::if_nametoindex(cfg.ifname.c_str()));
  if (s->ifindex_ == 0) return std::unexpected(Error{errno != 0 ? errno : ENODEV, "if_nametoindex"});
  auto r = s->setup(umem.claim_owner_fd());
  if (!r) return std::unexpected(r.error());
  return s;
}

std::expected<void, Error> XskSocket::setup(bool owner) {
  if (owner) {
    fd_ = umem_.fd();
  } else {
    fd_ = ::socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (fd_ < 0) return std::unexpected(Error{errno, "socket(AF_XDP)"});
    owns_fd_ = true;
  }
  // Every (netdev, queue) needs its own FILL/COMPLETION pair, also with a shared UMEM.
  if (!set_int(fd_, SOL_XDP, XDP_UMEM_FILL_RING, static_cast<int>(cfg_.fill_size))) {
    return std::unexpected(Error{errno, "XDP_UMEM_FILL_RING"});
  }
  if (!set_int(fd_, SOL_XDP, XDP_UMEM_COMPLETION_RING, static_cast<int>(cfg_.comp_size))) {
    return std::unexpected(Error{errno, "XDP_UMEM_COMPLETION_RING"});
  }
  if (!set_int(fd_, SOL_XDP, XDP_RX_RING, static_cast<int>(cfg_.rx_size))) return std::unexpected(Error{errno, "XDP_RX_RING"});
  if (!set_int(fd_, SOL_XDP, XDP_TX_RING, static_cast<int>(cfg_.tx_size))) return std::unexpected(Error{errno, "XDP_TX_RING"});
  xdp_mmap_offsets off{};
  socklen_t optlen = sizeof(off);
  if (::getsockopt(fd_, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) != 0) {
    return std::unexpected(Error{errno, "XDP_MMAP_OFFSETS"});
  }
  auto rx = map_ring(fd_, off.rx, cfg_.rx_size, sizeof(xdp_desc), XDP_PGOFF_RX_RING, "mmap rx");
  if (!rx) return std::unexpected(rx.error());
  maps_[0] = *rx;
  auto tx = map_ring(fd_, off.tx, cfg_.tx_size, sizeof(xdp_desc), XDP_PGOFF_TX_RING, "mmap tx");
  if (!tx) return std::unexpected(tx.error());
  maps_[1] = *tx;
  auto fr = map_ring(fd_, off.fr, cfg_.fill_size, sizeof(std::uint64_t), static_cast<off_t>(XDP_UMEM_PGOFF_FILL_RING), "mmap fill");
  if (!fr) return std::unexpected(fr.error());
  maps_[2] = *fr;
  auto cr = map_ring(fd_, off.cr, cfg_.comp_size, sizeof(std::uint64_t), static_cast<off_t>(XDP_UMEM_PGOFF_COMPLETION_RING),
                     "mmap completion");
  if (!cr) return std::unexpected(cr.error());
  maps_[3] = *cr;
  rx_ = RxRing(maps_[0]);
  tx_ = TxRing(maps_[1]);
  fill_ = FillRing(maps_[2]);
  comp_ = CompRing(maps_[3]);

  // Stock FILL before bind so the first packets have buffers.
  refill();

  sockaddr_xdp sxdp{};
  sxdp.sxdp_family = AF_XDP;
  sxdp.sxdp_ifindex = static_cast<std::uint32_t>(ifindex_);
  sxdp.sxdp_queue_id = cfg_.queue;
  const std::uint16_t base = cfg_.need_wakeup ? XDP_USE_NEED_WAKEUP : 0;
  auto try_bind = [&](std::uint16_t flags) {
    sxdp.sxdp_flags = flags;
    // EBUSY: a previous socket on this (netdev, queue) is still being released (the
    // kernel frees its pool after an RCU grace period). Startup path: retry briefly.
    for (int attempt = 0; attempt < 50; ++attempt) {
      if (::bind(fd_, reinterpret_cast<const sockaddr*>(&sxdp), sizeof(sxdp)) == 0) return true;
      if (errno != EBUSY) return false;
      const timespec ts{0, 2'000'000};
      ::nanosleep(&ts, nullptr);
    }
    return false;
  };
  bool bound = false;
  if (!owner) {
    // A shared-UMEM socket inherits copy/zero-copy and need-wakeup from the UMEM owner;
    // the kernel rejects those flags here (xsk_bind: "Cannot specify flags for shared
    // sockets"). The zero-copy check below still applies.
    sxdp.sxdp_shared_umem_fd = static_cast<std::uint32_t>(umem_.fd());
    bound = try_bind(XDP_SHARED_UMEM);
  } else {
    switch (cfg_.mode) {
      case BindMode::ZeroCopyRequired: bound = try_bind(base | XDP_ZEROCOPY); break;
      case BindMode::AllowCopy: bound = try_bind(base | XDP_ZEROCOPY) || try_bind(base | XDP_COPY); break;
      case BindMode::ForceCopy: bound = try_bind(base | XDP_COPY); break;
    }
  }
  if (!bound) return std::unexpected(Error{errno, cfg_.mode == BindMode::ZeroCopyRequired ? "bind(XDP_ZEROCOPY)" : "bind"});

  xdp_options opts{};
  optlen = sizeof(opts);
  if (::getsockopt(fd_, SOL_XDP, XDP_OPTIONS, &opts, &optlen) != 0) return std::unexpected(Error{errno, "XDP_OPTIONS"});
  zero_copy_ = (opts.flags & XDP_OPTIONS_ZEROCOPY) != 0;
  // 07 §2.3: refuse to start unless the kernel reports zero-copy.
  if (cfg_.mode == BindMode::ZeroCopyRequired && !zero_copy_) {
    return std::unexpected(Error{EOPNOTSUPP, "XDP_OPTIONS_ZEROCOPY not set"});
  }

  if (cfg_.busy_poll) {
    busy_poll_ok_ = set_int(fd_, SOL_SOCKET, SO_PREFER_BUSY_POLL, 1) &&
                    set_int(fd_, SOL_SOCKET, SO_BUSY_POLL, cfg_.busy_poll_usecs) &&
                    set_int(fd_, SOL_SOCKET, SO_BUSY_POLL_BUDGET, cfg_.busy_poll_budget);
    if (!busy_poll_ok_) return std::unexpected(Error{errno, "busy-poll socket options"});
  }
  return {};
}

XskSocket::~XskSocket() {
  for (auto& m : maps_) {
    if (m.mmap_base != nullptr) ::munmap(m.mmap_base, m.mmap_len);
  }
  if (owns_fd_ && fd_ >= 0) ::close(fd_);
}

void XskSocket::refill() noexcept {
  if (!fill_.valid() || on_fill_ >= cfg_.fill_frames) return;
  std::uint32_t want = cfg_.fill_frames - on_fill_;
  if (want > umem_.free_frames()) want = static_cast<std::uint32_t>(umem_.free_frames());
  if (want == 0) return;
  std::uint32_t idx = 0;
  const std::uint32_t got = fill_.reserve(want, &idx);
  for (std::uint32_t i = 0; i < got; ++i) {
    std::uint64_t addr = 0;
    (void)umem_.alloc(&addr);
    fill_.at(idx + i) = addr;
  }
  if (got != 0) {
    fill_.submit();
    on_fill_ += got;
  }
}

void XskSocket::kick_rx() noexcept {
  ++st_.rx_kicks;
  (void)::recvfrom(fd_, nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
}

void XskSocket::recycle(std::uint64_t addr) noexcept { umem_.release(addr); }

RxMeta XskSocket::read_meta(std::uint64_t addr) noexcept {
  RxMeta m;
  if (!cfg_.rx_metadata || addr - umem_.chunk_of(addr) < sizeof(RxMetaWire)) return m;
  std::byte* p = umem_.base() + addr - sizeof(RxMetaWire);
  RxMetaWire w;
  std::memcpy(&w, p, sizeof(w));
  if (w.magic != kRxMetaMagic) return m;
  m.meta_present = true;
  const std::uint32_t zero = 0;
  std::memcpy(p + offsetof(RxMetaWire, magic), &zero, sizeof(zero));  // the chunk is reused
  if (w.valid != 0) {
    ++st_.rx_meta_ts_valid;
    if (zero_copy_) {
      m.hw_rx_ns = static_cast<Nanos>(w.rx_hw_ns);
    } else {
      ++st_.rx_meta_ts_copy_mode;  // veth/copy mode: an skb software stamp, not hardware
    }
  }
  return m;
}

std::span<std::byte> XskSocket::tx_acquire() noexcept {
  if (pending_tx_ == ~0ull) {
    std::uint64_t addr = 0;
    if (!umem_.alloc(&addr)) {
      (void)reap();
      if (!umem_.alloc(&addr)) {
        ++st_.tx_no_frame;
        return {};
      }
    }
    pending_tx_ = addr;
  }
  const std::uint32_t ml = umem_.tx_metadata_len();
  return {umem_.base() + pending_tx_ + ml, umem_.frame_size() - ml};
}

bool XskSocket::tx_commit(std::size_t len, const TxOptions& opt) noexcept {
  if (pending_tx_ == ~0ull) return false;
  const std::uint64_t addr = pending_tx_;
  pending_tx_ = ~0ull;
  if (len == 0) {
    umem_.release(addr);
    return true;
  }
  std::uint32_t idx = 0;
  if (tx_.reserve(1, &idx) != 1) {
    flush();
    if (tx_.reserve(1, &idx) != 1) {
      ++st_.tx_ring_full;
      umem_.release(addr);
      return false;
    }
  }
  const std::uint32_t ml = umem_.tx_metadata_len();
  xdp_desc d{};
  d.addr = addr + ml;
  d.len = static_cast<std::uint32_t>(len);
  if (ml != 0) {
    xsk_tx_metadata md{};
    if (opt.timestamp) md.flags |= XDP_TXMD_FLAGS_TIMESTAMP;
    if (opt.checksum) {
      md.flags |= XDP_TXMD_FLAGS_CHECKSUM;
      md.request.csum_start = opt.csum_start;
      md.request.csum_offset = opt.csum_offset;
    }
    std::memcpy(umem_.base() + addr, &md, sizeof(md));  // always written: chunks are reused
    if (md.flags != 0) d.options |= XDP_TX_METADATA;
  }
  const auto slot = static_cast<std::size_t>(addr / umem_.frame_size());
  if (slot < tx_slots_.size()) {
    std::uint8_t f = 0;
    if (opt.timestamp && ml != 0) f |= kSlotTs;
    if (opt.notify) f |= kSlotNotify;
    tx_slots_[slot] = TxSlot{opt.cookie, f};
  }
  tx_.at(idx) = d;
  tx_.submit();
  ++tx_outstanding_;
  ++st_.tx_frames;
  tx_dirty_ = true;
  return true;
}

void XskSocket::flush() noexcept {
  // Kick while descriptors remain on the TX ring, not only after new commits: in copy
  // mode one sendto() transmits at most one kernel batch (32 descriptors), and the rest
  // would otherwise wait for the next commit.
  if (tx_dirty_ || (tx_outstanding_ != 0 && tx_.pending() != 0)) {
    tx_dirty_ = false;
    if (!cfg_.need_wakeup || tx_.needs_wakeup() || busy_poll_ok_) {
      ++st_.tx_kicks;
      // EAGAIN/EBUSY/ENOBUFS: the kernel will pick the descriptors up on the next kick.
      (void)::sendto(fd_, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
    }
  }
  (void)reap();
}

XskStats XskSocket::stats() const noexcept {
  XskStats s = st_;
  xdp_statistics x{};
  socklen_t len = sizeof(x);
  if (::getsockopt(fd_, SOL_XDP, XDP_STATISTICS, &x, &len) == 0) {
    s.rx_dropped = x.rx_dropped;
    s.rx_invalid_descs = x.rx_invalid_descs;
    s.tx_invalid_descs = x.tx_invalid_descs;
    s.rx_ring_full = x.rx_ring_full;
    s.rx_fill_ring_empty_descs = x.rx_fill_ring_empty_descs;
    s.tx_ring_empty_descs = x.tx_ring_empty_descs;
  }
  return s;
}

}  // namespace lle::net::xsk
