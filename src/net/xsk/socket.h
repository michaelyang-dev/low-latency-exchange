#pragma once
// AF_XDP socket (07 §2.3): RX/TX rings, its (netdev, queue) FILL/COMPLETION rings,
// bind with XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP, shared UMEM, need-wakeup kicks, socket
// busy polling, XDP_STATISTICS, RX metadata from data_meta and TX-metadata timestamps.
// TX timestamps reach the caller through a completion handler invoked from every reap
// path (set_tx_completion_handler), with a per-frame cookie.
//
// Zero-copy is enforced: create() fails unless getsockopt(XDP_OPTIONS) reports
// XDP_OPTIONS_ZEROCOPY. Only the explicit dev/test override (BindMode::AllowCopy /
// ForceCopy) accepts copy mode, as on veth and virtio in the VM and CI. Timestamps are
// reported as hardware timestamps only from a zero-copy socket; copy-mode values (veth
// returns skb software timestamps) are counted, never surfaced as hw_rx_ns (07 §2.5).
#include <linux/if_xdp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "common/types.h"
#include "net/xsk/ring.h"
#include "net/xsk/umem.h"

namespace lle::net::xsk {

enum class BindMode : std::uint8_t {
  ZeroCopyRequired,  // production: XDP_ZEROCOPY, refuse to start otherwise
  AllowCopy,         // dev/test override: zero-copy if the driver can, else copy
  ForceCopy,         // dev/test override: XDP_COPY
};

struct XskConfig {
  std::string ifname;
  std::uint32_t queue = 0;
  std::uint32_t rx_size = 2048;
  std::uint32_t tx_size = 2048;
  std::uint32_t fill_size = 4096;
  std::uint32_t comp_size = 4096;
  std::uint32_t fill_frames = 2048;  // frames placed on FILL at start
  BindMode mode = BindMode::ZeroCopyRequired;
  bool need_wakeup = true;
  // Socket busy polling (needs CAP_NET_ADMIN for prefer/budget).
  bool busy_poll = false;
  int busy_poll_usecs = 50;
  int busy_poll_budget = 64;
  // The XDP program writes struct RxMeta in front of each redirected frame.
  bool rx_metadata = false;
  // poll_rx() also reaps TX completions (for callers that only poll RX between sends);
  // completions are reported to the handler either way.
  bool reap_on_rx_poll = false;
};

// 16-byte data_meta written by bpf/md_steer.bpf.c in front of every redirected frame.
struct RxMetaWire {
  std::uint64_t rx_hw_ns;
  std::uint32_t valid;  // 1: rx_hw_ns from bpf_xdp_metadata_rx_timestamp()
  std::uint32_t magic;  // kRxMetaMagic: metadata present
};
static_assert(sizeof(RxMetaWire) == 16);
inline constexpr std::uint32_t kRxMetaMagic = 0x4C4C4D44;  // "LLMD"

struct RxMeta {
  Nanos hw_rx_ns = 0;        // hardware RX timestamp; 0 unless zero-copy and valid
  bool meta_present = false;
};

struct TxOptions {
  bool timestamp = false;      // XDP_TXMD_FLAGS_TIMESTAMP
  bool checksum = false;       // XDP_TXMD_FLAGS_CHECKSUM (L4; field pre-seeded with the pseudo-header sum)
  std::uint16_t csum_start = 0;
  std::uint16_t csum_offset = 0;
  // Completion reporting (set_tx_completion_handler): every frame that requests a
  // timestamp, and every frame with `notify`, is reported once with this cookie when
  // its completion is reaped, whichever call reaps it.
  std::uint64_t cookie = 0;
  bool notify = false;
};

// One reported TX completion (see XskSocket::set_tx_completion_handler).
struct TxCompletion {
  std::uint64_t cookie = 0;  // TxOptions::cookie of the frame
  Nanos hw_tx_ns = 0;        // NIC TX timestamp; 0 unless `valid`
  // A hardware timestamp: zero-copy socket, timestamp requested, value written by the
  // driver (mlx5: CQE time). Never true in copy mode, whose values are only counted
  // (XskStats::tx_ts_copy_mode), 07 §2.5.
  bool valid = false;
  bool ts_requested = false;  // the frame carried XDP_TXMD_FLAGS_TIMESTAMP
};

// Completion handler: a plain function pointer plus context (no allocation, no virtual
// dispatch). Called synchronously from inside reap(), on the polling thread.
using TxCompletionFn = void (*)(void* ctx, const TxCompletion& c) noexcept;

struct XskStats {
  // XDP_STATISTICS
  std::uint64_t rx_dropped = 0;
  std::uint64_t rx_invalid_descs = 0;
  std::uint64_t tx_invalid_descs = 0;
  std::uint64_t rx_ring_full = 0;
  std::uint64_t rx_fill_ring_empty_descs = 0;
  std::uint64_t tx_ring_empty_descs = 0;
  // ours
  std::uint64_t rx_frames = 0;
  std::uint64_t tx_frames = 0;
  std::uint64_t tx_completions = 0;
  std::uint64_t tx_no_frame = 0;      // no free UMEM frame for TX
  std::uint64_t tx_ring_full = 0;
  std::uint64_t rx_kicks = 0;
  std::uint64_t tx_kicks = 0;
  std::uint64_t rx_meta_ts_valid = 0;     // metadata with a valid timestamp (any mode)
  std::uint64_t rx_meta_ts_copy_mode = 0; // ...of which in copy mode: never reported as HW
  std::uint64_t tx_ts_completions = 0;    // completions of frames that requested a TX timestamp
  std::uint64_t tx_ts_valid = 0;          // ...with a hardware timestamp (zero-copy only)
  std::uint64_t tx_ts_copy_mode = 0;      // ...in copy mode with a nonzero value: never reported
  std::uint64_t tx_completions_reported = 0;  // handler invocations
  std::uint64_t stash_dropped = 0;
  [[nodiscard]] std::uint64_t drops() const noexcept {
    return rx_dropped + rx_invalid_descs + tx_invalid_descs + rx_ring_full;
  }
};

class XskSocket {
 public:
  static std::expected<std::unique_ptr<XskSocket>, Error> create(Umem& umem, const XskConfig& cfg);
  ~XskSocket();
  XskSocket(const XskSocket&) = delete;
  XskSocket& operator=(const XskSocket&) = delete;

  [[nodiscard]] int fd() const noexcept { return fd_; }
  [[nodiscard]] bool zero_copy() const noexcept { return zero_copy_; }
  [[nodiscard]] int ifindex() const noexcept { return ifindex_; }
  [[nodiscard]] std::uint32_t queue() const noexcept { return cfg_.queue; }
  [[nodiscard]] bool busy_poll_enabled() const noexcept { return busy_poll_ok_; }
  [[nodiscard]] Umem& umem() noexcept { return umem_; }

  // ---- RX --------------------------------------------------------------------
  // Two consumers can share one socket (e.g. the UDP feed and the utcp flow on one NIC
  // queue): cb(frame, meta) returns true when it handled the frame, false when the
  // frame belongs to the other consumer, which receives it from a stash on its next
  // poll. Frames go back to FILL after the callback.
  template <class Cb>
  std::size_t poll_rx(int consumer, Cb&& cb, std::uint32_t budget = 64);

  // ---- TX --------------------------------------------------------------------
  // A writable frame buffer from the UMEM (empty when none is free), then tx_commit()
  // with the frame length (0 returns the buffer).
  std::span<std::byte> tx_acquire() noexcept;
  bool tx_commit(std::size_t len, const TxOptions& opt = {}) noexcept;
  // Kicks the kernel for TX when needed and reaps completions.
  void flush() noexcept;
  // Reaps completions. Every reap path (this call, flush(), tx_acquire()'s and
  // tx_commit()'s internal reaps, poll_rx() with reap_on_rx_poll) goes through here, so
  // the completion handler sees every reported frame exactly once, in TX-ring order.
  // cb(tx_hw_ns) is additionally called for frames that requested a timestamp (0 unless
  // a hardware timestamp). Returns frames reaped.
  template <class Cb>
  std::size_t reap(Cb&& cb);
  std::size_t reap() {
    return reap([](Nanos) {});
  }
  // Registers the completion handler (nullptr removes it). Frames committed with
  // TxOptions::timestamp or ::notify are reported with their cookie.
  void set_tx_completion_handler(TxCompletionFn fn, void* ctx) noexcept {
    on_tx_done_ = fn;
    on_tx_ctx_ = ctx;
  }
  // Frames committed whose completion has not been reaped yet.
  [[nodiscard]] std::uint32_t tx_outstanding() const noexcept { return tx_outstanding_; }

  // XDP_STATISTICS merged with our counters.
  XskStats stats() const noexcept;
  [[nodiscard]] std::uint32_t frames_on_fill() const noexcept { return on_fill_; }

 private:
  XskSocket(Umem& u, const XskConfig& c) : umem_(u), cfg_(c) {}
  std::expected<void, Error> setup(bool owner);
  void refill() noexcept;
  void kick_rx() noexcept;
  RxMeta read_meta(std::uint64_t addr) noexcept;
  void recycle(std::uint64_t addr) noexcept;

  Umem& umem_;
  XskConfig cfg_;
  int fd_ = -1;
  bool owns_fd_ = false;
  int ifindex_ = 0;
  bool zero_copy_ = false;
  bool busy_poll_ok_ = false;
  RxRing rx_;
  TxRing tx_;
  FillRing fill_;
  CompRing comp_;
  RingMap maps_[4]{};
  std::uint32_t on_fill_ = 0;     // frames owned by the kernel via FILL / RX
  std::uint32_t tx_outstanding_ = 0;
  // Per-chunk TX bookkeeping, sized at create() (frame_count entries): the cookie and
  // reporting flags of the frame in flight in that chunk.
  struct TxSlot {
    std::uint64_t cookie = 0;
    std::uint8_t flags = 0;
  };
  static constexpr std::uint8_t kSlotTs = 1;
  static constexpr std::uint8_t kSlotNotify = 2;
  std::vector<TxSlot> tx_slots_;
  TxCompletionFn on_tx_done_ = nullptr;
  void* on_tx_ctx_ = nullptr;
  std::uint64_t pending_tx_ = ~0ull;
  bool tx_dirty_ = false;
  // Frames stashed for the other consumer: {addr, len}.
  struct Stashed {
    std::uint64_t addr;
    std::uint32_t len;
  };
  std::array<std::array<Stashed, 512>, 2> stash_{};
  std::array<std::size_t, 2> stash_head_{};
  std::array<std::size_t, 2> stash_count_{};
  mutable XskStats st_{};
};

// ---- inline templates ---------------------------------------------------------

template <class Cb>
std::size_t XskSocket::poll_rx(int consumer, Cb&& cb, std::uint32_t budget) {
  std::size_t handled = 0;
  const auto me = static_cast<std::size_t>(consumer & 1);
  // Frames the other consumer stashed for us.
  while (stash_count_[me] != 0 && handled < budget) {
    const Stashed s = stash_[me][stash_head_[me]];
    stash_head_[me] = (stash_head_[me] + 1) % stash_[me].size();
    --stash_count_[me];
    const RxMeta meta = read_meta(s.addr);
    (void)cb(std::span<const std::byte>(umem_.base() + s.addr, s.len), meta);
    recycle(s.addr);
    ++handled;
  }
  std::uint32_t idx = 0;
  const std::uint32_t n = rx_.peek(budget, &idx);
  for (std::uint32_t i = 0; i < n; ++i) {
    const xdp_desc d = rx_.at(idx + i);
    --on_fill_;
    ++st_.rx_frames;
    const RxMeta meta = read_meta(d.addr);
    if (cb(std::span<const std::byte>(umem_.base() + d.addr, d.len), meta)) {
      recycle(d.addr);
      ++handled;
      continue;
    }
    const std::size_t other = 1 - me;
    if (stash_count_[other] == stash_[other].size()) {
      ++st_.stash_dropped;
      recycle(d.addr);
      continue;
    }
    stash_[other][(stash_head_[other] + stash_count_[other]) % stash_[other].size()] = Stashed{d.addr, d.len};
    ++stash_count_[other];
  }
  if (n != 0) rx_.release(n);
  refill();
  if (n == 0 && (fill_.needs_wakeup() || busy_poll_ok_)) kick_rx();
  if (cfg_.reap_on_rx_poll && tx_outstanding_ != 0) (void)reap();
  return handled;
}

template <class Cb>
std::size_t XskSocket::reap(Cb&& cb) {
  std::uint32_t idx = 0;
  const std::uint32_t n = comp_.peek(comp_.size(), &idx);
  const std::uint32_t ml = umem_.tx_metadata_len();
  for (std::uint32_t i = 0; i < n; ++i) {
    const std::uint64_t addr = comp_.at(idx + i);
    const std::uint64_t chunk = umem_.chunk_of(addr);
    const std::size_t slot = static_cast<std::size_t>(chunk / umem_.frame_size());
    TxSlot ts{};
    if (slot < tx_slots_.size()) {
      ts = tx_slots_[slot];
      tx_slots_[slot] = TxSlot{};
    }
    if ((ts.flags & (kSlotTs | kSlotNotify)) != 0) {
      TxCompletion c;
      c.cookie = ts.cookie;
      if ((ts.flags & kSlotTs) != 0 && ml != 0) {
        c.ts_requested = true;
        ++st_.tx_ts_completions;
        xsk_tx_metadata md;
        std::memcpy(&md, umem_.base() + addr - ml, sizeof(md));
        const auto raw = static_cast<Nanos>(md.completion.tx_timestamp);
        if (zero_copy_) {
          if (raw != 0) {
            c.valid = true;
            c.hw_tx_ns = raw;
            ++st_.tx_ts_valid;
          }
        } else if (raw != 0) {
          ++st_.tx_ts_copy_mode;  // copy-mode completion time: not a hardware stamp (07 §2.5)
        }
        cb(c.hw_tx_ns);
      }
      if (on_tx_done_ != nullptr) {
        ++st_.tx_completions_reported;
        on_tx_done_(on_tx_ctx_, c);
      }
    }
    umem_.release(addr);
  }
  if (n != 0) {
    comp_.release(n);
    tx_outstanding_ -= n;
    st_.tx_completions += n;
  }
  return n;
}

}  // namespace lle::net::xsk
