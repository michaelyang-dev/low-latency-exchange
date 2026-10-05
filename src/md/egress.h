#pragma once
// The egress ring: every engine output on its way to the release-gated egress
// stages (01 §4 steps 4-5, ADR-005).
//
// The engine stage is the single producer. Every output it emits for journal
// record i (ITCH message, OUCH message for a session, or the end-of-day marker)
// becomes one entry tagged with i, in emission order. The consumers each see
// every entry, at their own pace (conc::BroadcastRing):
//
//   kIo    the io stage: appends released messages to the output log (06 §8)
//   kMd    the md stage: MoldUDP64 lines A/B and the re-request store (N-18)
//   kGw0   gateway gw0: OUCH egress for its sessions (N-17)
//   kGw1   gateway gw1
//
// The Output Rule is applied by the consumers: an entry is taken only once its
// index is <= the release watermark (paired: commit_index; solo: durable_index).
// An entry beyond the watermark stays in the ring, so the slowest consumer gates
// the engine, which in turn stops consuming the L2 ring: back-pressure reaches the
// sequencer and finally the gateways' TCP windows. Nothing is dropped.
//
// Entry layout (little-endian), the payload of one ring record:
//    0 u64 index     journal index of the record that caused the output
//    8 u32 session   OUCH destination session id (0 for ITCH and markers)
//   12 u16 len       message bytes
//   14 u8  kind      OutKind
//   15 u8  0
//   16 bytes[len]
//
// Include rules: this header is shared by the engine, io, md and gateway stages;
// it allocates only in init() (startup).
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>

#include "common/assert.h"
#include "common/cache.h"
#include "common/endian.h"
#include "concurrent/broadcast_ring.h"

namespace lle::md {

enum class OutKind : std::uint8_t {
  Itch = 1,    // one ITCH 5.0 message (MoldUDP64 numbering happens at release)
  Ouch = 2,    // one OUCH 5.0 message for `session` (SoupBinTCP numbering at release)
  DayEnd = 3,  // the DayEnd record was applied: end the SoupBinTCP and MoldUDP64 sessions
};

inline constexpr std::size_t kEntryHeader = 16;

// Consumer cursors.
inline constexpr std::size_t kIo = 0;
inline constexpr std::size_t kMd = 1;
inline constexpr std::size_t kGw0 = 2;
inline constexpr std::size_t kGateways = 2;  // gw0, gw1 (01 §7)
inline constexpr std::size_t kConsumers = 2 + kGateways;

struct OutEntry {
  std::uint64_t index = 0;
  std::uint32_t session = 0;
  OutKind kind = OutKind::Itch;
  std::span<const std::byte> msg;
};

[[nodiscard]] inline std::size_t entry_bytes(std::size_t msg_len) noexcept { return kEntryHeader + msg_len; }

inline void encode_entry(std::byte* p, std::uint64_t index, OutKind kind, std::uint32_t session,
                         std::span<const std::byte> msg) noexcept {
  store_le64(p, index);
  store_le32(p + 8, session);
  store_le16(p + 12, static_cast<std::uint16_t>(msg.size()));
  p[14] = static_cast<std::byte>(kind);
  p[15] = std::byte{0};
  if (!msg.empty()) std::memcpy(p + kEntryHeader, msg.data(), msg.size());
}

[[nodiscard]] inline OutEntry decode_entry(const std::byte* p, std::uint32_t n) noexcept {
  OutEntry e;
  e.index = load_le64(p);
  e.session = load_le32(p + 8);
  const std::size_t len = load_le16(p + 12);
  e.kind = static_cast<OutKind>(std::to_integer<std::uint8_t>(p[14]));
  LLE_DASSERT(kEntryHeader + len <= n);
  (void)n;
  e.msg = std::span<const std::byte>(p + kEntryHeader, len);
  return e;
}

// BroadcastRing over owned, 8-byte-aligned storage.
class EgressRing {
 public:
  EgressRing() = default;
  EgressRing(const EgressRing&) = delete;
  EgressRing& operator=(const EgressRing&) = delete;

  // `capacity` must be a power of two >= 64 KiB. Allocates (startup only).
  void init(std::size_t capacity) {
    LLE_ASSERT(capacity >= (std::size_t{1} << 16) && (capacity & (capacity - 1)) == 0, "egress ring capacity");
    mem_.reset(new std::uint64_t[capacity / 8]());
    ring_.init(reinterpret_cast<std::byte*>(mem_.get()), capacity);
    capacity_ = capacity;
  }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] void* storage() const noexcept { return mem_.get(); }

  // ---- producer (the engine stage) ----------------------------------------------
  bool try_push(std::uint64_t index, OutKind kind, std::uint32_t session, std::span<const std::byte> msg) noexcept {
    std::byte* p = ring_.try_reserve(static_cast<std::uint32_t>(entry_bytes(msg.size())));
    if (p == nullptr) return false;
    encode_entry(p, index, kind, session, msg);
    ring_.commit();
    return true;
  }

  // ---- consumer c ----------------------------------------------------------------
  // The next entry for cursor `c` (valid until release(c)); false when there is none.
  bool peek(std::size_t c, OutEntry& out) noexcept {
    std::uint32_t n = 0;
    const std::byte* p = ring_.peek(c, n);
    if (p == nullptr) return false;
    out = decode_entry(p, n);
    return true;
  }
  void release(std::size_t c) noexcept { ring_.release(c); }

  // Bytes published but not yet consumed by cursor `c` (approximate across threads).
  [[nodiscard]] std::uint64_t backlog(std::size_t c) const noexcept {
    return ring_.write_position() - ring_.cursor_position(c);
  }

 private:
  std::unique_ptr<std::uint64_t[]> mem_;
  std::size_t capacity_ = 0;
  conc::BroadcastRing<kConsumers> ring_;
};

// Watermarks shared between stages. Every field has exactly one writer.
struct alignas(kFalseSharingBytes) Watermark {
  std::atomic<std::uint64_t> v{0};
  [[nodiscard]] std::uint64_t load() const noexcept { return v.load(std::memory_order_acquire); }
  void store(std::uint64_t x) noexcept { v.store(x, std::memory_order_release); }
};

struct EgressState {
  Watermark release;   // Output Rule: outputs of records <= release may leave the node
  Watermark applied;   // the engine has applied (and emitted the outputs of) records <= applied
  // Outputs of records above `hold` may still be staged outside the ring: a rejoin's
  // reloaded outputs the engine stage hands on before new records (DST-013). No consumer
  // is done beyond it; the maximum when nothing is staged.
  Watermark hold{~std::uint64_t{0}};
  // done[c]: every output of a record <= done[c] has been handed on by consumer c
  // (written to a socket / packetized / appended to the output log).
  Watermark done[kConsumers];
};

// Drains the released entries of consumer `c`: f(const OutEntry&) for each entry whose
// index is <= `release`, up to `max`, stopping at the first entry beyond the watermark
// (it stays in the ring). Publishes done[c] when the consumer is idle or gated.
// F returns false to stop before releasing that entry (e.g. its output path is full).
template <class F>
std::size_t drain_released(EgressRing& ring, EgressState& st, std::size_t c, std::size_t max, F&& f) {
  // Read before peeking: see done[] above.
  const std::uint64_t applied = std::min(st.applied.load(), st.hold.load());
  const std::uint64_t release = st.release.load();
  std::size_t n = 0;
  OutEntry e;
  while (n < max) {
    if (!ring.peek(c, e)) {
      // Everything the engine emitted up to `applied` is consumed.
      const std::uint64_t d = applied < release ? applied : release;
      if (d > st.done[c].load()) st.done[c].store(d);
      return n;
    }
    if (e.index > release) {
      if (e.index - 1 > st.done[c].load()) st.done[c].store(e.index - 1);
      return n;
    }
    if (!f(e)) return n;
    ring.release(c);
    ++n;
  }
  return n;
}

}  // namespace lle::md
