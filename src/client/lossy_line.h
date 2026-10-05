#pragma once
// Seeded per-line impairments for mold_replay (03-protocols §6 "seeded loss
// injection per line", §9 "Real-feed arbitration").
//
// Each packet a line carries is independently dropped, duplicated, or held back
// by a delay (which reorders it behind later packets). Every packet consumes the
// same four draws from the line's own lle::Prng whatever the outcome, so:
//   - a seed reproduces exactly which packets were impaired;
//   - the loss pattern does not change when the duplication or reorder rates do;
//   - the two lines of a feed use different seeds and are independent.
// A packet that falls in a scripted outage (both lines dark over a sequence range,
// used to force snapshot joins) is dropped after its draws are consumed.
//
// Delayed packets are copied into a fixed pool and released by release(now) once
// due; time comes from the caller (sans-I/O). Nothing allocates after construction.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>

#include "common/assert.h"
#include "common/prng.h"
#include "common/types.h"

namespace lle::client {

inline constexpr std::uint32_t kPpm = 1'000'000;

struct LineImpairment {
  std::uint32_t loss_ppm = 0;     // probability (parts per million) that a packet is dropped
  std::uint32_t dup_ppm = 0;      // ... that a delivered packet is sent twice
  std::uint32_t reorder_ppm = 0;  // ... that a copy is held back by a delay in [1, max_reorder_delay] ns
  Nanos max_reorder_delay = 200'000;
};

struct LineStats {
  std::uint64_t packets = 0;           // offered by the packetizer
  std::uint64_t sent = 0;              // handed to the network, duplicates included
  std::uint64_t dropped = 0;           // by the seeded loss
  std::uint64_t outage_dropped = 0;    // inside a scripted outage
  std::uint64_t duplicated = 0;
  std::uint64_t delayed = 0;
  std::uint64_t pool_full = 0;         // a delay was drawn but no slot was free: sent at once
  std::uint64_t messages_dropped = 0;  // messages carried by dropped data packets (loss + outage)
};

class LossyLine {
 public:
  LossyLine(const LineImpairment& imp, std::uint64_t seed, std::size_t pool_slots = 4096,
            std::size_t max_packet = 2048)
      : imp_(imp),
        rng_(seed),
        max_packet_(max_packet),
        data_(std::make_unique<std::byte[]>(pool_slots * max_packet)),
        lens_(std::make_unique<std::uint32_t[]>(pool_slots)),
        heap_(std::make_unique<HeapEntry[]>(pool_slots)),
        free_(std::make_unique<std::uint32_t[]>(pool_slots)) {
    LLE_ASSERT(pool_slots >= 1 && pool_slots <= 0xFFFF'FFFFu && max_packet >= 1);
    LLE_ASSERT(imp.loss_ppm <= kPpm && imp.dup_ppm <= kPpm && imp.reorder_ppm <= kPpm);
    LLE_ASSERT(imp.max_reorder_delay >= 1);
    for (std::size_t i = 0; i < pool_slots; ++i) free_[i] = static_cast<std::uint32_t>(pool_slots - 1 - i);
    nfree_ = pool_slots;
  }

  // Offers one packet carrying `messages` messages (0 for heartbeats and end of
  // session). send(std::span<const std::byte>) is called for every copy sent now.
  template <class Send>
  void offer(std::span<const std::byte> pkt, std::uint16_t messages, bool in_outage, Nanos now, Send&& send) {
    ++st_.packets;
    const std::uint64_t u_loss = rng_.below(kPpm);
    const std::uint64_t u_dup = rng_.below(kPpm);
    const std::uint64_t u_reorder = rng_.below(kPpm);
    const auto delay = static_cast<Nanos>(1 + rng_.below(static_cast<std::uint64_t>(imp_.max_reorder_delay)));
    if (in_outage) {
      ++st_.outage_dropped;
      st_.messages_dropped += messages;
      return;
    }
    if (u_loss < imp_.loss_ppm) {
      ++st_.dropped;
      st_.messages_dropped += messages;
      return;
    }
    const bool dup = u_dup < imp_.dup_ppm;
    if (dup) ++st_.duplicated;
    // The first copy may be delayed; a duplicate always goes at once, so a
    // reordered packet also arrives as a duplicate later (both shapes occur).
    if (u_reorder < imp_.reorder_ppm && park(pkt, now + delay)) {
      ++st_.delayed;
    } else {
      ++st_.sent;
      send(pkt);
    }
    if (dup) {
      ++st_.sent;
      send(pkt);
    }
  }

  // Sends every delayed packet that is due, earliest first.
  template <class Send>
  void release(Nanos now, Send&& send) {
    while (heap_n_ != 0 && heap_[0].due <= now) pop_send(send);
  }

  // Sends every delayed packet now (end of the stream).
  template <class Send>
  void release_all(Send&& send) {
    while (heap_n_ != 0) pop_send(send);
  }

  [[nodiscard]] Nanos next_deadline() const noexcept {
    return heap_n_ == 0 ? std::numeric_limits<Nanos>::max() : heap_[0].due;
  }
  [[nodiscard]] std::size_t delayed_now() const noexcept { return heap_n_; }
  [[nodiscard]] const LineStats& stats() const noexcept { return st_; }
  [[nodiscard]] const LineImpairment& impairment() const noexcept { return imp_; }

 private:
  struct HeapEntry {
    Nanos due = 0;
    std::uint64_t order = 0;  // FIFO among equal due times
    std::uint32_t slot = 0;
  };

  [[nodiscard]] static bool before(const HeapEntry& a, const HeapEntry& b) noexcept {
    return a.due != b.due ? a.due < b.due : a.order < b.order;
  }

  bool park(std::span<const std::byte> pkt, Nanos due) noexcept {
    if (nfree_ == 0 || pkt.size() > max_packet_) {
      ++st_.pool_full;
      return false;
    }
    const std::uint32_t s = free_[--nfree_];
    std::memcpy(data_.get() + std::size_t{s} * max_packet_, pkt.data(), pkt.size());
    lens_[s] = static_cast<std::uint32_t>(pkt.size());
    std::size_t i = heap_n_++;
    heap_[i] = HeapEntry{due, order_++, s};
    while (i > 0) {
      const std::size_t p = (i - 1) / 2;
      if (!before(heap_[i], heap_[p])) break;
      std::swap(heap_[i], heap_[p]);
      i = p;
    }
    return true;
  }

  template <class Send>
  void pop_send(Send& send) {
    const std::uint32_t s = heap_[0].slot;
    heap_[0] = heap_[--heap_n_];
    std::size_t i = 0;
    for (;;) {
      const std::size_t l = 2 * i + 1, r = l + 1;
      std::size_t m = i;
      if (l < heap_n_ && before(heap_[l], heap_[m])) m = l;
      if (r < heap_n_ && before(heap_[r], heap_[m])) m = r;
      if (m == i) break;
      std::swap(heap_[i], heap_[m]);
      i = m;
    }
    ++st_.sent;
    send(std::span<const std::byte>(data_.get() + std::size_t{s} * max_packet_, lens_[s]));
    free_[nfree_++] = s;
  }

  LineImpairment imp_;
  Prng rng_;
  std::size_t max_packet_;
  std::unique_ptr<std::byte[]> data_;
  std::unique_ptr<std::uint32_t[]> lens_;
  std::unique_ptr<HeapEntry[]> heap_;
  std::unique_ptr<std::uint32_t[]> free_;
  std::size_t heap_n_ = 0;
  std::size_t nfree_ = 0;
  std::uint64_t order_ = 0;
  LineStats st_;
};

}  // namespace lle::client
