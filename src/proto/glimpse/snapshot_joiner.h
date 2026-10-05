#pragma once
// Client-side GLIMPSE-style join (03-protocols §8; R1b D5 "pattern for late
// joiners"): buffer live MoldUDP64 messages, apply the snapshot spin, and on
// End of Snapshot G(N) drop buffered messages below N and continue from N.
//
//   on_live(seq, msg)      live ITCH messages with their MoldUDP64 sequence
//                          (normally the in-order output of a LineArbiter or
//                          Depacketizer); buffered until the splice;
//   on_snapshot(payload)   one spin payload (ITCH S/R/H/Y/h/A/F, then 'G').
//
// Sink:
//   void on_snapshot_message(std::span<const std::byte> itch);  // spin message, apply to state
//   void on_message(SeqNo seq, std::span<const std::byte> itch); // live message from N onward, in order
//   void on_gap(SeqNo first_missing, SeqNo first_available);     // live data missing at/after N
//
// The live buffer keeps the newest `live_capacity` messages (older ones are
// dropped and counted), so memory is fixed at construction.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

#include "common/assert.h"
#include "common/types.h"
#include "proto/glimpse/glimpse.h"
#include "proto/itch50/itch50.h"

namespace lle::glimpse {

struct SnapshotJoinerConfig {
  std::size_t live_capacity = 1 << 16;  // power of two
  std::size_t slot_bytes = 64;          // ITCH 5.0 maximum is 50
};

struct SnapshotJoinerStats {
  std::uint64_t snapshot_messages = 0, rejected_snapshot_messages = 0;
  std::uint64_t live_buffered = 0, live_dropped_window = 0, live_dropped_before_splice = 0;
  std::uint64_t live_delivered = 0, live_duplicates = 0, oversize = 0, gaps = 0;
};

class SnapshotJoiner {
 public:
  enum class State : std::uint8_t { Buffering, Live };
  enum class SnapshotResult : std::uint8_t { Applied, Spliced, Rejected, IgnoredAfterSplice };

  explicit SnapshotJoiner(const SnapshotJoinerConfig& cfg = {})
      : cfg_(cfg),
        mask_(cfg.live_capacity - 1),
        slots_(std::make_unique<Slot[]>(cfg.live_capacity)),
        data_(std::make_unique<std::byte[]>(cfg.live_capacity * cfg.slot_bytes)) {
    LLE_ASSERT(cfg.live_capacity >= 2 && (cfg.live_capacity & mask_) == 0, "live_capacity must be a power of two");
    LLE_ASSERT(cfg.slot_bytes >= itch50::kMaxMsgLen && cfg.slot_bytes <= 0xFFFF);
  }

  template <class Sink>
  void on_live(SeqNo seq, std::span<const std::byte> msg, Sink& sink) {
    if (state_ == State::Live) {
      if (seq < next_) {
        ++st_.live_duplicates;
        return;
      }
      if (seq == next_) {
        deliver(seq, msg, sink);
        drain(sink);
        return;
      }
      if (seq - next_ >= cfg_.live_capacity) {
        ++st_.live_dropped_window;
        return;
      }
      if (put(seq, msg) && gap_reported_at_ != next_) {
        gap_reported_at_ = next_;
        ++st_.gaps;
        sink.on_gap(next_, seq);
      }
      return;
    }
    if (base_ == 0) base_ = seq == 0 ? 1 : seq;
    if (seq < base_) {
      ++st_.live_dropped_window;
      return;
    }
    if (seq - base_ >= cfg_.live_capacity) slide(seq - cfg_.live_capacity + 1);
    if (put(seq, msg)) ++st_.live_buffered;
  }

  template <class Sink>
  SnapshotResult on_snapshot(std::span<const std::byte> payload, Sink& sink) {
    if (state_ == State::Live) return SnapshotResult::IgnoredAfterSplice;
    if (!payload.empty() && static_cast<char>(payload[0]) == kEndOfSnapshotType) {
      const auto n = decode_end_of_snapshot(payload);
      if (!n || *n == 0) {
        ++st_.rejected_snapshot_messages;
        return SnapshotResult::Rejected;
      }
      splice(*n, sink);
      return SnapshotResult::Spliced;
    }
    const auto mv = itch50::decode(payload);
    if (!mv || !is_snapshot_type(mv->type())) {
      ++st_.rejected_snapshot_messages;
      return SnapshotResult::Rejected;
    }
    ++st_.snapshot_messages;
    sink.on_snapshot_message(payload);
    return SnapshotResult::Applied;
  }

  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] SeqNo splice_seq() const noexcept { return splice_; }
  [[nodiscard]] SeqNo next_expected() const noexcept { return next_; }
  [[nodiscard]] std::size_t buffered() const noexcept { return buffered_; }
  [[nodiscard]] const SnapshotJoinerStats& stats() const noexcept { return st_; }

 private:
  struct Slot {
    SeqNo seq = 0;
    std::uint16_t len = 0;
    bool present = false;
  };

  [[nodiscard]] std::byte* slot_data(SeqNo s) const noexcept { return data_.get() + (s & mask_) * cfg_.slot_bytes; }

  bool put(SeqNo s, std::span<const std::byte> msg) noexcept {
    if (msg.size() > cfg_.slot_bytes) {
      ++st_.oversize;
      return false;
    }
    Slot& sl = slots_[s & mask_];
    if (sl.present && sl.seq == s) return false;
    if (!sl.present) ++buffered_;
    sl = Slot{s, static_cast<std::uint16_t>(msg.size()), true};
    if (!msg.empty()) std::memcpy(slot_data(s), msg.data(), msg.size());
    return true;
  }

  void slide(SeqNo new_base) noexcept {
    if (new_base - base_ >= cfg_.live_capacity) {
      for (std::size_t i = 0; i <= mask_ && buffered_ != 0; ++i) {
        if (slots_[i].present) {
          slots_[i].present = false;
          --buffered_;
          ++st_.live_dropped_window;
        }
      }
    } else {
      for (SeqNo s = base_; s < new_base && buffered_ != 0; ++s) {
        Slot& sl = slots_[s & mask_];
        if (sl.present && sl.seq == s) {
          sl.present = false;
          --buffered_;
          ++st_.live_dropped_window;
        }
      }
    }
    base_ = new_base;
  }

  template <class Sink>
  void deliver(SeqNo s, std::span<const std::byte> msg, Sink& sink) {
    sink.on_message(s, msg);
    ++next_;
    ++st_.live_delivered;
  }

  template <class Sink>
  void drain(Sink& sink) {
    while (buffered_ != 0) {
      Slot& sl = slots_[next_ & mask_];
      if (!sl.present || sl.seq != next_) break;
      sl.present = false;
      --buffered_;
      deliver(next_, std::span<const std::byte>(slot_data(next_), sl.len), sink);
    }
  }

  template <class Sink>
  void splice(SeqNo n, Sink& sink) {
    state_ = State::Live;
    splice_ = next_ = n;
    // Messages below N are already reflected in the snapshot.
    SeqNo lowest_kept = ~SeqNo{0};
    for (std::size_t i = 0; i <= mask_ && buffered_ != 0; ++i) {
      Slot& sl = slots_[i];
      if (!sl.present) continue;
      if (sl.seq < n || sl.seq - n >= cfg_.live_capacity) {
        sl.present = false;
        --buffered_;
        ++st_.live_dropped_before_splice;
      } else if (sl.seq < lowest_kept) {
        lowest_kept = sl.seq;
      }
    }
    drain(sink);
    // Live data exists beyond N but N itself is missing (lost, or dropped from the window).
    if (buffered_ != 0 && lowest_kept > next_) {
      gap_reported_at_ = next_;
      ++st_.gaps;
      sink.on_gap(next_, lowest_kept);
    }
  }

  SnapshotJoinerConfig cfg_;
  SeqNo mask_;
  std::unique_ptr<Slot[]> slots_;
  std::unique_ptr<std::byte[]> data_;
  State state_ = State::Buffering;
  SeqNo base_ = 0;  // Buffering: lowest sequence the window accepts (0 = unset)
  SeqNo next_ = 0;
  SeqNo splice_ = 0;
  SeqNo gap_reported_at_ = 0;
  std::size_t buffered_ = 0;
  SnapshotJoinerStats st_;
};

}  // namespace lle::glimpse
