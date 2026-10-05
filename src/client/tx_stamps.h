#pragma once
// Stream TX timestamps of the client programs (07 §2.5; METHODOLOGY §12, §13).
//
// A message's TX time is the NIC timestamp of the first transmission of the frame that
// carries its last byte. Both stream backends report stamps keyed by stream offsets,
// counted from the first byte written after the connection was established:
//   - kernel TCP (sock, io_uring): SOF_TIMESTAMPING_OPT_ID_TCP keys the stamp of every
//     send() with the offset of its last byte; with one_msg_per_send each write() is one
//     skb (MSG_EOR), so a stamp covers exactly the write ending at its key
//     (StreamTxStamp{first = last = key});
//   - utcp over AF_XDP: FrameStampTracker requests a TX-metadata timestamp only for
//     frames that carry new data (never for retransmissions, so a lost stamp is never
//     replaced by a later one) and reports the range of new bytes the frame carried.
// StreamTxMatcher then assigns each stamp to the messages whose last byte it covers.
// A message whose stamp never arrives is counted missing (TsValidity), never guessed.
// Fixed capacities, allocated at init(); allocation-free afterwards.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "common/endian.h"
#include "common/types.h"
#include "net/common/fixed_queue.h"
#include "net/common/timestamps.h"
#include "net/utcp/wire.h"

namespace lle::client {

struct StreamTxStamp {
  std::uint32_t first = 0;  // stream offsets (bytes since the connection was established)
  std::uint32_t last = 0;   // inclusive
  net::RxTimestamps ts;     // sw_ns (software stamps) or hw_ns (NIC)
};

// Serial-number order on 32-bit stream offsets (TCP sequence arithmetic).
[[nodiscard]] constexpr bool seq_before(std::uint32_t a, std::uint32_t b) noexcept {
  return static_cast<std::int32_t>(a - b) < 0;
}

class StreamTxMatcher {
 public:
  void init(std::size_t capacity) { q_.init(capacity); }

  // A new connection: offsets restart; what is still pending never gets a stamp.
  void reset() noexcept {
    expire_all();
    written_ = 0;
  }
  // Bytes written on the connection (call after every write, with what it accepted).
  void on_written(std::size_t n) noexcept { written_ += static_cast<std::uint32_t>(n); }
  // The stream offset the next byte written will have.
  [[nodiscard]] std::uint32_t written() const noexcept { return written_; }

  // A message whose last byte is at stream offset `key`. Keys must not decrease.
  void expect(std::uint64_t tag, std::uint32_t key) noexcept {
    if (q_.full()) {
      q_.pop();
      ++validity_.missing;
    }
    (void)q_.push(Pending{tag, key});
  }

  // cb(tag, const net::RxTimestamps&) for each message the stamp covers.
  template <class F>
  void on_stamp(const StreamTxStamp& s, F&& cb) noexcept {
    while (!q_.empty() && seq_before(q_.front().key, s.first)) {
      q_.pop();
      ++validity_.missing;
    }
    while (!q_.empty() && !seq_before(s.last, q_.front().key)) {
      const Pending p = q_.front();
      q_.pop();
      validity_.record(net::classify(s.ts));
      cb(p.tag, s.ts);
    }
  }

  void expire_all() noexcept {
    validity_.missing += q_.size();
    q_.clear();
  }
  [[nodiscard]] std::size_t outstanding() const noexcept { return q_.size(); }
  [[nodiscard]] const net::TsValidity& validity() const noexcept { return validity_; }

 private:
  struct Pending {
    std::uint64_t tag = 0;
    std::uint32_t key = 0;
  };
  net::FixedQueue<Pending> q_;
  net::TsValidity validity_{};
  std::uint32_t written_ = 0;
};

// The AF_XDP side: decides which outgoing utcp frames request a TX timestamp and which
// stream bytes each stamped frame first transmitted. Each stamped frame gets an id
// (last_id(), passed as the frame's TX cookie); on_completion_for(id, ns) matches the
// completion by id, so a stamped frame whose completion never arrives is counted lost
// instead of shifting every later stamp. on_completion(ns) keeps the plain ring-order
// rule (the n-th timestamped completion belongs to the n-th stamped frame).
class FrameStampTracker {
 public:
  static constexpr std::size_t kMaxFlows = 64;

  struct Stamped {
    std::uint16_t local_port = 0;
    StreamTxStamp stamp;
    std::uint64_t id = 0;  // 1, 2, ... in on_tx() order
  };

  void init(std::size_t capacity) {
    inflight_.init(capacity);
    done_.init(capacity);
  }

  // An outgoing Ethernet/IPv4 frame. Returns true when it should request a timestamp
  // (then it must be committed, and its completion reported with on_completion).
  bool on_tx(std::span<const std::byte> frame) noexcept {
    auto seg = net::utcp::parse_tcp(frame, net::utcp::LinkType::Ethernet, false);
    if (!seg) return false;
    Flow* f = find(seg->src_port);
    if (seg->has(net::utcp::tcp_flag::kSyn)) {
      if (f == nullptr) f = alloc(seg->src_port);
      if (f == nullptr) {
        ++flow_table_full_;
        return false;
      }
      f->isn = seg->seq;
      f->sent_end = 0;
      f->known = true;
      return false;
    }
    if (f == nullptr || !f->known || seg->payload.empty()) return false;
    const std::uint32_t first = seg->seq - f->isn - 1;
    const std::uint32_t end = first + static_cast<std::uint32_t>(seg->payload.size());  // exclusive
    if (!seq_before(f->sent_end, end)) {
      ++retransmissions_;  // nothing new: never stamped
      return false;
    }
    const std::uint32_t new_first = seq_before(first, f->sent_end) ? f->sent_end : first;
    f->sent_end = end;
    if (inflight_.full()) {
      ++inflight_full_;
      return false;
    }
    (void)inflight_.push(Stamped{seg->src_port, StreamTxStamp{new_first, end - 1, {}}, ++next_id_});
    return true;
  }

  // Id of the frame the last on_tx() returning true accepted (its TX cookie).
  [[nodiscard]] std::uint64_t last_id() const noexcept { return next_id_; }

  // The completion of stamped frame `id` (0 ns = none: copy mode, or the NIC did not
  // stamp). Older in-flight frames whose completions were never reported are dropped
  // (counted lost); an id that is not in flight counts as unmatched.
  void on_completion_for(std::uint64_t id, Nanos hw_ns) noexcept {
    while (!inflight_.empty() && inflight_.front().id < id) {
      inflight_.pop();
      ++lost_completions_;
    }
    if (inflight_.empty() || inflight_.front().id != id) {
      ++unmatched_completions_;
      return;
    }
    Stamped s = inflight_.front();
    inflight_.pop();
    s.stamp.ts.hw_ns = hw_ns;
    if (!done_.push(s)) ++done_full_;
  }

  // One timestamped completion (0 = none: copy mode, or the NIC did not stamp).
  void on_completion(Nanos hw_ns) noexcept {
    if (inflight_.empty()) {
      ++unmatched_completions_;
      return;
    }
    Stamped s = inflight_.front();
    inflight_.pop();
    s.stamp.ts.hw_ns = hw_ns;
    if (!done_.push(s)) ++done_full_;
  }

  // A connection from `local_port` ended: its next SYN starts a new stream.
  void forget(std::uint16_t local_port) noexcept {
    if (Flow* f = find(local_port)) f->known = false;
  }

  // cb(const Stamped&) for every completed stamp, in order.
  template <class F>
  std::size_t drain(F&& cb) {
    std::size_t n = 0;
    while (!done_.empty()) {
      cb(static_cast<const Stamped&>(done_.front()));
      done_.pop();
      ++n;
    }
    return n;
  }

  // Stamped frames whose completion has not been seen.
  [[nodiscard]] std::size_t inflight() const noexcept { return inflight_.size(); }
  // Counted when completions were lost to another reaper: the in-flight stamps are
  // discarded (their messages count as missing).
  void discard_inflight() noexcept {
    discarded_ += inflight_.size();
    inflight_.clear();
  }

  [[nodiscard]] std::uint64_t retransmissions() const noexcept { return retransmissions_; }
  [[nodiscard]] std::uint64_t unmatched_completions() const noexcept { return unmatched_completions_; }
  // Stamped frames whose completion was never reported (skipped by a later id).
  [[nodiscard]] std::uint64_t lost_completions() const noexcept { return lost_completions_; }
  [[nodiscard]] std::uint64_t dropped() const noexcept {
    return inflight_full_ + done_full_ + flow_table_full_ + discarded_ + lost_completions_;
  }

 private:
  struct Flow {
    std::uint16_t local_port = 0;
    bool used = false;
    bool known = false;
    std::uint32_t isn = 0;
    std::uint32_t sent_end = 0;  // one past the highest stream offset transmitted
  };
  Flow* find(std::uint16_t port) noexcept {
    for (Flow& f : flows_)
      if (f.used && f.local_port == port) return &f;
    return nullptr;
  }
  Flow* alloc(std::uint16_t port) noexcept {
    for (Flow& f : flows_) {
      if (!f.used) {
        f = Flow{port, true, false, 0, 0};
        return &f;
      }
    }
    for (Flow& f : flows_) {  // reuse a forgotten flow
      if (!f.known) {
        f = Flow{port, true, false, 0, 0};
        return &f;
      }
    }
    return nullptr;
  }

  std::array<Flow, kMaxFlows> flows_{};
  net::FixedQueue<Stamped> inflight_, done_;
  std::uint64_t retransmissions_ = 0, unmatched_completions_ = 0, lost_completions_ = 0;
  std::uint64_t inflight_full_ = 0, done_full_ = 0, flow_table_full_ = 0, discarded_ = 0;
  std::uint64_t next_id_ = 0;
};

}  // namespace lle::client
