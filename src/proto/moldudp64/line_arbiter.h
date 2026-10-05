#pragma once
// A/B line arbitration for MoldUDP64 (03-protocols §7, T10; R1b D6).
//
// Two lines carry the same message sequence, possibly with different packet
// boundaries. For each packet (seq, count) from a source, with next = the next
// sequence to deliver:
//   1. seq + count <= next          duplicate: drop.
//   2. seq <= next < seq + count    partial overlap: skip next - seq blocks, deliver the rest.
//   3. seq > next                   gap: park the messages in a bounded reorder buffer
//                                   and arm the gap timer (2x measured p99.9 A/B skew).
//   4. Gap timer fires              re-request the missing ranges in one-packet chunks,
//                                   at most `max_outstanding` at a time, to server A;
//                                   after `request_timeout` retry the range on server B.
//   5. Gap > snapshot_gap_messages, gap older than max_gap_age, reorder-window
//      overflow, or both servers failing: signal on_snapshot_needed() and keep
//      buffering the live stream until resume_from_snapshot(S(P)+1).
//   6. Heartbeats and end of session advance the known end of the stream, which
//      exposes tail gaps during quiet periods.
// Delivery is exactly once and in sequence order. Sans-I/O and deterministic:
// packets, time (`now`) and timer ticks in; actions out through the sink. No
// allocation after construction.
//
// Sink (any type with these members; called synchronously, must not re-enter):
//   void on_message(SeqNo seq, std::span<const std::byte> msg);
//   void send_request(Server server, std::span<const std::byte> request_packet);
//   void on_snapshot_needed(SeqNo next_expected, SeqNo known_end);
//   void on_end_of_session(SeqNo end_seq);
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>

#include "common/assert.h"
#include "common/types.h"
#include "env/buggify.h"
#include "proto/moldudp64/histogram.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::mold {

// Where a packet came from: one of the two multicast lines, or a unicast
// re-request reply from server A or B.
enum class Source : std::uint8_t { LineA = 0, LineB = 1, RerequestA = 2, RerequestB = 3 };
enum class Server : std::uint8_t { A = 0, B = 1 };
inline constexpr std::size_t kNumSources = 4;

[[nodiscard]] constexpr bool is_line(Source s) noexcept { return s == Source::LineA || s == Source::LineB; }
[[nodiscard]] constexpr Server server_of(Source s) noexcept { return s == Source::RerequestA ? Server::A : Server::B; }
[[nodiscard]] constexpr Source reply_source(Server s) noexcept {
  return s == Server::A ? Source::RerequestA : Source::RerequestB;
}

struct LineArbiterConfig {
  Session session;                        // blank: learn from the first valid packet
  SeqNo first_seq = 1;                    // first sequence to deliver; 0 = late join (await a snapshot)
  std::size_t reorder_capacity = 65'536;  // messages; power of two
  std::size_t slot_bytes = 64;            // largest buffered message (ITCH 5.0 maximum is 50)
  // Starting values only: published runs set these from measurements
  // (2x p99.9 A/B skew; 2x re-request RTT p99, at least 1 ms), see
  // suggested_gap_timeout() / suggested_request_timeout().
  Nanos gap_timeout = 50'000;
  Nanos request_timeout = 1'000'000;
  std::uint32_t max_outstanding = 4;
  std::uint16_t request_max_count = 64;   // messages asked per request; the reply carries what fits
  std::uint64_t snapshot_gap_messages = 20'000;  // 0 disables
  Nanos max_gap_age = 0;                  // 0 disables
  // A re-request server that timed out counts as failed (requests go to the other one,
  // and a timeout there then escalates to a snapshot) until it replies or for this long.
  // Without the bound, one early timeout kept a server "failed" for a whole gap episode,
  // which under sustained loss can last minutes, so two unrelated timeouts escalated.
  Nanos server_fail_hold = 10'000'000;
  // Slots examined per request scan. After a large splice the window can hold millions
  // of buffered messages; the scan stops after this many and later calls (every packet
  // and timer) continue once next_ advances, so a call costs O(budget), not O(window).
  std::size_t request_scan_budget = 65'536;
};

struct LineArbiterMetrics {
  std::array<std::uint64_t, kNumSources> packets{};
  std::array<std::uint64_t, kNumSources> first_arrivals{};  // messages this source delivered or buffered first
  std::array<std::uint64_t, kNumSources> duplicate_packets{};
  std::array<std::uint64_t, kNumSources> partial_overlaps{};
  std::array<std::uint64_t, kNumSources> malformed{};
  std::uint64_t wrong_session = 0, heartbeats = 0, end_of_session_packets = 0, ignored_after_end = 0;
  std::uint64_t delivered = 0;
  std::uint64_t gaps_opened = 0;
  std::array<std::uint64_t, 2> gaps_filled_by_line{};  // [LineA, LineB]
  std::uint64_t gaps_filled_by_rerequest = 0, gaps_filled_by_snapshot = 0;
  std::array<std::uint64_t, 2> requests_sent{};     // [A, B]
  std::array<std::uint64_t, 2> request_timeouts{};  // [A, B]
  std::uint64_t failovers = 0, recovered_messages = 0, snapshot_signals = 0;
  std::uint64_t reorder_high_water = 0, buffer_overflows = 0, oversize_unbuffered = 0, snapshot_window_drops = 0;
  std::uint64_t skew_a_ahead = 0, skew_b_ahead = 0;
  Log2Histogram skew_ns;  // arrival time of a packet's first message on the later line minus the earlier one
  Log2Histogram rtt_ns;   // re-request sent -> reply carrying its first message

  // Share (parts per million) of first arrivals that came from `s`.
  [[nodiscard]] std::uint64_t first_arrival_ppm(Source s) const noexcept {
    std::uint64_t total = 0;
    for (auto n : first_arrivals) total += n;
    return total == 0 ? 0 : first_arrivals[static_cast<std::size_t>(s)] * 1'000'000 / total;
  }
};

class LineArbiter {
 public:
  enum class State : std::uint8_t { Live, AwaitingSnapshot, Ended };
  static constexpr Nanos kNever = std::numeric_limits<Nanos>::max();
  static constexpr std::uint32_t kMaxOutstanding = 16;

  explicit LineArbiter(const LineArbiterConfig& cfg)
      : cfg_(cfg),
        cap_(cfg.reorder_capacity),
        mask_(cfg.reorder_capacity - 1),
        session_(cfg.session),
        session_known_(!cfg.session.blank()),
        slots_(std::make_unique<Slot[]>(cfg.reorder_capacity)),
        data_(std::make_unique_for_overwrite<std::byte[]>(cfg.reorder_capacity * cfg.slot_bytes)),
        arrivals_(std::make_unique<Arrival[]>(cfg.reorder_capacity)) {
    LLE_ASSERT(cap_ >= 2 && (cap_ & mask_) == 0, "reorder_capacity must be a power of two");
    LLE_ASSERT(cfg.slot_bytes >= 1 && cfg.slot_bytes <= kMaxMessageLen);
    LLE_ASSERT(cfg.max_outstanding >= 1 && cfg.max_outstanding <= kMaxOutstanding);
    LLE_ASSERT(cfg.request_max_count >= 1 && cfg.gap_timeout >= 0 && cfg.request_timeout > 0);
    for (std::size_t i = 0; i < cap_; ++i) arrivals_[i].seq = ~SeqNo{0};
    if (cfg.first_seq == 0) {
      state_ = State::AwaitingSnapshot;
    } else {
      next_ = known_end_ = cfg.first_seq;
    }
  }

  template <class Sink>
  void on_packet(Source src, std::span<const std::byte> bytes, Nanos now, Sink& sink) {
    const auto si = static_cast<std::size_t>(src);
    const auto pv = PacketView::parse(bytes);
    if (!pv) {
      ++m_.malformed[si];
      return;
    }
    const PacketHeader& h = pv->header();
    if (!session_known_) {
      session_ = h.session;
      session_known_ = true;
    } else if (h.session != session_) {
      ++m_.wrong_session;
      return;
    }
    ++m_.packets[si];
    if (state_ == State::Ended) {
      ++m_.ignored_after_end;
      return;
    }
    if (!is_line(src)) on_reply(src, h.seq, now);

    if (h.is_heartbeat() || h.is_end_of_session()) {
      if (h.is_end_of_session()) {
        ++m_.end_of_session_packets;
        eos_seq_ = std::max(eos_seq_, h.seq);
      } else {
        ++m_.heartbeats;
      }
      if (h.seq > known_end_) {
        register_hole(known_end_, h.seq, now);
        known_end_ = h.seq;
      }
      after_progress(now, sink);
      return;
    }

    const SeqNo first = h.seq;
    const SeqNo end = pv->end_seq();
    if (is_line(src)) sample_skew(first, src, now);
    if (first > known_end_) register_hole(known_end_, first, now);
    known_end_ = std::max(known_end_, end);

    if (state_ == State::AwaitingSnapshot) {
      buffer_for_snapshot(*pv, src, now);
      return;
    }
    if (end <= next_) {
      ++m_.duplicate_packets[si];
      return;
    }
    if (first < next_) ++m_.partial_overlaps[si];
    std::uint64_t accepted = 0;
    pv->for_each_from(first < next_ ? static_cast<std::size_t>(next_ - first) : 0,
                      [&](SeqNo s, std::span<const std::byte> msg) {
                        if (s < next_) return;  // delivered meanwhile from the reorder buffer
                        if (s == next_) {
                          record_arrival(s, src, now);
                          deliver(s, msg, sink);
                          last_fill_ = src;
                          drain(sink);
                          ++accepted;
                        } else if (store(s, msg)) {
                          record_arrival(s, src, now);
                          ++accepted;
                        }
                      });
    m_.first_arrivals[si] += accepted;
    if (!is_line(src) && accepted != 0) {
      m_.recovered_messages += accepted;
      episode_used_rerequest_ = true;
    }
    after_progress(now, sink);
  }

  // Gap timer, re-request timeouts and failover. Call at next_deadline() or on any tick.
  template <class Sink>
  void on_timer(Nanos now, Sink& sink) {
    if (state_ != State::Live) return;
    if (gap_armed_ && now >= gap_deadline_) {
      gap_armed_ = false;
      if (next_ < pending_limit_) {
        requesting_ = true;
        request_limit_ = std::max(request_limit_, pending_limit_);
      }
      pending_limit_ = 0;
    }
    complete_requests();
    for (std::uint32_t i = 0; i < cfg_.max_outstanding; ++i) {
      Request& r = reqs_[i];
      if (!r.active || now - r.sent_at < cfg_.request_timeout) continue;
      const auto s = static_cast<std::size_t>(r.server);
      ++m_.request_timeouts[s];
      failed_until_[s] = now + cfg_.server_fail_hold;
      const Server other = r.server == Server::A ? Server::B : Server::A;
      if (r.attempts >= 2 || failed(other, now)) {
        trigger_snapshot(sink);  // both servers failed
        return;
      }
      ++m_.failovers;
      r.server = other;
      r.sent_at = now;
      ++r.attempts;
      send(r, sink);
    }
    after_progress(now, sink);
  }

  // The snapshot covers every message below `next_seq` (GLIMPSE 'G' = S(P)+1).
  // Buffered live messages from next_seq on are delivered; anything still
  // missing after the splice is recovered as a normal gap.
  template <class Sink>
  void resume_from_snapshot(SeqNo next_seq, Nanos now, Sink& sink) {
    LLE_ASSERT(next_seq >= 1);
    if (state_ == State::Ended) return;
    if (buffered_ != 0) {
      for (std::size_t i = 0; i < cap_; ++i) {
        Slot& sl = slots_[i];
        if (sl.present && (sl.seq < next_seq || sl.seq - next_seq >= cap_)) {
          sl.present = false;
          --buffered_;
        }
      }
    }
    next_ = next_seq;
    known_end_ = std::max(known_end_, next_seq);
    state_ = State::Live;
    window_base_ = 0;
    if (in_gap_) {
      ++m_.gaps_filled_by_snapshot;
      in_gap_ = false;
    }
    reset_recovery();
    drain(sink);
    if (next_ < known_end_) register_hole(next_, known_end_, now);
    after_progress(now, sink);
  }

  // Earliest time on_timer() has work, or kNever.
  [[nodiscard]] Nanos next_deadline() const noexcept {
    if (state_ != State::Live) return kNever;
    Nanos d = kNever;
    if (gap_armed_) d = gap_deadline_;
    for (std::uint32_t i = 0; i < cfg_.max_outstanding; ++i)
      if (reqs_[i].active) d = std::min(d, reqs_[i].sent_at + cfg_.request_timeout);
    if (in_gap_ && cfg_.max_gap_age > 0) d = std::min(d, gap_start_ + cfg_.max_gap_age);
    return d;
  }

  // 2x the measured p99.9 A/B skew (03-protocols §7 step 3); `fallback` until measured.
  [[nodiscard]] Nanos suggested_gap_timeout(Nanos fallback) const noexcept {
    return m_.skew_ns.count() == 0 ? fallback : static_cast<Nanos>(2 * m_.skew_ns.quantile_upper(999'000));
  }
  // 2x the measured re-request RTT p99, at least 1 ms (03-protocols §7 step 4).
  [[nodiscard]] Nanos suggested_request_timeout(Nanos fallback) const noexcept {
    if (m_.rtt_ns.count() == 0) return fallback;
    return std::max<Nanos>(1'000'000, static_cast<Nanos>(2 * m_.rtt_ns.quantile_upper(990'000)));
  }
  void set_gap_timeout(Nanos t) noexcept { cfg_.gap_timeout = t; }
  void set_request_timeout(Nanos t) noexcept { cfg_.request_timeout = t > 0 ? t : 1; }

  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] SeqNo next_expected() const noexcept { return next_; }
  [[nodiscard]] SeqNo known_end() const noexcept { return known_end_; }
  [[nodiscard]] std::size_t buffered() const noexcept { return buffered_; }
  [[nodiscard]] bool in_gap() const noexcept { return in_gap_; }
  [[nodiscard]] std::uint32_t outstanding_requests() const noexcept { return active_; }
  [[nodiscard]] const Session& session() const noexcept { return session_; }
  [[nodiscard]] const LineArbiterMetrics& metrics() const noexcept { return m_; }
  [[nodiscard]] const LineArbiterConfig& config() const noexcept { return cfg_; }

 private:
  struct Slot {
    SeqNo seq = 0;
    std::uint16_t len = 0;
    bool present = false;
  };
  struct Arrival {
    SeqNo seq = 0;
    Nanos t = 0;
    Source src = Source::LineA;
    bool sampled = false;
  };
  struct Request {
    SeqNo first = 0;
    Nanos sent_at = 0;
    std::uint16_t count = 0;
    Server server = Server::A;
    std::uint8_t attempts = 0;
    bool active = false;
  };

  [[nodiscard]] bool have(SeqNo s) const noexcept {
    if (s < next_) return true;
    const Slot& sl = slots_[s & mask_];
    return sl.present && sl.seq == s;
  }

  [[nodiscard]] std::byte* slot_data(SeqNo s) const noexcept { return data_.get() + (s & mask_) * cfg_.slot_bytes; }

  template <class Sink>
  void deliver(SeqNo s, std::span<const std::byte> msg, Sink& sink) {
    sink.on_message(s, msg);
    ++next_;
    ++m_.delivered;
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

  // Parks a message beyond next_ (Live state). False if not stored.
  bool store(SeqNo s, std::span<const std::byte> msg) noexcept {
    if (s - next_ >= cap_) {
      ++m_.buffer_overflows;
      overflow_ = true;
      return false;
    }
    return put(s, msg);
  }

  bool put(SeqNo s, std::span<const std::byte> msg) noexcept {
    if (msg.size() > cfg_.slot_bytes) {
      ++m_.oversize_unbuffered;
      return false;
    }
    Slot& sl = slots_[s & mask_];
    if (sl.present) {
      if (sl.seq == s) return false;  // already held
      --buffered_;                    // stale alias (cannot happen inside the window)
    }
    sl.seq = s;
    sl.len = static_cast<std::uint16_t>(msg.size());
    sl.present = true;
    if (!msg.empty()) std::memcpy(slot_data(s), msg.data(), msg.size());
    ++buffered_;
    m_.reorder_high_water = std::max<std::uint64_t>(m_.reorder_high_water, buffered_);
    return true;
  }

  // AwaitingSnapshot: keep the newest `cap_` messages of the live stream.
  void buffer_for_snapshot(const PacketView& pv, Source src, Nanos now) {
    std::uint64_t accepted = 0;
    pv.for_each([&](SeqNo s, std::span<const std::byte> msg) {
      if (window_base_ == 0) window_base_ = s == 0 ? 1 : s;
      if (s < window_base_) return;
      if (s - window_base_ >= cap_) slide_window(s - cap_ + 1);
      if (put(s, msg)) {
        record_arrival(s, src, now);
        ++accepted;
      }
    });
    m_.first_arrivals[static_cast<std::size_t>(src)] += accepted;
  }

  void slide_window(SeqNo new_base) noexcept {
    if (new_base - window_base_ >= cap_) {
      for (std::size_t i = 0; i < cap_ && buffered_ != 0; ++i) {
        if (slots_[i].present) {
          slots_[i].present = false;
          --buffered_;
          ++m_.snapshot_window_drops;
        }
      }
    } else {
      for (SeqNo s = window_base_; s < new_base; ++s) {
        Slot& sl = slots_[s & mask_];
        if (sl.present && sl.seq == s) {
          sl.present = false;
          --buffered_;
          ++m_.snapshot_window_drops;
        }
      }
    }
    window_base_ = new_base;
  }

  void record_arrival(SeqNo s, Source src, Nanos now) noexcept { arrivals_[s & mask_] = Arrival{s, now, src, false}; }

  void sample_skew(SeqNo first, Source src, Nanos now) noexcept {
    Arrival& a = arrivals_[first & mask_];
    if (a.seq != first || a.sampled || !is_line(a.src) || a.src == src) return;
    a.sampled = true;
    m_.skew_ns.add(static_cast<std::uint64_t>(now - a.t));
    ++(a.src == Source::LineA ? m_.skew_a_ahead : m_.skew_b_ahead);
  }

  void register_hole(SeqNo /*begin*/, SeqNo end, Nanos now) noexcept {
    if (state_ != State::Live) return;
    if (!gap_armed_) {
      gap_armed_ = true;
      gap_deadline_ = now + cfg_.gap_timeout;
    }
    pending_limit_ = std::max(pending_limit_, end);
  }

  void on_reply(Source src, SeqNo first, Nanos now) noexcept {
    const Server srv = server_of(src);
    failed_until_[static_cast<std::size_t>(srv)] = 0;
    for (std::uint32_t i = 0; i < cfg_.max_outstanding; ++i) {
      const Request& r = reqs_[i];
      if (r.active && r.first == first && r.server == srv) {
        m_.rtt_ns.add(static_cast<std::uint64_t>(now - r.sent_at));
        break;
      }
    }
  }

  void complete_requests() noexcept {
    for (std::uint32_t i = 0; i < cfg_.max_outstanding; ++i) {
      if (reqs_[i].active && have(reqs_[i].first)) {
        reqs_[i].active = false;
        --active_;
      }
    }
  }

  [[nodiscard]] const Request* covering(SeqNo s) const noexcept {
    for (std::uint32_t i = 0; i < cfg_.max_outstanding; ++i) {
      const Request& r = reqs_[i];
      if (r.active && s >= r.first && s - r.first < r.count) return &r;
    }
    return nullptr;
  }

  [[nodiscard]] bool failed(Server s, Nanos now) const noexcept {
    return now < failed_until_[static_cast<std::size_t>(s)];
  }
  [[nodiscard]] Server preferred_server(Nanos now) const noexcept {
    return failed(Server::A, now) && !failed(Server::B, now) ? Server::B : Server::A;
  }

  template <class Sink>
  void send(const Request& r, Sink& sink) {
    std::byte pkt[kRequestLen];
    (void)encode_request(pkt, RequestPacket{session_, r.first, r.count});
    ++m_.requests_sent[static_cast<std::size_t>(r.server)];
    sink.send_request(r.server, std::span<const std::byte>(pkt, kRequestLen));
  }

  template <class Sink>
  void maybe_send_requests(Nanos now, Sink& sink) {
    if (!requesting_ || active_ >= cfg_.max_outstanding) return;
    const SeqNo limit = std::min({request_limit_, known_end_, next_ + cap_});
    SeqNo s = next_;
    std::size_t budget = cfg_.request_scan_budget == 0 ? ~std::size_t{0} : cfg_.request_scan_budget;
    while (active_ < cfg_.max_outstanding && s < limit && budget-- > 0) {
      if (have(s)) {
        ++s;
        continue;
      }
      if (const Request* r = covering(s)) {
        s = r->first + r->count;
        continue;
      }
      const SeqNo a = s;
      SeqNo b = s + 1;
      while (b < limit && b - a < cfg_.request_max_count && !have(b) && covering(b) == nullptr) ++b;
      for (std::uint32_t i = 0; i < cfg_.max_outstanding; ++i) {
        Request& r = reqs_[i];
        if (r.active) continue;
        r = Request{a, now, static_cast<std::uint16_t>(b - a), preferred_server(now), 1, true};
        ++active_;
        send(r, sink);
        break;
      }
      s = b;
    }
  }

  void reset_recovery() noexcept {
    requesting_ = false;
    gap_armed_ = false;
    pending_limit_ = 0;
    request_limit_ = 0;
    overflow_ = false;
    failed_until_ = {0, 0};
    for (auto& r : reqs_) r.active = false;
    active_ = 0;
  }

  template <class Sink>
  void trigger_snapshot(Sink& sink) {
    state_ = State::AwaitingSnapshot;
    ++m_.snapshot_signals;
    window_base_ = next_;  // keep what is buffered; slide forward with the live stream
    reset_recovery();
    sink.on_snapshot_needed(next_, known_end_);
  }

  template <class Sink>
  void after_progress(Nanos now, Sink& sink) {
    if (state_ != State::Live) return;
    complete_requests();
    if (next_ >= known_end_) {
      if (in_gap_) {
        in_gap_ = false;
        if (episode_used_rerequest_ || !is_line(last_fill_)) {
          ++m_.gaps_filled_by_rerequest;
          SIM_PROBE("arb.both_lines_loss_rerequest");  // 09 §8: loss on both lines, recovered
        } else {
          ++m_.gaps_filled_by_line[static_cast<std::size_t>(last_fill_)];
          if (last_fill_ == Source::LineB) SIM_PROBE("arb.a_gap_filled_by_b");  // 09 §8
        }
        reset_recovery();
      }
      if (eos_seq_ != 0 && next_ >= eos_seq_) {
        state_ = State::Ended;
        sink.on_end_of_session(eos_seq_);
      }
      return;
    }
    if (!in_gap_) {
      in_gap_ = true;
      gap_start_ = now;
      episode_used_rerequest_ = false;
      ++m_.gaps_opened;
    }
    const SeqNo missing = known_end_ - next_ - buffered_;
    if (overflow_ || (cfg_.snapshot_gap_messages != 0 && missing > cfg_.snapshot_gap_messages) ||
        (cfg_.max_gap_age > 0 && now - gap_start_ >= cfg_.max_gap_age)) {
      trigger_snapshot(sink);
      return;
    }
    maybe_send_requests(now, sink);
  }

  LineArbiterConfig cfg_;
  std::size_t cap_;
  SeqNo mask_;
  Session session_;
  bool session_known_;
  State state_ = State::Live;
  SeqNo next_ = 0;
  SeqNo known_end_ = 0;  // exclusive: every sequence below it is known to exist
  SeqNo eos_seq_ = 0;
  std::unique_ptr<Slot[]> slots_;
  std::unique_ptr<std::byte[]> data_;
  std::unique_ptr<Arrival[]> arrivals_;
  std::size_t buffered_ = 0;
  SeqNo window_base_ = 0;  // AwaitingSnapshot only; 0 = not set yet
  bool overflow_ = false;
  // Gap episode and recovery.
  bool in_gap_ = false;
  bool episode_used_rerequest_ = false;
  Source last_fill_ = Source::LineA;
  Nanos gap_start_ = 0;
  bool gap_armed_ = false;
  Nanos gap_deadline_ = 0;
  SeqNo pending_limit_ = 0;  // end of the newest hole waiting for the gap timer
  SeqNo request_limit_ = 0;  // requests cover only sequences below this
  bool requesting_ = false;
  std::array<Request, kMaxOutstanding> reqs_{};
  std::uint32_t active_ = 0;
  std::array<Nanos, 2> failed_until_{};  // a server counts as failed until then (or its next reply)
  LineArbiterMetrics m_;
};

}  // namespace lle::mold
