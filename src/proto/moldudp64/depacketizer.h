#pragma once
// Single-line MoldUDP64 receiver core (03-protocols §6; spec receiver flow in
// R1b D1): validates packets, locks the session, delivers each message once and
// in sequence order, and reports gaps. Packets that start beyond the next
// expected sequence are dropped (GapPolicy::Drop, the spec flowchart: the
// caller re-requests [next, seq) and waits) or skipped over (GapPolicy::Skip,
// for tools that tolerate loss). A/B arbitration with reordering and recovery
// is LineArbiter's job.
//
// Sink:
//   void on_message(SeqNo seq, std::span<const std::byte> msg);
//   void on_gap(SeqNo first_missing, SeqNo end_missing);   // [first, end)
//   void on_end_of_session(SeqNo next_seq);
#include <cstdint>
#include <span>

#include "common/types.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::mold {

enum class GapPolicy : std::uint8_t { Drop, Skip };

struct DepacketizerConfig {
  Session session;  // blank: learn from the first valid packet
  SeqNo first_seq = 1;
  GapPolicy gap_policy = GapPolicy::Drop;
};

struct DepacketizerStats {
  std::uint64_t packets = 0, messages = 0, duplicates = 0, partial_overlaps = 0, gaps = 0, skipped_messages = 0;
  std::uint64_t heartbeats = 0, end_of_session = 0, malformed = 0, wrong_session = 0;
};

class Depacketizer {
 public:
  enum class Result : std::uint8_t { Delivered, Duplicate, Gap, Heartbeat, EndOfSession, Malformed, WrongSession };

  explicit Depacketizer(const DepacketizerConfig& cfg) noexcept
      : cfg_(cfg), session_(cfg.session), session_known_(!cfg.session.blank()), next_(cfg.first_seq) {}

  template <class Sink>
  Result on_packet(std::span<const std::byte> bytes, Sink& sink) {
    const auto pv = PacketView::parse(bytes);
    if (!pv) {
      ++stats_.malformed;
      return Result::Malformed;
    }
    const PacketHeader& h = pv->header();
    if (!session_known_) {
      session_ = h.session;
      session_known_ = true;
    } else if (h.session != session_) {
      ++stats_.wrong_session;
      return Result::WrongSession;
    }
    ++stats_.packets;
    if (h.is_heartbeat() || h.is_end_of_session()) {
      const bool eos = h.is_end_of_session();
      ++(eos ? stats_.end_of_session : stats_.heartbeats);
      if (h.seq > next_) {
        // Tail gap exposed by a heartbeat / end of session.
        ++stats_.gaps;
        sink.on_gap(next_, h.seq);
        if (cfg_.gap_policy == GapPolicy::Skip) {
          stats_.skipped_messages += h.seq - next_;
          next_ = h.seq;
        } else {
          return Result::Gap;
        }
      }
      if (eos) {
        if (!ended_) sink.on_end_of_session(h.seq);
        ended_ = true;
        return Result::EndOfSession;
      }
      return Result::Heartbeat;
    }
    const SeqNo first = h.seq;
    const SeqNo end = pv->end_seq();
    if (end <= next_) {
      ++stats_.duplicates;
      return Result::Duplicate;
    }
    if (first > next_) {
      ++stats_.gaps;
      sink.on_gap(next_, first);
      if (cfg_.gap_policy == GapPolicy::Drop) return Result::Gap;
      stats_.skipped_messages += first - next_;
      next_ = first;
    }
    if (first < next_) ++stats_.partial_overlaps;
    pv->for_each_from(static_cast<std::size_t>(next_ - first), [&](SeqNo s, std::span<const std::byte> m) {
      sink.on_message(s, m);
      ++stats_.messages;
    });
    next_ = end;
    return Result::Delivered;
  }

  [[nodiscard]] SeqNo next_expected() const noexcept { return next_; }
  [[nodiscard]] const Session& session() const noexcept { return session_; }
  [[nodiscard]] bool session_known() const noexcept { return session_known_; }
  [[nodiscard]] bool ended() const noexcept { return ended_; }
  [[nodiscard]] const DepacketizerStats& stats() const noexcept { return stats_; }

 private:
  DepacketizerConfig cfg_;
  Session session_;
  bool session_known_;
  bool ended_ = false;
  SeqNo next_;
  DepacketizerStats stats_;
};

}  // namespace lle::mold
