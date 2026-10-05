#pragma once
// The publishing core of mold_replay (03-protocols §6, §9; 07 §3): one message
// stream published as MoldUDP64 on line A and line B, each line packetized
// independently and impaired independently.
//
//   append(msg) --+--> Packetizer A (max_packet[0], burst cadence A) --> LossyLine A --> send(0, pkt)
//                 +--> Packetizer B (max_packet[1], burst cadence B) --> LossyLine B --> send(1, pkt)
//
// Packet boundaries are a pure function of the input and the seed: a line emits
// its open packet when the next message does not fit, or when its seeded burst
// of 1..max_burst messages is complete (the "input queue empty" flush of the
// Packetizer, driven by a seeded cadence instead of wall-clock timing). The two
// lines use different maximum payloads and different cadences, so their
// boundaries differ and the arbiter's partial-overlap path is exercised (03 §6).
// Loss, duplication and reordering per line come from LossyLine, seeded per line.
//
// Scripted outages drop every packet of both lines that carries a message in a
// sequence range (and heartbeats announcing a sequence inside it). They model
// a total feed outage, which forces the receiver into a snapshot join (03 §7
// step 5) when the range exceeds its snapshot threshold.
//
// Sans-I/O: messages and time in, packets out through send(int line, bytes),
// valid only during the call. No allocation after construction.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

#include "client/lossy_line.h"
#include "common/assert.h"
#include "common/hash.h"
#include "common/prng.h"
#include "common/types.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/moldudp64/packetizer.h"

namespace lle::client {

struct Outage {
  SeqNo first = 1;
  std::uint64_t count = 0;
};

struct ReplayFeedConfig {
  mold::Session session{"LLEREPLAY1"};
  std::array<std::size_t, 2> max_packet{mold::kDefaultMaxPacket, 1200};
  std::array<std::uint32_t, 2> max_burst{48, 64};
  std::array<LineImpairment, 2> impair{};
  std::uint64_t seed = 1;
  Nanos heartbeat_interval = kNsPerSec;
  Nanos end_of_session_linger = 10 * kNsPerSec;
  std::vector<Outage> outages;  // sorted by first, non-overlapping
  std::size_t delay_slots = 4096;
};

// Per-line seeds derived from the run seed: independent streams for the burst
// cadence and the impairments of each line.
[[nodiscard]] constexpr std::uint64_t line_seed(std::uint64_t seed, int line, std::uint64_t purpose) noexcept {
  return mix64(seed ^ mix64(0x4C494E45'00000000ull + static_cast<std::uint64_t>(line) * 16 + purpose));
}

class ReplayFeed {
 public:
  static constexpr Nanos kNever = std::numeric_limits<Nanos>::max();

  explicit ReplayFeed(const ReplayFeedConfig& cfg)
      : cfg_(cfg),
        pub_{mold::Packetizer(pcfg(cfg, 0)), mold::Packetizer(pcfg(cfg, 1))},
        line_{LossyLine(cfg.impair[0], line_seed(cfg.seed, 0, 1), cfg.delay_slots, cfg.max_packet[0]),
              LossyLine(cfg.impair[1], line_seed(cfg.seed, 1, 1), cfg.delay_slots, cfg.max_packet[1])},
        burst_rng_{Prng(line_seed(cfg.seed, 0, 2)), Prng(line_seed(cfg.seed, 1, 2))} {
    LLE_ASSERT(cfg.max_burst[0] >= 1 && cfg.max_burst[1] >= 1);
    for (std::size_t i = 1; i < cfg_.outages.size(); ++i)
      LLE_ASSERT(cfg_.outages[i - 1].first + cfg_.outages[i - 1].count <= cfg_.outages[i].first,
                 "outages must be sorted and disjoint");
    for (std::size_t l = 0; l < 2; ++l) draw_burst(l);
  }

  // Publishes the next message (sequence next_seq()). Returns its sequence.
  template <class Send>
  SeqNo append(std::span<const std::byte> msg, Nanos now, Send&& send) {
    const SeqNo seq = pub_[0].next_seq();
    for (std::size_t l = 0; l < 2; ++l) {
      auto emit = [&](std::span<const std::byte> p) { offer(l, p, now, send); };
      const auto r = pub_[l].append(msg, now, emit);
      LLE_ASSERT(r == mold::Packetizer::AppendResult::Ok, "message does not fit a MoldUDP64 packet");
      if (--burst_left_[l] == 0) {
        pub_[l].flush(now, emit);
        draw_burst(l);
      }
    }
    return seq;
  }

  // Emits the open packet of both lines (input exhausted for now).
  template <class Send>
  void flush(Nanos now, Send&& send) {
    for (std::size_t l = 0; l < 2; ++l) {
      auto emit = [&](std::span<const std::byte> p) { offer(l, p, now, send); };
      if (pub_[l].flush(now, emit)) draw_burst(l);
    }
  }

  // Heartbeats, end-of-session repeats and delayed packets that are due.
  template <class Send>
  void on_timer(Nanos now, Send&& send) {
    for (std::size_t l = 0; l < 2; ++l) {
      auto emit = [&](std::span<const std::byte> p) { offer(l, p, now, send); };
      (void)pub_[l].on_timer(now, emit);
      line_[l].release(now, [&](std::span<const std::byte> p) { send(static_cast<int>(l), p); });
    }
  }

  // Flushes both lines and starts the end of session (repeated for the linger).
  template <class Send>
  void end_session(Nanos now, Send&& send) {
    for (std::size_t l = 0; l < 2; ++l) {
      auto emit = [&](std::span<const std::byte> p) { offer(l, p, now, send); };
      pub_[l].end_session(now, emit);
    }
  }

  // Sends every delayed packet immediately.
  template <class Send>
  void release_all(Send&& send) {
    for (std::size_t l = 0; l < 2; ++l)
      line_[l].release_all([&](std::span<const std::byte> p) { send(static_cast<int>(l), p); });
  }

  [[nodiscard]] Nanos next_deadline() const noexcept {
    Nanos d = kNever;
    for (std::size_t l = 0; l < 2; ++l) {
      d = std::min(d, pub_[l].next_deadline());
      d = std::min(d, line_[l].next_deadline());
    }
    return d;
  }

  [[nodiscard]] SeqNo next_seq() const noexcept { return pub_[0].next_seq(); }
  [[nodiscard]] bool done() const noexcept {
    return pub_[0].done() && pub_[1].done() && line_[0].delayed_now() == 0 && line_[1].delayed_now() == 0;
  }
  [[nodiscard]] const mold::PacketizerStats& packetizer_stats(std::size_t l) const noexcept { return pub_[l].stats(); }
  [[nodiscard]] const LineStats& line_stats(std::size_t l) const noexcept { return line_[l].stats(); }
  [[nodiscard]] const ReplayFeedConfig& config() const noexcept { return cfg_; }

  // True when the packet must be dropped by a scripted outage.
  [[nodiscard]] bool in_outage(SeqNo first, std::uint16_t count, bool control) const noexcept {
    if (cfg_.outages.empty()) return false;
    const SeqNo end = control ? first + 1 : first + count;  // exclusive
    // The last outage starting before `end` is the only one that can overlap
    // [first, end): the ranges are sorted and disjoint.
    const auto it = std::upper_bound(cfg_.outages.begin(), cfg_.outages.end(), end - 1,
                                     [](SeqNo s, const Outage& o) { return s < o.first; });
    if (it == cfg_.outages.begin()) return false;
    const Outage& o = *(it - 1);
    return o.first + o.count > first;
  }

 private:
  static mold::PacketizerConfig pcfg(const ReplayFeedConfig& c, std::size_t l) {
    return mold::PacketizerConfig{c.session, c.max_packet[l], c.heartbeat_interval, c.end_of_session_linger, 1};
  }

  void draw_burst(std::size_t l) noexcept {
    burst_left_[l] = 1 + static_cast<std::uint32_t>(burst_rng_[l].below(cfg_.max_burst[l]));
  }

  template <class Send>
  void offer(std::size_t l, std::span<const std::byte> pkt, Nanos now, Send& send) {
    const mold::PacketHeader h = mold::decode_header(pkt.data());
    const bool eos = h.is_end_of_session();
    const bool outage = !eos && in_outage(h.seq, h.message_count(), h.is_heartbeat());
    line_[l].offer(pkt, h.message_count(), outage, now,
                   [&](std::span<const std::byte> p) { send(static_cast<int>(l), p); });
  }

  ReplayFeedConfig cfg_;
  std::array<mold::Packetizer, 2> pub_;
  std::array<LossyLine, 2> line_;
  std::array<Prng, 2> burst_rng_;
  std::array<std::uint32_t, 2> burst_left_{};
};

}  // namespace lle::client
