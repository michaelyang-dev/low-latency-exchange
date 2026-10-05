#pragma once
// Deterministic in-memory link for utcp tests: two endpoints, seeded loss, duplication,
// reordering (extra delay), delay jitter and corruption. A SimClock is advanced by the
// test driver; MemFramePort implements utcp::FramePort over one side of the link.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <queue>
#include <span>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "net/utcp/connection.h"

namespace lle::net::utcp::test {

struct SimClock {
  Nanos t = 0;
  Nanos now_mono() const noexcept { return t; }
  Nanos now_real() const noexcept { return t; }
  std::uint64_t tsc() const noexcept { return static_cast<std::uint64_t>(t); }
};

struct Impairments {
  std::uint32_t loss_ppm = 0;
  std::uint32_t dup_ppm = 0;
  std::uint32_t reorder_ppm = 0;  // frames given an extra delay in [0, reorder_delay]
  std::uint32_t corrupt_ppm = 0;  // one bit flipped
  Nanos delay = 10'000;           // base one-way delay
  Nanos jitter = 0;               // uniform extra delay in [0, jitter]
  Nanos reorder_delay = 0;
};

struct LinkStats {
  std::uint64_t sent = 0;
  std::uint64_t delivered = 0;
  std::uint64_t lost = 0;
  std::uint64_t duplicated = 0;
  std::uint64_t reordered = 0;
  std::uint64_t corrupted = 0;
};

class SimLink {
 public:
  SimLink(std::uint64_t seed, const Impairments& imp)
      : rng_(seed), imp_(imp), trace_(std::getenv("UTCP_TRACE") != nullptr) {}

  void set_impairments(const Impairments& imp) { imp_ = imp; }
  void set_down(bool down) { down_ = down; }

  // Frame sent by side `from` (0/1) at `now`.
  void send(int from, std::span<const std::byte> f, Nanos now) {
    ++stats_.sent;
    const bool lost = down_ || rng_.chance(imp_.loss_ppm, 1'000'000);
    if (trace_) print(from, f, now, lost);
    if (lost) {
      ++stats_.lost;
      return;
    }
    const int copies = rng_.chance(imp_.dup_ppm, 1'000'000) ? 2 : 1;
    if (copies == 2) ++stats_.duplicated;
    for (int c = 0; c < copies; ++c) {
      Frame fr;
      fr.at = now + imp_.delay;
      if (imp_.jitter > 0) fr.at += static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(imp_.jitter) + 1));
      if (imp_.reorder_delay > 0 && rng_.chance(imp_.reorder_ppm, 1'000'000)) {
        ++stats_.reordered;
        fr.at += static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(imp_.reorder_delay) + 1));
      }
      fr.order = order_++;
      fr.bytes.assign(f.begin(), f.end());
      if (!fr.bytes.empty() && rng_.chance(imp_.corrupt_ppm, 1'000'000)) {
        ++stats_.corrupted;
        fr.bytes[rng_.below(fr.bytes.size())] ^= std::byte{static_cast<unsigned char>(1u << rng_.below(8))};
      }
      q_[static_cast<std::size_t>(1 - from)].push(std::move(fr));
    }
  }

  // Delivers frames due at `now` to side `to`.
  template <class Cb>
  std::size_t deliver(int to, Nanos now, Cb&& cb) {
    auto& q = q_[static_cast<std::size_t>(to)];
    std::size_t n = 0;
    while (!q.empty() && q.top().at <= now) {
      Frame fr = q.top();
      q.pop();
      ++stats_.delivered;
      cb(std::span<const std::byte>(fr.bytes.data(), fr.bytes.size()), Nanos{0});
      ++n;
    }
    return n;
  }

  [[nodiscard]] Nanos next_delivery() const noexcept {
    Nanos t = kNoDeadline;
    for (const auto& q : q_) {
      if (!q.empty() && q.top().at < t) t = q.top().at;
    }
    return t;
  }
  [[nodiscard]] bool idle() const noexcept { return q_[0].empty() && q_[1].empty(); }
  [[nodiscard]] const LinkStats& stats() const noexcept { return stats_; }

 private:
  struct Frame {
    Nanos at = 0;
    std::uint64_t order = 0;
    std::vector<std::byte> bytes;
  };
  struct Later {
    bool operator()(const Frame& a, const Frame& b) const noexcept {
      return a.at != b.at ? a.at > b.at : a.order > b.order;
    }
  };
  static void print(int from, std::span<const std::byte> f, Nanos now, bool lost) {
    auto seg = parse_tcp(f, LinkType::Ethernet, false);
    if (!seg) {
      std::printf("%12lld %s non-tcp %zu bytes%s\n", static_cast<long long>(now), from == 0 ? "c>s" : "s>c", f.size(),
                  lost ? " LOST" : "");
      return;
    }
    std::printf("%12lld %s dmac ..%02x %c%c%c%c%c seq %u ack %u len %zu win %u%s\n", static_cast<long long>(now),
                from == 0 ? "c>s" : "s>c", seg->dst_mac.b[5], seg->has(tcp_flag::kSyn) ? 'S' : '-', seg->has(tcp_flag::kFin) ? 'F' : '-',
                seg->has(tcp_flag::kRst) ? 'R' : '-', seg->has(tcp_flag::kPsh) ? 'P' : '-',
                seg->has(tcp_flag::kAck) ? '.' : '-', seg->seq, seg->ack, seg->payload.size(), seg->window,
                lost ? " LOST" : "");
  }

  Prng rng_;
  Impairments imp_;
  bool trace_ = false;
  bool down_ = false;
  std::uint64_t order_ = 0;
  std::priority_queue<Frame, std::vector<Frame>, Later> q_[2];
  LinkStats stats_{};
};

class MemFramePort {
 public:
  MemFramePort(SimLink& link, int side, SimClock& clock) : link_(link), side_(side), clock_(clock) {}
  bool send_frame(std::span<const std::byte> f) {
    link_.send(side_, f, clock_.t);
    return true;
  }
  template <class Cb>
  std::size_t poll_frames(Cb&& cb) {
    return link_.deliver(side_, clock_.t, cb);
  }

 private:
  SimLink& link_;
  int side_;
  SimClock& clock_;
};

}  // namespace lle::net::utcp::test
