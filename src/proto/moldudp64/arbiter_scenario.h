#pragma once
// Deterministic end-to-end A/B feed scenario for tests, fuzzing and the
// simulator's arbiter_* scenarios (03-protocols §7 "Oracle", §9).
//
//   publisher -> Packetizer A (max_packet_a) -> lossy line A --+
//             -> Packetizer B (max_packet_b) -> lossy line B ---> LineArbiter
//             -> MessageRing -> RerequestServer A / B <---------- re-requests
//                               snapshot service <--------------- on_snapshot_needed
//
// Lines independently drop, duplicate and delay (reorder) packets; servers can
// be down or lose replies. All randomness comes from one lle::Prng seed and
// time is virtual, so a seed reproduces a run exactly.
//
// Oracle: every sequence 1..N is delivered exactly once, in order, with the
// published bytes, except ranges covered by a snapshot splice; end of session
// is delivered once, after the last message. Test-support code: it allocates.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <queue>
#include <string>
#include <vector>

#include "common/hash.h"
#include "common/prng.h"
#include "common/types.h"
#include "env/concepts.h"
#include "proto/moldudp64/line_arbiter.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/packetizer.h"
#include "proto/moldudp64/rerequest_server.h"

namespace lle::mold::scenario {

struct ScenarioConfig {
  std::uint64_t seed = 1;
  std::uint64_t messages = 5'000;
  std::uint32_t max_batch = 8;          // messages published per input burst
  Nanos burst_interval = 2'000;         // between bursts
  std::size_t max_packet_a = 1'472;
  std::size_t max_packet_b = 1'200;     // B also flushes on its own cadence (different boundaries)
  std::uint32_t loss_ppm_a = 0, loss_ppm_b = 0;
  std::uint32_t dup_ppm = 0;            // per line packet duplication
  std::uint32_t reorder_ppm = 0;        // packet gets an extra delay up to max_reorder_delay
  Nanos max_reorder_delay = 40'000;
  Nanos delay_a = 5'000, delay_b = 9'000, jitter = 2'000;
  bool server_a_up = true, server_b_up = true;
  std::uint32_t reply_loss_ppm = 0;
  Nanos server_rtt = 30'000;
  Nanos snapshot_latency = 500'000;
  Nanos heartbeat_interval = 200'000;
  std::uint32_t outage_every = 0;       // if > 0: every Nth burst both lines drop everything for outage_len bursts
  std::uint32_t outage_len = 0;
  LineArbiterConfig arbiter{};
  Nanos time_limit = 120 * kNsPerSec;
};

struct ScenarioResult {
  bool ok = false;
  std::string error;
  std::uint64_t delivered = 0;
  std::uint64_t snapshot_covered = 0;
  std::uint64_t snapshots = 0;
  bool ended = false;
  Nanos end_time = 0;
  LineArbiterMetrics metrics;
};

// Deterministic content of message `seq`: 1..48 bytes derived from (seed, seq).
inline std::size_t fill_message(std::uint64_t seed, SeqNo seq, std::byte* out) noexcept {
  std::uint64_t h = mix64(seed ^ (seq * 0x9E3779B97F4A7C15ull));
  const std::size_t len = 1 + h % 48;
  for (std::size_t i = 0; i < len; ++i) {
    if (i % 8 == 0) h = mix64(h + i);
    out[i] = static_cast<std::byte>(h >> (8 * (i % 8)));
  }
  return len;
}

namespace detail {

enum class EvKind : std::uint8_t { Packet, Request, Resume };

struct Event {
  Nanos t = 0;
  std::uint64_t order = 0;  // FIFO among equal times
  EvKind kind = EvKind::Packet;
  Source src = Source::LineA;  // Packet: arbiter source; Request: Server via src (RerequestA/B)
  SeqNo resume_seq = 0;
  std::vector<std::byte> bytes;
  friend bool operator>(const Event& a, const Event& b) { return a.t != b.t ? a.t > b.t : a.order > b.order; }
};

}  // namespace detail

inline ScenarioResult run_scenario(const ScenarioConfig& cfg) {
  using detail::Event;
  using detail::EvKind;
  ScenarioResult res;
  Prng rng(cfg.seed);
  const Session session("SCENARIO01");

  std::priority_queue<Event, std::vector<Event>, std::greater<>> q;
  std::uint64_t order = 0;
  auto push = [&](Nanos t, EvKind k, Source s, std::span<const std::byte> b, SeqNo r = 0) {
    q.push(Event{t, order++, k, s, r, std::vector<std::byte>(b.begin(), b.end())});
  };

  MessageRing store(1 << 20, 64 << 20);
  RerequestConfig rcfg;
  rcfg.session = session;
  rcfg.max_packet = cfg.max_packet_a;
  rcfg.bucket_capacity = 1'000'000;
  RerequestServer<MessageRing> srv_a(rcfg, store);
  RerequestServer<MessageRing> srv_b(rcfg, store);

  // End of session repeats long enough that losing every copy on both lines is negligible.
  PacketizerConfig pa{session, cfg.max_packet_a, cfg.heartbeat_interval, 40 * cfg.heartbeat_interval, 1};
  PacketizerConfig pb{session, cfg.max_packet_b, cfg.heartbeat_interval, 40 * cfg.heartbeat_interval, 1};
  Packetizer pub_a(pa), pub_b(pb);

  LineArbiterConfig acfg = cfg.arbiter;
  acfg.session = session;
  LineArbiter arb(acfg);

  bool outage = false;
  auto send_line = [&](Source line, std::span<const std::byte> pkt, Nanos now) {
    const bool is_a = line == Source::LineA;
    if (outage) return;
    if (rng.chance(is_a ? cfg.loss_ppm_a : cfg.loss_ppm_b, 1'000'000)) return;
    const int copies = rng.chance(cfg.dup_ppm, 1'000'000) ? 2 : 1;
    for (int c = 0; c < copies; ++c) {
      Nanos d = (is_a ? cfg.delay_a : cfg.delay_b) + static_cast<Nanos>(rng.below(static_cast<std::uint64_t>(cfg.jitter) + 1));
      if (rng.chance(cfg.reorder_ppm, 1'000'000))
        d += static_cast<Nanos>(rng.below(static_cast<std::uint64_t>(cfg.max_reorder_delay) + 1));
      push(now + d, EvKind::Packet, line, pkt);
    }
  };

  // Oracle state.
  SeqNo expect = 1;
  std::byte want[64];
  Nanos now = 0;

  struct Sink {
    ScenarioResult& res;
    const ScenarioConfig& cfg;
    SeqNo& expect;
    std::byte* want;
    std::function<void(EvKind, Source, std::span<const std::byte>, SeqNo)> schedule;
    void on_message(SeqNo s, std::span<const std::byte> m) {
      if (!res.error.empty()) return;
      if (s != expect) {
        res.error = "delivered seq " + std::to_string(s) + " expected " + std::to_string(expect);
        return;
      }
      const std::size_t n = fill_message(cfg.seed, s, want);
      if (m.size() != n || std::memcmp(m.data(), want, n) != 0) {
        res.error = "content mismatch at seq " + std::to_string(s);
        return;
      }
      ++expect;
      ++res.delivered;
    }
    void send_request(Server v, std::span<const std::byte> b) {
      schedule(EvKind::Request, v == Server::A ? Source::RerequestA : Source::RerequestB, b, 0);
    }
    void on_snapshot_needed(SeqNo, SeqNo) {
      ++res.snapshots;
      schedule(EvKind::Resume, Source::LineA, {}, 0);
    }
    void on_end_of_session(SeqNo e) {
      if (res.ended) res.error = "end of session delivered twice";
      if (e != expect && res.error.empty())
        res.error = "end of session " + std::to_string(e) + " but next expected " + std::to_string(expect);
      res.ended = true;
    }
  };
  Sink sink{res, cfg, expect, want,
            [&](EvKind k, Source s, std::span<const std::byte> b, SeqNo r) {
              const Nanos lat = k == EvKind::Resume ? cfg.snapshot_latency : cfg.server_rtt / 2;
              push(now + lat, k, s, b, r);
            }};

  // Publisher schedule.
  SeqNo published = 0;
  Nanos next_burst = 0;
  std::uint32_t burst_no = 0;
  std::uint64_t b_left = 1 + rng.below(2 * std::uint64_t{cfg.max_batch});
  bool ended_pub = false;
  std::byte msg[64];
  auto emit_a = [&](std::span<const std::byte> p) { send_line(Source::LineA, p, now); };
  auto emit_b = [&](std::span<const std::byte> p) { send_line(Source::LineB, p, now); };

  while (now < cfg.time_limit && res.error.empty() && !res.ended) {
    // Next event time.
    Nanos t = LineArbiter::kNever;
    if (!q.empty()) t = q.top().t;
    t = std::min(t, arb.next_deadline());
    if (!ended_pub) t = std::min(t, next_burst);
    t = std::min({t, pub_a.next_deadline(), pub_b.next_deadline()});
    if (t == LineArbiter::kNever) {
      res.error = "stalled: nothing scheduled";
      break;
    }
    now = std::max(now, t);

    if (!ended_pub && now >= next_burst) {
      ++burst_no;
      if (cfg.outage_every != 0) outage = (burst_no % cfg.outage_every) < cfg.outage_len;
      const std::uint64_t k = 1 + rng.below(cfg.max_batch);
      for (std::uint64_t i = 0; i < k && published < cfg.messages; ++i) {
        ++published;
        const std::size_t n = fill_message(cfg.seed, published, msg);
        const std::span<const std::byte> m(msg, n);
        store.append(m);
        (void)pub_a.append(m, now, emit_a);
        (void)pub_b.append(m, now, emit_b);
        // Line B models a backup publisher whose input arrives in different
        // chunks: it flushes on its own cadence, so its packet boundaries differ.
        if (--b_left == 0) {
          pub_b.flush(now, emit_b);
          b_left = 1 + rng.below(2 * std::uint64_t{cfg.max_batch});
        }
      }
      pub_a.flush(now, emit_a);
      if (published >= cfg.messages) {
        outage = false;
        pub_a.end_session(now, emit_a);
        pub_b.end_session(now, emit_b);
        ended_pub = true;
      }
      next_burst = now + cfg.burst_interval;
    }
    pub_a.on_timer(now, emit_a);
    pub_b.on_timer(now, emit_b);

    while (!q.empty() && q.top().t <= now && res.error.empty() && !res.ended) {
      Event e = q.top();
      q.pop();
      if (e.kind == EvKind::Packet) {
        arb.on_packet(e.src, e.bytes, now, sink);
      } else if (e.kind == EvKind::Request) {
        const bool to_a = e.src == Source::RerequestA;
        if (!(to_a ? cfg.server_a_up : cfg.server_b_up)) continue;
        auto& srv = to_a ? srv_a : srv_b;
        srv.on_request(e.bytes, env::Endpoint{1, 1}, now, [&](const env::Endpoint&, std::span<const std::byte> pkt) {
          if (rng.chance(cfg.reply_loss_ppm, 1'000'000)) return;
          push(now + cfg.server_rtt / 2, EvKind::Packet, e.src, pkt);
        });
      } else {
        // Snapshot service: state as of everything released so far.
        const SeqNo g = store.highest() + 1;
        if (g > expect) res.snapshot_covered += g - expect;
        if (g >= expect) expect = g;
        arb.resume_from_snapshot(g, now, sink);
      }
    }
    if (arb.next_deadline() <= now) arb.on_timer(now, sink);
  }
  res.metrics = arb.metrics();
  res.end_time = now;
  if (res.error.empty() && !res.ended) res.error = "did not reach end of session (next " + std::to_string(expect) + ")";
  if (res.error.empty() && res.delivered + res.snapshot_covered != cfg.messages)
    res.error = "delivered " + std::to_string(res.delivered) + " + snapshot " + std::to_string(res.snapshot_covered) +
                " != published " + std::to_string(cfg.messages);
  res.ok = res.error.empty();
  return res;
}

}  // namespace lle::mold::scenario
