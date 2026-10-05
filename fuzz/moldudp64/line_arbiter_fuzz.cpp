// Fuzz target: LineArbiter (03-protocols §7 oracle: exactly once, in order).
//
// Mode 0 (scenario): the input selects an end-to-end scenario (seed, per-line
// loss/duplication/reordering, server outages, line outages, arbiter limits)
// run by scenario::run_scenario; the oracle must hold for every input.
// Mode 1 (raw): the input is a program of adversarial operations (packets with
// arbitrary sequence ranges from any source, heartbeats and end of session
// anywhere, malformed and foreign-session packets, timer ticks, re-request
// replies, forced snapshot splices). Every packet for sequence s carries the
// same bytes, so delivery must be strictly consecutive (restarting only at a
// splice point) with the right content, and end of session at most once.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "common/hash.h"
#include "proto/moldudp64/arbiter_scenario.h"
#include "proto/moldudp64/line_arbiter.h"

using namespace lle;
using namespace lle::mold;

namespace {

class Input {
 public:
  Input(const std::uint8_t* d, std::size_t n) : d_(d), n_(n) {}
  std::uint8_t u8() { return at_ < n_ ? d_[at_++] : 0; }
  std::uint16_t u16() { return static_cast<std::uint16_t>((u8() << 8) | u8()); }
  std::uint64_t u64() {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | u8();
    return v;
  }
  [[nodiscard]] bool done() const { return at_ >= n_; }

 private:
  const std::uint8_t* d_;
  std::size_t n_;
  std::size_t at_ = 0;
};

void run_scenario_mode(Input& in) {
  scenario::ScenarioConfig c;
  c.seed = in.u64();
  c.messages = 200 + in.u16() % 1500;
  c.max_batch = 1 + in.u8() % 24;
  c.max_packet_b = 100 + in.u16() % 1372;
  c.loss_ppm_a = in.u8() * 1500u;
  c.loss_ppm_b = in.u8() * 1500u;
  c.dup_ppm = in.u8() * 400u;
  c.reorder_ppm = in.u8() * 400u;
  const std::uint8_t flags = in.u8();
  c.server_a_up = (flags & 1) == 0;
  c.server_b_up = (flags & 2) == 0;
  c.reply_loss_ppm = in.u8() * 1000u;
  if ((flags & 4) != 0) {
    c.outage_every = 20 + in.u8();
    c.outage_len = in.u8() % c.outage_every;
  }
  c.arbiter.reorder_capacity = std::size_t{1} << (8 + in.u8() % 6);
  c.arbiter.snapshot_gap_messages = 50 + in.u16() % 5000;
  c.arbiter.max_outstanding = 1 + in.u8() % 8;
  c.arbiter.request_max_count = static_cast<std::uint16_t>(1 + in.u8() % 100);
  c.arbiter.gap_timeout = in.u8() * 1000;
  c.arbiter.request_timeout = 50'000 + in.u8() * 10'000;
  if ((flags & 8) != 0) c.arbiter.max_gap_age = 1'000'000 + in.u8() * 100'000;
  const auto r = scenario::run_scenario(c);
  if (!r.ok) {
    std::fprintf(stderr, "scenario oracle failed: %s\n", r.error.c_str());
    std::abort();
  }
}

// Content of sequence s in raw mode: 1..40 bytes derived from s.
std::size_t content(SeqNo s, std::byte* out) {
  std::uint64_t h = mix64(s);
  const std::size_t len = 1 + h % 40;
  for (std::size_t i = 0; i < len; ++i) out[i] = static_cast<std::byte>(mix64(h + i));
  return len;
}

struct RawSink {
  SeqNo expect = 0;  // 0: unknown (late join, before the first splice)
  bool ended = false;
  std::vector<RequestPacket> requests;
  bool snapshot_pending = false;
  SeqNo snapshot_next = 0;
  void on_message(SeqNo s, std::span<const std::byte> m) {
    LLE_ASSERT(!ended, "delivery after end of session");
    LLE_ASSERT(expect != 0, "delivery before the snapshot splice");
    LLE_ASSERT(s == expect, "out-of-order or duplicate delivery");
    std::byte want[64];
    const std::size_t n = content(s, want);
    LLE_ASSERT(m.size() == n && std::memcmp(m.data(), want, n) == 0, "content mismatch");
    ++expect;
  }
  void send_request(Server, std::span<const std::byte> b) {
    const auto r = decode_request(b);
    LLE_ASSERT(r.has_value() && r->count >= 1 && r->seq >= 1, "arbiter sent a malformed request");
    if (requests.size() < 64) requests.push_back(*r);
  }
  void on_snapshot_needed(SeqNo next, SeqNo known_end) {
    LLE_ASSERT(next <= known_end);
    snapshot_pending = true;
    snapshot_next = next;
  }
  void on_end_of_session(SeqNo) {
    LLE_ASSERT(!ended, "end of session delivered twice");
    ended = true;
  }
};

std::vector<std::byte> make_packet(const Session& s, SeqNo first, std::uint16_t count) {
  std::vector<std::byte> buf(kHeaderLen + count * 42);
  PacketBuilder b(buf, s, first);
  std::byte m[64];
  for (std::uint16_t i = 0; i < count; ++i) b.add(std::span<const std::byte>(m, content(first + i, m)));
  const auto p = b.finish();
  return {p.begin(), p.end()};
}

void run_raw_mode(Input& in) {
  const Session session("RAWFUZZ001");
  LineArbiterConfig cfg;
  cfg.session = session;
  const std::uint8_t setup = in.u8();
  cfg.first_seq = (setup & 1) != 0 ? 0 : 1 + in.u8() % 4;
  cfg.reorder_capacity = std::size_t{1} << (4 + setup % 6);
  cfg.snapshot_gap_messages = (setup & 0x40) != 0 ? 0 : 1 + in.u8();
  cfg.gap_timeout = in.u8();
  cfg.request_timeout = 1 + in.u8() * 10;
  cfg.max_outstanding = 1 + in.u8() % 4;
  cfg.request_max_count = static_cast<std::uint16_t>(1 + in.u8() % 50);
  cfg.max_gap_age = (setup & 0x80) != 0 ? 1 + in.u8() * 50 : 0;
  LineArbiter arb(cfg);
  RawSink sink;
  if (cfg.first_seq != 0) sink.expect = cfg.first_seq;
  Nanos now = 0;
  int ops = 0;
  while (!in.done() && ++ops < 2000) {
    const std::uint8_t op = in.u8();
    now += op % 16;
    const SeqNo base = arb.next_expected() > 30 ? arb.next_expected() - 30 : 1;
    switch (op % 9) {
      case 0:
      case 1:
      case 2: {
        const auto src = static_cast<Source>(in.u8() % 4);
        const SeqNo first = base + in.u16() % 200;
        const auto count = static_cast<std::uint16_t>(1 + in.u8() % 24);
        arb.on_packet(src, make_packet(session, first, count), now, sink);
        break;
      }
      case 3: {
        std::vector<std::byte> p(kHeaderLen);
        encode_control(p, session, base + in.u8() % 80, (op & 0x80) != 0);
        arb.on_packet(static_cast<Source>(in.u8() % 2), p, now, sink);
        break;
      }
      case 4: {
        std::vector<std::byte> junk(in.u8() % 48);
        for (auto& b : junk) b = static_cast<std::byte>(in.u8());
        arb.on_packet(static_cast<Source>(in.u8() % 4), junk, now, sink);
        break;
      }
      case 5:
        arb.on_packet(Source::LineB, make_packet(Session("FOREIGN"), base, 3), now, sink);
        break;
      case 6:
        now += in.u8() * 13;
        arb.on_timer(now, sink);
        break;
      case 7: {  // answer queued re-requests (maybe from the wrong server or truncated)
        // Take the queue first: replies can make the arbiter send new requests.
        const std::vector<RequestPacket> pending = std::move(sink.requests);
        sink.requests.clear();
        for (const auto& r : pending) {
          const auto n = static_cast<std::uint16_t>(1 + in.u8() % r.count);
          arb.on_packet(static_cast<Source>(2 + in.u8() % 2), make_packet(session, r.seq, n), now, sink);
        }
        break;
      }
      default: {  // splice: requested snapshot, or a forced resync now and then
        if (!sink.snapshot_pending && (in.u8() & 7) != 0) break;
        const SeqNo floor = sink.snapshot_pending ? sink.snapshot_next : arb.next_expected();
        const SeqNo g = std::max<SeqNo>(1, floor + in.u8() % 40);
        sink.snapshot_pending = false;
        if (!sink.ended) sink.expect = g;
        arb.resume_from_snapshot(g, now, sink);
        break;
      }
    }
    if (arb.next_deadline() <= now) arb.on_timer(now, sink);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  Input in(data + 1, size - 1);
  if ((data[0] & 1) == 0) {
    // Scenario runs are expensive; keep their share of random inputs small.
    if ((data[0] & 0x0E) == 0) run_scenario_mode(in);
  } else {
    run_raw_mode(in);
  }
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 4 || cap < 64) return 0;
  // 0, 1: scenario mode (clean, lossy); 2, 3: raw mode programs.
  std::size_t n = 0;
  if (index <= 1) {
    buf[n++] = 0;
    for (std::size_t i = 0; i < 8; ++i) buf[n++] = static_cast<std::uint8_t>(index * 31 + i);
    buf[n++] = 1;  // messages
    buf[n++] = 0;
    buf[n++] = 8;  // max batch
    buf[n++] = 2;
    buf[n++] = 0;  // max_packet_b
    buf[n++] = index == 1 ? 60 : 0;
    buf[n++] = index == 1 ? 60 : 0;
    buf[n++] = index == 1 ? 20 : 0;
    buf[n++] = index == 1 ? 20 : 0;
  } else {
    buf[n++] = 1;
    buf[n++] = static_cast<std::uint8_t>(index == 2 ? 0x06 : 0x47);
    for (std::size_t i = 0; i < 40; ++i) buf[n++] = static_cast<std::uint8_t>((i * 37 + index) & 0xFF);
  }
  return n;
}
