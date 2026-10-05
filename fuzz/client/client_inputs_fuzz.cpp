// Fuzz target: the client programs' parsers of untrusted bytes (07 §3).
//
// The first input byte picks the consumer; the rest is a program for it.
//   0  refclient's feed handler: MoldUDP64 packets from any source (raw bytes or
//      well-formed packets around a moving sequence with ITCH payloads from the
//      input), timer ticks, snapshot spin payloads, splices. The book's full
//      structural check must hold at the end and delivery must be consecutive.
//   1  HA order entry: SoupBinTCP server bytes on either instance, sends of
//      arbitrary OUCH, connects and closes. Pending stays bounded, responses are
//      handed out at most once per sequence.
//   2  loadgen's response accounting: arbitrary OUCH outbound messages.
//   3  itch2ouch's converter: arbitrary ITCH messages; every emitted record must
//      be a whole OUCH message the inbound decoder frames.
//   4  the instruments' text parsers: flat JSON reports, loadgen profiles, metrics
//      sample lines (no crash; a parsed profile satisfies its own checks).
//   5  TX-stamp attribution: arbitrary frames into FrameStampTracker, completions and
//      expected messages into StreamTxMatcher; every message is matched at most once.
// Each run is deterministic for its input.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "client/feed_handler.h"
#include "client/itch2ouch.h"
#include "client/loadgen.h"
#include "client/backlog.h"
#include "client/loadgen_profile.h"
#include "client/order_entry.h"
#include "client/report.h"
#include "client/tx_stamps.h"
#include "common/assert.h"
#include "common/endian.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/ouch50/ouch50.h"

using namespace lle;

namespace {

class Input {
 public:
  Input(const std::uint8_t* d, std::size_t n) : d_(d), n_(n) {}
  std::uint8_t u8() { return at_ < n_ ? d_[at_++] : 0; }
  std::uint16_t u16() { return static_cast<std::uint16_t>((u8() << 8) | u8()); }
  std::uint32_t u32() { return (std::uint32_t{u16()} << 16) | u16(); }
  std::span<const std::byte> bytes(std::size_t n) {
    n = std::min(n, n_ - at_);
    const auto* p = reinterpret_cast<const std::byte*>(d_ + at_);
    at_ += n;
    return {p, n};
  }
  [[nodiscard]] bool done() const { return at_ >= n_; }

 private:
  const std::uint8_t* d_;
  std::size_t n_;
  std::size_t at_ = 0;
};

struct FeedDown {
  SeqNo last = 0;
  void on_book_message(SeqNo seq, std::span<const std::byte>) {
    // Exactly once and in order: never a sequence at or below one delivered
    // (consecutive except across a snapshot splice, which only moves forward).
    if (seq <= last) __builtin_trap();
    last = seq;
  }
  void on_snapshot_message(std::span<const std::byte>) {}
  void send_request(mold::Server, std::span<const std::byte> r) {
    if (r.size() != mold::kRequestLen) __builtin_trap();
  }
  void on_snapshot_needed(SeqNo, SeqNo) {}
  void on_end_of_session(SeqNo) {}
};

void fuzz_feed(Input& in) {
  client::FeedConfig c;
  c.book.reserve_orders = 1 << 10;
  c.book.reserve_levels = 1 << 8;
  c.arbiter.session = mold::Session("FUZZ");
  c.arbiter.reorder_capacity = 1 << 10;
  c.arbiter.snapshot_gap_messages = 1 + in.u8();
  c.arbiter.gap_timeout = 1'000;
  c.arbiter.request_timeout = 5'000;
  c.checkpoints.every = 1 + in.u8();
  client::FeedHandler<book::BboRecorder> fh(c);
  FeedDown down;
  Nanos now = 0;
  SeqNo base = 1;
  std::vector<std::byte> pkt(1500);
  while (!in.done()) {
    now += in.u8() * 100;
    const std::uint8_t op = in.u8() % 6;
    const auto src = static_cast<mold::Source>(in.u8() % 4);
    if (op == 0) {  // raw bytes
      fh.on_packet(src, in.bytes(in.u8()), now, down);
    } else if (op <= 2) {  // a well-formed packet near the current position
      const SeqNo seq = base + in.u8() % 32;
      mold::PacketBuilder b(pkt, mold::Session("FUZZ"), seq);
      const std::uint8_t k = in.u8() % 8;
      for (std::uint8_t i = 0; i < k; ++i) {
        const std::uint8_t len = in.u8() % 51;
        (void)b.add(in.bytes(len));
      }
      fh.on_packet(src, b.finish(), now, down);
      if (in.u8() % 4 == 0) base += k;
    } else if (op == 3) {
      if (now >= fh.next_deadline()) fh.on_timer(now, down);
    } else if (op == 4) {  // a spin payload
      fh.on_snapshot_payload(in.bytes(in.u8() % 60), now, down);
    } else if (in.u8() % 2 == 0) {
      fh.abort_snapshot();
    } else {
      fh.begin_snapshot();
    }
  }
  std::string err;
  if (!fh.book().check_invariants(&err)) __builtin_trap();
}

void fuzz_orders(Input& in) {
  client::OrderEntryConfig c;
  c.pending_capacity = 8;
  c.session.username = Alpha<6>("U00001");
  client::HaOrderEntry oe(c);
  Nanos now = 0;
  SeqNo last = 0;
  while (!in.done()) {
    now += in.u8() * 1'000;
    const std::size_t i = in.u8() % 2;
    switch (in.u8() % 6) {
      case 0: oe.on_connected(i, now); break;
      case 1: oe.on_closed(i, now); break;
      case 2:
        oe.on_bytes(i, in.bytes(in.u8()), now, [&](SeqNo s, std::span<const std::byte>) {
          if (s <= last) __builtin_trap();  // each sequence once, increasing
          last = s;
        });
        break;
      case 3: (void)oe.send(in.bytes(in.u8()), now); break;
      case 4: oe.on_timer(now); break;
      default: oe.consume_tx(i, in.u16()); break;
    }
    if (oe.pending() > c.pending_capacity) __builtin_trap();
  }
}

void fuzz_accounting(Input& in) {
  client::lg::ScheduleConfig sc;
  sc.sessions = 2;
  sc.symbols = 4;
  sc.rate = 1'000'000;
  sc.duration = 50'000;
  sc.prefill = 20;
  sc.seed = in.u8();
  const auto s = client::lg::build_schedule(sc);
  client::lg::Accounting acc(s);
  for (std::size_t i = 0; i < s.items.size(); ++i)
    if (in.u8() % 2 == 0) acc.on_sent(i, 0, s.items[i].t);
  while (!in.done()) acc.on_response(static_cast<std::uint16_t>(in.u8() % 3), in.bytes(in.u8()), in.u32());
  acc.finish();
  if (acc.stats().acked > acc.stats().sent) __builtin_trap();
}

void fuzz_converter(Input& in) {
  client::i2o::Converter conv(client::i2o::ConvertConfig{static_cast<std::uint16_t>(1 + in.u8() % 4),
                                                          ouch50::TimeInForce::Gtx});
  SeqNo seq = 0;
  while (!in.done()) {
    std::span<const std::byte> m = in.bytes(in.u8() % 52);
    conv.on_itch(++seq, m, [](Nanos, std::uint16_t s, std::span<const std::byte> ouch, const client::i2o::Origin&) {
      if (s == 0 || ouch.empty() || !ouch50::InboundDecoder::decode(ouch)) __builtin_trap();
    });
  }
}

void fuzz_text(const std::uint8_t* data, std::size_t size) {
  const std::string text(reinterpret_cast<const char*>(data), size);
  (void)client::parse_flat_json(text);
  (void)client::parse_sample_line(text);
  if (const auto p = client::lg::parse_profile(text, "fuzz")) {
    const auto& c = p->base;
    LLE_ASSERT(c.mix.enter_pct + c.mix.cancel_pct + c.mix.replace_pct + c.mix.ioc_pct == 100);
    LLE_ASSERT(c.sessions >= 1 && c.sessions <= c.symbols && c.symbols <= 9999);
    (void)client::lg::exchanged_risk_rows(*p, 1, 2);
  }
}

void fuzz_stamps(Input& in) {
  client::FrameStampTracker t;
  t.init(64);
  client::StreamTxMatcher m;
  m.init(64);
  std::vector<std::uint8_t> seen(4096, 0);
  std::uint64_t tag = 0;
  while (!in.done()) {
    switch (in.u8() % 4) {
      case 0: {  // a frame: Ethernet + IPv4 + TCP header bytes from the input
        const std::size_t n = in.u8();
        (void)t.on_tx(in.bytes(n));
        break;
      }
      case 1: t.on_completion(static_cast<Nanos>(in.u32())); break;
      case 2:
        m.on_written(in.u8());
        if (tag < seen.size()) m.expect(tag++, m.written() + in.u8());
        break;
      default:
        t.drain([&](const client::FrameStampTracker::Stamped& s) {
          m.on_stamp(s.stamp, [&](std::uint64_t k, const net::RxTimestamps&) {
            LLE_ASSERT(k < seen.size() && seen[k] == 0, "a message matched twice");
            seen[k] = 1;
          });
        });
        break;
    }
  }
  const net::TsValidity& v = m.validity();
  LLE_ASSERT(v.total() + m.outstanding() <= tag);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  Input in(data, size);
  switch (in.u8() % 6) {
    case 0: fuzz_feed(in); break;
    case 1: fuzz_orders(in); break;
    case 2: fuzz_accounting(in); break;
    case 3: fuzz_converter(in); break;
    case 4: fuzz_text(data + (size > 0 ? 1 : 0), size > 0 ? size - 1 : 0); break;
    default: fuzz_stamps(in); break;
  }
  return 0;
}

// Seeds: one program per consumer.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 6 || cap < 256) return 0;
  std::size_t n = 0;
  buf[n++] = static_cast<std::uint8_t>(index);
  if (index == 3) {
    // An ITCH Add Order then its delete.
    itch50::AddOrder a;
    a.stock_locate = 1;
    a.order_ref = 7;
    a.side = Side::Buy;
    a.shares = 100;
    a.stock = Symbol8("AAPL");
    a.price = 1'000'000;
    buf[n++] = 1;
    buf[n++] = 36;
    itch50::encode_unchecked(reinterpret_cast<std::byte*>(buf + n), a);
    n += 36;
    itch50::OrderDelete d;
    d.order_ref = 7;
    buf[n++] = 19;
    itch50::encode_unchecked(reinterpret_cast<std::byte*>(buf + n), d);
    n += 19;
    return n;
  }
  if (index == 4) {  // a profile
    static const char kText[] = "status = TBD_BY_PILOT\n[mix]\nenter = 45\ncancel = 40\nreplace = 10\nioc = 5\n"
                                "[book]\nsymbols = 20\nlots = 1-10\n[sessions]\ncount = 4\n[risk]\nlop = 1\n";
    std::memcpy(buf + n, kText, sizeof kText - 1);
    return n + sizeof kText - 1;
  }
  for (std::size_t i = 0; i < 64; ++i) buf[n++] = static_cast<std::uint8_t>(i * 37 + index);
  return n;
}
