// Unit tests for utcp::Connection driven directly (two endpoints, frames pumped by hand).
#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "net/utcp/connection.h"

namespace lle::net::utcp {
namespace {

using namespace tcp_flag;

constexpr Nanos kMs = 1'000'000;
constexpr MacAddr kMacA{{0x02, 0, 0, 0, 0, 0x0A}};
constexpr MacAddr kMacB{{0x02, 0, 0, 0, 0, 0x0B}};

std::span<const std::byte> as_bytes(const std::string& s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }

std::string drain(Connection& c, Nanos now) {
  std::string out;
  auto sp = c.readable();
  for (auto b : sp.first) out.push_back(std::to_integer<char>(b));
  for (auto b : sp.second) out.push_back(std::to_integer<char>(b));
  (void)c.consume(out.size(), now);
  return out;
}

ConnConfig test_config() {
  ConnConfig c;
  c.mss = 1000;
  c.rx_buffer = 8192;
  c.tx_buffer = 65536;
  c.initial_rto = 100 * kMs;
  c.min_rto = 10 * kMs;
  c.max_rto = 2000 * kMs;
  c.time_wait = 500 * kMs;
  return c;
}

struct Pair {
  explicit Pair(ConnConfig ca = test_config(), ConnConfig cb = test_config()) : a(ca), b(cb) {}

  Connection a;
  Connection b;
  Nanos now = 0;
  std::vector<std::byte> buf = std::vector<std::byte>(4096);
  // Return false to drop the frame.
  std::function<bool(const TcpSegment&, bool from_a)> filter;
  std::uint32_t a_events = 0;
  std::uint32_t b_events = 0;

  FlowAddr flow_a() const { return {kMacA, kMacB, 0x0A000001, 0x0A000002, 40000, 8080}; }
  FlowAddr flow_b() const { return {kMacB, kMacA, 0x0A000002, 0x0A000001, 8080, 40000}; }

  std::vector<TcpSegment> segs;  // last pumped segments (views into frames that die; keep fields only)

  int pump(Connection& from, Connection& to, bool from_a) {
    int n = 0;
    while (std::size_t len = from.next_tx(buf, now)) {
      auto seg = parse_tcp(std::span<const std::byte>(buf.data(), len), LinkType::Ethernet, true);
      EXPECT_TRUE(seg.has_value());
      ++n;
      if (filter && !filter(*seg, from_a)) continue;
      const Actions act = to.on_segment(std::span<const std::byte>(buf.data(), len), now);
      (from_a ? b_events : a_events) |= act.events;
      EXPECT_TRUE(to.invariants_ok());
    }
    return n;
  }
  void settle() {
    for (int i = 0; i < 1000; ++i) {
      if (pump(a, b, true) + pump(b, a, false) == 0) return;
    }
    ADD_FAILURE() << "did not settle";
  }
  // Fires timers on both ends at `t`.
  void advance(Nanos t) {
    now = t;
    a_events |= a.on_timer(now).events;
    b_events |= b.on_timer(now).events;
  }
  void handshake() {
    a_events |= a.connect(flow_a(), 1000, now).events;
    std::size_t len = a.next_tx(buf, now);
    ASSERT_GT(len, 0u);
    auto syn = parse_tcp(std::span<const std::byte>(buf.data(), len), LinkType::Ethernet, true);
    ASSERT_TRUE(syn.has_value());
    ASSERT_EQ(syn->flags, kSyn);
    b_events |= b.accept(flow_b(), *syn, 5000, now).events;
    settle();
  }
};

TEST(Connection, HandshakeNegotiatesMss) {
  ConnConfig cb = test_config();
  cb.mss = 700;
  Pair p(test_config(), cb);
  p.handshake();
  EXPECT_EQ(p.a.state(), State::Established);
  EXPECT_EQ(p.b.state(), State::Established);
  EXPECT_TRUE(p.a_events & ev::kConnected);
  EXPECT_TRUE(p.b_events & ev::kConnected);
  EXPECT_EQ(p.a.snd_mss(), 700);
  EXPECT_EQ(p.b.snd_mss(), 700);
  EXPECT_EQ(p.a.snd_una(), 1001u);
  EXPECT_EQ(p.b.snd_una(), 5001u);
  EXPECT_EQ(p.a.rcv_nxt(), 5001u);
  EXPECT_EQ(p.b.rcv_nxt(), 1001u);
  EXPECT_EQ(p.a.snd_wnd(), 8192u);
  EXPECT_GT(p.a.stats().rtt_samples, 0u);
}

TEST(Connection, BidirectionalDataAndSegmentation) {
  Pair p;
  p.handshake();
  std::string big(5000, 'x');
  for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>('a' + i % 26);
  EXPECT_EQ(p.a.send(as_bytes(big), p.now).accepted, 5000u);
  EXPECT_EQ(p.b.send(as_bytes("pong"), p.now).accepted, 4u);
  p.settle();
  EXPECT_EQ(drain(p.b, p.now), big);
  EXPECT_EQ(drain(p.a, p.now), "pong");
  EXPECT_GE(p.a.stats().segs_out, 5u);  // 1000-byte MSS
  EXPECT_EQ(p.a.snd_una(), p.a.snd_max());
  EXPECT_EQ(p.a.deadline(), kNoDeadline);  // RTO stopped once all is acknowledged
}

TEST(Connection, OrderlyCloseActiveSide) {
  Pair p;
  p.handshake();
  (void)p.a.send(as_bytes("bye"), p.now);
  (void)p.a.close(p.now);
  EXPECT_EQ(p.a.state(), State::FinWait1);
  p.settle();
  EXPECT_EQ(p.b.state(), State::CloseWait);
  EXPECT_TRUE(p.b_events & ev::kPeerFin);
  EXPECT_EQ(p.a.state(), State::FinWait2);
  EXPECT_EQ(drain(p.b, p.now), "bye");
  (void)p.b.close(p.now);
  EXPECT_EQ(p.b.state(), State::LastAck);
  p.settle();
  EXPECT_EQ(p.b.state(), State::Closed);
  EXPECT_EQ(p.b.close_reason(), CloseReason::Normal);
  EXPECT_EQ(p.a.state(), State::TimeWait);
  p.advance(p.now + 499 * kMs);
  EXPECT_EQ(p.a.state(), State::TimeWait);
  p.advance(p.now + 1 * kMs);
  EXPECT_EQ(p.a.state(), State::Closed);
  EXPECT_EQ(p.a.close_reason(), CloseReason::Normal);
}

TEST(Connection, SimultaneousClose) {
  Pair p;
  p.handshake();
  (void)p.a.close(p.now);
  (void)p.b.close(p.now);
  // Both FINs cross on the wire.
  std::vector<std::byte> fa(2048), fb(2048);
  const std::size_t la = p.a.next_tx(fa, p.now);
  const std::size_t lb = p.b.next_tx(fb, p.now);
  ASSERT_GT(la, 0u);
  ASSERT_GT(lb, 0u);
  (void)p.b.on_segment(std::span<const std::byte>(fa.data(), la), p.now);
  (void)p.a.on_segment(std::span<const std::byte>(fb.data(), lb), p.now);
  EXPECT_EQ(p.a.state(), State::Closing);
  EXPECT_EQ(p.b.state(), State::Closing);
  p.settle();
  EXPECT_EQ(p.a.state(), State::TimeWait);
  EXPECT_EQ(p.b.state(), State::TimeWait);
}

TEST(Connection, AbortSendsRstAndPeerResets) {
  Pair p;
  p.handshake();
  (void)p.a.abort(p.now);
  EXPECT_EQ(p.a.state(), State::Closed);
  EXPECT_EQ(p.a.close_reason(), CloseReason::Aborted);
  p.settle();
  EXPECT_EQ(p.b.state(), State::Closed);
  EXPECT_EQ(p.b.close_reason(), CloseReason::Reset);
}

TEST(Connection, RetransmissionWithBackoff) {
  Pair p;
  p.handshake();
  int dropped = 0;
  p.filter = [&](const TcpSegment& s, bool from_a) {
    if (from_a && !s.payload.empty() && dropped < 3) {
      ++dropped;
      return false;
    }
    return true;
  };
  (void)p.a.send(as_bytes("hello"), p.now);
  p.settle();
  EXPECT_EQ(dropped, 1);
  const Nanos rto0 = p.a.rto();
  const Nanos d0 = p.a.deadline();
  EXPECT_EQ(d0, p.now + rto0);
  p.advance(d0);
  p.settle();  // retransmission dropped again
  EXPECT_EQ(dropped, 2);
  EXPECT_EQ(p.a.rto(), 2 * rto0);
  p.advance(p.a.deadline());
  p.settle();
  EXPECT_EQ(dropped, 3);
  EXPECT_EQ(p.a.rto(), 4 * rto0);
  p.advance(p.a.deadline());
  p.settle();
  EXPECT_EQ(drain(p.b, p.now), "hello");
  EXPECT_EQ(p.a.stats().rto_expiries, 3u);
  EXPECT_EQ(p.a.stats().retransmit_segs, 3u);
}

TEST(Connection, RetransmitLimitResets) {
  ConnConfig c = test_config();
  c.max_retransmits = 2;
  Pair p(c, test_config());
  p.handshake();
  p.filter = [](const TcpSegment& s, bool from_a) { return !(from_a && !s.payload.empty()); };
  (void)p.a.send(as_bytes("lost"), p.now);
  p.settle();
  for (int i = 0; i < 3; ++i) {
    p.advance(p.a.deadline());
    p.settle();
  }
  EXPECT_EQ(p.a.state(), State::Closed);
  EXPECT_EQ(p.a.close_reason(), CloseReason::Timeout);
  EXPECT_EQ(p.b.state(), State::Closed);  // the RST got through
  EXPECT_EQ(p.b.close_reason(), CloseReason::Reset);
}

TEST(Connection, ZeroWindowBackpressureAndProbe) {
  ConnConfig cb = test_config();
  cb.rx_buffer = 2000;
  Pair p(test_config(), cb);
  p.handshake();
  std::string data(6000, 'z');
  EXPECT_EQ(p.a.send(as_bytes(data), p.now).accepted, 6000u);
  p.settle();
  EXPECT_EQ(p.b.readable_bytes(), 2000u);
  EXPECT_EQ(p.a.snd_wnd(), 0u);
  EXPECT_EQ(p.b.rcv_window(), 0u);
  // Persist timer runs; each probe is answered with a zero window.
  const Nanos d = p.a.deadline();
  ASSERT_NE(d, kNoDeadline);
  p.advance(d);
  p.settle();
  EXPECT_EQ(p.a.stats().zero_window_probes, 1u);
  p.advance(p.a.deadline());
  p.settle();
  EXPECT_GE(p.a.stats().zero_window_probes, 2u);
  EXPECT_EQ(p.a.state(), State::Established);
  // Reader drains: window update reopens the flow.
  std::string got = drain(p.b, p.now);
  p.settle();
  while (got.size() < data.size()) {
    std::string more = drain(p.b, p.now);
    if (more.empty()) {
      p.advance(p.a.deadline() == kNoDeadline ? p.now + kMs : p.a.deadline());
    }
    got += more;
    p.settle();
  }
  EXPECT_EQ(got, data);
  EXPECT_GE(p.b.stats().window_updates, 1u);
}

TEST(Connection, OutOfOrderDroppedFastRetransmit) {
  Pair p;
  p.handshake();
  bool dropped = false;
  p.filter = [&](const TcpSegment& s, bool from_a) {
    if (from_a && !dropped && !s.payload.empty()) {
      dropped = true;
      return false;
    }
    return true;
  };
  std::string data(6000, 'q');
  (void)p.a.send(as_bytes(data), p.now);
  p.settle();
  EXPECT_EQ(p.b.stats().ooo_dropped, 5u);
  EXPECT_EQ(p.b.stats().dupacks_out, 5u);
  EXPECT_EQ(p.a.stats().fast_retransmits, 1u);
  EXPECT_EQ(drain(p.b, p.now), data);  // recovered without an RTO
  EXPECT_EQ(p.a.stats().rto_expiries, 0u);
}

TEST(Connection, RstNotExactGetsChallengeAck) {
  Pair p;
  p.handshake();
  TcpHeaderSpec h;
  h.src_mac = kMacB;
  h.dst_mac = kMacA;
  h.src_ip = 0x0A000002;
  h.dst_ip = 0x0A000001;
  h.src_port = 8080;
  h.dst_port = 40000;
  h.seq = p.a.rcv_nxt() + 10;  // in window, not exact
  h.flags = kRst;
  const std::size_t n = build_tcp(p.buf, LinkType::Ethernet, h, {}, {}, false);
  (void)p.a.on_segment(std::span<const std::byte>(p.buf.data(), n), p.now);
  EXPECT_EQ(p.a.state(), State::Established);
  EXPECT_EQ(p.a.stats().challenge_acks, 1u);
  EXPECT_TRUE(p.a.tx_pending());
  h.seq = p.a.rcv_nxt();
  const std::size_t m = build_tcp(p.buf, LinkType::Ethernet, h, {}, {}, false);
  (void)p.a.on_segment(std::span<const std::byte>(p.buf.data(), m), p.now);
  EXPECT_EQ(p.a.state(), State::Closed);
  EXPECT_EQ(p.a.close_reason(), CloseReason::Reset);
}

TEST(Connection, SynRetransmissionAndRefused) {
  Pair p;
  (void)p.a.connect(p.flow_a(), 77, p.now);
  ASSERT_GT(p.a.next_tx(p.buf, p.now), 0u);  // SYN lost
  EXPECT_EQ(p.a.deadline(), 100 * kMs);
  p.advance(100 * kMs);
  const std::size_t len = p.a.next_tx(p.buf, p.now);
  ASSERT_GT(len, 0u);
  auto syn = parse_tcp(std::span<const std::byte>(p.buf.data(), len), LinkType::Ethernet, true);
  ASSERT_TRUE(syn.has_value());
  EXPECT_EQ(syn->seq, 77u);
  EXPECT_EQ(syn->flags, kSyn);
  EXPECT_EQ(p.a.deadline(), 300 * kMs);  // backed off to 200 ms
  // RST,ACK answering the SYN: refused.
  TcpHeaderSpec h;
  h.src_mac = kMacB;
  h.dst_mac = kMacA;
  h.src_ip = 0x0A000002;
  h.dst_ip = 0x0A000001;
  h.src_port = 8080;
  h.dst_port = 40000;
  h.ack = 78;
  h.flags = kRst | kAck;
  const std::size_t n = build_tcp(p.buf, LinkType::Ethernet, h, {}, {}, false);
  const Actions a = p.a.on_segment(std::span<const std::byte>(p.buf.data(), n), p.now);
  EXPECT_TRUE(a.has(ev::kClosed));
  EXPECT_EQ(p.a.close_reason(), CloseReason::Refused);
}

TEST(Connection, SimultaneousOpen) {
  Pair p;
  (void)p.a.connect(p.flow_a(), 100, p.now);
  (void)p.b.connect(p.flow_b(), 900, p.now);
  std::vector<std::byte> fa(2048), fb(2048);
  const std::size_t la = p.a.next_tx(fa, p.now);
  const std::size_t lb = p.b.next_tx(fb, p.now);
  (void)p.b.on_segment(std::span<const std::byte>(fa.data(), la), p.now);
  (void)p.a.on_segment(std::span<const std::byte>(fb.data(), lb), p.now);
  EXPECT_EQ(p.a.state(), State::SynReceived);
  EXPECT_EQ(p.b.state(), State::SynReceived);
  p.settle();
  EXPECT_EQ(p.a.state(), State::Established);
  EXPECT_EQ(p.b.state(), State::Established);
}

TEST(Connection, OldDuplicateIsAckedAndIgnored) {
  Pair p;
  p.handshake();
  (void)p.a.send(as_bytes("abc"), p.now);
  std::vector<std::byte> keep(2048);
  const std::size_t len = p.a.next_tx(keep, p.now);
  (void)p.b.on_segment(std::span<const std::byte>(keep.data(), len), p.now);
  p.settle();
  EXPECT_EQ(drain(p.b, p.now), "abc");
  (void)p.b.on_segment(std::span<const std::byte>(keep.data(), len), p.now);  // duplicate
  EXPECT_EQ(p.b.readable_bytes(), 0u);
  EXPECT_EQ(p.b.stats().unacceptable_in, 1u);
  EXPECT_TRUE(p.b.tx_pending());  // re-ACK
}

}  // namespace
}  // namespace lle::net::utcp
