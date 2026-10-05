// UtcpStreamPort API tests: env::StreamPortLike conformance, listener/RST behavior, ARP
// resolution and reply, gratuitous ARP, read backpressure, ConnId lifetime, and the
// no-allocation rule on the per-packet path.
#include <gtest/gtest.h>

#include <array>
#include <string>
#include <vector>

#include "net/utcp/datagram_frame_port.h"
#include "net/utcp/stream_port.h"
#include "sim_link.h"

namespace lle::net::utcp::test {
namespace {

using Port = UtcpStreamPort<MemFramePort, SimClock>;
static_assert(env::StreamPortLike<Port>);
static_assert(env::StreamEndpointLike<Port>);
static_assert(FramePort<MemFramePort>);

constexpr std::uint32_t kIpA = 0x0A000001;
constexpr std::uint32_t kIpB = 0x0A000002;
constexpr MacAddr kMacA{{0x02, 0, 0, 0, 0, 0x01}};
constexpr MacAddr kMacB{{0x02, 0, 0, 0, 0, 0x02}};

StackConfig cfg(bool a) {
  StackConfig s;
  s.local_mac = a ? kMacA : kMacB;
  s.local_ip = a ? kIpA : kIpB;
  s.conn.initial_rto = 50'000'000;
  s.conn.min_rto = 5'000'000;
  s.conn.time_wait = 20'000'000;
  s.arp_retry = 10'000'000;
  s.arp_attempts = 3;
  s.max_connections = 4;
  return s;
}

std::span<const std::byte> as_bytes(const std::string& s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }

struct Events {
  std::vector<env::StreamEvent> list;
  std::string data;
  void operator()(const env::StreamEvent& e) {
    list.push_back(e);
    if (e.kind == env::StreamEventKind::Data) {
      for (auto b : e.data) data.push_back(std::to_integer<char>(b));
    }
  }
  bool has(env::StreamEventKind k) const {
    for (const auto& e : list) {
      if (e.kind == k) return true;
    }
    return false;
  }
};

struct World {
  explicit World(StackConfig ca = cfg(true), StackConfig cb = cfg(false))
      : link(1, Impairments{}), pa(link, 0, clock), pb(link, 1, clock), a(pa, clock, ca), b(pb, clock, cb) {}
  SimClock clock;
  SimLink link;
  MemFramePort pa;
  MemFramePort pb;
  Port a;
  Port b;
  Events ea;
  Events eb;
  // Runs until both stacks and the link are idle or `until` is reached.
  void run(Nanos until) {
    for (int i = 0; i < 100000; ++i) {
      (void)a.poll(ea);
      (void)b.poll(eb);
      const Nanos t = std::min({link.next_delivery(), a.next_deadline(), b.next_deadline()});
      if (t == kNoDeadline || t > until) {
        clock.t = until;
        (void)a.poll(ea);
        (void)b.poll(eb);
        return;
      }
      clock.t = std::max(clock.t + 1, t);
    }
  }
};

TEST(UtcpStreamPort, ArpResolveConnectEchoClose) {
  World w;
  ASSERT_TRUE(w.b.listen(env::Endpoint{0, 8080}));
  const env::ConnId c = w.a.connect(env::Endpoint{kIpB, 8080}).value_or(env::kNoConn);
  ASSERT_NE(c, env::kNoConn);
  EXPECT_EQ(w.a.write(c, as_bytes("early")), 0u);  // next hop unresolved yet
  w.run(1'000'000'000);
  EXPECT_EQ(w.a.stats().arp_requests, 1u);
  EXPECT_EQ(w.b.stats().arp_replies, 1u);
  EXPECT_EQ(w.a.neighbors().lookup(kIpB), kMacB);
  EXPECT_EQ(w.b.neighbors().lookup(kIpA), kMacA);  // learned from the request (RFC 826 merge)
  ASSERT_TRUE(w.ea.has(env::StreamEventKind::Connected));
  ASSERT_TRUE(w.eb.has(env::StreamEventKind::Accepted));
  env::ConnId sc = env::kNoConn;
  for (const auto& e : w.eb.list) {
    if (e.kind == env::StreamEventKind::Accepted) sc = e.conn;
  }
  EXPECT_EQ(w.a.write(c, as_bytes("hello")), 5u);
  w.run(w.clock.t + 1'000'000);
  EXPECT_EQ(w.eb.data, "hello");
  EXPECT_EQ(w.b.write(sc, as_bytes("world")), 5u);
  w.run(w.clock.t + 1'000'000);
  EXPECT_EQ(w.ea.data, "world");
  w.a.close(c);
  w.run(w.clock.t + 1'000'000'000);
  EXPECT_TRUE(w.eb.has(env::StreamEventKind::Closed));
  EXPECT_FALSE(w.ea.has(env::StreamEventKind::Closed));  // the app closed it itself
  EXPECT_EQ(w.a.slots_in_use(), 0u);
  EXPECT_EQ(w.b.slots_in_use(), 0u);
  EXPECT_EQ(w.a.write(c, as_bytes("x")), 0u);  // stale ConnId
  EXPECT_EQ(w.a.connection(c), nullptr);
}

TEST(UtcpStreamPort, ConnectToClosedPortIsRefused) {
  StackConfig ca = cfg(true);
  ca.static_next_hop = kMacB;
  World w(ca);
  const env::ConnId c = w.a.connect(env::Endpoint{kIpB, 9999}).value_or(env::kNoConn);
  w.run(1'000'000'000);
  EXPECT_EQ(w.b.stats().rst_sent, 1u);
  ASSERT_TRUE(w.ea.has(env::StreamEventKind::Closed));
  EXPECT_EQ(w.a.connection(c), nullptr);
  EXPECT_EQ(w.a.stats().arp_requests, 0u);  // static next hop
}

TEST(UtcpStreamPort, UnresolvableNextHopReportsClosed) {
  World w;
  w.link.set_down(true);
  const env::ConnId c = w.a.connect(env::Endpoint{kIpB, 8080}).value_or(env::kNoConn);
  ASSERT_NE(c, env::kNoConn);
  w.run(1'000'000'000);
  EXPECT_EQ(w.a.stats().arp_requests, 3u);
  ASSERT_TRUE(w.ea.has(env::StreamEventKind::Closed));
  EXPECT_EQ(w.a.slots_in_use(), 0u);
}

TEST(UtcpStreamPort, GratuitousArpRefresh) {
  StackConfig ca = cfg(true);
  ca.garp_interval = 100'000'000;
  World w(ca);
  w.run(450'000'000);
  EXPECT_EQ(w.a.stats().garp_sent, 5u);  // t = 0, 100, 200, 300, 400 ms
  EXPECT_EQ(w.b.neighbors().lookup(kIpA), std::nullopt);  // merge only updates known entries
}

TEST(UtcpStreamPort, PauseReadingAppliesZeroWindow) {
  StackConfig cb = cfg(false);
  cb.conn.rx_buffer = 3000;
  StackConfig ca = cfg(true);
  ca.static_next_hop = kMacB;
  cb.static_next_hop = kMacA;
  World w(ca, cb);
  ASSERT_TRUE(w.b.listen(env::Endpoint{0, 8080}));
  const env::ConnId c = w.a.connect(env::Endpoint{kIpB, 8080}).value_or(env::kNoConn);
  w.run(100'000'000);
  env::ConnId sc = env::kNoConn;
  for (const auto& e : w.eb.list) {
    if (e.kind == env::StreamEventKind::Accepted) sc = e.conn;
  }
  ASSERT_NE(sc, env::kNoConn);
  w.b.pause_reading(sc, true);
  std::string big(10000, 'p');
  EXPECT_EQ(w.a.write(c, as_bytes(big)), 10000u);
  w.run(w.clock.t + 500'000'000);
  EXPECT_EQ(w.eb.data.size(), 0u);
  const Connection* conn_b = w.b.connection(sc);
  const Connection* conn_a = w.a.connection(c);
  ASSERT_NE(conn_b, nullptr);
  ASSERT_NE(conn_a, nullptr);
  EXPECT_EQ(conn_b->rcv_window(), 0u);
  EXPECT_EQ(conn_a->snd_wnd(), 0u);
  EXPECT_GT(conn_a->stats().zero_window_probes, 0u);
  w.b.pause_reading(sc, false);
  w.run(w.clock.t + 3'000'000'000);
  EXPECT_EQ(w.eb.data, big);
}

TEST(UtcpStreamPort, SlotExhaustionDropsSyn) {
  StackConfig ca = cfg(true);
  ca.static_next_hop = kMacB;
  ca.max_connections = 3;
  StackConfig cb = cfg(false);
  cb.max_connections = 2;
  World w(ca, cb);
  ASSERT_TRUE(w.b.listen(env::Endpoint{0, 8080}));
  const env::ConnId c1 = w.a.connect(env::Endpoint{kIpB, 8080}).value_or(env::kNoConn);
  const env::ConnId c2 = w.a.connect(env::Endpoint{kIpB, 8080}).value_or(env::kNoConn);
  const env::ConnId c3 = w.a.connect(env::Endpoint{kIpB, 8080}).value_or(env::kNoConn);
  EXPECT_NE(c1, c2);
  EXPECT_NE(c2, c3);
  EXPECT_FALSE(w.a.connect(env::Endpoint{kIpB, 8080}));  // client pool full
  w.run(30'000'000);
  EXPECT_GE(w.b.stats().syn_dropped, 1u);
  EXPECT_EQ(w.b.slots_in_use(), 2u);
}

// A minimal env::DatagramPortLike network (two nodes, in-order, lossless) standing in
// for the simulator's sim::DatagramPort, to check the RawIp adapter end to end.
struct TinyNet {
  struct Msg {
    env::Endpoint src, dst;
    std::vector<std::byte> b;
  };
  std::vector<Msg> q;
};
class TinyDatagramPort {
 public:
  TinyDatagramPort(TinyNet& n, env::Endpoint local) : n_(n), local_(local) {}
  bool send(env::Endpoint dst, std::span<const std::byte> b) {
    n_.q.push_back(TinyNet::Msg{local_, dst, std::vector<std::byte>(b.begin(), b.end())});
    return true;
  }
  template <class Cb>
  std::size_t poll_rx(Cb&& cb) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < n_.q.size();) {
      if (n_.q[i].dst == local_) {
        TinyNet::Msg m = std::move(n_.q[i]);
        n_.q.erase(n_.q.begin() + static_cast<std::ptrdiff_t>(i));
        env::RxDatagram r;
        r.data = std::span<const std::byte>(m.b.data(), m.b.size());
        r.src = m.src;
        r.dst = m.dst;
        cb(r);
        ++n;
      } else {
        ++i;
      }
    }
    return n;
  }

 private:
  TinyNet& n_;
  env::Endpoint local_;
};
static_assert(env::DatagramPortLike<TinyDatagramPort>);
static_assert(FramePort<DatagramFramePort<TinyDatagramPort>>);

TEST(UtcpStreamPort, RawIpOverDatagramPort) {
  TinyNet net;
  TinyDatagramPort da(net, env::Endpoint{kIpA, 6000});
  TinyDatagramPort db(net, env::Endpoint{kIpB, 6000});
  DatagramFramePort<TinyDatagramPort> fa(da, 6000);
  DatagramFramePort<TinyDatagramPort> fb(db, 6000);
  SimClock clock;
  StackConfig ca = cfg(true);
  StackConfig cb = cfg(false);
  ca.link = cb.link = LinkType::RawIp;
  UtcpStreamPort<DatagramFramePort<TinyDatagramPort>, SimClock> a(fa, clock, ca);
  UtcpStreamPort<DatagramFramePort<TinyDatagramPort>, SimClock> b(fb, clock, cb);
  ASSERT_TRUE(b.listen(env::Endpoint{0, 8080}));
  const auto c = a.connect(env::Endpoint{kIpB, 8080});
  ASSERT_TRUE(c);
  Events ea, eb;
  for (int i = 0; i < 20; ++i) {
    clock.t += 1000;
    (void)a.poll(ea);
    (void)b.poll(eb);
  }
  ASSERT_TRUE(ea.has(env::StreamEventKind::Connected));
  EXPECT_EQ(a.write(*c, as_bytes("over the simulator's datagrams")), 30u);
  for (int i = 0; i < 20; ++i) {
    clock.t += 1000;
    (void)a.poll(ea);
    (void)b.poll(eb);
  }
  EXPECT_EQ(eb.data, "over the simulator's datagrams");
}

}  // namespace
}  // namespace lle::net::utcp::test
