#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "env/concepts.h"
#include "sim/dist.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/sim_env.h"
#include "sim/world.h"
#include "test_util.h"

namespace lle::sim {
namespace {

static_assert(env::DatagramPortLike<DatagramPort>);
static_assert(env::StreamPortLike<StreamPort>);
static_assert(env::StreamEndpointLike<StreamPort>);

TEST(Stream, ListenBindsEphemeralAndRejectsForeignOrTakenAddresses) {
  World w(15, base_fault_config());
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  StreamPort p(a);
  StreamPort q(a);
  const auto e1 = p.listen(env::Endpoint{0, 0});
  ASSERT_TRUE(e1.has_value());
  EXPECT_EQ(e1->ipv4, a.ip());
  EXPECT_NE(e1->port, 0);
  const auto e2 = q.listen(env::Endpoint{0, 0});
  ASSERT_TRUE(e2.has_value());
  EXPECT_NE(e2->port, e1->port);
  EXPECT_FALSE(q.listen(*e1).has_value());                       // taken
  EXPECT_FALSE(p.listen(env::Endpoint{b.ip(), 9}).has_value());  // not this node
  EXPECT_TRUE(p.listen(env::Endpoint{a.ip(), 9}).has_value());
}

std::vector<std::byte> bytes_of(std::string_view s) {
  std::vector<std::byte> v(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) v[i] = static_cast<std::byte>(s[i]);
  return v;
}

struct Rx {
  std::vector<std::string> payloads;
  std::vector<env::Endpoint> srcs;
  std::size_t drain(DatagramPort& p) {
    return p.poll_rx([&](const env::RxDatagram& d) {
      payloads.emplace_back(reinterpret_cast<const char*>(d.data.data()), d.data.size());
      srcs.push_back(d.src);
    });
  }
};

// Runs the world, draining `port` after every event.
void pump(World& w, DatagramPort& port, Rx& rx, Nanos d) {
  const Nanos end = w.now() + d;
  while (w.pending_events() > 0 && w.next_event_time() <= end) {
    w.step();
    rx.drain(port);
  }
  w.run_until_time(end);
}

TEST(Datagram, DeliversAfterLinkLatencyWithSourceEndpoint) {
  World w(1, base_fault_config());
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  DatagramPort pa(a, 1000);
  DatagramPort pb(b, 2000);
  const auto msg = bytes_of("hello");
  ASSERT_TRUE(pa.send(env::Endpoint{b.ip(), 2000}, msg));
  Rx rx;
  ASSERT_TRUE(test::run_until(w, [&] { return rx.drain(pb) > 0; }, kMs));
  ASSERT_EQ(rx.payloads.size(), 1u);
  EXPECT_EQ(rx.payloads[0], "hello");
  EXPECT_EQ(rx.srcs[0], (env::Endpoint{a.ip(), 1000}));
  // Base config: fixed 10 us +-50% per link, no exponential tail.
  EXPECT_GE(w.now(), 5 * kUs);
  EXPECT_LE(w.now(), 15 * kUs);
  // Unbound destination: silently dropped.
  ASSERT_TRUE(pa.send(env::Endpoint{b.ip(), 9999}, msg));
  pump(w, pb, rx, kMs);
  EXPECT_EQ(rx.payloads.size(), 1u);
  EXPECT_FALSE(pa.send(env::Endpoint{b.ip(), 2000}, std::vector<std::byte>(kMaxDatagram + 1)));
}

TEST(Datagram, LossAndDuplicationApplyOnlyInSafetyPhase) {
  World w(2, base_fault_config());
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  DatagramPort pa(a, 1);
  DatagramPort pb(b, 2);
  w.net().link_params(a.id(), b.id()).loss_ppm = 1'000'000;
  const auto msg = bytes_of("x");
  Rx rx;
  w.set_phase(Phase::Safety);
  for (int i = 0; i < 10; ++i) pa.send(env::Endpoint{b.ip(), 2}, msg);
  pump(w, pb, rx, kMs);
  EXPECT_EQ(rx.payloads.size(), 0u);
  EXPECT_EQ(w.stats().net_loss, 10u);
  w.set_phase(Phase::Heal);
  for (int i = 0; i < 10; ++i) pa.send(env::Endpoint{b.ip(), 2}, msg);
  pump(w, pb, rx, kMs);
  EXPECT_EQ(rx.payloads.size(), 10u);

  w.set_phase(Phase::Safety);
  w.net().link_params(a.id(), b.id()).loss_ppm = 0;
  w.net().link_params(a.id(), b.id()).dup_ppm = 1'000'000;
  rx.payloads.clear();
  for (int i = 0; i < 10; ++i) pa.send(env::Endpoint{b.ip(), 2}, msg);
  pump(w, pb, rx, kMs);
  EXPECT_EQ(rx.payloads.size(), 20u);
  EXPECT_EQ(w.stats().net_dup, 10u);
}

TEST(Datagram, ExponentialDelaysReorder) {
  World w(3, base_fault_config());
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  DatagramPort pa(a, 1);
  DatagramPort pb(b, 2);
  w.net().link_params(a.id(), b.id()).delay_mean = kMs;
  Rx rx;
  for (int i = 0; i < 200; ++i) pa.send(env::Endpoint{b.ip(), 2}, bytes_of(std::to_string(i)));
  pump(w, pb, rx, 100 * kMs);
  ASSERT_EQ(rx.payloads.size(), 200u);
  int inversions = 0;
  for (std::size_t i = 1; i < rx.payloads.size(); ++i) {
    inversions += std::stoi(rx.payloads[i]) < std::stoi(rx.payloads[i - 1]) ? 1 : 0;
  }
  EXPECT_GT(inversions, 10);
  EXPECT_GT(w.stats().net_reorder, 10u);
  EXPECT_EQ(w.net().link_reorders(a.id(), b.id()), w.stats().net_reorder);
}

TEST(Datagram, MulticastFansOutToSubscribers) {
  World w(4, base_fault_config());
  Node& pub = w.add_node("pub");
  std::vector<std::unique_ptr<DatagramPort>> subs;
  std::vector<Node*> nodes;
  for (int i = 0; i < 4; ++i) nodes.push_back(&w.add_node("s" + std::to_string(i)));
  for (int i = 0; i < 4; ++i) subs.push_back(std::make_unique<DatagramPort>(*nodes[static_cast<std::size_t>(i)], 5000));
  const env::Endpoint group{0xEF00'0001u, 5000};
  ASSERT_TRUE(is_multicast(group));
  for (int i = 0; i < 3; ++i) subs[static_cast<std::size_t>(i)]->join(group);
  DatagramPort pp(pub, 1);
  pp.send(group, bytes_of("tick"));
  test::run_for(w, kMs);
  std::vector<std::size_t> got;
  for (auto& s : subs) {
    Rx rx;
    got.push_back(rx.drain(*s));
  }
  EXPECT_EQ(got, (std::vector<std::size_t>{1, 1, 1, 0}));
  subs[0]->leave(group);
  pp.send(group, bytes_of("tock"));
  test::run_for(w, kMs);
  got.clear();
  for (auto& s : subs) {
    Rx rx;
    got.push_back(rx.drain(*s));
  }
  EXPECT_EQ(got, (std::vector<std::size_t>{0, 1, 1, 0}));
}

TEST(Datagram, PartitionsSymmetricAsymmetricAndFlapping) {
  World w(5, base_fault_config());
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  DatagramPort pa(a, 1);
  DatagramPort pb(b, 2);
  const env::Endpoint ea{a.ip(), 1};
  const env::Endpoint eb{b.ip(), 2};
  Rx ra;
  Rx rb;
  auto exchange = [&] {
    pa.send(eb, bytes_of("ab"));
    pb.send(ea, bytes_of("ba"));
    const Nanos end = w.now() + 100 * kUs;
    while (w.pending_events() > 0 && w.next_event_time() <= end) {
      w.step();
      ra.drain(pa);
      rb.drain(pb);
    }
    w.run_until_time(end);
  };
  w.net().partition(0b01, 0b10, /*symmetric=*/true, 10 * kMs);
  exchange();
  EXPECT_EQ(ra.payloads.size() + rb.payloads.size(), 0u);
  test::run_for(w, 10 * kMs);  // partition ends
  exchange();
  EXPECT_EQ(ra.payloads.size(), 1u);
  EXPECT_EQ(rb.payloads.size(), 1u);

  w.net().partition(0b01, 0b10, /*symmetric=*/false, 10 * kMs);  // a -> b cut only
  exchange();
  EXPECT_EQ(rb.payloads.size(), 1u);
  EXPECT_EQ(ra.payloads.size(), 2u);
  w.net().heal_all();
  exchange();
  EXPECT_EQ(rb.payloads.size(), 2u);

  // Flapping: alternating short cuts; traffic gets through only between them.
  for (int k = 0; k < 4; ++k) {
    w.net().partition(0b01, 0b10, true, kMs);
    exchange();
    test::run_for(w, kMs);
    exchange();
  }
  EXPECT_EQ(rb.payloads.size(), 6u);
  EXPECT_GE(w.stats().partitions, 6u);
  EXPECT_GT(w.stats().net_partition_drop, 0u);
}

TEST(Datagram, InFlightDatagramsReachARestartedProcess) {
  World w(6, base_fault_config());
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  DatagramPort pa(a, 1);
  w.net().link_params(a.id(), b.id()).delay_min = 5 * kMs;
  auto pb = std::make_unique<DatagramPort>(b, 2);
  pa.send(env::Endpoint{b.ip(), 2}, bytes_of("late"));
  test::run_for(w, kMs);
  pb.reset();  // old process gone
  pb = std::make_unique<DatagramPort>(b, 2);
  Rx rx;
  pump(w, *pb, rx, 10 * kMs);
  EXPECT_EQ(rx.payloads.size(), 1u);
}

// ---------------------------------------------------------------------------
// Streams

struct StreamLog {
  std::vector<env::StreamEventKind> kinds;
  std::vector<env::ConnId> conns;
  std::vector<std::byte> data;
  std::vector<std::size_t> chunk_sizes;
  std::size_t drain(StreamPort& p) {
    return p.poll([&](const env::StreamEvent& e) {
      kinds.push_back(e.kind);
      conns.push_back(e.conn);
      if (e.kind == env::StreamEventKind::Data) {
        data.insert(data.end(), e.data.begin(), e.data.end());
        chunk_sizes.push_back(e.data.size());
      }
    });
  }
  [[nodiscard]] int count(env::StreamEventKind k) const {
    int n = 0;
    for (const auto x : kinds) n += x == k ? 1 : 0;
    return n;
  }
};

struct StreamPair {
  World w;
  Node& cn;
  Node& sn;
  std::unique_ptr<StreamPort> client;
  std::unique_ptr<StreamPort> server;
  StreamLog clog;
  StreamLog slog;
  env::ConnId cconn = env::kNoConn;
  env::ConnId sconn = env::kNoConn;

  explicit StreamPair(std::uint64_t seed, FaultConfig f = base_fault_config())
      : w(seed, f), cn(w.add_node("client")), sn(w.add_node("server")) {
    client = std::make_unique<StreamPort>(cn);
    server = std::make_unique<StreamPort>(sn);
    EXPECT_EQ(server->listen(env::Endpoint{0, 80}), (env::Endpoint{sn.ip(), 80}));
  }
  void pump(Nanos d) {
    const Nanos end = w.now() + d;
    while (w.pending_events() > 0 && w.next_event_time() <= end) {
      w.step();
      if (client) clog.drain(*client);
      if (server) slog.drain(*server);
      if (sconn == env::kNoConn) {
        for (std::size_t i = 0; i < slog.kinds.size(); ++i) {
          if (slog.kinds[i] == env::StreamEventKind::Accepted) sconn = slog.conns[i];
        }
      }
    }
    w.run_until_time(end);
  }
  void connect() {
    cconn = *client->connect(env::Endpoint{sn.ip(), 80});
    pump(10 * kMs);
  }
};

std::vector<std::byte> pattern(std::size_t n, std::uint64_t seed) {
  std::vector<std::byte> v(n);
  Prng r(seed);
  for (auto& b : v) b = static_cast<std::byte>(r.next_u64());
  return v;
}

TEST(Stream, ConnectAcceptAndInOrderReliableDelivery) {
  StreamPair p(7);
  p.connect();
  ASSERT_EQ(p.clog.count(env::StreamEventKind::Connected), 1);
  ASSERT_EQ(p.slog.count(env::StreamEventKind::Accepted), 1);
  ASSERT_NE(p.sconn, env::kNoConn);
  const auto payload = pattern(1 << 20, 1);
  std::size_t off = 0;
  const Nanos end = p.w.now() + 10 * kSec;
  while (p.slog.data.size() < payload.size() && p.w.now() < end) {
    if (off < payload.size()) {
      off += p.client->write(p.cconn, std::span<const std::byte>(payload).subspan(off));
    }
    p.pump(100 * kUs);
  }
  EXPECT_EQ(p.slog.data, payload);
}

TEST(Stream, SegmentationAndCoalescingVaryDeliverySizes) {
  FaultConfig f = base_fault_config();
  f.set(Param::NetStreamSegPpm, 500'000);
  f.set(Param::NetDelayMeanNs, 50'000);
  StreamPair p(8, f);
  p.w.set_phase(Phase::Safety);
  p.connect();
  // Receiver reads after every event: each read is one segment (1..MTU).
  const auto payload = pattern(100'000, 2);
  std::size_t off = 0;
  for (int i = 0; i < 20'000 && p.slog.data.size() < payload.size(); ++i) {
    if (off < payload.size()) off += p.client->write(p.cconn, std::span<const std::byte>(payload).subspan(off));
    p.pump(20 * kUs);
  }
  ASSERT_EQ(p.slog.data, payload);
  std::size_t small = 0;
  for (const std::size_t s : p.slog.chunk_sizes) {
    small += s < kStreamMtu ? 1u : 0u;
    ASSERT_LE(s, kStreamMtu);
  }
  EXPECT_GT(small, 10u);
  EXPECT_GT(p.w.stats().stream_short_segments, 10u);

  // Receiver reads rarely: segments that arrived meanwhile coalesce.
  p.slog.data.clear();
  p.slog.chunk_sizes.clear();
  off = 0;
  for (int i = 0; i < 20'000 && p.slog.data.size() < payload.size(); ++i) {
    if (off < payload.size()) off += p.client->write(p.cconn, std::span<const std::byte>(payload).subspan(off));
    test::run_for(p.w, 2 * kMs);
    p.slog.drain(*p.server);
    p.clog.drain(*p.client);
  }
  ASSERT_EQ(p.slog.data, payload);
  std::size_t big = 0;
  for (const std::size_t s : p.slog.chunk_sizes) big += s > kStreamMtu ? 1u : 0u;
  EXPECT_GT(big, 0u);
}

TEST(Stream, FlowControlLimitsUnreadBytes) {
  StreamPair p(9);
  p.connect();
  const auto payload = pattern(kStreamRingBytes * 2, 3);
  const std::size_t n = p.client->write(p.cconn, payload);
  EXPECT_EQ(n, kStreamRingBytes);
  EXPECT_EQ(p.client->write(p.cconn, payload), 0u);
}

TEST(Stream, PartitionShorterThanTimeoutOnlyDelays) {
  StreamPair p(10);
  p.connect();
  const auto payload = pattern(10'000, 4);
  p.w.net().partition(0b11, 0b11, true, 100 * kMs);  // base reset timeout: 1 s
  ASSERT_EQ(p.client->write(p.cconn, payload), payload.size());
  p.pump(50 * kMs);
  EXPECT_TRUE(p.slog.data.empty());
  p.pump(500 * kMs);
  EXPECT_EQ(p.slog.data, payload);
  EXPECT_EQ(p.clog.count(env::StreamEventKind::Closed), 0);
}

TEST(Stream, PartitionLongerThanTimeoutResetsBothEnds) {
  StreamPair p(11);
  p.connect();
  p.w.net().partition(0b01, 0b10, false, 5 * kSec);  // asymmetric still kills TCP
  p.pump(2 * kSec);
  EXPECT_EQ(p.clog.count(env::StreamEventKind::Closed), 1);
  EXPECT_EQ(p.slog.count(env::StreamEventKind::Closed), 1);
  EXPECT_EQ(p.w.stats().stream_resets, 1u);
  EXPECT_EQ(p.client->write(p.cconn, pattern(10, 5)), 0u);
  p.pump(10 * kMs);
  EXPECT_EQ(p.w.net().st_connections(), 0u);
}

TEST(Stream, PeerCrashResetsConnection) {
  StreamPair p(12);
  p.connect();
  p.server.reset();  // server process memory gone
  p.pump(10 * kMs);
  EXPECT_EQ(p.clog.count(env::StreamEventKind::Closed), 1);
  // Reconnecting with nobody listening is refused.
  p.cconn = *p.client->connect(env::Endpoint{p.sn.ip(), 80});
  p.pump(10 * kMs);
  EXPECT_EQ(p.clog.count(env::StreamEventKind::Closed), 2);
  EXPECT_GE(p.w.stats().stream_refused, 1u);
}

TEST(Stream, CloseDeliversRemainingDataThenFin) {
  StreamPair p(13);
  p.connect();
  const auto payload = pattern(5000, 6);
  ASSERT_EQ(p.server->write(p.sconn, payload), payload.size());
  p.server->close(p.sconn);
  p.pump(10 * kMs);
  EXPECT_EQ(p.clog.data, payload);
  ASSERT_FALSE(p.clog.kinds.empty());
  EXPECT_EQ(p.clog.kinds.back(), env::StreamEventKind::Closed);
  p.client->close(p.cconn);
  p.pump(10 * kMs);
  EXPECT_EQ(p.w.net().st_connections(), 0u);
}

TEST(Stream, ConnectTimesOutAcrossPartition) {
  StreamPair p(14);
  p.w.net().partition(0b01, 0b10, true, 10 * kSec);
  p.cconn = *p.client->connect(env::Endpoint{p.sn.ip(), 80});
  p.pump(3 * kSec);
  EXPECT_EQ(p.clog.count(env::StreamEventKind::Closed), 1);
  EXPECT_EQ(p.clog.count(env::StreamEventKind::Connected), 0);
}

}  // namespace
}  // namespace lle::sim
