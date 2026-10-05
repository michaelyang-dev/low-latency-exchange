// sock::TcpPort over loopback: accept/connect/data/close events, flow-controlled writes,
// stale ConnIds, connection-table limits, shared vs private reactor.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "net/sock/tcp_port.h"
#include "test_util.h"

namespace lle::net::sock {
namespace {

using env::StreamEvent;
using env::StreamEventKind;
using test::bytes;
using test::kWaitSlice;
using test::pump_until;
using test::str;

struct Recorder {
  std::vector<StreamEventKind> kinds;
  std::vector<ConnId> conns;
  std::string data;
  void operator()(const StreamEvent& e) {
    kinds.push_back(e.kind);
    conns.push_back(e.conn);
    if (e.kind == StreamEventKind::Data) data += str(e.data);
  }
  [[nodiscard]] int count(StreamEventKind k) const {
    int n = 0;
    for (auto x : kinds) n += x == k ? 1 : 0;
    return n;
  }
  [[nodiscard]] ConnId first(StreamEventKind k) const {
    for (std::size_t i = 0; i < kinds.size(); ++i)
      if (kinds[i] == k) return conns[i];
    return kNoConn;
  }
};

// Server and client ports on one shared Poller, pumped with bounded blocking waits.
struct Pair {
  Poller poller;
  TcpPort server, client;
  Recorder s, c;
  Endpoint at{};

  explicit Pair(TcpConfig cfg = {}) {
    EXPECT_TRUE(poller.open().has_value());
    EXPECT_TRUE(server.open(cfg, &poller).has_value());
    EXPECT_TRUE(client.open(cfg, &poller).has_value());
    auto ep = server.listen(Endpoint{kLoopbackV4, 0});
    EXPECT_TRUE(ep.has_value());
    if (ep) at = *ep;
  }
  void step() {
    (void)poller.poll(kWaitSlice);
    server.poll(s);
    client.poll(c);
  }
  template <class Done>
  bool until(Done&& d) {
    return pump_until([this] { step(); }, d);
  }
};

TEST(SockTcp, ConnectAcceptEchoClose) {
  Pair p;
  ASSERT_NE(p.at.port, 0);
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  EXPECT_EQ(p.c.first(StreamEventKind::Connected), *cid);
  const ConnId sid = p.s.first(StreamEventKind::Accepted);
  EXPECT_TRUE(p.server.is_open(sid));
  EXPECT_TRUE(p.client.is_open(*cid));

  EXPECT_EQ(p.client.write(*cid, bytes("ping")), 4u);
  ASSERT_TRUE(p.until([&] { return p.s.data == "ping"; }));
  EXPECT_EQ(p.server.write(sid, bytes("pong!")), 5u);
  ASSERT_TRUE(p.until([&] { return p.c.data == "pong!"; }));

  // Peer close → Closed on the other side, and the id dies.
  p.client.close(*cid);
  EXPECT_FALSE(p.client.is_open(*cid));
  EXPECT_EQ(p.client.write(*cid, bytes("x")), 0u) << "stale id";
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Closed) == 1; }));
  EXPECT_EQ(p.s.first(StreamEventKind::Closed), sid);
  EXPECT_FALSE(p.server.is_open(sid));
  EXPECT_EQ(p.c.count(StreamEventKind::Closed), 0) << "local close produces no event";
  EXPECT_EQ(p.server.stats().accepted, 1u);
  EXPECT_EQ(p.client.stats().connected, 1u);
  EXPECT_EQ(p.server.stats().closed, 1u);
}

TEST(SockTcp, LargeTransferArrivesInOrder) {
  TcpConfig cfg;
  cfg.rx_buf_bytes = 1024;  // force many reads
  cfg.max_reads_per_poll = 4;
  Pair p(cfg);
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  std::string payload;
  for (int i = 0; i < 20'000; ++i) payload += static_cast<char>('a' + i % 26);
  std::size_t off = 0;
  ASSERT_TRUE(p.until([&] {
    if (off < payload.size()) off += p.client.write(*cid, bytes(std::string_view(payload).substr(off)));
    return p.s.data.size() == payload.size();
  }));
  EXPECT_EQ(p.s.data, payload);
  EXPECT_GE(p.server.stats().rx_reads, 20u);
}

TEST(SockTcp, WriteReportsFlowControl) {
  TcpConfig cfg;
  cfg.sndbuf = 4096;
  cfg.rcvbuf = 4096;
  Pair p(cfg);
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  // The server never reads: the kernel buffers fill and write() must accept less than offered.
  const std::string chunk(16 * 1024, 'q');
  std::size_t total = 0;
  bool short_write = false;
  for (int i = 0; i < 4096 && !short_write; ++i) {
    const std::size_t n = p.client.write(*cid, bytes(chunk));
    total += n;
    short_write = n < chunk.size();
  }
  EXPECT_TRUE(short_write) << "accepted " << total << " bytes without pushback";
  EXPECT_GE(p.client.stats().tx_short, 1u);
  EXPECT_TRUE(p.client.is_open(*cid)) << "backpressure is not an error";
}

TEST(SockTcp, ConnectRefusedReportsClosedOrError) {
  // Grab a free port, then close the listener so nothing listens there.
  Endpoint dead{};
  {
    TcpPort tmp;
    ASSERT_TRUE(tmp.open(TcpConfig{}).has_value());
    auto ep = tmp.listen(Endpoint{kLoopbackV4, 0});
    ASSERT_TRUE(ep.has_value());
    dead = *ep;
  }
  TcpPort client;
  ASSERT_TRUE(client.open(TcpConfig{}).has_value());  // private reactor
  auto cid = client.connect(dead);
  if (!cid) {
    EXPECT_EQ(cid.error().code, ECONNREFUSED);
    return;
  }
  Recorder r;
  ASSERT_TRUE(pump_until([&] { client.poll(r); }, [&] { return r.count(StreamEventKind::Closed) == 1; }, 100'000));
  EXPECT_EQ(r.first(StreamEventKind::Closed), *cid);
  EXPECT_EQ(r.count(StreamEventKind::Connected), 0);
  EXPECT_EQ(client.live_conns(), 0u);
}

TEST(SockTcp, TableFullRejectsExtraConnections) {
  TcpConfig scfg;
  scfg.max_conns = 1;
  Poller poller;
  ASSERT_TRUE(poller.open().has_value());
  TcpPort server, client;
  ASSERT_TRUE(server.open(scfg, &poller).has_value());
  ASSERT_TRUE(client.open(TcpConfig{}, &poller).has_value());
  auto at = server.listen(Endpoint{kLoopbackV4, 0});
  ASSERT_TRUE(at.has_value());
  Recorder s, c;
  ASSERT_TRUE(client.connect(*at).has_value());
  ASSERT_TRUE(client.connect(*at).has_value());
  ASSERT_TRUE(pump_until(
      [&] {
        (void)poller.poll(kWaitSlice);
        server.poll(s);
        client.poll(c);
      },
      [&] { return server.stats().accepted + server.stats().accept_rejected == 2 && c.count(StreamEventKind::Closed) >= 1; }));
  EXPECT_EQ(server.stats().accepted, 1u);
  EXPECT_EQ(server.stats().accept_rejected, 1u);
  EXPECT_EQ(s.count(StreamEventKind::Accepted), 1);
}

TEST(SockTcp, PeerResetMidStreamIsClosed) {
  Pair p;
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  const ConnId sid = p.s.first(StreamEventKind::Accepted);
  EXPECT_EQ(p.client.write(*cid, bytes("abc")), 3u);
  ASSERT_TRUE(p.until([&] { return p.s.data == "abc"; }));
  p.server.close(sid);
  // The client sees FIN (Closed from poll) or, if it writes first, EPIPE/RST (deferred Closed).
  ASSERT_TRUE(p.until([&] {
    (void)p.client.write(*cid, bytes("more"));
    return p.c.count(StreamEventKind::Closed) == 1;
  }));
  EXPECT_FALSE(p.client.is_open(*cid));
}

TEST(SockTcp, PrivateReactorWorksWithoutExternalPolling) {
  TcpPort server, client;
  ASSERT_TRUE(server.open(TcpConfig{}).has_value());
  ASSERT_TRUE(client.open(TcpConfig{}).has_value());
  auto at = server.listen(Endpoint{kLoopbackV4, 0});
  ASSERT_TRUE(at.has_value());
  auto cid = client.connect(*at);
  ASSERT_TRUE(cid.has_value());
  Recorder s, c;
  // Send exactly once: on a loaded machine the server may read only after several pump
  // iterations, and writing on every iteration until then made it receive "hihi...".
  bool sent = false;
  ASSERT_TRUE(pump_until(
      [&] {
        server.poll(s);
        client.poll(c);
        if (!sent && c.count(StreamEventKind::Connected) == 1) sent = client.write(*cid, bytes("hi")) == 2;
      },
      [&] { return s.data == "hi"; }, 200'000));
  EXPECT_EQ(s.count(StreamEventKind::Accepted), 1);
}

}  // namespace
}  // namespace lle::net::sock
