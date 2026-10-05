// io_uring backend on Linux loopback: ring setup flags, DEFER_TASKRUN polling (idle spin
// without syscalls), multishot recvmsg over a provided-buffer ring with re-arm after
// -ENOBUFS, SEND on registered files, shared rings, NAPI registration call path (iii-n),
// TX timestamps through SOCKET_URING_OP_TX_TIMESTAMP and the error-queue fallback, and
// TCP accept/connect/data/close with interop against the kernel-socket backend.
// Loopback yields only SOFTWARE timestamps; nothing here is reported as hardware.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../net_sock/test_util.h"
#include "net/hwts/abi.h"
#include "net/hwts/tx_correlator.h"
#include "net/sock/tcp_port.h"
#include "net/sock/udp_port.h"
#include "net/uring/backend.h"

namespace lle::net::uring {
namespace {

using env::StreamEvent;
using env::StreamEventKind;
using test::bytes;
using test::kWaitSlice;
using test::pump_until;
using test::str;

UdpConfig lo_udp() {
  UdpConfig c;
  c.bind = Endpoint{kLoopbackV4, 0};
  c.rx_buffers = 64;
  c.tx_slots = 16;
  return c;
}

TEST(UringRing, SetupFlagsMatchVariantIii) {
  Ring r;
  auto ok = r.open();
  ASSERT_TRUE(ok.has_value()) << to_string(ok.error());
  const unsigned f = r.setup_flags();
  EXPECT_NE(f & IORING_SETUP_SINGLE_ISSUER, 0u);
  EXPECT_NE(f & IORING_SETUP_DEFER_TASKRUN, 0u);
  EXPECT_TRUE(r.ring_fd_registered());
  EXPECT_TRUE(r.idle_check()) << "TASKRUN_FLAG lets poll(0) skip io_uring_enter when idle";
  EXPECT_FALSE(r.cqe32());
  EXPECT_FALSE(r.napi_registered());
  // An idle poll costs no syscall.
  const auto enters = r.stats().enters;
  EXPECT_EQ(r.poll(0), 0);
  EXPECT_EQ(r.stats().enters, enters);
  EXPECT_GE(r.stats().idle_skips, 1u);
  EXPECT_FALSE(r.open().has_value()) << "open twice";
}

TEST(UringRing, NapiRegistrationCallPath) {
  RingConfig c = Backend<BackendKind::UringNapi>::ring_config();
  EXPECT_TRUE(c.napi.enable);
  EXPECT_EQ(c.napi.busy_poll_us, 50u);
  Ring r;
  auto ok = r.open(c);
  ASSERT_TRUE(ok.has_value()) << to_string(ok.error()) << " (IORING_REGISTER_NAPI needs kernel >= 6.9)";
  EXPECT_TRUE(r.napi_registered());
  // (iii-n) loop shape: wait with a positive timeout so the kernel busy-polls (no NAPI
  // on loopback, so it simply times out here).
  EXPECT_EQ(r.poll(1'000'000), 0);
}

TEST(UringUdp, MultishotRecvmsgDeliversDatagrams) {
  UdpPort rx;
  auto ok = rx.open(lo_udp());
  ASSERT_TRUE(ok.has_value()) << to_string(ok.error());
  sock::UdpPort tx;
  ASSERT_TRUE(tx.open(lo_udp()).has_value());
  for (int i = 0; i < 5; ++i) ASSERT_TRUE(tx.send(rx.local(), bytes("u" + std::to_string(i))));
  std::vector<std::string> got;
  env::Endpoint src{}, dst{};
  ASSERT_TRUE(pump_until([] {},
                         [&] {
                           rx.poll_rx([&](const env::RxDatagram& d) {
                             got.push_back(str(d.data));
                             src = d.src;
                             dst = d.dst;
                           });
                           return got.size() == 5;
                         },
                         1'000'000));
  for (int i = 0; i < 5; ++i) EXPECT_EQ(got[static_cast<std::size_t>(i)], "u" + std::to_string(i));
  EXPECT_EQ(src, tx.local());
  EXPECT_EQ(dst, rx.local()) << "IP_PKTINFO cmsg parsed out of io_uring_recvmsg_out";
  EXPECT_EQ(rx.stats().rx_packets, 5u);
  EXPECT_EQ(rx.stats().rearms, 0u) << "one multishot request served every datagram";
  EXPECT_GE(rx.ring().stats().idle_skips, 1u) << "spin loop skipped syscalls while idle";
}

TEST(UringUdp, RearmsAfterProvidedBuffersRunOut) {
  UdpConfig c = lo_udp();
  c.rx_buffers = 4;  // the 5th datagram finds no buffer: -ENOBUFS ends the multishot
  c.batch = 64;
  c.rcvbuf = 1 << 20;
  UdpPort rx;
  ASSERT_TRUE(rx.open(c).has_value());
  sock::UdpPort tx;
  ASSERT_TRUE(tx.open(lo_udp()).has_value());
  constexpr int kN = 32;
  for (int i = 0; i < kN; ++i) ASSERT_TRUE(tx.send(rx.local(), bytes("d" + std::to_string(i))));
  // Let the kernel fill all four buffers before the application consumes anything.
  for (int i = 0; i < 50; ++i) (void)rx.ring().poll(1'000'000);
  std::vector<std::string> got;
  ASSERT_TRUE(pump_until([&] { (void)rx.ring().poll(kWaitSlice); },
                         [&] {
                           rx.poll_rx([&](const env::RxDatagram& d) { got.push_back(str(d.data)); });
                           return got.size() == kN;
                         }));
  for (int i = 0; i < kN; ++i) EXPECT_EQ(got[static_cast<std::size_t>(i)], "d" + std::to_string(i)) << "order kept";
  EXPECT_GE(rx.stats().no_buffers, 1u);
  EXPECT_GE(rx.stats().rearms, 1u) << "re-armed after a CQE without IORING_CQE_F_MORE";
}

TEST(UringUdp, SendOnSharedRingAndBlockingWait) {
  Ring ring;
  ASSERT_TRUE(ring.open().has_value());
  UdpPort a, b;
  ASSERT_TRUE(a.open(lo_udp(), &ring).has_value());
  ASSERT_TRUE(b.open(lo_udp(), &ring).has_value());
  ASSERT_TRUE(a.send(b.local(), bytes("ping")));
  std::string got;
  ASSERT_TRUE(pump_until([&] { (void)ring.poll(kWaitSlice); },
                         [&] {
                           b.poll_rx([&](const env::RxDatagram& d) {
                             got = str(d.data);
                             EXPECT_TRUE(b.send(d.src, bytes("pong")));
                           });
                           return !got.empty();
                         }));
  EXPECT_EQ(got, "ping");
  std::string back;
  ASSERT_TRUE(pump_until([&] { (void)ring.poll(kWaitSlice); },
                         [&] {
                           a.poll_rx([&](const env::RxDatagram& d) { back = str(d.data); });
                           return !back.empty();
                         }));
  EXPECT_EQ(back, "pong");
  (void)a.poll_rx([](const env::RxDatagram&) {});  // reap send completions
  EXPECT_EQ(a.stats().tx_packets, 1u);
  EXPECT_EQ(a.tx_slots_free(), 16u) << "TX slot returned on completion";
  EXPECT_NE(a.fixed_index(), b.fixed_index()) << "both sockets in the registered-file table";
}

TEST(UringUdp, TxSlotsBoundInflightSends) {
  UdpConfig c = lo_udp();
  c.tx_slots = 2;
  UdpPort tx;
  ASSERT_TRUE(tx.open(c).has_value());
  sock::UdpPort sink;
  ASSERT_TRUE(sink.open(lo_udp()).has_value());
  int sent = 0;
  for (int i = 0; i < 100; ++i) sent += tx.send(sink.local(), bytes("x")) ? 1 : 0;
  EXPECT_EQ(sent, 100) << "slots recycle as SENDs complete inline";
  EXPECT_FALSE(tx.send(sink.local(), bytes(std::string(4096, 'z')))) << "larger than max_datagram";
  EXPECT_EQ(tx.stats().tx_errors, 1u);
}

TEST(UringUdp, SoftwareRxTimestampsThroughRecvmsgCmsgs) {
  UdpConfig c = lo_udp();
  c.rx_ts = TsMode::Software;
  UdpPort rx;
  ASSERT_TRUE(rx.open(c).has_value());
  sock::UdpPort tx;
  ASSERT_TRUE(tx.open(lo_udp()).has_value());
  ASSERT_TRUE(tx.send(rx.local(), bytes("t")));
  RxTimestamps ts{};
  bool got = false;
  ASSERT_TRUE(pump_until([] {},
                         [&] {
                           rx.poll_rx_ts([&](const env::RxDatagram& d, const RxTimestamps& t) {
                             got = true;
                             ts = t;
                             EXPECT_EQ(d.hw_rx_ns, 0);
                           });
                           return got;
                         },
                         1'000'000));
  EXPECT_GT(ts.sw_ns, 0) << "SCM_TIMESTAMPING ts[0] (software) from the provided buffer";
  EXPECT_EQ(ts.hw_ns, 0) << "loopback: no hardware stamp";
  EXPECT_EQ(rx.stats().rx_ts.sw, 1u);
}

std::vector<TxStamp> collect_tx_stamps(UdpPort& p, std::size_t want) {
  std::vector<TxStamp> out;
  for (int i = 0; i < test::kMaxIters && out.size() < want; ++i) {
    (void)p.ring().poll(kWaitSlice);
    p.drain_tx_timestamps([&](const TxStamp& s) { out.push_back(s); });
  }
  return out;
}

TEST(UringUdp, TxTimestampsViaUringCommand) {
  if (!tx_timestamp_cmd_compiled()) GTEST_SKIP() << "liburing < 2.12";
  UdpConfig c = lo_udp();
  c.tx_ts = TsMode::Software;
  UdpPort tx;
  ASSERT_TRUE(tx.open(c).has_value());  // private ring: CQE32 added automatically
  ASSERT_TRUE(tx.ring().cqe32());
  sock::UdpPort sink;
  ASSERT_TRUE(sink.open(lo_udp()).has_value());
  hwts::TxCorrelator corr;
  corr.init(hwts::KeyMode::Datagram, 64);
  constexpr int kN = 6;
  for (int i = 0; i < kN; ++i) {
    ASSERT_TRUE(tx.send(sink.local(), bytes("o" + std::to_string(i))));
    (void)corr.on_send(static_cast<std::uint64_t>(i), 2);
  }
  const auto stamps = collect_tx_stamps(tx, kN);
  if (!tx.tx_timestamps_via_uring()) GTEST_SKIP() << "kernel rejected SOCKET_URING_OP_TX_TIMESTAMP (< 6.17)";
  ASSERT_EQ(stamps.size(), static_cast<std::size_t>(kN));
  std::vector<std::uint64_t> tags;
  for (const TxStamp& s : stamps) {
    EXPECT_EQ(s.type, hwts::abi::kTstampSnd);
    EXPECT_EQ(s.kind(), TsKind::Software) << "IORING_CQE_F_TSTAMP_HW clear on loopback";
    EXPECT_GT(s.ts.sw_ns, 0);
    (void)corr.on_stamp(s, [&](std::uint64_t tag, const TxStamp&) { tags.push_back(tag); });
  }
  EXPECT_EQ(tags, (std::vector<std::uint64_t>{0, 1, 2, 3, 4, 5}));
  EXPECT_FALSE(corr.validity().valid()) << "software stamps never validate a run";
}

TEST(UringUdp, TxTimestampsFallBackToErrorQueueWithoutCqe32) {
  Ring ring;  // shared ring without CQE32
  ASSERT_TRUE(ring.open().has_value());
  UdpConfig c = lo_udp();
  c.tx_ts = TsMode::Software;
  UdpPort tx;
  ASSERT_TRUE(tx.open(c, &ring).has_value());
  EXPECT_FALSE(tx.tx_timestamps_via_uring());
  sock::UdpPort sink;
  ASSERT_TRUE(sink.open(lo_udp()).has_value());
  for (int i = 0; i < 3; ++i) ASSERT_TRUE(tx.send(sink.local(), bytes("e")));
  const auto stamps = collect_tx_stamps(tx, 3);
  ASSERT_EQ(stamps.size(), 3u);
  for (std::size_t i = 0; i < stamps.size(); ++i) {
    EXPECT_EQ(stamps[i].id, i);
    EXPECT_EQ(stamps[i].kind(), TsKind::Software);
  }
}

TEST(UringUdp, ReopenOnSharedRingIgnoresStaleCompletions) {
  Ring ring;
  ASSERT_TRUE(ring.open().has_value());
  sock::UdpPort tx;
  ASSERT_TRUE(tx.open(lo_udp()).has_value());
  for (int round = 0; round < 3; ++round) {
    UdpPort rx;
    ASSERT_TRUE(rx.open(lo_udp(), &ring).has_value());
    ASSERT_TRUE(tx.send(rx.local(), bytes("r" + std::to_string(round))));
    std::string got;
    ASSERT_TRUE(pump_until([&] { (void)ring.poll(kWaitSlice); },
                           [&] {
                             rx.poll_rx([&](const env::RxDatagram& d) { got = str(d.data); });
                             return !got.empty();
                           }));
    EXPECT_EQ(got, "r" + std::to_string(round));
  }
  // Cancellation CQEs of the closed ports arrive after their sinks are gone: they are
  // counted, never delivered to a later port.
  for (int i = 0; i < 10; ++i) (void)ring.poll(1'000'000);
  EXPECT_GE(ring.stats().ignored + ring.stats().dropped, 1u);
}

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

TcpConfig small_tcp() {
  TcpConfig c;
  c.max_conns = 8;
  c.rx_buffers = 64;
  c.rx_buf_bytes = 4096;
  c.tx_staging_bytes = 16 * 1024;
  return c;
}

struct UringPair {
  Ring ring;
  TcpPort server, client;
  Recorder s, c;
  Endpoint at{};
  explicit UringPair(TcpConfig cfg = small_tcp()) {
    EXPECT_TRUE(ring.open().has_value());
    EXPECT_TRUE(server.open(cfg, &ring).has_value());
    EXPECT_TRUE(client.open(cfg, &ring).has_value());
    auto ep = server.listen(Endpoint{kLoopbackV4, 0});
    EXPECT_TRUE(ep.has_value());
    if (ep) at = *ep;
  }
  void step() {
    (void)ring.poll(kWaitSlice);
    server.poll(s);
    client.poll(c);
  }
  template <class D>
  bool until(D&& d) {
    return pump_until([this] { step(); }, d);
  }
};

TEST(UringTcp, AcceptConnectEchoClose) {
  UringPair p;
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  const ConnId sid = p.s.first(StreamEventKind::Accepted);
  EXPECT_EQ(p.c.first(StreamEventKind::Connected), *cid);
  EXPECT_EQ(p.client.write(*cid, bytes("ENTER")), 5u);
  ASSERT_TRUE(p.until([&] { return p.s.data == "ENTER"; }));
  EXPECT_EQ(p.server.write(sid, bytes("ACCEPTED")), 8u);
  ASSERT_TRUE(p.until([&] { return p.c.data == "ACCEPTED"; }));
  p.client.close(*cid);
  EXPECT_FALSE(p.client.is_open(*cid));
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Closed) == 1; }));
  EXPECT_EQ(p.s.first(StreamEventKind::Closed), sid);
  EXPECT_EQ(p.c.count(StreamEventKind::Closed), 0);
  EXPECT_EQ(p.server.live_conns(), 0u);
}

TEST(UringTcp, OneSendPerMessageAndOrderedStream) {
  UringPair p;
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  std::string expect;
  int writes = 0;
  for (int i = 0; i < 200; ++i) {
    const std::string m = "msg" + std::to_string(i) + ";";
    if (p.client.write(*cid, bytes(m)) == m.size()) {
      expect += m;
      ++writes;
    } else {
      p.step();
      --i;
    }
  }
  ASSERT_TRUE(p.until([&] { return p.s.data.size() == expect.size() && p.client.tx_pending(*cid) == 0; }));
  EXPECT_EQ(p.s.data, expect);
  EXPECT_EQ(p.client.stats().tx_sends, static_cast<std::uint64_t>(writes)) << "one SEND per write (one_msg_per_send)";
}

TEST(UringTcp, LargeTransferWrapsStagingBuffer) {
  TcpConfig cfg = small_tcp();
  cfg.one_msg_per_send = false;  // coalesce staged bytes into larger SENDs
  UringPair p(cfg);
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  std::string payload;
  for (int i = 0; i < 300'000; ++i) payload += static_cast<char>('A' + i % 26);
  std::size_t off = 0;
  bool short_seen = false;
  ASSERT_TRUE(p.until([&] {
    while (off < payload.size()) {
      const std::size_t n = p.client.write(*cid, bytes(std::string_view(payload).substr(off, 7000)));
      if (n == 0) {
        short_seen = true;
        break;
      }
      off += n;
    }
    return p.s.data.size() == payload.size();
  }));
  EXPECT_EQ(p.s.data, payload);
  EXPECT_TRUE(short_seen) << "16 KiB staging must push back on a 300 KB burst";
  EXPECT_LT(p.client.stats().tx_sends, 300'000u / 7000u * 2) << "coalesced";
}

TEST(UringTcp, WriteIsAllOrNothingPerMessageWhenStagingIsFull) {
  TcpConfig cfg = small_tcp();
  cfg.tx_staging_bytes = 4096;
  cfg.sndbuf = 4096;
  cfg.rcvbuf = 4096;
  UringPair p(cfg);
  auto cid = p.client.connect(p.at);
  ASSERT_TRUE(cid.has_value());
  ASSERT_TRUE(p.until([&] { return p.s.count(StreamEventKind::Accepted) == 1 && p.c.count(StreamEventKind::Connected) == 1; }));
  // The server never polls its data (we stop polling it), so kernel buffers and then the
  // staging buffer fill; write() must then refuse whole messages.
  const std::string m(1000, 'm');
  std::size_t refused = 0;
  for (int i = 0; i < 10'000 && refused == 0; ++i) {
    const std::size_t n = p.client.write(*cid, bytes(m));
    EXPECT_TRUE(n == 0 || n == m.size()) << n;
    if (n == 0) ++refused;
    (void)p.ring.poll(0);
    p.client.poll(p.c);
  }
  EXPECT_EQ(refused, 1u);
  EXPECT_TRUE(p.client.is_open(*cid));
}

TEST(UringTcp, InteropWithKernelSocketBackend) {
  // uring server ⇄ sock (epoll/kqueue) client and the reverse, in one test.
  Ring ring;
  ASSERT_TRUE(ring.open().has_value());
  TcpPort userver;
  ASSERT_TRUE(userver.open(small_tcp(), &ring).has_value());
  auto uat = userver.listen(Endpoint{kLoopbackV4, 0});
  ASSERT_TRUE(uat.has_value());
  sock::TcpPort sclient;
  ASSERT_TRUE(sclient.open(TcpConfig{}).has_value());
  auto cid = sclient.connect(*uat);
  ASSERT_TRUE(cid.has_value());
  Recorder us, sc;
  bool sent = false;
  ASSERT_TRUE(pump_until(
      [&] {
        (void)ring.poll(kWaitSlice);
        userver.poll(us);
        sclient.poll(sc);
        if (!sent && sc.count(StreamEventKind::Connected) == 1) sent = sclient.write(*cid, bytes("from-epoll")) == 10;
        if (us.data == "from-epoll" && sc.data.empty()) (void)userver.write(us.first(StreamEventKind::Accepted), bytes("from-uring"));
      },
      [&] { return sc.data == "from-uring"; }));
  sclient.close(*cid);
  ASSERT_TRUE(pump_until(
      [&] {
        (void)ring.poll(kWaitSlice);
        userver.poll(us);
      },
      [&] { return us.count(StreamEventKind::Closed) == 1; }));
}

TEST(UringTcp, ConnectRefusedIsClosed) {
  Endpoint dead{};
  {
    sock::TcpPort tmp;
    ASSERT_TRUE(tmp.open(TcpConfig{}).has_value());
    auto ep = tmp.listen(Endpoint{kLoopbackV4, 0});
    ASSERT_TRUE(ep.has_value());
    dead = *ep;
  }
  TcpPort client;
  ASSERT_TRUE(client.open(small_tcp()).has_value());  // private ring
  auto cid = client.connect(dead);
  ASSERT_TRUE(cid.has_value());
  Recorder r;
  ASSERT_TRUE(pump_until([&] { client.poll(r); }, [&] { return r.count(StreamEventKind::Closed) == 1; }, 1'000'000));
  EXPECT_EQ(r.first(StreamEventKind::Closed), *cid);
  EXPECT_EQ(client.live_conns(), 0u);
}

TEST(UringTcp, TxTimestampsPerConnection) {
  if (!tx_timestamp_cmd_compiled()) GTEST_SKIP() << "liburing < 2.12";
  RingConfig rc;
  rc.cqe32 = true;
  Ring ring;
  ASSERT_TRUE(ring.open(rc).has_value());
  TcpConfig cfg = small_tcp();
  cfg.tx_ts = TsMode::Software;
  TcpPort server, client;
  ASSERT_TRUE(server.open(small_tcp(), &ring).has_value());
  ASSERT_TRUE(client.open(cfg, &ring).has_value());
  auto at = server.listen(Endpoint{kLoopbackV4, 0});
  ASSERT_TRUE(at.has_value());
  auto cid = client.connect(*at);
  ASSERT_TRUE(cid.has_value());
  Recorder s, c;
  ASSERT_TRUE(pump_until(
      [&] {
        (void)ring.poll(kWaitSlice);
        server.poll(s);
        client.poll(c);
      },
      [&] { return c.count(StreamEventKind::Connected) == 1 && s.count(StreamEventKind::Accepted) == 1; }));
  hwts::TxCorrelator corr;
  corr.init(hwts::KeyMode::Stream, 64);
  const std::vector<std::string> msgs = {std::string(49, 'O'), std::string(23, 'X')};
  for (std::size_t i = 0; i < msgs.size(); ++i) {
    ASSERT_EQ(client.write(*cid, bytes(msgs[i])), msgs[i].size());
    (void)corr.on_send(i, msgs[i].size());
    // Keep one message per skb: wait for the SEND to complete before the next write.
    ASSERT_TRUE(pump_until(
        [&] {
          (void)ring.poll(kWaitSlice);
          client.poll(c);
        },
        [&] { return client.tx_pending(*cid) == 0; }));
  }
  std::vector<std::uint64_t> tags;
  ASSERT_TRUE(pump_until(
      [&] {
        (void)ring.poll(kWaitSlice);
        server.poll(s);
        client.poll(c);
        client.drain_tx_timestamps(*cid, [&](const TxStamp& st) {
          EXPECT_EQ(st.kind(), TsKind::Software);
          (void)corr.on_stamp(st, [&](std::uint64_t tag, const TxStamp&) { tags.push_back(tag); });
        });
      },
      [&] { return tags.size() == msgs.size(); }));
  EXPECT_EQ(tags, (std::vector<std::uint64_t>{0, 1}));
  EXPECT_TRUE(client.tx_timestamps_via_uring());
}

}  // namespace
}  // namespace lle::net::uring
