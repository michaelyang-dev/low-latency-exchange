// sock::UdpPort over loopback: unicast, batching, truncation, readiness with a shared
// Poller (blocking waits), multicast on the loopback interface (skipped where the OS
// refuses), software RX timestamps.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "net/common/iface.h"
#include "net/sock/backend.h"
#include "net/sock/udp_port.h"
#include "test_util.h"

namespace lle::net::sock {
namespace {

using test::bytes;
using test::kWaitSlice;
using test::pump_until;
using test::str;

UdpConfig loopback_cfg() {
  UdpConfig c;
  c.bind = Endpoint{kLoopbackV4, 0};
  return c;
}

TEST(SockUdp, UnicastLoopbackWithoutPoller) {
  UdpPort rx, tx;
  ASSERT_TRUE(rx.open(loopback_cfg()).has_value());
  ASSERT_TRUE(tx.open(loopback_cfg()).has_value());
  EXPECT_EQ(rx.poll_rx([](const env::RxDatagram&) { FAIL() << "nothing sent yet"; }), 0u);
  ASSERT_TRUE(tx.send(rx.local(), bytes("hello")));
  std::vector<std::string> got;
  env::Endpoint src{}, dst{};
  ASSERT_TRUE(pump_until([] {},
                         [&] {
                           rx.poll_rx([&](const env::RxDatagram& d) {
                             got.push_back(str(d.data));
                             src = d.src;
                             dst = d.dst;
                             EXPECT_EQ(d.hw_rx_ns, 0);
                           });
                           return !got.empty();
                         },
                         100'000));
  ASSERT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0], "hello");
  EXPECT_EQ(src, tx.local());
  EXPECT_EQ(dst, rx.local());  // IP_PKTINFO / IP_RECVDSTADDR
  EXPECT_EQ(rx.stats().rx_packets, 1u);
  EXPECT_EQ(tx.stats().tx_packets, 1u);
  EXPECT_EQ(tx.stats().tx_bytes, 5u);
}

TEST(SockUdp, PollerDrivenBatchesAndEdgeTriggering) {
  Poller poller;
  ASSERT_TRUE(poller.open().has_value());
  UdpConfig cfg = loopback_cfg();
  cfg.batch = 4;
  cfg.rcvbuf = 1 << 20;
  UdpPort rx, tx;
  ASSERT_TRUE(rx.open(cfg, &poller).has_value());
  ASSERT_TRUE(tx.open(loopback_cfg()).has_value());
  // Drain the "try once" readiness set at open.
  EXPECT_EQ(rx.poll_rx([](const env::RxDatagram&) {}), 0u);
  EXPECT_EQ(rx.poll_rx([](const env::RxDatagram&) {}), 0u);
  const std::uint64_t calls_idle = rx.stats().rx_calls;
  EXPECT_EQ(rx.poll_rx([](const env::RxDatagram&) {}), 0u);
  EXPECT_EQ(rx.stats().rx_calls, calls_idle) << "no syscall while the poller reports nothing";

  constexpr int kN = 10;
  for (int i = 0; i < kN; ++i) ASSERT_TRUE(tx.send(rx.local(), bytes("m" + std::to_string(i))));
  std::vector<std::string> got;
  ASSERT_TRUE(pump_until(
      [&] {
        (void)poller.poll(kWaitSlice);
        std::size_t n;
        do {
          n = rx.poll_rx([&](const env::RxDatagram& d) { got.push_back(str(d.data)); });
          EXPECT_LE(n, 4u);
        } while (n == 4);
      },
      [&] { return got.size() == kN; }));
  for (int i = 0; i < kN; ++i) EXPECT_EQ(got[static_cast<std::size_t>(i)], "m" + std::to_string(i));
  EXPECT_GE(rx.stats().rx_calls, 3u);
}

TEST(SockUdp, BlockingWaitWakesOnArrival) {
  Poller poller;
  ASSERT_TRUE(poller.open().has_value());
  UdpPort rx, tx;
  ASSERT_TRUE(rx.open(loopback_cfg(), &poller).has_value());
  ASSERT_TRUE(tx.open(loopback_cfg()).has_value());
  (void)rx.poll_rx([](const env::RxDatagram&) {});
  EXPECT_EQ(poller.poll(0), 0);
  ASSERT_TRUE(tx.send(rx.local(), bytes("x")));
  int n = 0;
  for (int i = 0; i < test::kMaxIters && n == 0; ++i) n = poller.poll(kWaitSlice);
  EXPECT_EQ(n, 1);
  std::size_t got = rx.poll_rx([](const env::RxDatagram& d) { EXPECT_EQ(d.data.size(), 1u); });
  EXPECT_EQ(got, 1u);
}

TEST(SockUdp, TruncatedDatagramsAreDroppedAndCounted) {
  UdpConfig cfg = loopback_cfg();
  cfg.max_datagram = 16;
  UdpPort rx, tx;
  ASSERT_TRUE(rx.open(cfg).has_value());
  ASSERT_TRUE(tx.open(loopback_cfg()).has_value());
  ASSERT_TRUE(tx.send(rx.local(), bytes(std::string(64, 'z'))));
  ASSERT_TRUE(tx.send(rx.local(), bytes("short")));
  std::vector<std::string> got;
  ASSERT_TRUE(pump_until([] {},
                         [&] {
                           rx.poll_rx([&](const env::RxDatagram& d) { got.push_back(str(d.data)); });
                           return !got.empty();
                         },
                         100'000));
  EXPECT_EQ(got.front(), "short");
  EXPECT_EQ(rx.stats().rx_truncated, 1u);
}

TEST(SockUdp, SoftwareRxTimestampsWhenRequested) {
  UdpConfig cfg = loopback_cfg();
  cfg.rx_ts = TsMode::Software;
  UdpPort rx, tx;
  ASSERT_TRUE(rx.open(cfg).has_value());
  ASSERT_TRUE(tx.open(loopback_cfg()).has_value());
  ASSERT_TRUE(tx.send(rx.local(), bytes("ts")));
  RxTimestamps ts{};
  bool got = false;
  ASSERT_TRUE(pump_until([] {},
                         [&] {
                           rx.poll_rx_ts([&](const env::RxDatagram& d, const RxTimestamps& t) {
                             got = true;
                             ts = t;
                             EXPECT_EQ(d.hw_rx_ns, 0) << "loopback has no hardware timestamps";
                           });
                           return got;
                         },
                         100'000));
  EXPECT_GT(ts.sw_ns, 0) << "software timestamp (SO_TIMESTAMPING / SO_TIMESTAMP)";
  EXPECT_EQ(ts.hw_ns, 0);
  EXPECT_EQ(rx.stats().rx_ts.sw, 1u);
  EXPECT_EQ(rx.stats().rx_ts.hw, 0u);
  EXPECT_FALSE(rx.stats().rx_ts.valid()) << "software stamps never validate a run";
}

TEST(SockUdp, MulticastOnLoopback) {
  const char* lo = loopback_ifname();
  const std::uint32_t group = ipv4(239, 77, 1, 3);
  UdpConfig rcfg;
  rcfg.bind = Endpoint{kAnyV4, 0};
  rcfg.groups = {group};
  rcfg.ifname = lo;
  UdpPort rx;
  if (auto r = rx.open(rcfg); !r) GTEST_SKIP() << "multicast join on " << lo << " refused: " << to_string(r.error());
  UdpConfig tcfg = loopback_cfg();
  tcfg.ifname = lo;
  tcfg.mcast_loop = true;
  UdpPort tx;
  ASSERT_TRUE(tx.open(tcfg).has_value());
  if (!tx.send(Endpoint{group, rx.local().port}, bytes("tick")))
    GTEST_SKIP() << "multicast send via " << lo << " refused (no route)";
  std::vector<std::string> got;
  env::Endpoint dst{};
  const bool ok = pump_until([] {},
                             [&] {
                               rx.poll_rx([&](const env::RxDatagram& d) {
                                 got.push_back(str(d.data));
                                 dst = d.dst;
                               });
                               return !got.empty();
                             },
                             200'000);
  if (!ok) GTEST_SKIP() << "multicast not looped back on " << lo << " by this OS configuration";
  EXPECT_EQ(got.front(), "tick");
  EXPECT_EQ(dst.ipv4, group) << "dst carries the multicast group";
}

TEST(SockUdp, BackendBindingSatisfiesConcepts) {
  static_assert(env::DatagramPortLike<Backend<BackendKind::Epoll>::DatagramPort>);
  static_assert(env::StreamPortLike<Backend<BackendKind::Epoll>::StreamPort>);
  UdpPort p;
  ASSERT_TRUE(p.open(loopback_cfg()).has_value());
  EXPECT_FALSE(p.open(loopback_cfg()).has_value()) << "open twice";
  p.close();
  EXPECT_FALSE(p.is_open());
}

}  // namespace
}  // namespace lle::net::sock
