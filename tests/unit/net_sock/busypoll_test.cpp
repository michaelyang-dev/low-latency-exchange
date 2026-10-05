// Variant (ii) knobs on Linux: EPIOCSPARAMS round trip, per-socket busy-poll options
// applied through the port configs, NAPI-ID query, sysfs read-back and the netdev
// netlink NAPI dump. Options that need CAP_NET_ADMIN are skipped when not root (the vm
// integration test runs this binary as root as well). Nothing here changes host state.
#include <gtest/gtest.h>
#include <net/if.h>
#include <unistd.h>

#include <array>

#include "net/busypoll/busypoll.h"
#include "net/common/iface.h"
#include "test_util.h"

namespace lle::net::busypoll {
namespace {

using test::bytes;

bool is_root() { return ::geteuid() == 0; }

TEST(BusyPoll, EpollParamsRoundTrip) {
  sock::Poller p;
  ASSERT_TRUE(p.open().has_value());
  Config cfg;  // 07 §1: {50 us, budget 64, prefer}
  auto r = configure_reactor(p, cfg);
  ASSERT_TRUE(r.has_value()) << to_string(r.error()) << " (EPIOCSPARAMS needs kernel >= 6.9)";
  auto got = get_epoll_params(p.fd());
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got->busy_poll_usecs, 50u);
  EXPECT_EQ(got->budget, 64);
  EXPECT_TRUE(got->prefer);
  // Budgets above NAPI_POLL_WEIGHT need CAP_NET_ADMIN.
  auto big = set_epoll_params(p.fd(), EpollParams{50, 1024, true});
  if (!is_root()) {
    ASSERT_FALSE(big.has_value());
    EXPECT_EQ(big.error().code, EPERM);
  }
  EXPECT_FALSE(set_epoll_params(-1, EpollParams{}).has_value());
}

TEST(BusyPoll, BusyPollReactorStillDeliversTraffic) {
  sock::Poller p;
  ASSERT_TRUE(p.open().has_value());
  ASSERT_TRUE(configure_reactor(p, Config{}).has_value());
  UdpConfig rc;
  rc.bind = Endpoint{kLoopbackV4, 0};
  UdpConfig tc = rc;
  sock::UdpPort rx, tx;
  ASSERT_TRUE(rx.open(rc, &p).has_value());
  ASSERT_TRUE(tx.open(tc).has_value());
  (void)rx.poll_rx([](const env::RxDatagram&) {});
  ASSERT_TRUE(tx.send(rx.local(), bytes("bp")));
  std::size_t got = 0;
  for (int i = 0; i < test::kMaxIters && got == 0; ++i) {
    (void)p.poll(test::kWaitSlice);  // epoll_wait busy-polls (no NAPI on lo: falls through)
    got += rx.poll_rx([](const env::RxDatagram& d) { EXPECT_EQ(d.data.size(), 2u); });
  }
  EXPECT_EQ(got, 1u);
}

TEST(BusyPoll, PerSocketOptionsViaPortConfig) {
  Config cfg;
  UdpConfig uc;
  uc.bind = Endpoint{kLoopbackV4, 0};
  apply_to(uc, cfg);
  EXPECT_EQ(uc.busy_poll.busy_poll_us, 50u);
  sock::UdpPort port;
  auto r = port.open(uc);
  if (!r && r.error().code == EPERM && !is_root()) GTEST_SKIP() << "SO_PREFER_BUSY_POLL/BUDGET need CAP_NET_ADMIN";
  ASSERT_TRUE(r.has_value()) << to_string(r.error());
  auto o = read_socket_options(port.fd());
  ASSERT_TRUE(o.has_value()) << to_string(o.error());
  EXPECT_EQ(o->busy_poll_us, 50u);
  EXPECT_TRUE(o->prefer);
  EXPECT_TRUE(o->budget == 0 || o->budget == 64) << "no getter for SO_BUSY_POLL_BUDGET on most kernels";
}

TEST(BusyPoll, UnprivilegedSoBusyPollAlone) {
  // SO_BUSY_POLL by itself (no prefer, default budget).
  UdpConfig uc;
  uc.bind = Endpoint{kLoopbackV4, 0};
  uc.busy_poll = BusyPollOptions{50, false, 0};
  sock::UdpPort port;
  auto r = port.open(uc);
  if (!r && r.error().code == EPERM) GTEST_SKIP() << "kernel requires CAP_NET_ADMIN to raise SO_BUSY_POLL";
  ASSERT_TRUE(r.has_value()) << to_string(r.error());
  auto o = read_socket_options(port.fd());
  ASSERT_TRUE(o.has_value()) << to_string(o.error());
  EXPECT_EQ(o->busy_poll_us, 50u);
  EXPECT_FALSE(o->prefer);
}

TEST(BusyPoll, TcpConfigCarriesBusyPoll) {
  Config cfg;
  TcpConfig tc;
  apply_to(tc, cfg);
  EXPECT_TRUE(tc.busy_poll.prefer);
  sock::TcpPort port;
  ASSERT_TRUE(port.open(tc).has_value());
  auto ep = port.listen(Endpoint{kLoopbackV4, 0});
  if (!ep && ep.error().code == EPERM && !is_root()) GTEST_SKIP() << "prefer busy poll needs CAP_NET_ADMIN";
  ASSERT_TRUE(ep.has_value()) << to_string(ep.error());
}

TEST(BusyPoll, NapiIdIsZeroOnLoopback) {
  UdpConfig uc;
  uc.bind = Endpoint{kLoopbackV4, 0};
  sock::UdpPort rx, tx;
  ASSERT_TRUE(rx.open(uc).has_value());
  ASSERT_TRUE(tx.open(uc).has_value());
  ASSERT_TRUE(tx.send(rx.local(), bytes("n")));
  std::size_t got = 0;
  for (int i = 0; i < 100'000 && got == 0; ++i) got = rx.poll_rx([](const env::RxDatagram&) {});
  auto id = incoming_napi_id(rx.fd());
  ASSERT_TRUE(id.has_value());
  EXPECT_EQ(*id, 0u) << "loopback traffic has no NAPI context";
}

TEST(BusyPoll, BusyPollRxPacketsCounterReadable) {
  auto n = busy_poll_rx_packets();
  ASSERT_TRUE(n.has_value()) << to_string(n.error());
  auto again = busy_poll_rx_packets();
  ASSERT_TRUE(again.has_value());
  EXPECT_GE(*again, *n);
}

TEST(BusyPoll, SysfsReadBack) {
  auto d = napi_defer_hard_irqs(loopback_ifname());
  ASSERT_TRUE(d.has_value()) << to_string(d.error());
  auto g = gro_flush_timeout(loopback_ifname());
  ASSERT_TRUE(g.has_value());
  EXPECT_FALSE(napi_defer_hard_irqs("../etc").has_value());
  EXPECT_FALSE(set_gro_flush_timeout("a/b", 1).has_value());
}

TEST(BusyPoll, NetlinkNapiDump) {
  // The first non-loopback interface (virtio/veth in the VM, a NIC in the lab).
  std::array<NapiInfo, 64> napis{};
  std::size_t total = 0;
  bool any_if = false;
  for (unsigned idx = 1; idx < 64; ++idx) {
    char name[IF_NAMESIZE] = {};
    if (::if_indextoname(idx, name) == nullptr || std::string_view(name) == loopback_ifname()) continue;
    any_if = true;
    auto n = list_napi(idx, napis);
    ASSERT_TRUE(n.has_value()) << to_string(n.error()) << " (netdev napi-get needs kernel >= 6.8)";
    for (std::size_t i = 0; i < *n && i < napis.size(); ++i) {
      EXPECT_EQ(napis[i].ifindex, idx);
      EXPECT_NE(napis[i].id, 0u);
    }
    total += *n;
  }
  if (!any_if) GTEST_SKIP() << "no non-loopback interface";
  RecordProperty("napi_instances", static_cast<int>(total));
  auto lo = list_napi(::if_nametoindex(loopback_ifname()), napis);
  ASSERT_TRUE(lo.has_value());
  EXPECT_EQ(*lo, 0u) << "loopback has no NAPI";
}

TEST(BusyPoll, NapiSetRequiresAdmin) {
  if (is_root()) GTEST_SKIP() << "would change host state as root";
  NapiSettings s;
  s.napi_id = 0xFFFF'FFF0u;
  s.irq_suspend_timeout_ns = 1;
  auto r = set_napi(s);
  ASSERT_FALSE(r.has_value());
  EXPECT_TRUE(r.error().code == EPERM || r.error().code == ENOENT || r.error().code == EINVAL) << to_string(r.error());
}

}  // namespace
}  // namespace lle::net::busypoll
