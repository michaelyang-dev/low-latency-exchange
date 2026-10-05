// net/common: endpoints, interface lookup, buffer arena, fixed queue, connection table,
// backend selection.
#include <gtest/gtest.h>

#include <array>
#include <set>

#include "net/common/buffer_arena.h"
#include "net/common/conn_table.h"
#include "net/common/endpoint.h"
#include "net/common/fixed_queue.h"
#include "net/common/iface.h"
#include "net/common/port.h"
#include "net/common/sockopt.h"
#include "net/common/timestamps.h"

namespace lle::net {
namespace {

TEST(Endpoint, ParsesDottedQuad) {
  EXPECT_EQ(parse_ipv4("127.0.0.1"), kLoopbackV4);
  EXPECT_EQ(parse_ipv4("0.0.0.0"), kAnyV4);
  EXPECT_EQ(parse_ipv4("239.1.2.3"), ipv4(239, 1, 2, 3));
  EXPECT_EQ(parse_ipv4("255.255.255.255"), 0xFFFF'FFFFu);
  for (const char* bad : {"", "1.2.3", "1.2.3.4.5", "256.0.0.1", "1..2.3", "a.b.c.d", "1.2.3.4 ", " 1.2.3.4", "1.2.3.-4",
                          "1.2.3.0004", "1.2.3."}) {
    EXPECT_FALSE(parse_ipv4(bad).has_value()) << bad;
  }
}

TEST(Endpoint, ParsesAndFormatsEndpoints) {
  const auto e = parse_endpoint("10.1.2.3:26400");
  ASSERT_TRUE(e.has_value());
  EXPECT_EQ(e->ipv4, ipv4(10, 1, 2, 3));
  EXPECT_EQ(e->port, 26400);
  EXPECT_EQ(to_string(*e), "10.1.2.3:26400");
  EXPECT_EQ(to_string(Endpoint{0xFFFF'FFFFu, 65535}), "255.255.255.255:65535");
  EXPECT_EQ(ipv4_to_string(kLoopbackV4), "127.0.0.1");
  EXPECT_FALSE(parse_endpoint("10.1.2.3").has_value());
  EXPECT_FALSE(parse_endpoint("10.1.2.3:").has_value());
  EXPECT_FALSE(parse_endpoint("10.1.2.3:65536").has_value());
  EXPECT_FALSE(parse_endpoint("10.1.2.3:12x").has_value());
  std::array<char, 8> small{};
  EXPECT_EQ(format_endpoint(*e, small), 0u);
}

TEST(Endpoint, SockaddrRoundTrip) {
  const Endpoint e{ipv4(192, 168, 7, 9), 4242};
  const sockaddr_in sa = to_sockaddr(e);
  EXPECT_EQ(sa.sin_family, AF_INET);
  EXPECT_EQ(from_sockaddr(sa), e);
}

TEST(Endpoint, MulticastRange) {
  EXPECT_TRUE(is_multicast(ipv4(224, 0, 0, 1)));
  EXPECT_TRUE(is_multicast(ipv4(239, 255, 255, 255)));
  EXPECT_FALSE(is_multicast(ipv4(223, 255, 255, 255)));
  EXPECT_FALSE(is_multicast(ipv4(240, 0, 0, 0)));
}

TEST(Iface, LooksUpLoopback) {
  const auto lo = lookup_iface(loopback_ifname());
  ASSERT_TRUE(lo.has_value()) << to_string(lo.error());
  EXPECT_NE(lo->index, 0u);
  EXPECT_EQ(lo->ipv4, kLoopbackV4);
  const auto none = lookup_iface("");
  ASSERT_TRUE(none.has_value());
  EXPECT_EQ(none->index, 0u);
  EXPECT_FALSE(lookup_iface("lle-no-such-if0").has_value());
}

TEST(SockOpt, CreatesNonBlockingSocketWithOptions) {
  auto fd = open_socket(SOCK_DGRAM);
  ASSERT_TRUE(fd.has_value());
  EXPECT_TRUE(set_reuse_addr(fd->get(), true).has_value());
  EXPECT_TRUE(set_rcvbuf(fd->get(), 1 << 16).has_value());
  EXPECT_TRUE(bind_ipv4(fd->get(), Endpoint{kLoopbackV4, 0}).has_value());
  const auto local = local_endpoint(fd->get());
  ASSERT_TRUE(local.has_value());
  EXPECT_EQ(local->ipv4, kLoopbackV4);
  EXPECT_NE(local->port, 0);
  EXPECT_EQ(socket_error(fd->get()).value_or(-1), 0);
  EXPECT_FALSE(join_multicast(fd->get(), kLoopbackV4, Iface{}).has_value());  // not a group
  EXPECT_TRUE(apply_busy_poll(fd->get(), BusyPollOptions{}).has_value());    // nothing requested
}

TEST(BufferArena, FixedBuffersAndFreeList) {
  BufferArena a;
  EXPECT_FALSE(a.init(0, 64).has_value());
  ASSERT_TRUE(a.init(8, 100, 4096).has_value());
  EXPECT_FALSE(a.init(8, 100).has_value());  // once
  EXPECT_EQ(reinterpret_cast<std::uintptr_t>(a.base()) % 4096, 0u);
  EXPECT_EQ(a.stride(), 128u);
  EXPECT_EQ(a.buffer(3).size(), 100u);
  EXPECT_EQ(a.index_of(a.data(5) + 17), 5u);
  std::set<std::uint32_t> got;
  std::uint32_t idx = 0;
  while (a.acquire(idx)) got.insert(idx);
  EXPECT_EQ(got.size(), 8u);
  EXPECT_EQ(a.free_count(), 0u);
  a.release(6);
  ASSERT_TRUE(a.acquire(idx));
  EXPECT_EQ(idx, 6u);  // LIFO: the warm buffer comes back first
}

TEST(FixedQueue, RingSemantics) {
  FixedQueue<int> q;
  q.init(3);
  EXPECT_EQ(q.capacity(), 4u);
  for (int i = 0; i < 4; ++i) EXPECT_TRUE(q.push(i));
  EXPECT_FALSE(q.push(9));
  EXPECT_EQ(q.front(), 0);
  q.pop();
  EXPECT_TRUE(q.push(4));
  EXPECT_EQ(q[3], 4);
  int expect = 1;
  while (!q.empty()) {
    EXPECT_EQ(q.front(), expect++);
    q.pop();
  }
}

TEST(ConnTable, GenerationsRejectStaleIds) {
  ConnTable<int> t;
  t.init(2);
  const ConnId a = t.alloc();
  const ConnId b = t.alloc();
  ASSERT_NE(a, kNoConn);
  ASSERT_NE(b, kNoConn);
  EXPECT_EQ(t.alloc(), kNoConn);
  int* pa = t.get(a);
  ASSERT_NE(pa, nullptr);
  *pa = 7;
  EXPECT_EQ(t.at(conn_slot(a)), 7);
  t.free(a);
  EXPECT_EQ(t.get(a), nullptr);
  const ConnId c = t.alloc();
  EXPECT_EQ(conn_slot(c), conn_slot(a));
  EXPECT_NE(c, a);
  EXPECT_EQ(t.get(a), nullptr);
  EXPECT_NE(t.get(c), nullptr);
  EXPECT_EQ(t.get(kNoConn), nullptr);
  EXPECT_EQ(t.live(), 2u);
}

TEST(ConnTable, GenerationWrapsWithoutProducingNoConn) {
  ConnTable<int> t;
  t.init(1);
  for (int i = 0; i < 0x2'0000; ++i) {
    const ConnId c = t.alloc();
    ASSERT_NE(c, kNoConn);
    ASSERT_NE(conn_gen(c), 0u);
    ASSERT_NE(conn_gen(c), 0xFFFFu);
    t.free(c);
  }
}

TEST(Backend, ParsesNames) {
  for (const BackendKind k : kAllBackends) EXPECT_EQ(parse_backend(to_string(k)), k);
  EXPECT_EQ(parse_backend("sock"), BackendKind::Epoll);
  EXPECT_EQ(parse_backend("kqueue"), BackendKind::Epoll);
  EXPECT_FALSE(parse_backend("dpdk").has_value());
  EXPECT_TRUE(backend_compiled(BackendKind::Epoll));
#if defined(__APPLE__)
  EXPECT_FALSE(backend_compiled(BackendKind::BusyPoll));
  EXPECT_FALSE(backend_compiled(BackendKind::Uring));
#endif
}

TEST(TsValidity, NinetyNinePointNinePercentRule) {
  TsValidity v;
  EXPECT_FALSE(v.valid());  // nothing measured
  for (int i = 0; i < 999; ++i) v.record(TsKind::Hardware);
  v.record(TsKind::None);
  EXPECT_TRUE(v.valid());
  EXPECT_EQ(v.hw_ppm(), 999'000u);
  v.record(TsKind::None);
  EXPECT_FALSE(v.valid());  // 999 / 1001 < 99.9%
  TsValidity w;
  for (int i = 0; i < 10'000; ++i) w.record(TsKind::Hardware);
  w.record(TsKind::Software);
  EXPECT_FALSE(w.valid());  // any software stamp invalidates (07 §2.5)
  EXPECT_EQ(classify(RxTimestamps{5, 0}), TsKind::Software);
  EXPECT_EQ(classify(RxTimestamps{5, 6}), TsKind::Hardware);
  EXPECT_EQ(classify(RxTimestamps{}), TsKind::None);
}

}  // namespace
}  // namespace lle::net
