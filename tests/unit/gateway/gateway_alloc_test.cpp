// No allocation on the gateway's per-message paths after start-up (conventions "Hot
// paths"; 07 §3): inbound framing and the SCQ push, release-gated egress into the
// session store and onto the connection, timers. Connection setup (accept, login)
// constructs the session and is outside the counted region. This TU replaces every
// form of the global operator new/delete for the whole binary.
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

#include "concurrent/mpsc_scq.h"
#include "fake_net.h"
#include "gateway/gateway.h"
#include "md/egress.h"
#include "proto/soupbin/client_session.h"
#include "proto/soupbin/packets.h"

namespace {

std::atomic<bool> g_counting{false};
std::atomic<std::uint64_t> g_allocations{0};

void* counted_alloc(std::size_t n, std::size_t align = 0) {
  if (g_counting.load(std::memory_order_relaxed)) g_allocations.fetch_add(1, std::memory_order_relaxed);
  void* p = nullptr;
  if (align <= alignof(std::max_align_t)) {
    p = std::malloc(n == 0 ? 1 : n);
  } else if (::posix_memalign(&p, align, n == 0 ? align : n) != 0) {
    p = nullptr;
  }
  if (p == nullptr) throw std::bad_alloc();
  return p;
}
void* counted_nothrow(std::size_t n, std::size_t align = 0) noexcept {
  try {
    return counted_alloc(n, align);
  } catch (...) {
    return nullptr;
  }
}

}  // namespace

void* operator new(std::size_t n) { return counted_alloc(n); }
void* operator new[](std::size_t n) { return counted_alloc(n); }
void* operator new(std::size_t n, std::align_val_t a) { return counted_alloc(n, static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n, std::align_val_t a) { return counted_alloc(n, static_cast<std::size_t>(a)); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n); }
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }

namespace lle::gw {
namespace {

struct Env {
  using Net = testnet::FakeNet;
  using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 1024>;
  using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 64>;
  using Clock = testnet::FakeClock;
};

TEST(GatewayAlloc, InboundEgressAndTimersDoNotAllocateAfterLogin) {
  const std::vector<std::uint8_t> salt = {1, 2, 3};
  std::vector<SessionSpec> specs = {SessionSpec{1, 100, "ALPHA", Credential::make("pw", salt), 0, false}};
  const SessionTable table = *SessionTable::build(std::move(specs), md::kGateways);
  auto ouch = std::make_unique<Env::OuchQueue>();
  auto events = std::make_unique<Env::SessionQueue>();
  testnet::FakeClock clock;
  md::EgressRing egress;
  egress.init(std::size_t{1} << 20);
  md::EgressState state;
  std::atomic<bool> mirror{false};
  GatewayConfig c;
  c.soup.session = soup::SessionId::from("S1");
  c.tcp.max_conns = 4;
  Gateway<Env> gw(c, table, {}, *ouch, *events, clock, GatewayShared{&egress, &state, &mirror});
  ASSERT_TRUE(gw.start());
  gw.port().discard = true;

  // Login (connection setup: may allocate).
  soup::ClientConfig cc;
  cc.username = Alpha<soup::kUsernameLen>("ALPHA");
  cc.password = Alpha<soup::kPasswordLen>("pw");
  soup::ClientSession client(cc);
  const env::ConnId conn = gw.port().accept();
  const soup::Actions& login = client.connect(clock.mono);
  gw.port().data(conn, login.write);
  for (int i = 0; i < 3; ++i) (void)gw.poll();
  ASSERT_EQ(gw.stats().logins, 1u);
  seq::InboundMsg ev;  // the Login, tagged, in the OUCH queue (DST-004)
  while (ouch->try_pop(ev)) {
  }

  // Inbound packets and egress entries prepared up front.
  std::vector<std::byte> order(48, std::byte{'O'});
  std::byte pkt[64];
  const std::size_t plen = soup::encode_packet(pkt, soup::PacketType::UnsequencedData, order);
  std::vector<std::byte> out(60, std::byte{'A'});
  constexpr int kRounds = 2000;
  for (int i = 0; i < kRounds; ++i) gw.port().data(conn, std::span<const std::byte>(pkt, plen));

  g_allocations.store(0);
  g_counting.store(true);
  std::uint64_t index = 1;
  seq::InboundMsg m;
  for (int i = 0; i < kRounds; ++i) {
    (void)egress.try_push(index, md::OutKind::Ouch, 1, out);
    state.applied.store(index);
    state.release.store(index);
    ++index;
    clock.mono += 1000;
    (void)gw.poll();
    while (ouch->try_pop(m)) {
    }
  }
  clock.mono += 5 * kNsPerSec;  // heartbeats
  (void)gw.poll();
  g_counting.store(false);
  EXPECT_EQ(g_allocations.load(), 0u);
  EXPECT_EQ(gw.stats().msgs_in, static_cast<std::uint64_t>(kRounds));
  EXPECT_EQ(gw.stats().msgs_out, static_cast<std::uint64_t>(kRounds));
}

}  // namespace
}  // namespace lle::gw
