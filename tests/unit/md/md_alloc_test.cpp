// No allocation on the md stage's per-message path after start-up (conventions "Hot
// paths"): released ITCH into the re-request ring and both packetizers, packets onto
// the lines, re-requests served from the ring. This TU replaces every form of the
// global operator new/delete for the whole binary.
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

#include "../gateway/fake_net.h"
#include "md/egress.h"
#include "md/publisher.h"
#include "proto/itch50/itch50.h"
#include "proto/moldudp64/moldudp64.h"

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

namespace lle::md {
namespace {

struct Env {
  using Net = testnet::FakeNet;
  using Clock = testnet::FakeClock;
};

TEST(MdAlloc, ReleasePacketizeAndRerequestDoNotAllocate) {
  testnet::FakeClock clock;
  EgressRing egress;
  egress.init(std::size_t{1} << 20);
  EgressState state;
  std::atomic<std::uint8_t> lines{kLineA | kLineB};
  MdConfig c;
  c.session = mold::Session("S1");
  c.ring_messages = 1 << 12;
  c.ring_bytes = 1 << 18;
  c.rerequest.bucket_capacity = 100'000;
  MdStage<Env> md(c, clock, MdShared{&egress, &state, &lines});
  ASSERT_TRUE(md.start());
  itch50::AddOrder a{};
  a.stock_locate = 1;
  a.order_ref = 1;
  a.shares = 100;
  a.stock = Symbol8("AAPL");
  a.price = 1'000'000;
  std::byte msg[itch50::AddOrder::kLen];
  (void)itch50::encode(msg, a);
  std::byte req[mold::kRequestLen];
  (void)mold::encode_request(req, mold::RequestPacket{mold::Session("S1"), 1, 10});
  md.line_port().discard = true;
  md.rerequest_port().discard = true;
  for (int i = 0; i < 500; ++i) md.rerequest_port().inbox.emplace_back(env::Endpoint{0x7F000001u, 9}, std::vector<std::byte>(req, req + sizeof req));
  // Warm-up: the first packet of each line and the first request.
  (void)egress.try_push(1, OutKind::Itch, 0, msg);
  state.applied.store(1);
  state.release.store(1);
  (void)md.poll();
  g_allocations.store(0);
  g_counting.store(true);
  for (std::uint64_t i = 2; i <= 20'000; ++i) {
    (void)egress.try_push(i, OutKind::Itch, 0, msg);
    if (i % 8 == 0) {
      // The other consumers (io, gateways) keep up.
      for (std::size_t cons : {kIo, kGw0, kGw0 + 1}) {
        OutEntry e;
        while (egress.peek(cons, e)) egress.release(cons);
      }
      state.applied.store(i);
      state.release.store(i);
      clock.mono += 10'000;
      (void)md.poll();
    }
  }
  g_counting.store(false);
  EXPECT_EQ(g_allocations.load(), 0u);
  EXPECT_EQ(md.stats().messages, 20'000u);
  EXPECT_GT(md.stats().rerequests_served, 400u);
  EXPECT_GT(md.line_port().discarded, 2'000u);
}

}  // namespace
}  // namespace lle::md
