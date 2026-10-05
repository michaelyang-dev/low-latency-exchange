// No allocation on utcp's per-packet path (conventions: hot paths allocate nothing after
// startup). Replaces the global operator new, so it lives in an *alloc_test.cpp file,
// which MSan builds skip.
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <new>

#include "net/utcp/stream_port.h"
#include "sim_link.h"

namespace {
std::atomic<bool> g_count_allocs{false};
std::atomic<std::uint64_t> g_allocs{0};
}  // namespace

// The whole replaceable set (plain, array and nothrow forms) is replaced so every pairing
// stays consistent: libstdc++'s temporary buffers use the nothrow form, and ASan reports
// a mismatch if new and delete come from different allocators.
// Aligned forms too (docs/dev/conventions.md), and noinline so GCC does not
// inline them into new-expressions and flag malloc/free as a mismatched pair.
namespace {
void* counted(std::size_t n, std::size_t align = 0) noexcept {
  if (g_count_allocs.load(std::memory_order_relaxed)) g_allocs.fetch_add(1, std::memory_order_relaxed);
  if (align <= alignof(std::max_align_t)) return std::malloc(n == 0 ? 1 : n);
  void* p = nullptr;
  return ::posix_memalign(&p, align, n == 0 ? align : n) == 0 ? p : nullptr;
}
}  // namespace
[[gnu::noinline]] void* operator new(std::size_t n) {
  if (void* p = counted(n)) return p;
  throw std::bad_alloc();
}
[[gnu::noinline]] void* operator new[](std::size_t n) {
  if (void* p = counted(n)) return p;
  throw std::bad_alloc();
}
[[gnu::noinline]] void* operator new(std::size_t n, std::align_val_t a) {
  if (void* p = counted(n, static_cast<std::size_t>(a))) return p;
  throw std::bad_alloc();
}
[[gnu::noinline]] void* operator new[](std::size_t n, std::align_val_t a) {
  if (void* p = counted(n, static_cast<std::size_t>(a))) return p;
  throw std::bad_alloc();
}
[[gnu::noinline]] void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return counted(n); }
[[gnu::noinline]] void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return counted(n); }
[[gnu::noinline]] void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted(n, static_cast<std::size_t>(a));
}
[[gnu::noinline]] void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted(n, static_cast<std::size_t>(a));
}
[[gnu::noinline]] void operator delete(void* p) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete[](void* p) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete(void* p, std::size_t) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }

namespace lle::net::utcp::test {
namespace {

constexpr std::uint32_t kIpA = 0x0A000001;
constexpr std::uint32_t kIpB = 0x0A000002;
constexpr MacAddr kMacA{{0x02, 0, 0, 0, 0, 0x01}};
constexpr MacAddr kMacB{{0x02, 0, 0, 0, 0, 0x02}};

// A link with fixed storage, so the steady-state loop can be checked for allocations.
class RingLinkPort {
 public:
  struct Q {
    std::array<std::array<std::byte, 2048>, 256> frames{};
    std::array<std::size_t, 256> len{};
    std::size_t head = 0;
    std::size_t count = 0;
  };
  RingLinkPort(Q& out, Q& in) : out_(out), in_(in) {}
  bool send_frame(std::span<const std::byte> f) {
    if (out_.count == out_.frames.size() || f.size() > 2048) return false;
    const std::size_t i = (out_.head + out_.count) % out_.frames.size();
    std::memcpy(out_.frames[i].data(), f.data(), f.size());
    out_.len[i] = f.size();
    ++out_.count;
    return true;
  }
  template <class Cb>
  std::size_t poll_frames(Cb&& cb) {
    std::size_t n = 0;
    while (in_.count != 0) {
      cb(std::span<const std::byte>(in_.frames[in_.head].data(), in_.len[in_.head]), Nanos{0});
      in_.head = (in_.head + 1) % in_.frames.size();
      --in_.count;
      ++n;
    }
    return n;
  }

 private:
  Q& out_;
  Q& in_;
};

StackConfig cfg(bool a) {
  StackConfig s;
  s.local_mac = a ? kMacA : kMacB;
  s.local_ip = a ? kIpA : kIpB;
  s.static_next_hop = a ? kMacB : kMacA;
  s.max_connections = 4;
  return s;
}

TEST(UtcpStreamPortAlloc, NoAllocationOnPerPacketPath) {
  static RingLinkPort::Q qab, qba;
  RingLinkPort pa(qab, qba);
  RingLinkPort pb(qba, qab);
  SimClock clock;
  UtcpStreamPort<RingLinkPort, SimClock> a(pa, clock, cfg(true));
  UtcpStreamPort<RingLinkPort, SimClock> b(pb, clock, cfg(false));
  ASSERT_TRUE(b.listen(env::Endpoint{0, 8080}));
  const auto c = a.connect(env::Endpoint{kIpB, 8080});
  ASSERT_TRUE(c);
  env::ConnId sc = env::kNoConn;
  std::uint64_t got = 0;
  auto on_b = [&](const env::StreamEvent& e) {
    if (e.kind == env::StreamEventKind::Accepted) sc = e.conn;
    if (e.kind == env::StreamEventKind::Data) got += e.data.size();
  };
  auto on_a = [&](const env::StreamEvent&) {};
  for (int i = 0; i < 10; ++i) {
    clock.t += 1000;
    (void)a.poll(on_a);
    (void)b.poll(on_b);
  }
  ASSERT_NE(sc, env::kNoConn);
  std::array<std::byte, 100> msg{};
  g_allocs = 0;
  g_count_allocs = true;
  for (int i = 0; i < 20000; ++i) {
    clock.t += 1000;
    (void)a.write(*c, msg);
    (void)b.write(sc, msg);
    (void)a.poll(on_a);
    (void)b.poll(on_b);
  }
  g_count_allocs = false;
  EXPECT_EQ(g_allocs.load(), 0u);
  EXPECT_GT(got, 1'000'000u);
}

}  // namespace
}  // namespace lle::net::utcp::test
