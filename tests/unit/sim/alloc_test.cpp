// The event loop is allocation-free in steady state (09 §16 "simulator too
// slow" mitigation; conventions: no allocation after startup on hot paths).
// A mixed datagram / stream / disk workload is warmed up, then every global
// operator new call is counted over the next window of simulated time.
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdlib>
#include <new>

#include "sim/disk.h"
#include "sim/dist.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/world.h"
#include "test_util.h"

namespace {
std::uint64_t g_allocs = 0;
bool g_counting = false;

void* counted_alloc(std::size_t n, std::size_t align = 0) {
  if (g_counting) ++g_allocs;
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

// Replacement global allocation functions: every form, so nothing the standard
// library allocates through the array, aligned or nothrow forms is freed by a
// different allocator (ASan with libstdc++ reports alloc-dealloc-mismatch for a
// partial set; docs/dev/conventions.md). noinline keeps GCC from inlining them
// into new-expressions and then flagging malloc/free as a mismatched pair.
[[gnu::noinline]] void* operator new(std::size_t n) { return counted_alloc(n); }
[[gnu::noinline]] void* operator new[](std::size_t n) { return counted_alloc(n); }
[[gnu::noinline]] void* operator new(std::size_t n, std::align_val_t a) {
  return counted_alloc(n, static_cast<std::size_t>(a));
}
[[gnu::noinline]] void* operator new[](std::size_t n, std::align_val_t a) {
  return counted_alloc(n, static_cast<std::size_t>(a));
}
[[gnu::noinline]] void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n); }
[[gnu::noinline]] void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n); }
[[gnu::noinline]] void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
}
[[gnu::noinline]] void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
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

namespace lle::sim {
namespace {

constexpr std::uint16_t kPort = 5000;

struct PingProc : Process {
  struct Stage {
    PingProc* p;
    bool poll() { return p->poll(); }
  };
  PingProc(Node& n, env::Endpoint peer) : port(n, kPort), file(n, "log"), peer_(peer), stage{this} {
    n.add_stage(stage, "ping");
  }
  bool poll() {
    bool did = false;
    port.poll_rx([&](const env::RxDatagram&) {
      --outstanding;
      did = true;
    });
    while (outstanding < 8) {
      port.send(peer_, msg);
      ++outstanding;
      did = true;
    }
    file.poll([&](const env::DiskCompletion& c) {
      --disk_inflight;
      if (c.tag == 1) sync_inflight = false;
      did = true;
    });
    if (disk_inflight < 4) {
      file.submit_write((writes++ % 16) * 4096, block, false, 0);
      ++disk_inflight;
      did = true;
    }
    if (!sync_inflight && writes % 8 == 0) {
      sync_inflight = file.submit_sync(1);
      disk_inflight += sync_inflight ? 1 : 0;
    }
    return did;
  }
  DatagramPort port;
  DiskFile file;
  env::Endpoint peer_;
  std::array<std::byte, 64> msg{};
  std::array<std::byte, 4096> block{};
  int outstanding = 0;
  int disk_inflight = 0;
  std::uint64_t writes = 0;
  bool sync_inflight = false;
  Stage stage;
};

struct EchoProc : Process {
  struct Stage {
    EchoProc* p;
    bool poll() {
      return p->port.poll_rx([&](const env::RxDatagram& d) { p->port.send(d.src, d.data); }) > 0;
    }
  };
  explicit EchoProc(Node& n) : port(n, kPort), stage{this} { n.add_stage(stage, "echo"); }
  DatagramPort port;
  Stage stage;
};

struct StreamClientProc : Process {
  struct Stage {
    StreamClientProc* p;
    bool poll() { return p->poll(); }
  };
  StreamClientProc(Node& n, env::Endpoint server) : port(n), stage{this} {
    conn = *port.connect(server);
    n.add_stage(stage, "client");
  }
  bool poll() {
    bool did = false;
    port.poll([&](const env::StreamEvent& e) {
      did = true;
      if (e.kind == env::StreamEventKind::Connected) connected = true;
      if (e.kind == env::StreamEventKind::Data) outstanding -= e.data.size();
    });
    while (connected && outstanding < 8192) {
      const std::size_t w = port.write(conn, chunk);
      if (w == 0) break;
      outstanding += w;
      did = true;
    }
    return did;
  }
  StreamPort port;
  env::ConnId conn = env::kNoConn;
  bool connected = false;
  std::size_t outstanding = 0;
  std::array<std::byte, 512> chunk{};
  Stage stage;
};

struct StreamServerProc : Process {
  struct Stage {
    StreamServerProc* p;
    bool poll() {
      return p->port.poll([&](const env::StreamEvent& e) {
        if (e.kind == env::StreamEventKind::Data) p->port.write(e.conn, e.data);
      }) > 0;
    }
  };
  explicit StreamServerProc(Node& n) : port(n), stage{this} {
    (void)port.listen(env::Endpoint{0, 80});
    n.add_stage(stage, "server");
  }
  StreamPort port;
  Stage stage;
};

TEST(Allocation, EventLoopIsAllocationFreeInSteadyState) {
  FaultConfig f = base_fault_config();
  f.set(Param::NetDelayMeanNs, 20'000);  // exponential delays: reordering, heap churn
  World w(9, f);
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  Node& c = w.add_node("c");
  Node& s = w.add_node("s");
  a.set_boot([&](Node& n, BootReason) { n.emplace_process<PingProc>(n, env::Endpoint{b.ip(), kPort}); });
  b.set_boot([](Node& n, BootReason) { n.emplace_process<EchoProc>(n); });
  c.set_boot([&](Node& n, BootReason) { n.emplace_process<StreamClientProc>(n, env::Endpoint{s.ip(), 80}); });
  s.set_boot([](Node& n, BootReason) { n.emplace_process<StreamServerProc>(n); });
  for (NodeId i = 0; i < w.node_count(); ++i) w.node(i).boot();

  test::run_for(w, 200 * kMs);  // warm-up: pools, rings and the heap reach their high-water marks
  const std::uint64_t before = w.events();
  g_allocs = 0;
  g_counting = true;
  test::run_for(w, 200 * kMs);
  g_counting = false;
  const std::uint64_t events = w.events() - before;
  EXPECT_GT(events, 100'000u);
  EXPECT_GT(w.stats().net_delivered, 10'000u);
  EXPECT_GT(w.stats().disk_syncs, 100u);
  EXPECT_EQ(g_allocs, 0u) << "allocations in " << events << " steady-state events";
}

}  // namespace
}  // namespace lle::sim
