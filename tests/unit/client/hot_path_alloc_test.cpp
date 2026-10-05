// Design rule (conventions "Hot paths", 07 §3): once refclient is set up, the
// hot loop's work (arbitration, book, strategy, OUCH encode, order entry) does
// not allocate. Checked with a counting global operator new; this TU replaces
// every form for the whole test binary and counts only while a test asks.
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <span>
#include <vector>

#include "client/feed_handler.h"
#include "client/order_entry.h"
#include "client/replay_feed.h"
#include "client/strategy.h"
#include "client/tx_stamps.h"
#include "net/utcp/wire.h"
#include "itch_gen.h"
#include "proto/soupbin/sequenced_store.h"
#include "proto/soupbin/server_session.h"

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

namespace lle::client {
namespace {

struct Policy {
  soup::LoginDecision authorize(const soup::LoginRequest&) { return soup::LoginDecision::Accept; }
};

TEST(ClientHotPathAlloc, FeedBookStrategyAndOrderEntryDoNotAllocate) {
  // Set-up (allocation allowed): a lossy dual-line capture of a generated day.
  const auto msgs = test::ItchGen(21).make(40'000);
  ReplayFeedConfig rf;
  rf.seed = 3;
  rf.impair[0].loss_ppm = 50'000;  // line B is clean, so every gap fills from it
  rf.impair[0].reorder_ppm = 20'000;
  ReplayFeed pub(rf);
  std::vector<std::pair<int, std::vector<std::byte>>> packets;
  auto cap = [&](int line, std::span<const std::byte> p) { packets.emplace_back(line, std::vector<std::byte>(p.begin(), p.end())); };
  for (const auto& m : msgs) (void)pub.append(m, 0, cap);
  pub.flush(0, cap);
  pub.release_all(cap);

  FeedConfig fc;
  fc.book.reserve_orders = 1 << 15;
  fc.book.reserve_levels = 1 << 12;
  fc.book.levels_per_side = 1024;  // X27: per-book level vectors reserved at the directory message
  fc.arbiter.reorder_capacity = 1 << 15;
  FeedHandler<> fh(fc);
  StrategyConfig sc;
  sc.symbol = test::ItchGen::symbol(3);
  sc.on_sell = true;
  sc.sell_threshold = 1'011'000;  // the generator's offers start at $101.00
  TriggerStrategy strat(sc);
  OrderEntryConfig oc;
  oc.pending_capacity = 1 << 12;
  HaOrderEntry oe(oc);
  soup::MemorySequencedStore store(16, 4096);
  Policy pol;
  soup::ServerConfig scfg;
  scfg.session = soup::SessionId::from("S");
  soup::ServerSession<soup::MemorySequencedStore, Policy> srv(scfg, store, pol, 0);
  oe.on_connected(0, 0);
  {
    const auto tx = oe.tx(0);
    const std::vector<std::byte> login(tx.begin(), tx.end());
    oe.consume_tx(0, login.size());
    const auto& a = srv.on_bytes(login, 0);
    const std::vector<std::byte> acc(a.write.begin(), a.write.end());
    oe.on_bytes(0, acc, 0, [](SeqNo, std::span<const std::byte>) {});
  }
  ASSERT_EQ(oe.active(), 0);

  struct Down {
    TriggerStrategy* strat;
    HaOrderEntry* oe;
    std::uint64_t delivered = 0, requests = 0;
    Nanos now = 0;
    UserRefNum next_urn() { return oe->next_urn(); }
    bool send(std::span<const std::byte> b) {
      const bool ok = oe->send(b, now);
      oe->consume_tx(0, oe->tx(0).size());  // "written to the socket"
      return ok;
    }
    void on_book_message(SeqNo seq, std::span<const std::byte> m) {
      ++delivered;
      strat->on_itch(seq, m, *this);
    }
    void on_snapshot_message(std::span<const std::byte>) {}
    void send_request(mold::Server, std::span<const std::byte>) { ++requests; }
    void on_snapshot_needed(SeqNo, SeqNo) {}
    void on_end_of_session(SeqNo) {}
  } down{&strat, &oe};

  // Warm up on the first part (first-touch of pools and buffers), then count.
  const std::size_t warm = packets.size() / 4;
  Nanos now = 0;
  for (std::size_t i = 0; i < warm; ++i) {
    down.now = now += 1'000;
    fh.on_packet(packets[i].first == 0 ? mold::Source::LineA : mold::Source::LineB, packets[i].second, now, down);
    if (now >= fh.next_deadline()) fh.on_timer(now, down);
  }
  g_allocations.store(0);
  g_counting.store(true);
  for (std::size_t i = warm; i < packets.size(); ++i) {
    down.now = now += 1'000;
    fh.on_packet(packets[i].first == 0 ? mold::Source::LineA : mold::Source::LineB, packets[i].second, now, down);
    if (now >= fh.next_deadline()) fh.on_timer(now, down);
    oe.on_timer(now);
  }
  g_counting.store(false);
  EXPECT_EQ(g_allocations.load(), 0u);
  EXPECT_EQ(down.delivered, msgs.size());
  EXPECT_GT(strat.stats().orders, 10u);
  EXPECT_GT(oe.stats().sent, 10u);
}


// M13 instruments: TX-stamp attribution (refclient's order log, loadgen's probes, the
// AF_XDP frame tracker) is allocation-free after init().
TEST(ClientHotPathAlloc, TxStampAttributionDoesNotAllocate) {
  namespace tf = net::utcp::tcp_flag;
  auto frame = [](std::uint32_t seq, std::uint8_t flags, std::size_t payload) {
    net::utcp::TcpHeaderSpec h;
    h.src_ip = 1;
    h.dst_ip = 2;
    h.src_port = 40000;
    h.dst_port = 9;
    h.seq = seq;
    h.flags = flags;
    std::vector<std::byte> data(payload, std::byte{1}), out(2048);
    out.resize(net::utcp::build_tcp(out, net::utcp::LinkType::Ethernet, h, data, {}, false));
    return out;
  };
  std::vector<std::vector<std::byte>> frames;
  frames.push_back(frame(100, tf::kSyn, 0));
  for (std::uint32_t i = 0; i < 1000; ++i) frames.push_back(frame(101 + i * 47, tf::kAck, 47));
  StreamTxMatcher m;
  m.init(1 << 12);
  FrameStampTracker t;
  t.init(1 << 12);
  std::uint64_t matched = 0;
  g_allocations.store(0);
  g_counting.store(true);
  for (std::size_t i = 0; i < frames.size(); ++i) {
    if (i > 0) m.expect(i, m.written() + 46);
    if (i > 0) m.on_written(47);
    if (t.on_tx(frames[i])) t.on_completion(static_cast<Nanos>(1000 + i));
    t.drain([&](const FrameStampTracker::Stamped& s) {
      m.on_stamp(s.stamp, [&](std::uint64_t, const net::RxTimestamps&) { ++matched; });
    });
  }
  g_counting.store(false);
  EXPECT_EQ(g_allocations.load(), 0u);
  EXPECT_EQ(matched, 1000u);
  EXPECT_EQ(m.validity().hw, 1000u);
}

}  // namespace
}  // namespace lle::client
