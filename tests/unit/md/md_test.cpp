// Market-data stage pieces (07 §3, N-18): the egress ring and its release gate, the
// re-request store (ring then output log), the md stage over an in-memory datagram port
// (two independently packetized lines, line selection, heartbeats, re-requests, end of
// session), the GLIMPSE state and the GLIMPSE server.
#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <vector>

#include "../gateway/fake_net.h"
#include "gateway/credentials.h"
#include "md/egress.h"
#include "md/glimpse_server.h"
#include "md/glimpse_state.h"
#include "md/itch_store.h"
#include "md/publisher.h"
#include "md/work_meter.h"
#include "outlog/day.h"
#include "proto/glimpse/snapshot_server.h"
#include "proto/itch50/itch50.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/soupbin/client_session.h"

namespace lle::md {
namespace {

using testnet::Bytes;

Bytes itch_add(std::uint64_t ref, std::uint32_t shares, std::uint32_t price, char side = 'B', std::uint16_t loc = 1) {
  itch50::AddOrder a{};
  a.stock_locate = loc;
  a.timestamp = ref * 1000;
  a.order_ref = ref;
  a.side = static_cast<Side>(side);
  a.shares = shares;
  a.stock = Symbol8("AAPL");
  a.price = price;
  Bytes b(itch50::AddOrder::kLen);
  (void)itch50::encode(b, a);
  return b;
}

TEST(EgressRing, EveryConsumerSeesEveryEntryInOrder) {
  EgressRing r;
  r.init(std::size_t{1} << 16);
  const Bytes m = {std::byte{1}, std::byte{2}, std::byte{3}};
  ASSERT_TRUE(r.try_push(7, OutKind::Itch, 0, m));
  ASSERT_TRUE(r.try_push(8, OutKind::Ouch, 42, m));
  for (std::size_t c = 0; c < kConsumers; ++c) {
    OutEntry e;
    ASSERT_TRUE(r.peek(c, e));
    EXPECT_EQ(e.index, 7u);
    EXPECT_EQ(e.kind, OutKind::Itch);
    r.release(c);
    ASSERT_TRUE(r.peek(c, e));
    EXPECT_EQ(e.index, 8u);
    EXPECT_EQ(e.session, 42u);
    EXPECT_EQ(e.kind, OutKind::Ouch);
    EXPECT_TRUE(std::equal(m.begin(), m.end(), e.msg.begin()));
    r.release(c);
    EXPECT_FALSE(r.peek(c, e));
  }
}

TEST(EgressRing, TheSlowestConsumerGatesTheProducer) {
  EgressRing r;
  r.init(std::size_t{1} << 16);
  const Bytes m(1000, std::byte{9});
  std::size_t pushed = 0;
  while (r.try_push(pushed + 1, OutKind::Itch, 0, m)) ++pushed;
  EXPECT_GT(pushed, 0u);
  // Three consumers drain everything; the fourth (a gateway) has not moved.
  for (std::size_t c = 0; c + 1 < kConsumers; ++c) {
    OutEntry e;
    while (r.peek(c, e)) r.release(c);
  }
  EXPECT_FALSE(r.try_push(pushed + 1, OutKind::Itch, 0, m)) << "nothing is overwritten under a lagging consumer";
  OutEntry e;
  ASSERT_TRUE(r.peek(kConsumers - 1, e));
  r.release(kConsumers - 1);
  EXPECT_TRUE(r.try_push(pushed + 1, OutKind::Itch, 0, m));
}

TEST(EgressRing, DrainReleasedStopsAtTheWatermarkAndPublishesDone) {
  EgressRing r;
  r.init(std::size_t{1} << 16);
  EgressState st;
  const Bytes m(10, std::byte{1});
  for (std::uint64_t i = 1; i <= 5; ++i) ASSERT_TRUE(r.try_push(i, OutKind::Itch, 0, m));
  st.applied.store(5);
  st.release.store(3);
  std::vector<std::uint64_t> got;
  auto take = [&](const OutEntry& e) {
    got.push_back(e.index);
    return true;
  };
  EXPECT_EQ(drain_released(r, st, kMd, 100, take), 3u);
  EXPECT_EQ(got, (std::vector<std::uint64_t>{1, 2, 3}));
  EXPECT_EQ(st.done[kMd].load(), 3u);
  st.release.store(5);
  EXPECT_EQ(drain_released(r, st, kMd, 1, take), 1u);  // batch limit
  EXPECT_EQ(drain_released(r, st, kMd, 100, take), 1u);
  EXPECT_EQ(drain_released(r, st, kMd, 100, take), 0u);
  EXPECT_EQ(st.done[kMd].load(), 5u);
  EXPECT_EQ(got.back(), 5u);
}

TEST(ItchStore, RingFirstThenTheOutputLog) {
  const auto root = std::filesystem::temp_directory_path() / ("lle-md-store-" + std::to_string(::getpid()));
  std::filesystem::remove_all(root);
  const std::uint32_t ids[] = {1};
  outlog::OutlogDay day;
  ASSERT_TRUE(day.open(root.string(), 20261001, ids));
  ItchStore<> store(2, 4096, 1, outlog::OutlogDay::itch_path(root.string(), 20261001));
  for (std::uint64_t i = 1; i <= 5; ++i) {
    const Bytes m = itch_add(i, 100, 1'500'000);
    ASSERT_TRUE(day.itch().append(m));
    ASSERT_TRUE(store.append(m));
  }
  ASSERT_TRUE(day.flush_all());
  EXPECT_EQ(store.highest(), 5u);
  EXPECT_EQ(store.lowest(), 1u);
  for (std::uint64_t i = 1; i <= 5; ++i) {
    const auto m = store.get(i);
    ASSERT_TRUE(m.has_value()) << i;
    EXPECT_TRUE(std::equal(m->begin(), m->end(), itch_add(i, 100, 1'500'000).begin())) << i;
  }
  EXPECT_EQ(store.log_reads(), 3u);
  EXPECT_FALSE(store.get(6).has_value());
  EXPECT_FALSE(store.get(0).has_value());
  ItchStore<> ring_only(2, 4096, 1, "");
  for (std::uint64_t i = 1; i <= 5; ++i) ASSERT_TRUE(ring_only.append(itch_add(i, 1, 1)));
  EXPECT_EQ(ring_only.lowest(), 4u);
  EXPECT_FALSE(ring_only.get(3).has_value());
  std::filesystem::remove_all(root);
}

struct MdEnv {
  using Net = testnet::FakeNet;
  using Clock = testnet::FakeClock;
};

struct MdFixture {
  explicit MdFixture(std::uint8_t lines_mask = kLineA | kLineB, std::size_t max_b = 100) {
    egress.init(std::size_t{1} << 16);
    lines.store(lines_mask);
    MdConfig c;
    c.session = mold::Session("SESS000001");
    c.line_a = env::Endpoint{0x7F000001u, 1001};
    c.line_b = env::Endpoint{0x7F000001u, 1002};
    c.max_packet_a = 400;
    c.max_packet_b = max_b;
    c.ring_messages = 64;
    c.ring_bytes = 8192;
    md = std::make_unique<MdStage<MdEnv>>(c, clock, MdShared{&egress, &state, &lines});
    EXPECT_TRUE(md->start());
  }
  void push(std::uint64_t index, const Bytes& m) { ASSERT_TRUE(egress.try_push(index, OutKind::Itch, 0, m)); }
  void release(std::uint64_t w) {
    state.applied.store(w);
    state.release.store(w);
  }
  // Messages carried by the packets sent to `port`, by sequence; and the packet count.
  std::vector<std::pair<SeqNo, Bytes>> messages(std::uint16_t port, std::size_t* data_packets = nullptr,
                                                std::size_t* heartbeats = nullptr, std::size_t* eos = nullptr) {
    std::vector<std::pair<SeqNo, Bytes>> v;
    for (const auto& [to, bytes] : md->line_port().sent) {
      if (to.port != port) continue;
      const auto pv = mold::PacketView::parse(bytes);
      EXPECT_TRUE(pv.has_value());
      if (!pv) continue;
      if (pv->is_heartbeat() && heartbeats) ++*heartbeats;
      if (pv->is_end_of_session() && eos) ++*eos;
      if (pv->message_count() > 0 && data_packets) ++*data_packets;
      pv->for_each([&](SeqNo s, std::span<const std::byte> m) { v.emplace_back(s, Bytes(m.begin(), m.end())); });
    }
    return v;
  }
  testnet::FakeClock clock;
  EgressRing egress;
  EgressState state;
  std::atomic<std::uint8_t> lines{0};
  std::unique_ptr<MdStage<MdEnv>> md;
};

TEST(MdStage, ReleasedItchGetsSequencedOnTwoIndependentlyPacketizedLines) {
  MdFixture f;
  for (std::uint64_t i = 1; i <= 12; ++i) f.push(i, itch_add(i, 100, 1'500'000));
  f.release(6);
  (void)f.md->poll();
  std::size_t pa = 0, pb = 0;
  auto a = f.messages(1001, &pa);
  auto b = f.messages(1002, &pb);
  ASSERT_EQ(a.size(), 6u) << "only the released messages leave (ADR-005)";
  ASSERT_EQ(b.size(), 6u);
  for (std::size_t i = 0; i < 6; ++i) {
    EXPECT_EQ(a[i].first, i + 1);
    EXPECT_EQ(a[i], b[i]);
    EXPECT_EQ(a[i].second, itch_add(i + 1, 100, 1'500'000));
  }
  EXPECT_EQ(pa, 1u) << "line A: one packet for the burst";
  EXPECT_EQ(pb, 3u) << "line B: smaller packets, different boundaries";
  EXPECT_EQ(f.state.done[kMd].load(), 6u);
  f.release(12);
  (void)f.md->poll();
  EXPECT_EQ(f.messages(1001).size(), 12u);
  EXPECT_EQ(f.md->next_seq(), 13u);
}

// After recovery the output log may hold messages md never multicast (regenerated from
// records released only now): they go out first, from the log, then the released stream.
TEST(MdStage, RecoveredTailIsRepublishedBeforeTheReleasedStream) {
  const auto root = std::filesystem::temp_directory_path() / ("lle-md-repub-" + std::to_string(::getpid()));
  std::filesystem::remove_all(root);
  const std::uint32_t ids[] = {1};
  outlog::OutlogDay day;
  ASSERT_TRUE(day.open(root.string(), 20261001, ids));
  for (std::uint64_t i = 1; i <= 5; ++i) ASSERT_TRUE(day.itch().append(itch_add(i, 100, 1'500'000)));
  ASSERT_TRUE(day.flush_all());
  EgressRing egress;
  egress.init(std::size_t{1} << 16);
  EgressState state;
  std::atomic<std::uint8_t> lines{kLineA | kLineB};
  testnet::FakeClock clock;
  MdConfig c;
  c.session = mold::Session("SESS000001");
  c.line_a = env::Endpoint{0x7F000001u, 1001};
  c.line_b = env::Endpoint{0x7F000001u, 1002};
  c.max_packet_a = 400;
  c.max_packet_b = 100;
  c.ring_messages = 64;
  c.ring_bytes = 8192;
  c.itch_log_path = outlog::OutlogDay::itch_path(root.string(), 20261001);
  c.first_seq = 6;       // the log holds 1..5
  c.republish_from = 3;  // 1..2 were in the log before recovery, 3..5 were regenerated
  MdStage<MdEnv> md(c, clock, MdShared{&egress, &state, &lines});
  ASSERT_TRUE(md.start());
  ASSERT_TRUE(egress.try_push(1, OutKind::Itch, 0, itch_add(6, 100, 1'500'000)));
  state.applied.store(1);
  state.release.store(1);
  for (int i = 0; i < 3; ++i) (void)md.poll();
  for (std::uint16_t port : {std::uint16_t{1001}, std::uint16_t{1002}}) {
    std::vector<std::pair<SeqNo, Bytes>> got;
    for (const auto& [to, bytes] : md.line_port().sent) {
      if (to.port != port) continue;
      const auto pv = mold::PacketView::parse(bytes);
      ASSERT_TRUE(pv.has_value());
      pv->for_each([&](SeqNo q, std::span<const std::byte> m) { got.emplace_back(q, Bytes(m.begin(), m.end())); });
    }
    ASSERT_EQ(got.size(), 4u) << port;
    for (std::size_t i = 0; i < 4; ++i) {
      EXPECT_EQ(got[i].first, 3 + i) << port;
      EXPECT_EQ(got[i].second, itch_add(3 + i, 100, 1'500'000)) << port;
    }
  }
  EXPECT_EQ(md.stats().republished, 3u);
  EXPECT_EQ(md.next_seq(), 7u);
  std::filesystem::remove_all(root);
}

TEST(MdStage, LinesMaskSelectsWhatThisNodeTransmitsWithoutLosingSequence) {
  MdFixture f(kLineB);  // a backup: line B only (10 §3)
  for (std::uint64_t i = 1; i <= 3; ++i) f.push(i, itch_add(i, 1, 1));
  f.release(3);
  (void)f.md->poll();
  EXPECT_TRUE(f.messages(1001).empty());
  EXPECT_EQ(f.messages(1002).size(), 3u);
  f.lines.store(kLineA | kLineB);  // took over: both lines (10 §4 step 4)
  f.push(4, itch_add(4, 1, 1));
  f.release(4);
  (void)f.md->poll();
  const auto a = f.messages(1001);
  ASSERT_EQ(a.size(), 1u);
  EXPECT_EQ(a[0].first, 4u) << "line A continues at the current sequence number";
}

TEST(MdStage, HeartbeatsWhenIdleAndEndOfSessionAfterDayEnd) {
  MdFixture f;
  (void)f.md->poll();
  f.clock.mono += 2 * kNsPerSec;
  (void)f.md->poll();
  std::size_t hb = 0, eos = 0;
  (void)f.messages(1001, nullptr, &hb, &eos);
  EXPECT_GE(hb, 1u);
  f.push(1, itch_add(1, 1, 1));
  ASSERT_TRUE(f.egress.try_push(2, OutKind::DayEnd, 0, {}));
  f.release(2);
  (void)f.md->poll();
  hb = eos = 0;
  (void)f.messages(1001, nullptr, &hb, &eos);
  EXPECT_EQ(eos, 1u);
  EXPECT_TRUE(f.md->stats().ended);
}

TEST(MdStage, RerequestsAreServedFromTheStore) {
  MdFixture f;
  for (std::uint64_t i = 1; i <= 5; ++i) f.push(i, itch_add(i, 10, 20));
  f.release(5);
  (void)f.md->poll();
  Bytes req(mold::kRequestLen);
  (void)mold::encode_request(req, mold::RequestPacket{mold::Session("SESS000001"), 2, 3});
  const env::Endpoint client{0x7F000001u, 5555};
  f.md->rerequest_port().inbox.emplace_back(client, req);
  (void)f.md->poll();
  const auto& sent = f.md->rerequest_port().sent;
  ASSERT_EQ(sent.size(), 1u);
  EXPECT_EQ(sent[0].first, client);
  const auto pv = mold::PacketView::parse(sent[0].second);
  ASSERT_TRUE(pv.has_value());
  EXPECT_EQ(pv->seq(), 2u);
  EXPECT_EQ(pv->message_count(), 3u);
  EXPECT_EQ(f.md->stats().rerequests_served, 1u);
  // Beyond what was released: refused, nothing sent.
  (void)mold::encode_request(req, mold::RequestPacket{mold::Session("SESS000001"), 9, 1});
  f.md->rerequest_port().inbox.emplace_back(client, req);
  (void)f.md->poll();
  EXPECT_EQ(f.md->rerequest_port().sent.size(), 1u);
  EXPECT_EQ(f.md->stats().rerequests_refused, 1u);
}

// Work time (METHODOLOGY §16, T32): two counter reads per non-empty batch, none for an
// empty poll, and only the time from the first item to the end of the poll.
TEST(WorkMeter, TwoCounterReadsPerNonEmptyPollAndNoneOtherwise) {
  testnet::FakeClock clock;
  WorkMeter<testnet::FakeClock> m(&clock);
  m.finish();  // an empty poll
  EXPECT_EQ(clock.tsc_reads, 0u);
  EXPECT_EQ(m.stats().batches, 0u);
  // Three items in one poll: the first start() reads, the others do not; finish() reads.
  for (int i = 0; i < 3; ++i) {
    m.start();
    m.add();
  }
  EXPECT_EQ(clock.tsc_reads, 1u);
  m.finish();
  EXPECT_EQ(clock.tsc_reads, 2u);
  EXPECT_EQ(m.stats().items, 3u);
  EXPECT_EQ(m.stats().batches, 1u);
  EXPECT_EQ(m.stats().tsc, clock.tsc_step) << "start -> end of the batch";
  m.finish();
  m.finish();
  EXPECT_EQ(clock.tsc_reads, 2u) << "empty polls read nothing";
  // Items counted in bulk.
  m.start();
  m.add(5);
  m.finish();
  EXPECT_EQ(clock.tsc_reads, 4u);
  EXPECT_EQ(m.stats().items, 8u);
  EXPECT_EQ(m.stats().batches, 2u);
  // Started but nothing processed: not a batch, no second read.
  m.start();
  m.finish();
  EXPECT_EQ(clock.tsc_reads, 5u);
  EXPECT_EQ(m.stats().batches, 2u);
  EXPECT_EQ(m.stats().items, 8u);
}

TEST(MdStage, WorkTimeCoversOnlyPollsThatProcessedItems) {
  MdFixture f;
  const std::uint64_t r0 = f.clock.tsc_reads;
  for (int i = 0; i < 5; ++i) (void)f.md->poll();
  EXPECT_EQ(f.clock.tsc_reads, r0) << "idle polls read no counter";
  EXPECT_EQ(f.md->work().batches, 0u);
  for (std::uint64_t i = 1; i <= 6; ++i) f.push(i, itch_add(i, 10, 20));
  f.release(4);
  (void)f.md->poll();
  EXPECT_EQ(f.clock.tsc_reads, r0 + 2);
  EXPECT_EQ(f.md->work().items, 4u) << "the released messages";
  EXPECT_EQ(f.md->work().batches, 1u);
  EXPECT_GT(f.md->work().tsc, 0u);
  (void)f.md->poll();  // nothing more released
  EXPECT_EQ(f.clock.tsc_reads, r0 + 2);
  // A heartbeat is not an item (its poll is not metered).
  f.clock.mono += 2 * kNsPerSec;
  (void)f.md->poll();
  EXPECT_EQ(f.clock.tsc_reads, r0 + 2);
  f.release(6);
  (void)f.md->poll();
  EXPECT_EQ(f.clock.tsc_reads, r0 + 4);
  EXPECT_EQ(f.md->work().items, 6u);
  EXPECT_EQ(f.md->work().batches, 2u);
  EXPECT_EQ(f.md->work().items, f.md->stats().messages);
}

TEST(GlimpseState, SpinIsTheStateOfTheAppliedStream) {
  GlimpseState g(2);
  std::vector<Bytes> stream;
  auto push = [&](const auto& m) {
    Bytes b(std::remove_cvref_t<decltype(m)>::kLen);
    (void)itch50::encode(b, m);
    stream.push_back(b);
    g.apply(b);
  };
  itch50::SystemEvent s{};
  s.event_code = itch50::EventCode::StartOfMessages;
  push(s);
  itch50::StockDirectory r{};
  r.stock_locate = 1;
  r.stock = Symbol8("AAPL");
  push(r);
  itch50::StockTradingAction h{};
  h.stock_locate = 1;
  h.stock = Symbol8("AAPL");
  h.trading_state = itch50::TradingState::Trading;
  push(h);
  g.apply(itch_add(1, 300, 1'500'000));  // rests
  g.apply(itch_add(2, 100, 1'490'000));  // rests, then partly executed
  g.apply(itch_add(3, 50, 1'480'000));   // deleted
  itch50::OrderExecuted e{};
  e.stock_locate = 1;
  e.order_ref = 2;
  e.executed_shares = 40;
  push(e);
  itch50::OrderDelete d{};
  d.stock_locate = 1;
  d.order_ref = 3;
  push(d);
  itch50::OrderReplace u{};
  u.stock_locate = 1;
  u.original_order_ref = 1;
  u.new_order_ref = 4;
  u.shares = 200;
  u.price = 1'510'000;
  push(u);
  EXPECT_EQ(g.applied(), 9u);
  EXPECT_EQ(g.resting_orders(), 2u);
  std::vector<Bytes> spin;
  const auto st = glimpse::SnapshotServer{}.emit(g, [&](std::span<const std::byte> m) { spin.emplace_back(m.begin(), m.end()); });
  EXPECT_EQ(st.next_seq, 10u);
  ASSERT_EQ(spin.size(), 6u);  // S, R, H, A(2: 60 left), A(4: replaced), G
  EXPECT_EQ(static_cast<char>(spin[0][0]), 'S');
  EXPECT_EQ(static_cast<char>(spin[1][0]), 'R');
  EXPECT_EQ(static_cast<char>(spin[2][0]), 'H');
  const auto a2 = itch50::decode(spin[3]);
  ASSERT_TRUE(a2.has_value());
  EXPECT_EQ(a2->as<itch50::AddOrderView>().order_ref(), 2u);
  EXPECT_EQ(a2->as<itch50::AddOrderView>().shares(), 60u);
  const auto a4 = itch50::decode(spin[4]);
  EXPECT_EQ(a4->as<itch50::AddOrderView>().order_ref(), 4u);
  EXPECT_EQ(a4->as<itch50::AddOrderView>().shares(), 200u);
  EXPECT_EQ(a4->as<itch50::AddOrderView>().price(), 1'510'000u);
  EXPECT_EQ(static_cast<char>(spin[5][0]), 'G');
  EXPECT_EQ(g.spin_messages(), spin.size());
}

// Spin order: locate by locate, the buy side then the sell side, levels from the worst
// price to the best, FIFO (time priority) within a level; a replace re-queues (new ref).
TEST(GlimpseState, SpinListsLevelsWorstToBestFifoWithinALevel) {
  GlimpseState g(3);
  auto add = [&](std::uint64_t ref, char side, std::uint32_t px, std::uint16_t loc) {
    g.apply(itch_add(ref, 100, px, side, loc));
  };
  add(1, 'B', 1'000'000, 2);  // locate 2 comes after locate 1
  add(2, 'B', 1'500'000, 1);  // best bid
  add(3, 'S', 1'600'000, 1);  // best ask
  add(4, 'B', 1'400'000, 1);
  add(5, 'B', 1'500'000, 1);  // same level as 2, behind it
  add(6, 'S', 1'700'000, 1);  // worst ask
  add(7, 'S', 1'600'000, 1);  // same level as 3, behind it
  add(8, 'B', 1'400'000, 1);
  // Order 2 is replaced at the same price: it re-queues behind 5 with ref 9.
  itch50::OrderReplace u{};
  u.stock_locate = 1;
  u.original_order_ref = 2;
  u.new_order_ref = 9;
  u.shares = 100;
  u.price = 1'500'000;
  Bytes ub(itch50::OrderReplace::kLen);
  (void)itch50::encode(ub, u);
  g.apply(ub);
  std::vector<std::uint64_t> refs;
  g.visit_orders([&](const auto& m) { refs.push_back(m.order_ref); });
  //            buys 1.40: 4, 8   1.50: 5, 9   sells 1.70: 6   1.60: 3, 7   locate 2: 1
  EXPECT_EQ(refs, (std::vector<std::uint64_t>{4, 8, 5, 9, 6, 3, 7, 1}));
}

struct GlimpseEnv {
  using Net = testnet::FakeNet;
  using Clock = testnet::FakeClock;
};

// GLIMPSE: the login spins the state of itch.bin (S, R, H, the resting orders, End of
// Snapshot G), then End of Session; the port is closed only once all of it is out,
// including bytes the port stages until a SEND completes (io_uring: close() cancels).
TEST(GlimpseServer, SpinAndEndOfSessionAreFlushedBeforeTheClose) {
  const auto root = std::filesystem::temp_directory_path() / ("lle-md-glimpse-" + std::to_string(::getpid()));
  std::filesystem::remove_all(root);
  const std::uint32_t ids[] = {1};
  outlog::OutlogDay day;
  ASSERT_TRUE(day.open(root.string(), 20261001, ids));
  auto put = [&](const auto& m) {
    Bytes b(std::remove_cvref_t<decltype(m)>::kLen);
    (void)itch50::encode(b, m);
    ASSERT_TRUE(day.itch().append(b));
  };
  itch50::SystemEvent se{};
  se.event_code = itch50::EventCode::StartOfMessages;
  put(se);
  itch50::StockDirectory r{};
  r.stock_locate = 1;
  r.stock = Symbol8("AAPL");
  put(r);
  itch50::StockTradingAction h{};
  h.stock_locate = 1;
  h.stock = Symbol8("AAPL");
  h.trading_state = itch50::TradingState::Trading;
  put(h);
  for (std::uint64_t i = 1; i <= 3; ++i) ASSERT_TRUE(day.itch().append(itch_add(i, 100, static_cast<std::uint32_t>(1'500'000 - i * 1000))));
  ASSERT_TRUE(day.flush_all());

  GlimpseConfig c;
  c.soup.session = soup::SessionId::from("GLIMPSE001");
  c.tcp.max_conns = 4;
  c.itch_log_path = outlog::OutlogDay::itch_path(root.string(), 20261001);
  c.user = "GLIMPS";
  c.credential = gw::Credential::make("glimpse-pw", std::vector<std::uint8_t>{1, 2, 3});
  c.refresh_interval = 0;
  c.locates = 2;
  testnet::FakeClock clock;
  GlimpseServer<GlimpseEnv> g(c, clock);
  ASSERT_TRUE(g.start());
  for (int i = 0; i < 3; ++i) (void)g.poll();
  EXPECT_EQ(g.stats().applied, 6u);

  testnet::FakeStreamPort& port = g.port();
  port.write_budget = 11;  // a few bytes per write, staged until completed
  port.stage_tx = true;
  soup::ClientConfig cc;
  cc.username = Alpha<soup::kUsernameLen>("glimps");
  cc.password = Alpha<soup::kPasswordLen>("glimpse-pw");
  cc.sequence = 1;
  soup::ClientSession client(cc);
  const env::ConnId conn = port.accept();
  const soup::Actions& a = client.connect(clock.mono);
  port.data(conn, a.write);
  client.consume_tx(a.write.size());
  int polls = 0;
  for (; polls < 1000 && port.closed_by_stage.count(conn) == 0; ++polls) {
    (void)g.poll();
    if (polls % 2 == 1) port.complete_tx();  // completions arrive later
  }
  ASSERT_EQ(port.closed_by_stage.count(conn), 1u) << "never closed";
  EXPECT_TRUE(port.lost_at_close.empty()) << "closed with a SEND in flight";
  EXPECT_EQ(g.stats().linger_timeouts, 0u);

  const Bytes b = port.take(conn);
  bool logged_in = false, ended = false;
  std::vector<char> types;
  for (std::size_t off = 0; off < b.size();) {
    const soup::Actions& x = client.on_bytes(std::span<const std::byte>(b).subspan(off), clock.mono);
    for (const soup::Event& e : x.events) {
      if (e.kind == soup::EventKind::LoggedIn) logged_in = true;
      if (e.kind == soup::EventKind::EndOfSession) ended = true;
    }
    for (const soup::Delivered& d : x.delivered)
      if (d.seq != 0) types.push_back(static_cast<char>(d.data[0]));
    off += x.consumed;
    if (x.consumed == 0) break;
  }
  EXPECT_TRUE(logged_in);
  EXPECT_EQ(std::string(types.begin(), types.end()), "SRHAAAG");
  EXPECT_TRUE(ended) << "End of Session lost";
  EXPECT_EQ(g.stats().spins, 1u);
  std::filesystem::remove_all(root);
}

}  // namespace
}  // namespace lle::md
