// GLIMPSE-style snapshot: End of Snapshot golden bytes, server spin order and
// content, joiner splice semantics, and an end-to-end late join over
// MoldUDP64 that must reconstruct the same state as a full replay.
#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include "proto/glimpse/glimpse.h"
#include "proto/glimpse/snapshot_joiner.h"
#include "proto/glimpse/snapshot_server.h"
#include "proto/itch50/itch50.h"
#include "proto/moldudp64/depacketizer.h"
#include "proto/moldudp64/packetizer.h"

namespace lle::glimpse {
namespace {

using Bytes = std::vector<std::byte>;

Bytes str_bytes(std::string_view s) {
  Bytes b;
  for (char c : s) b.push_back(static_cast<std::byte>(c));
  return b;
}

template <class M>
Bytes bytes_of(const M& m) {
  Bytes b(M::kLen);
  EXPECT_EQ(itch50::encode(b, m), M::kLen);
  return b;
}

TEST(EndOfSnapshot, GoldenBytesAndTolerantParse) {
  Bytes g(kEndOfSnapshotLen);
  ASSERT_EQ(encode_end_of_snapshot(g, 13), 21u);
  EXPECT_EQ(g, str_bytes("G                  13"));
  EXPECT_EQ(decode_end_of_snapshot(g).value(), 13u);
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("G00000000000000000013")).value(), 13u);
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("G13                  ")).value(), 13u);
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("G18446744073709551615")).value(), ~SeqNo{0});
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("G18446744073709551616")).error(), EndOfSnapshotError::BadNumber);
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("G                    ")).error(), EndOfSnapshotError::BadNumber);
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("G              1 3   ")).error(), EndOfSnapshotError::BadNumber);
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("G13")).error(), EndOfSnapshotError::BadLength);
  EXPECT_EQ(decode_end_of_snapshot(str_bytes("S                  13")).error(), EndOfSnapshotError::NotEndOfSnapshot);
  Bytes max(kEndOfSnapshotLen);
  encode_end_of_snapshot(max, ~SeqNo{0});
  EXPECT_EQ(max, str_bytes("G18446744073709551615"));
  EXPECT_TRUE(is_snapshot_type('h'));
  EXPECT_FALSE(is_snapshot_type('D'));
  EXPECT_FALSE(is_snapshot_type('G'));
}

// A small replica state; visits in insertion order.
struct TestState {
  SeqNo next = 1;
  std::vector<itch50::SystemEvent> events;
  std::vector<itch50::StockDirectory> dir;
  std::vector<itch50::StockTradingAction> actions;
  std::vector<itch50::RegShoRestriction> regsho;
  std::vector<itch50::OperationalHalt> halts;
  std::map<OrderRef, itch50::AddOrder> orders;
  std::map<OrderRef, itch50::AddOrderMpid> mpid_orders;

  SeqNo snapshot_next_seq() const { return next; }
  template <class F> void visit_system_events(F&& f) const { for (const auto& m : events) f(m); }
  template <class F> void visit_stock_directory(F&& f) const { for (const auto& m : dir) f(m); }
  template <class F> void visit_trading_actions(F&& f) const { for (const auto& m : actions) f(m); }
  template <class F> void visit_reg_sho(F&& f) const { for (const auto& m : regsho) f(m); }
  template <class F> void visit_operational_halts(F&& f) const { for (const auto& m : halts) f(m); }
  template <class F> void visit_orders(F&& f) const {
    for (const auto& [ref, m] : orders) f(m);
    for (const auto& [ref, m] : mpid_orders) f(m);
  }
};
static_assert(SnapshotStateLike<TestState>);

itch50::StockDirectory directory(Locate loc, const char* sym) {
  return itch50::StockDirectory{.stock_locate = loc, .tracking_number = 0, .timestamp = 1, .stock = Symbol8(sym),
                                .market_category = itch50::MarketCategory::NasdaqGlobalSelect,
                                .financial_status = itch50::FinancialStatus::Normal, .round_lot_size = 100,
                                .round_lots_only = itch50::YesNo::No,
                                .issue_classification = itch50::IssueClassification::CommonStock,
                                .issue_sub_type = Alpha<2>("Z"), .authenticity = itch50::Authenticity::LiveProduction,
                                .short_sale_threshold = itch50::YesNoBlank::No, .ipo_flag = itch50::IpoFlag::NotNewIpo,
                                .luld_tier = itch50::LuldTier::Tier1, .etp_flag = itch50::YesNoBlank::No,
                                .etp_leverage_factor = 0, .inverse_indicator = itch50::YesNo::No};
}

itch50::AddOrder add(OrderRef ref, Locate loc, std::uint64_t ts, PxE4 px) {
  return itch50::AddOrder{.stock_locate = loc, .tracking_number = 0, .timestamp = ts, .order_ref = ref,
                          .side = ref % 2 ? Side::Buy : Side::Sell, .shares = 100, .stock = Symbol8("AAPL"), .price = px};
}

TEST(SnapshotServer, SpinOrderContentAndEndOfSnapshot) {
  TestState st;
  st.next = 1001;
  st.events.push_back({.stock_locate = 0, .tracking_number = 0, .timestamp = 5, .event_code = itch50::EventCode::StartOfMessages});
  st.events.push_back({.stock_locate = 0, .tracking_number = 0, .timestamp = 6, .event_code = itch50::EventCode::StartOfSystemHours});
  st.dir.push_back(directory(1, "AAPL"));
  st.actions.push_back({.stock_locate = 1, .tracking_number = 0, .timestamp = 7, .stock = Symbol8("AAPL"),
                        .trading_state = itch50::TradingState::Trading, .reserved = ' ', .reason = Alpha<4>()});
  st.regsho.push_back({.stock_locate = 1, .tracking_number = 0, .timestamp = 8, .stock = Symbol8("AAPL"),
                       .reg_sho_action = itch50::RegShoAction::NoPriceTest});
  st.halts.push_back({.stock_locate = 1, .tracking_number = 0, .timestamp = 9, .stock = Symbol8("AAPL"),
                      .market_code = itch50::MarketCode::Psx, .action = itch50::OperationalHaltAction::Resumed});
  st.orders.emplace(11, add(11, 1, 10, 1'000'000));
  st.mpid_orders.emplace(12, itch50::AddOrderMpid{.stock_locate = 1, .tracking_number = 0, .timestamp = 11, .order_ref = 12,
                                                  .side = Side::Sell, .shares = 5, .stock = Symbol8("AAPL"),
                                                  .price = 1'000'100, .attribution = Mpid4("GSCO")});
  std::vector<Bytes> spin;
  const SpinStats s = SnapshotServer{}.emit(st, [&](std::span<const std::byte> p) { spin.emplace_back(p.begin(), p.end()); });
  ASSERT_EQ(spin.size(), 9u);
  EXPECT_EQ(s.messages, 9u);
  EXPECT_EQ(s.next_seq, 1001u);
  std::string order;
  for (const auto& p : spin) order += static_cast<char>(p[0]);
  EXPECT_EQ(order, "SSRHYhAFG");
  EXPECT_EQ(spin[0], bytes_of(st.events[0]));
  EXPECT_EQ(spin[6], bytes_of(st.orders.at(11)));
  EXPECT_EQ(spin[7], bytes_of(st.mpid_orders.at(12)));
  EXPECT_EQ(spin[8], str_bytes("G                1001"));
  EXPECT_EQ(s.by_type['S'], 2u);
  EXPECT_EQ(s.by_type['G'], 1u);
}

struct JSink {
  std::vector<Bytes> snapshot;
  std::vector<std::pair<SeqNo, Bytes>> live;
  std::vector<std::pair<SeqNo, SeqNo>> gaps;
  void on_snapshot_message(std::span<const std::byte> m) { snapshot.emplace_back(m.begin(), m.end()); }
  void on_message(SeqNo s, std::span<const std::byte> m) { live.emplace_back(s, Bytes(m.begin(), m.end())); }
  void on_gap(SeqNo a, SeqNo b) { gaps.emplace_back(a, b); }
};

Bytes live_msg(SeqNo s) {
  itch50::OrderDelete d{.stock_locate = 1, .tracking_number = 0, .timestamp = s, .order_ref = s};
  return bytes_of(d);
}

TEST(SnapshotJoiner, BuffersLiveAndSplicesAtEndOfSnapshot) {
  SnapshotJoiner j(SnapshotJoinerConfig{1024, 64});
  JSink sink;
  for (SeqNo s = 100; s < 120; ++s) j.on_live(s, live_msg(s), sink);
  EXPECT_TRUE(sink.live.empty());
  EXPECT_EQ(j.buffered(), 20u);
  const Bytes sys = bytes_of(itch50::SystemEvent{.stock_locate = 0, .tracking_number = 0, .timestamp = 1,
                                                 .event_code = itch50::EventCode::StartOfMessages});
  EXPECT_EQ(j.on_snapshot(sys, sink), SnapshotJoiner::SnapshotResult::Applied);
  EXPECT_EQ(j.on_snapshot(live_msg(5), sink), SnapshotJoiner::SnapshotResult::Rejected);  // 'D' is not a spin type
  Bytes truncated = sys;
  truncated.pop_back();
  EXPECT_EQ(j.on_snapshot(truncated, sink), SnapshotJoiner::SnapshotResult::Rejected);
  Bytes g(kEndOfSnapshotLen);
  encode_end_of_snapshot(g, 110);
  EXPECT_EQ(j.on_snapshot(g, sink), SnapshotJoiner::SnapshotResult::Spliced);
  EXPECT_EQ(j.state(), SnapshotJoiner::State::Live);
  EXPECT_EQ(j.splice_seq(), 110u);
  ASSERT_EQ(sink.snapshot.size(), 1u);
  ASSERT_EQ(sink.live.size(), 10u);  // 110..119; 100..109 are in the snapshot
  for (SeqNo s = 110; s < 120; ++s) {
    EXPECT_EQ(sink.live[s - 110].first, s);
    EXPECT_EQ(sink.live[s - 110].second, live_msg(s));
  }
  EXPECT_EQ(j.stats().live_dropped_before_splice, 10u);
  // After the splice live messages pass straight through.
  j.on_live(119, live_msg(119), sink);
  j.on_live(120, live_msg(120), sink);
  EXPECT_EQ(sink.live.size(), 11u);
  EXPECT_EQ(j.stats().live_duplicates, 1u);
  EXPECT_EQ(j.on_snapshot(g, sink), SnapshotJoiner::SnapshotResult::IgnoredAfterSplice);
  EXPECT_TRUE(sink.gaps.empty());
}

TEST(SnapshotJoiner, SnapshotAheadOfLiveWaitsForLive) {
  SnapshotJoiner j(SnapshotJoinerConfig{64, 64});
  JSink sink;
  j.on_live(10, live_msg(10), sink);
  Bytes g(kEndOfSnapshotLen);
  encode_end_of_snapshot(g, 15);
  j.on_snapshot(g, sink);
  EXPECT_TRUE(sink.live.empty());
  EXPECT_TRUE(sink.gaps.empty());
  for (SeqNo s = 11; s <= 16; ++s) j.on_live(s, live_msg(s), sink);
  ASSERT_EQ(sink.live.size(), 2u);
  EXPECT_EQ(sink.live[0].first, 15u);
  EXPECT_EQ(sink.live[1].first, 16u);
}

TEST(SnapshotJoiner, ReportsGapWhenSpliceSequenceWasNotBuffered) {
  SnapshotJoiner j(SnapshotJoinerConfig{8, 64});  // tiny window: older live data falls out
  JSink sink;
  for (SeqNo s = 1; s <= 30; ++s) j.on_live(s, live_msg(s), sink);
  EXPECT_EQ(j.buffered(), 8u);  // 23..30
  EXPECT_EQ(j.stats().live_dropped_window, 22u);
  Bytes g(kEndOfSnapshotLen);
  encode_end_of_snapshot(g, 20);
  j.on_snapshot(g, sink);
  EXPECT_TRUE(sink.live.empty());
  ASSERT_EQ(sink.gaps.size(), 1u);
  EXPECT_EQ(sink.gaps[0], std::make_pair(SeqNo{20}, SeqNo{23}));
  // After the splice the window is [20, 28): 28..30 were dropped with the old window.
  EXPECT_EQ(j.buffered(), 5u);
  // Recovered 20..22 (e.g. by re-request) let the buffered 23..27 through.
  for (SeqNo s = 20; s <= 22; ++s) j.on_live(s, live_msg(s), sink);
  ASSERT_EQ(sink.live.size(), 8u);
  EXPECT_EQ(sink.live.back().first, 27u);
  // The next hole is reported once, when data beyond it arrives.
  j.on_live(29, live_msg(29), sink);
  ASSERT_EQ(sink.gaps.size(), 2u);
  EXPECT_EQ(sink.gaps[1], std::make_pair(SeqNo{28}, SeqNo{29}));
  j.on_live(28, live_msg(28), sink);
  EXPECT_EQ(sink.live.back().first, 29u);
}

// End-to-end late join: a day of ITCH messages is published over MoldUDP64.
// A late joiner starts listening mid-stream, takes a snapshot at P, splices
// at P+1, and must end with the same live-order set as a full replay.
TEST(SnapshotJoin, LateJoinerReconstructsFullReplayState) {
  std::vector<Bytes> stream;  // index i = sequence i+1
  stream.push_back(bytes_of(itch50::SystemEvent{.stock_locate = 0, .tracking_number = 0, .timestamp = 1,
                                                .event_code = itch50::EventCode::StartOfMessages}));
  stream.push_back(bytes_of(directory(1, "AAPL")));
  for (OrderRef ref = 1; ref <= 400; ++ref) {
    stream.push_back(bytes_of(add(ref, 1, 100 + ref, 1'000'000 + static_cast<PxE4>(ref))));
    if (ref % 3 == 0)
      stream.push_back(bytes_of(itch50::OrderDelete{.stock_locate = 1, .tracking_number = 0, .timestamp = 100 + ref,
                                                    .order_ref = ref - 2}));
  }
  // Order book semantics for this test: A inserts, D removes.
  struct Book {
    std::map<OrderRef, itch50::AddOrder> live;
    void apply(std::span<const std::byte> m) {
      (void)itch50::visit(m, [&](auto v) {
        using V = decltype(v);
        if constexpr (std::is_same_v<V, itch50::AddOrderView>) live[v.order_ref()] = v.to_struct();
        if constexpr (std::is_same_v<V, itch50::OrderDeleteView>) live.erase(v.order_ref());
      });
    }
  };
  Book full;
  for (const auto& m : stream) full.apply(m);

  // Publish everything over MoldUDP64.
  mold::PacketizerConfig pc;
  pc.session = mold::Session("GLIMPSE001");
  pc.max_packet = 400;
  mold::Packetizer pub(pc);
  std::vector<Bytes> packets;
  auto emit = [&](std::span<const std::byte> p) { packets.emplace_back(p.begin(), p.end()); };
  for (const auto& m : stream) pub.append(m, 0, emit);
  pub.end_session(0, emit);

  // Snapshot at P: replica state after the first P messages.
  const SeqNo P = 300;
  TestState snap;
  snap.next = P + 1;
  {
    Book at_p;
    for (SeqNo s = 1; s <= P; ++s) at_p.apply(stream[s - 1]);
    snap.events.push_back(itch50::SystemEventView{stream[0].data()}.to_struct());
    snap.dir.push_back(itch50::StockDirectoryView{stream[1].data()}.to_struct());
    snap.orders = at_p.live;
  }

  // The joiner hears the live stream from packet 40 on (late), buffered until G.
  struct Client {
    Book book;
    SnapshotJoiner joiner{SnapshotJoinerConfig{4096, 64}};
    std::uint64_t gaps = 0;
    void on_snapshot_message(std::span<const std::byte> m) { book.apply(m); }
    void on_message(SeqNo, std::span<const std::byte> m) { book.apply(m); }
    void on_gap(SeqNo, SeqNo) { ++gaps; }
    // Depacketizer sink:
    void on_end_of_session(SeqNo) {}
  } client;
  struct LiveSink {
    Client& c;
    void on_message(SeqNo s, std::span<const std::byte> m) { c.joiner.on_live(s, m, c); }
    void on_gap(SeqNo, SeqNo) {}
    void on_end_of_session(SeqNo) {}
  } live_sink{client};
  mold::Depacketizer depack(mold::DepacketizerConfig{pc.session, 1, mold::GapPolicy::Skip});
  // Start listening at the first packet from sequence 200 on (well after the
  // start of the day, before P), and receive live data up to ~350 before the spin.
  std::size_t pi = 0;
  while (mold::decode_header(packets[pi].data()).seq < 200) ++pi;
  ASSERT_GT(pi, 0u);
  for (; mold::decode_header(packets[pi].data()).seq < 350; ++pi) depack.on_packet(packets[pi], live_sink);
  const SpinStats spin = SnapshotServer{}.emit(snap, [&](std::span<const std::byte> p) { client.joiner.on_snapshot(p, client); });
  EXPECT_EQ(spin.next_seq, P + 1);
  for (; pi < packets.size(); ++pi) depack.on_packet(packets[pi], live_sink);

  EXPECT_EQ(client.joiner.state(), SnapshotJoiner::State::Live);
  EXPECT_EQ(client.gaps, 0u);
  EXPECT_EQ(client.joiner.next_expected(), stream.size() + 1);
  EXPECT_EQ(client.book.live.size(), full.live.size());
  EXPECT_TRUE(client.book.live == full.live);
}

}  // namespace
}  // namespace lle::glimpse
