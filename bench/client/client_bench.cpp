// refclient's hot path, piece by piece (07 §3 steps 2-5): arbitration + book per
// message, the strategy's Enter Order build, and the whole per-message path with
// the strategy and order entry. Indicative numbers only (plan 12 §1).
#include <benchmark/benchmark.h>

#include <vector>

#include "client/feed_handler.h"
#include "client/order_entry.h"
#include "client/replay_feed.h"
#include "client/strategy.h"
#include "common/endian.h"
#include "itch_gen.h"
#include "proto/ouch50/ouch50.h"

namespace {

using namespace lle;
using namespace lle::client;

struct Packets {
  std::vector<std::vector<std::byte>> line_a;
  std::size_t messages = 0;
};

const Packets& packets() {
  static const Packets p = [] {
    Packets out;
    const auto msgs = test::ItchGen(77, 50).make(200'000);
    ReplayFeedConfig rf;
    ReplayFeed pub(rf);
    auto cap = [&](int line, std::span<const std::byte> b) {
      if (line == 0) out.line_a.emplace_back(b.begin(), b.end());
    };
    for (const auto& m : msgs) (void)pub.append(m, 0, cap);
    pub.flush(0, cap);
    out.messages = msgs.size();
    return out;
  }();
  return p;
}

struct NullDown {
  std::uint64_t n = 0;
  void on_book_message(SeqNo, std::span<const std::byte>) { ++n; }
  void on_snapshot_message(std::span<const std::byte>) {}
  void send_request(mold::Server, std::span<const std::byte>) {}
  void on_snapshot_needed(SeqNo, SeqNo) {}
  void on_end_of_session(SeqNo) {}
};

FeedConfig feed_config() {
  FeedConfig c;
  c.book.reserve_orders = 1 << 18;
  c.book.levels_per_side = 256;
  c.arbiter.reorder_capacity = 1 << 16;
  return c;
}

// Line A only, in order: the arbiter's fast path plus the book, per message.
void BM_FeedArbiterAndBook(benchmark::State& st) {
  const Packets& p = packets();
  for (auto _ : st) {
    st.PauseTiming();
    auto fh = std::make_unique<FeedHandler<>>(feed_config());
    NullDown d;
    st.ResumeTiming();
    for (const auto& pkt : p.line_a) fh->on_packet(mold::Source::LineA, pkt, 0, d);
    benchmark::DoNotOptimize(d.n);
    st.PauseTiming();
    fh.reset();
    st.ResumeTiming();
  }
  st.SetItemsProcessed(static_cast<std::int64_t>(st.iterations()) * static_cast<std::int64_t>(p.messages));
}
BENCHMARK(BM_FeedArbiterAndBook)->Unit(benchmark::kMillisecond);

void BM_StrategyBuildEnter(benchmark::State& st) {
  StrategyConfig c;
  TriggerStrategy s(c);
  std::array<std::byte, TriggerStrategy::kEnterLen> b{};
  SeqNo seq = 123'456'789;
  UserRefNum u = 1;
  for (auto _ : st) {
    s.build(std::span<std::byte, TriggerStrategy::kEnterLen>(b), ++u, ++seq, ouch50::Side::Buy, 100, 1'000'000);
    benchmark::DoNotOptimize(b.data());
  }
}
BENCHMARK(BM_StrategyBuildEnter);

// Trigger -> Enter Order -> SoupBinTCP Unsequenced Data in the session's buffer.
void BM_StrategyToOrderEntry(benchmark::State& st) {
  OrderEntryConfig oc;
  oc.pending_capacity = 1 << 16;
  HaOrderEntry oe(oc);
  oe.on_connected(0, 0);
  // Log in by hand: feed a Login Accepted.
  const char acc[] = "\x00\x1F" "A" "   SESSION" "                   1";
  oe.on_bytes(0, std::as_bytes(std::span(acc, 33)), 0, [](SeqNo, std::span<const std::byte>) {});
  oe.consume_tx(0, oe.tx(0).size());
  StrategyConfig c;
  TriggerStrategy s(c);
  std::array<std::byte, TriggerStrategy::kEnterLen> b{};
  ouch50::out::OrderAccepted a;
  std::array<std::byte, 128> ack{};
  const std::size_t ack_len = ouch50::encode(std::span<std::byte>(ack), a);
  SeqNo seq = 1;
  for (auto _ : st) {
    const UserRefNum u = oe.next_urn();
    s.build(std::span<std::byte, TriggerStrategy::kEnterLen>(b), u, ++seq, ouch50::Side::Buy, 100, 1'000'000);
    benchmark::DoNotOptimize(oe.send(b, 0));
    oe.consume_tx(0, oe.tx(0).size());
    store_be32(ack.data() + 9, u);  // the Accepted releases the pending entry
    oe.on_response(std::span<const std::byte>(ack.data(), ack_len));
  }
  st.counters["active"] = oe.active();
}
BENCHMARK(BM_StrategyToOrderEntry);

}  // namespace

BENCHMARK_MAIN();
