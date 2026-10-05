// itch2ouch (07 §3, WP N-19): the ITCH -> OUCH mapping, the script format, and
// the divergence report on days where the real engine must reproduce the
// source book exactly (executions always against the order at the front of the
// best level) and on days where it cannot.
#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#include "book/itch_adapter.h"
#include "book/variants.h"
#include "client/divergence.h"
#include "client/itch2ouch.h"
#include "common/endian.h"
#include "common/prng.h"
#include "itch_gen.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client::i2o {
namespace {

using Msgs = std::vector<std::vector<std::byte>>;

template <class M>
std::vector<std::byte> enc(M m, std::uint64_t ts = 10ull * 3600 * 1'000'000'000) {
  m.timestamp = ts;
  std::vector<std::byte> b(M::kLen);
  itch50::encode_unchecked(b.data(), m);
  return b;
}

std::vector<std::byte> dir(Locate l, const char* s) {
  itch50::StockDirectory r;
  r.stock_locate = l;
  r.stock = Symbol8(s);
  r.round_lot_size = 100;
  r.luld_tier = static_cast<itch50::LuldTier>('1');
  r.etp_flag = static_cast<itch50::YesNoBlank>('N');
  return enc(r, 3ull * 3600 * 1'000'000'000);
}

std::vector<std::byte> add(Locate l, const char* s, OrderRef ref, Side side, Qty q, PxE4 px) {
  itch50::AddOrder a;
  a.stock_locate = l;
  a.order_ref = ref;
  a.side = side;
  a.shares = q;
  a.stock = Symbol8(s);
  a.price = px;
  return enc(a);
}

struct Rec {
  Nanos t;
  std::uint16_t session;
  std::vector<std::byte> ouch;
  Origin og;
};

std::vector<Rec> convert(const Msgs& msgs, std::uint16_t sessions = 2) {
  Converter c(ConvertConfig{sessions, ouch50::TimeInForce::Gtx});
  std::vector<Rec> out;
  SeqNo seq = 0;
  for (const auto& m : msgs)
    c.on_itch(++seq, m, [&](Nanos t, std::uint16_t s, std::span<const std::byte> o, const Origin& og) {
      out.push_back(Rec{t, s, {o.begin(), o.end()}, og});
    });
  return out;
}

TEST(Itch2Ouch, MappingOfEveryBookMessage) {
  Msgs m;
  m.push_back(dir(3, "AAPL"));
  m.push_back(add(3, "AAPL", 100, Side::Buy, 500, 1'000'000));
  {
    itch50::OrderExecuted e;
    e.stock_locate = 3;
    e.order_ref = 100;
    e.executed_shares = 100;
    m.push_back(enc(e));
  }
  {
    itch50::OrderCancel x;
    x.stock_locate = 3;
    x.order_ref = 100;
    x.cancelled_shares = 150;
    m.push_back(enc(x));
  }
  {
    itch50::OrderReplace u;
    u.stock_locate = 3;
    u.original_order_ref = 100;
    u.new_order_ref = 101;
    u.shares = 400;
    u.price = 1'000'100;
    m.push_back(enc(u));
  }
  {
    itch50::OrderExecutedWithPrice c;
    c.stock_locate = 3;
    c.order_ref = 101;
    c.executed_shares = 40;
    c.printable = static_cast<itch50::YesNo>('N');
    c.execution_price = 999'900;
    m.push_back(enc(c));
  }
  {
    itch50::OrderDelete d;
    d.stock_locate = 3;
    d.order_ref = 101;
    m.push_back(enc(d));
  }
  {
    itch50::Trade p;  // non-displayed execution: not reproduced
    p.stock_locate = 3;
    p.shares = 77;
    m.push_back(enc(p));
  }
  const auto r = convert(m);
  ASSERT_EQ(r.size(), 6u);
  for (const auto& x : r) {
    EXPECT_EQ(x.session, 3 % 2 + 1);  // locate mod K, 1-based
    EXPECT_TRUE(ouch50::validate_inbound(x.ouch).has_value());
  }
  // A -> Enter (GTX, displayed, ISO no), ClOrdID = ITCH reference.
  const auto e0 = ouch50::in::EnterOrder::decode_base(r[0].ouch.data());
  EXPECT_EQ(e0.user_ref_num, 1u);
  EXPECT_EQ(e0.side, ouch50::Side::Buy);
  EXPECT_EQ(e0.quantity, 500u);
  EXPECT_EQ(e0.price, 1'000'000u);
  EXPECT_EQ(e0.symbol, Symbol8("AAPL"));
  EXPECT_EQ(e0.time_in_force, ouch50::TimeInForce::Gtx);
  EXPECT_EQ(e0.cl_ord_id.view(), "100");
  EXPECT_EQ(r[0].t, 10ll * 3600 * 1'000'000'000);
  // E -> IOC sell at the resting price for the executed shares, new UserRefNum.
  const auto e1 = ouch50::in::EnterOrder::decode_base(r[1].ouch.data());
  EXPECT_EQ(e1.user_ref_num, 2u);
  EXPECT_EQ(e1.side, ouch50::Side::Sell);
  EXPECT_EQ(e1.quantity, 100u);
  EXPECT_EQ(e1.price, 1'000'000u);
  EXPECT_EQ(e1.time_in_force, ouch50::TimeInForce::Ioc);
  EXPECT_EQ(e1.cl_ord_id.view(), "100");
  // X 150 of the 400 open, 100 executed -> Cancel to the chain total 100 + 250.
  const auto c2 = ouch50::in::CancelOrder::decode_base(r[2].ouch.data());
  EXPECT_EQ(c2.user_ref_num, 1u);
  EXPECT_EQ(c2.quantity, 350u);
  // U -> Replace: new UserRefNum 3, quantity = 100 executed + 400 new shares.
  const auto u3 = ouch50::in::ReplaceOrder::decode_base(r[3].ouch.data());
  EXPECT_EQ(u3.orig_user_ref_num, 1u);
  EXPECT_EQ(u3.user_ref_num, 3u);
  EXPECT_EQ(u3.quantity, 500u);
  EXPECT_EQ(u3.price, 1'000'100u);
  EXPECT_EQ(u3.cl_ord_id.view(), "101");
  // C -> IOC at the resting order's price (not the execution price), counted.
  const auto e4 = ouch50::in::EnterOrder::decode_base(r[4].ouch.data());
  EXPECT_EQ(e4.price, 1'000'100u);
  EXPECT_EQ(e4.quantity, 40u);
  EXPECT_EQ(e4.user_ref_num, 4u);
  EXPECT_EQ(r[4].og.exec_price, 999'900);
  EXPECT_FALSE(r[4].og.printable);
  // D -> Cancel 0 on the replacement's UserRefNum.
  const auto c5 = ouch50::in::CancelOrder::decode_base(r[5].ouch.data());
  EXPECT_EQ(c5.user_ref_num, 3u);
  EXPECT_EQ(c5.quantity, 0u);
  Converter conv(ConvertConfig{});
  SeqNo s = 0;
  for (const auto& x : m) conv.on_itch(++s, x, [](Nanos, std::uint16_t, std::span<const std::byte>, const Origin&) {});
  EXPECT_EQ(conv.stats().hidden_trades, 1u);
  EXPECT_EQ(conv.stats().hidden_shares, 77u);
  EXPECT_EQ(conv.stats().c_nonprintable, 1u);
  EXPECT_EQ(conv.stats().c_price_differs, 1u);
  EXPECT_EQ(conv.live(), 0u);
}

TEST(Itch2Ouch, UnknownReferencesAreCountedNotEmitted) {
  Msgs m;
  itch50::OrderDelete d;
  d.order_ref = 5;
  m.push_back(enc(d));
  Converter c(ConvertConfig{});
  std::size_t n = 0;
  c.on_itch(1, m[0], [&](Nanos, std::uint16_t, std::span<const std::byte>, const Origin&) { ++n; });
  EXPECT_EQ(n, 0u);
  EXPECT_EQ(c.stats().unknown_ref, 1u);
}

class TempFile {
 public:
  explicit TempFile(const std::string& name) : path_(::testing::TempDir() + "/" + name) {}
  ~TempFile() { std::remove(path_.c_str()); }
  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  std::string path_;
};

void write_day(const std::string& path, const Msgs& msgs) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  ASSERT_NE(f, nullptr);
  for (const auto& m : msgs) {
    std::byte l[2];
    store_be16(l, static_cast<std::uint16_t>(m.size()));
    std::fwrite(l, 1, 2, f);
    std::fwrite(m.data(), 1, m.size(), f);
  }
  std::fclose(f);
}

TEST(Itch2Ouch, ScriptRoundTripPlainAndGzip) {
  const auto msgs = test::ItchGen(31).make(3'000);
  const auto recs = convert(msgs, 3);
  for (const char* name : {"lle_script.ofs", "lle_script.ofs.gz"}) {
    TempFile tf(name);
    ScriptHeader h;
    h.date = 20260102;
    h.sessions = 3;
    h.symbols.push_back(SymbolInfo{Symbol8("AAA"), 100, 1, '1', 'N'});
    h.symbols.push_back(SymbolInfo{Symbol8("BBB"), 10, 2, '2', 'Y'});
    ScriptWriter w;
    std::string err;
    ASSERT_TRUE(w.open(tf.path(), h, &err)) << err;
    for (const auto& r : recs) ASSERT_TRUE(w.write(r.t, r.session, r.ouch));
    ASSERT_TRUE(w.close());
    ScriptReader rd;
    ASSERT_TRUE(rd.open(tf.path(), &err)) << err;
    EXPECT_EQ(rd.header().date, 20260102u);
    EXPECT_EQ(rd.header().sessions, 3u);
    ASSERT_EQ(rd.header().symbols.size(), 2u);
    EXPECT_EQ(rd.header().symbols[1].symbol, Symbol8("BBB"));
    EXPECT_EQ(rd.header().symbols[1].round_lot, 10u);
    EXPECT_EQ(rd.header().symbols[1].etp, 'Y');
    ScriptRecord rec;
    std::size_t i = 0;
    while (rd.next(rec)) {
      ASSERT_LT(i, recs.size());
      EXPECT_EQ(rec.t, recs[i].t);
      EXPECT_EQ(rec.session, recs[i].session);
      EXPECT_TRUE(std::equal(rec.ouch.begin(), rec.ouch.end(), recs[i].ouch.begin(), recs[i].ouch.end()));
      ++i;
    }
    EXPECT_TRUE(rd.error().empty()) << rd.error();
    EXPECT_EQ(i, recs.size());
  }
}

TEST(Itch2Ouch, ScriptReaderRejectsGarbage) {
  TempFile tf("lle_garbage.ofs");
  std::FILE* f = std::fopen(tf.path().c_str(), "wb");
  std::fputs("not a script at all, really not", f);
  std::fclose(f);
  ScriptReader rd;
  std::string err;
  EXPECT_FALSE(rd.open(tf.path(), &err));
  EXPECT_NE(err.find("magic"), std::string::npos);
}

// A day the engine reproduces exactly: executions always take the order at the
// front of the best opposite level, cancels and replaces are arbitrary.
Msgs priority_day(std::uint64_t seed, std::size_t n) {
  Msgs m;
  const char* syms[3] = {"AAA", "BBB", "CCC"};
  for (Locate l = 1; l <= 3; ++l) m.push_back(dir(l, syms[l - 1]));
  book::OptBook<> b;
  Prng rng(seed);
  OrderRef next = 1;
  std::vector<std::pair<OrderRef, Locate>> live;
  std::uint64_t ts = 10ull * 3600 * 1'000'000'000;
  auto stamp = [&]() { return ts += 1'000; };
  while (m.size() < n) {
    const std::uint64_t r = rng.below(100);
    if (live.size() < 20 || r < 50) {
      const auto l = static_cast<Locate>(1 + rng.below(3));
      const Side s = rng.below(2) ? Side::Buy : Side::Sell;
      const PxE4 px = s == Side::Buy ? 990'000 - static_cast<PxE4>(rng.below(5)) * 100
                                     : 1'000'000 + static_cast<PxE4>(rng.below(5)) * 100;
      itch50::AddOrder a;
      a.stock_locate = l;
      a.order_ref = next++;
      a.side = s;
      a.shares = static_cast<Qty>(100 * (1 + rng.below(5)));
      a.stock = Symbol8(syms[l - 1]);
      a.price = px;
      m.push_back(enc(a, stamp()));
      (void)b.add(a.order_ref, l, s, px, a.shares);
      live.emplace_back(a.order_ref, l);
      continue;
    }
    if (r < 70) {
      // Execute the front order of a random symbol's best level.
      const auto l = static_cast<Locate>(1 + rng.below(3));
      const Side s = rng.below(2) ? Side::Buy : Side::Sell;
      OrderRef front = 0;
      Qty qty = 0;
      bool first = true;
      b.for_each_order(l, s, [&](PxE4, OrderRef ref, Qty q) {
        if (first) {
          front = ref;
          qty = q;
          first = false;
        }
      });
      if (front == 0) continue;
      itch50::OrderExecuted e;
      e.stock_locate = l;
      e.order_ref = front;
      e.executed_shares = std::min<Qty>(qty, 100);
      m.push_back(enc(e, stamp()));
      (void)b.reduce(front, e.executed_shares);
      if (!b.find_order(front)) std::erase_if(live, [&](const auto& x) { return x.first == front; });
      continue;
    }
    const std::size_t i = static_cast<std::size_t>(rng.below(live.size()));
    const auto [ref, l] = live[i];
    const auto o = b.find_order(ref);
    if (r < 85) {
      itch50::OrderDelete d;
      d.stock_locate = l;
      d.order_ref = ref;
      m.push_back(enc(d, stamp()));
      (void)b.remove(ref);
      live[i] = live.back();
      live.pop_back();
    } else if (r < 92 && o->qty > 100) {
      itch50::OrderCancel x;
      x.stock_locate = l;
      x.order_ref = ref;
      x.cancelled_shares = 100;
      m.push_back(enc(x, stamp()));
      (void)b.reduce(ref, 100);
    } else {
      itch50::OrderReplace u;
      u.stock_locate = l;
      u.original_order_ref = ref;
      u.new_order_ref = next++;
      u.shares = static_cast<Qty>(100 * (1 + rng.below(5)));
      u.price = o->px;  // same price: back of the same queue
      m.push_back(enc(u, stamp()));
      (void)b.replace(ref, u.new_order_ref, u.price, u.shares);
      live[i].first = u.new_order_ref;
    }
  }
  return m;
}

TEST(Divergence, EngineReproducesAPriorityConsistentDayExactly) {
  const auto msgs = priority_day(41, 6'000);
  TempFile day("lle_priority_day.bin");
  write_day(day.path(), msgs);
  DivergenceConfig c;
  c.itch_path = day.path();
  c.sessions = 2;
  c.checkpoint_every = 1'000;
  c.reserve_orders = 1 << 14;
  DivergenceReport r;
  std::string err;
  ASSERT_TRUE(run_divergence(c, r, &err)) << err;
  EXPECT_EQ(r.records, r.convert.ops[0] + r.convert.ops[1] + r.convert.ops[2] + r.convert.ops[3]);
  EXPECT_GT(r.convert.ops[3], 100u);
  EXPECT_EQ(r.enter_ok, r.convert.ops[0]);
  EXPECT_EQ(r.cancel_ok, r.convert.ops[1]);
  EXPECT_EQ(r.replace_ok, r.convert.ops[2]);
  EXPECT_EQ(r.ioc_exact, r.convert.ops[3]);
  EXPECT_EQ(r.enter_crossed + r.cancel_no_order + r.cancel_shares_differ + r.ioc_other_orders, 0u);
  EXPECT_EQ(r.unmapped_engine_orders, 0u);
  ASSERT_FALSE(r.checkpoints.empty());
  for (const BookDiff& d : r.checkpoints) {
    EXPECT_EQ(d.source_digest, d.engine_digest) << "seq " << d.seq;
    EXPECT_EQ(d.identical, d.source_orders);
    EXPECT_EQ(d.levels_queue_order_differs, 0u);
  }
  const std::string j = divergence_json(c, r);
  EXPECT_NE(j.find("\"digests_equal\": true"), std::string::npos);
}

TEST(Divergence, ExecutionsOutOfPriorityAreClassified) {
  // The generated day executes random live orders, not the front of the queue,
  // and its adds may lock the book: the report must say so, not hide it.
  const auto msgs = test::ItchGen(42).make(8'000);
  TempFile day("lle_random_day.bin");
  write_day(day.path(), msgs);
  DivergenceConfig c;
  c.itch_path = day.path();
  c.reserve_orders = 1 << 14;
  DivergenceReport r;
  std::string err;
  ASSERT_TRUE(run_divergence(c, r, &err)) << err;
  EXPECT_GT(r.ioc_other_orders + r.ioc_short + r.ioc_none, 0u);
  EXPECT_FALSE(r.checkpoints.empty());
  const BookDiff& last = r.checkpoints.back();
  EXPECT_NE(last.source_digest, last.engine_digest);
  EXPECT_GT(last.missing_in_engine + last.extra_in_engine + last.shares_differ, 0u);
  EXPECT_EQ(r.convert.hidden_trades, 0u);
}

}  // namespace
}  // namespace lle::client::i2o
