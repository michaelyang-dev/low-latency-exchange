// book/itch_adapter.h: ITCH 5.0 messages, encoded with the itch50 codec, applied
// to book variants (04-order-book §5, R1a Q6 semantics).
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <vector>

#include "book/digested_book.h"
#include "book/itch_adapter.h"
#include "book/variants.h"

namespace lle::book {
namespace {

struct Msg {
  std::array<std::byte, itch50::kMaxMsgLen> b{};
  std::size_t n = 0;
  [[nodiscard]] const std::byte* data() const { return b.data(); }
};

template <class M>
Msg enc(M m, Locate loc) {
  m.stock_locate = loc;
  Msg out;
  out.n = itch50::encode(std::span<std::byte>(out.b), m);
  return out;
}

Msg directory(Locate loc) {
  itch50::StockDirectory m{};
  m.stock = Symbol8("TEST");
  return enc(m, loc);
}
Msg add(Locate loc, OrderRef ref, Side s, PxE4 px, Qty q) {
  itch50::AddOrder m{};
  m.order_ref = ref;
  m.side = s;
  m.shares = q;
  m.stock = Symbol8("TEST");
  m.price = px;
  return enc(m, loc);
}
Msg add_mpid(Locate loc, OrderRef ref, Side s, PxE4 px, Qty q) {
  itch50::AddOrderMpid m{};
  m.order_ref = ref;
  m.side = s;
  m.shares = q;
  m.stock = Symbol8("TEST");
  m.price = px;
  m.attribution = Mpid4("MPID");
  return enc(m, loc);
}
Msg executed(Locate loc, OrderRef ref, Qty q) {
  itch50::OrderExecuted m{};
  m.order_ref = ref;
  m.executed_shares = q;
  m.match_number = 7;
  return enc(m, loc);
}
Msg executed_px(Locate loc, OrderRef ref, Qty q, itch50::YesNo printable) {
  itch50::OrderExecutedWithPrice m{};
  m.order_ref = ref;
  m.executed_shares = q;
  m.match_number = 8;
  m.printable = printable;
  m.execution_price = 99'999;  // not a book input
  return enc(m, loc);
}
Msg cancel(Locate loc, OrderRef ref, Qty q) {
  itch50::OrderCancel m{};
  m.order_ref = ref;
  m.cancelled_shares = q;
  return enc(m, loc);
}
Msg del(Locate loc, OrderRef ref) {
  itch50::OrderDelete m{};
  m.order_ref = ref;
  return enc(m, loc);
}
Msg replace(Locate loc, OrderRef old_ref, OrderRef new_ref, PxE4 px, Qty q) {
  itch50::OrderReplace m{};
  m.original_order_ref = old_ref;
  m.new_order_ref = new_ref;
  m.shares = q;
  m.price = px;
  return enc(m, loc);
}

template <class V>
class AdapterTest : public ::testing::Test {};

using Variants = ::testing::Types<VarB0, VarVecIntrFlat, VarOpt, VarWin, VarMapIntrFlat>;
TYPED_TEST_SUITE(AdapterTest, Variants);

TYPED_TEST(AdapterTest, AppliesEveryBookMessage) {
  DigestedBook<TypeParam> db;
  auto& b = db.book();
  auto apply = [&](const Msg& m) { return apply_itch(b, m.data(), m.n); };
  constexpr Locate kLoc = 5;

  EXPECT_EQ(apply(directory(kLoc)).kind, ItchKind::kDirectory);
  auto r = apply(add(kLoc, 1, Side::Buy, 10'000, 100));
  EXPECT_EQ(r.kind, ItchKind::kAdd);
  EXPECT_EQ(r.status, Status::kOk);
  r = apply(add_mpid(kLoc, 2, Side::Sell, 10'100, 200));
  EXPECT_EQ(r.kind, ItchKind::kAdd);
  EXPECT_EQ(b.bbo(kLoc).bid.px, 10'000);
  EXPECT_EQ(b.bbo(kLoc).bid.qty, 100u);
  EXPECT_EQ(b.bbo(kLoc).ask.px, 10'100);
  EXPECT_EQ(b.bbo(kLoc).ask.qty, 200u);

  EXPECT_EQ(apply(executed(kLoc, 1, 30)).kind, ItchKind::kExecute);
  EXPECT_EQ(b.bbo(kLoc).bid.qty, 70u);
  // C reduces the order whatever its Printable flag (R1a Q6).
  EXPECT_EQ(apply(executed_px(kLoc, 1, 20, itch50::YesNo::No)).kind, ItchKind::kExecPrice);
  EXPECT_EQ(b.bbo(kLoc).bid.qty, 50u);
  EXPECT_EQ(apply(cancel(kLoc, 2, 50)).kind, ItchKind::kCancel);
  EXPECT_EQ(b.bbo(kLoc).ask.qty, 150u);

  // U: new ref, new price, old side and locate, back of the queue.
  r = apply(replace(kLoc, 2, 3, 10'200, 75));
  EXPECT_EQ(r.kind, ItchKind::kReplace);
  EXPECT_EQ(r.status, Status::kOk);
  EXPECT_FALSE(b.find_order(2).has_value());
  ASSERT_TRUE(b.find_order(3).has_value());
  EXPECT_EQ(b.find_order(3)->side, Side::Sell);
  EXPECT_EQ(b.find_order(3)->locate, kLoc);
  EXPECT_EQ(b.bbo(kLoc).ask.px, 10'200);
  EXPECT_EQ(b.bbo(kLoc).ask.qty, 75u);

  EXPECT_EQ(apply(del(kLoc, 3)).kind, ItchKind::kDelete);
  EXPECT_EQ(b.bbo(kLoc).ask.qty, 0u);
  EXPECT_EQ(b.live_orders(), 1u);

  // Unknown refs are reported, not applied.
  EXPECT_EQ(apply(del(kLoc, 99)).status, Status::kUnknownRef);
  std::string err;
  EXPECT_TRUE(b.check_invariants(&err)) << err;
}

TYPED_TEST(AdapterTest, IgnoresNonBookAndMalformedMessages) {
  DigestedBook<TypeParam> db;
  auto& b = db.book();
  itch50::SystemEvent s{};
  s.event_code = itch50::EventCode::StartOfMessages;
  const Msg sys = enc(s, 0);
  EXPECT_EQ(apply_itch(b, sys.data(), sys.n).kind, ItchKind::kOther);

  const Msg a = add(1, 1, Side::Buy, 10'000, 100);
  EXPECT_EQ(apply_itch(b, a.data(), a.n - 1).kind, ItchKind::kMalformed);  // short
  EXPECT_EQ(apply_itch(b, a.data(), 0).kind, ItchKind::kMalformed);
  EXPECT_EQ(b.live_orders(), 0u);
  EXPECT_EQ(db.recorder().digest.events, 0u);
}

TEST(ItchAdapter, DecodeBookEvent) {
  const Msg u = replace(9, 11, 12, 123'400, 300);
  const ItchEvent e = decode_book_event(u.data(), u.n);
  EXPECT_EQ(e.kind, ItchKind::kReplace);
  EXPECT_EQ(e.loc, 9);
  EXPECT_EQ(e.ref, 11u);
  EXPECT_EQ(e.new_ref, 12u);
  EXPECT_EQ(e.px, 123'400);
  EXPECT_EQ(e.qty, 300u);

  const Msg f = add_mpid(3, 77, Side::Sell, 5, 1);
  const ItchEvent ef = decode_book_event(f.data(), f.n);
  EXPECT_EQ(ef.kind, ItchKind::kAdd);
  EXPECT_EQ(ef.side, Side::Sell);
  EXPECT_EQ(ef.ref, 77u);

  const Msg x = cancel(3, 77, 1);
  EXPECT_EQ(decode_book_event(x.data(), x.n).kind, ItchKind::kCancel);
  EXPECT_EQ(decode_book_event(x.data(), x.n + 1).kind, ItchKind::kMalformed);
}

TEST(ItchAdapter, PrefetchAcceptsEveryType) {
  DigestedBook<VarOpt> opt;
  DigestedBook<VarB0> b0;  // StdStore: prefetch is a no-op
  const std::vector<Msg> all = {directory(1),      add(1, 1, Side::Buy, 1, 1), add_mpid(1, 2, Side::Sell, 1, 1),
                                executed(1, 1, 1), executed_px(1, 1, 1, itch50::YesNo::Yes), cancel(1, 1, 1),
                                del(1, 1),         replace(1, 1, 2, 1, 1)};
  for (const Msg& m : all) {
    prefetch_itch(opt.book(), m.data());
    prefetch_itch(b0.book(), m.data());
  }
  SUCCEED();
}

}  // namespace
}  // namespace lle::book
