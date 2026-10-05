// Risk gate properties (05-matching-engine §7, T04): over random limits,
// books and order flow,
//   (1) no accepted order violates an active limit, and
//   (2) every rejection names the first failing check in the documented order.
// The oracle below evaluates the documented checks one by one on the state
// before each order (quotes and exposure read from the engine, whose
// bookkeeping Engine::check() verifies against the orders after every step;
// rate buckets and the duplicate filter re-derived here from the rules).
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <deque>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/hash.h"
#include "common/int128.h"
#include "common/prng.h"
#include "engine/engine.h"
#include "engine/scenario.h"

namespace lle::engine {
namespace {

using OS = ouch50::Side;
using RR = ouch50::RejectReason;
constexpr std::uint16_t C(RR r) { return static_cast<std::uint16_t>(r); }

struct Sink {
  std::vector<std::vector<std::byte>> out;
  void itch(std::uint64_t, std::span<const std::byte>) {}
  void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte> b) { out.emplace_back(b.begin(), b.end()); }
  void audit(std::uint64_t, const AuditEvent&) {}
};

// The limits the oracle knows (one account), mirroring what the test configured.
struct Lim {
  std::uint32_t perms = 0;
  std::int64_t max_qty = 0, max_notional = 0, ff_bps = 0, ff_abs = 0, lop = 1, dup = 0, port = 0, symrate = 0,
               gross = 0, symnot = 0, adv = 0;
  bool restricted[3] = {}, htb[3] = {};
};

struct Bucket {
  std::int64_t level = 0, last = INT64_MIN;
  bool take(std::int64_t rate, std::int64_t now) {
    const std::int64_t unit = 1'000'000'000;
    std::int64_t lv = rate * unit;
    if (last != INT64_MIN) lv = std::min(rate * unit, level + std::clamp<std::int64_t>(now - last, 0, unit) * rate);
    last = now;
    if (lv < unit) {
      level = lv;
      return false;
    }
    level = lv - unit;
    return true;
  }
};

TEST(RiskProperty, AcceptedOrdersRespectLimitsAndRejectionsNameTheFirstFailingCheck) {
  std::uint64_t accepted = 0, rejected = 0;
  std::map<std::uint16_t, std::uint64_t> by_code;
  for (std::uint64_t seed = 1; seed <= 300; ++seed) {
    Prng rng(seed);
    Scenario sc;
    Engine eng(EngineConfig{BookConfig{1u << 12, 1u << 10, 8}, 1u << 12, 256});
    sc.day_start();
    std::array<SymbolEntry, 2> syms{};
    syms[0].symbol = Symbol8("AAPL");
    syms[0].prior_close = 1'000'000;
    syms[0].adv = static_cast<std::uint32_t>(rng.below(20'000));
    syms[1].symbol = Symbol8("MSFT");
    syms[1].prior_close = 0;
    syms[1].adv = static_cast<std::uint32_t>(rng.below(20'000));
    std::array<AccountEntry, 2> accts{};
    accts[0].account_id = 1;
    accts[0].firms[0] = Mpid4("AAAA");
    accts[1].account_id = 2;
    accts[1].firms[0] = Mpid4("BBBB");
    std::array<SessionEntry, 2> sess{};
    sess[0] = SessionEntry{1, 1, SessionEntry::kMarketOrders, 'N'};
    sess[1] = SessionEntry{2, 2, SessionEntry::kMarketOrders, 'N'};
    sc.symbols(syms);
    sc.accounts(accts);
    sc.sessions(sess);
    // Random limits for account 1 (account 2 is the unrestricted counterparty).
    Lim L;
    std::vector<RiskEntry> rl;
    auto add = [&](RiskKind k, std::int64_t v, Locate l = 0) {
      RiskEntry e;
      e.account_id = 1;
      e.kind = k;
      e.value = v;
      if (l != 0) e.symbol = syms[l - 1].symbol;
      rl.push_back(e);
    };
    auto maybe = [&] { return rng.chance(1, 3); };
    if (maybe()) add(RiskKind::Permissions, L.perms = static_cast<std::uint32_t>(rng.below(128)) & ~3u);
    if (maybe()) add(RiskKind::MaxOrderQty, L.max_qty = rng.range(1, 600));
    if (maybe()) add(RiskKind::MaxOrderNotional, L.max_notional = rng.range(1, 500) * 1'000'000);
    if (maybe()) add(RiskKind::FatFingerBps, L.ff_bps = rng.range(1, 500));
    if (maybe()) add(RiskKind::FatFingerAbs, L.ff_abs = rng.range(1, 50) * 100);
    if (maybe()) add(RiskKind::Lop, L.lop = static_cast<std::int64_t>(rng.below(2)));
    if (maybe()) add(RiskKind::DupWindowSec, L.dup = rng.range(0, 30));
    if (maybe()) add(RiskKind::PortRate, L.port = rng.range(1, 50));
    if (maybe()) add(RiskKind::SymbolRate, L.symrate = rng.range(1, 30));
    if (maybe()) add(RiskKind::GrossExposure, L.gross = rng.range(1, 2'000) * 1'000'000);
    if (maybe()) add(RiskKind::SymbolNotional, L.symnot = rng.range(1, 1'000) * 1'000'000);
    if (maybe()) add(RiskKind::AdvPct, L.adv = rng.range(0, 10));
    for (Locate l = 1; l <= 2; ++l) {
      if (rng.chance(1, 6)) add(RiskKind::Restricted, L.restricted[l] = true, l);
      if (rng.chance(1, 4)) add(RiskKind::HardToBorrow, L.htb[l] = true, l);
    }
    sc.risk(rl);
    sc.schedule(params_only('R'));
    sc.admin(AdminCommand::LuldBands,
             AdminArgsBuilder{}.symbol("AAPL").i64(AdminTag::Lower, 950'000).i64(AdminTag::Upper, 1'050'000));
    Sink sink;
    for (std::size_t i = 0; i < sc.size(); ++i) eng.apply(sc[i], sink);

    std::map<std::pair<std::uint32_t, Locate>, Bucket> symb;
    Bucket port;
    std::map<std::int64_t, std::deque<std::uint64_t>> dup;
    UserRefNum urn[3] = {0, 1, 1};
    for (int op = 0; op < 300; ++op) {
      if (rng.chance(1, 8)) sc.set_time(sc.now() + rng.range(1, 1'500'000'000));
      const bool mine = rng.chance(2, 3);
      const std::uint32_t s = mine ? 1 : 2;
      const Locate l = static_cast<Locate>(1 + rng.below(2));
      const PxE4 mid = l == 1 ? 1'000'000 : 200'000;
      const std::uint64_t r = rng.below(10);
      const OS side = r < 5 ? OS::Buy : (r < 8 ? OS::Sell : (r < 9 ? OS::SellShort : OS::SellShortExempt));
      const bool market = rng.chance(1, 12);
      const PxE4 px = mid + static_cast<PxE4>(rng.range(-80, 80)) * 100 * (rng.chance(1, 10) ? 20 : 1);
      const Qty q = static_cast<Qty>(rng.chance(1, 4) ? rng.range(1, 2'000) : rng.range(1, 3) * 100);
      ouch50::TagSet tags;
      const bool located = rng.chance(1, 3);
      if (located) tags.set_shares_located(ouch50::SharesLocated::Yes);
      EnterArgs ea{.urn = urn[s]++, .side = side, .qty = q, .symbol = l == 1 ? "AAPL" : "MSFT",
                   .price = market ? ouch50::kMarketPrice : static_cast<std::uint64_t>(std::max<PxE4>(px, 100)),
                   .tif = market || rng.chance(1, 5) ? ouch50::TimeInForce::Ioc : ouch50::TimeInForce::Day};
      const PxE4 lpx = market ? 0 : static_cast<PxE4>(ea.price);
      // ---- the oracle, on the state before the record
      const std::int64_t now = static_cast<std::int64_t>(sc.now());
      std::uint16_t want = 0;
      if (mine) {
        const bool buy = side == OS::Buy;
        const PxE4 bid = eng.book().displayed_best(l, Side::Buy), ask = eng.book().displayed_best(l, Side::Sell);
        const SymbolInfo& y = eng.symbol(l);
        const PxE4 ref = (buy ? ask : bid) > 0 ? (buy ? ask : bid) : y.last_sale;
        const PxE4 rp = market ? (ref > 0 ? ref : y.prior_close) : lpx;
        const i128 notional = i128{q} * rp;
        const i128 sym_open = eng.risk().tracks_symbols(0) ? eng.risk().symbol_open(0, l) : i128{0};
        const std::uint64_t key = dup_content(l, side, q, ea.price, ea.tif, ea.display, ea.cross);
        const PxE4 thr = ref > 0 ? (buy ? lpx - ref : ref - lpx) : 0;
        // Evaluate in the documented order, stopping at the first failure (rates consume tokens only when reached).
        auto first = [&]() -> std::uint16_t {
          if (L.port > 0 && !port.take(L.port, now)) return C(RR::RiskPortMsgRateRestriction);
          if (L.symrate > 0 && !symb[{s, l}].take(L.symrate, now)) return C(RR::RiskSymbolMsgRateRestriction);
          if ((L.perms & kNoShortSell) && side == OS::SellShort) return C(RR::RiskShortSellNotAllowed);
          if ((L.perms & kNoShortExempt) && side == OS::SellShortExempt) return C(RR::RiskShortSellExemptNotAllowed);
          if ((L.perms & kNoMarketOrders) && market) return C(RR::RiskMarketOrderNotAllowed);
          if (L.restricted[l]) return C(RR::RiskRestrictedStock);
          if (L.htb[l] && (side == OS::SellShort || side == OS::SellShortExempt) && !located)
            return C(RR::RiskLocateRequired);
          if (L.max_qty > 0 && q > L.max_qty) return C(RR::RiskMaxQuantityExceeded);
          if (L.adv > 0 && y.adv > 0 && std::int64_t{q} * 100 > std::int64_t{y.adv} * L.adv)
            return C(RR::RiskExceedsAdvLimit);
          if (L.max_notional > 0 && notional > L.max_notional) return C(RR::RiskSingleOrderNotionalExceeded);
          if (!market) {
            if (ref > 0 && L.lop != 0 && thr > std::max<PxE4>(ref / 10, 5'000)) return C(RR::FatFinger);
            if (ref > 0 && L.ff_bps > 0 && i128{thr} * 10'000 > i128{ref} * L.ff_bps) return C(RR::RiskFatFinger);
            if (ref > 0 && L.ff_abs > 0 && thr > L.ff_abs) return C(RR::RiskFatFinger);
            if ((L.perms & kNoThroughBand) && l == 1 && (buy ? lpx > 1'050'000 : lpx < 950'000))
              return C(RR::RiskMarketImpact);
          }
          if (L.symnot > 0 && sym_open + notional > L.symnot) return C(RR::ExceedsMaxAllowedNotional);
          if (L.gross > 0 && eng.risk().open(0) + notional + eng.risk().executed(0) > L.gross)
            return C(RR::RiskAggregateExposureExceeded);
          if (L.dup > 0) {
            const std::int64_t sec = now / 1'000'000'000;
            for (std::int64_t x = sec - L.dup + 1; x <= sec; ++x) {
              const auto it = dup.find(x);
              if (it != dup.end() && std::find(it->second.begin(), it->second.end(), key) != it->second.end())
                return C(RR::RiskDuplicateMsgRateRestriction);
            }
            std::erase_if(dup, [&](const auto& e) { return e.first <= sec - 32; });
            auto& d = dup[sec];
            d.push_back(key);
            if (d.size() > 8) d.pop_front();
          }
          return 0;
        };
        want = first();
      }
      sink.out.clear();
      eng.apply(sc.ouch(s, s, enter_msg(ea, tags)), sink);
      ASSERT_FALSE(sink.out.empty());
      const char t = static_cast<char>(sink.out[0][0]);
      const std::uint16_t got =
          t == 'J' ? static_cast<std::uint16_t>((std::to_integer<unsigned>(sink.out[0][13]) << 8) |
                                                std::to_integer<unsigned>(sink.out[0][14]))
                   : 0;
      ASSERT_TRUE(t == 'A' || t == 'J') << t;
      if (mine) {
        ASSERT_EQ(got, want) << "seed " << seed << " op " << op;
        ++(got == 0 ? accepted : rejected);
        ++by_code[got];
      }
      std::string err;
      ASSERT_TRUE(eng.check(&err)) << err << " seed " << seed << " op " << op;
    }
  }
  EXPECT_GT(accepted, 10'000u);
  EXPECT_GT(rejected, 10'000u);
  for (const RR c : {RR::FatFinger, RR::RiskAggregateExposureExceeded, RR::RiskMarketImpact, RR::RiskRestrictedStock,
                     RR::RiskExceedsAdvLimit, RR::RiskFatFinger, RR::RiskLocateRequired, RR::RiskSymbolMsgRateRestriction,
                     RR::RiskPortMsgRateRestriction, RR::RiskDuplicateMsgRateRestriction, RR::RiskShortSellNotAllowed,
                     RR::RiskMarketOrderNotAllowed, RR::RiskShortSellExemptNotAllowed,
                     RR::RiskSingleOrderNotionalExceeded, RR::RiskMaxQuantityExceeded, RR::ExceedsMaxAllowedNotional})
    EXPECT_GT(by_code[C(c)], 0u) << std::hex << C(c);
}

}  // namespace
}  // namespace lle::engine
