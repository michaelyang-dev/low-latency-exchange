// itch_synth: seeded synthetic TotalView-ITCH 5.0 day in BinaryFILE framing
// (M2 "synthetic ITCH"). CI uses it to drive lob_replay, itch_validate and the
// book harnesses end to end without NASDAQ data. Synthetic days are never used
// for T11/T12 headlines (04-order-book §1).
//
//   itch_synth --out FILE [--messages N] [--symbols K] [--live L] [--seed S] [--drain]
//
// The stream is semantically valid: system events O, S, Q (09:30), M, E, C in
// order; one R and one H(T) per locate before any order; adds (A, F) at
// prices around a per-symbol random walk; D, U, X, E and C only on live
// orders, with E/C/X never exceeding the open shares; P (non-displayed trades)
// with order reference 0; strictly unique, increasing order references and
// match numbers; non-decreasing timestamps. The add rate leans towards adds
// below L live orders and away above it, so the book hovers near L.
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/alpha.h"
#include "common/endian.h"
#include "common/prng.h"
#include "proto/itch50/itch50.h"

namespace {

using namespace lle;

struct Args {
  std::string out;
  std::uint64_t messages = 1'000'000;
  unsigned symbols = 500;
  std::uint64_t live = 100'000;
  std::uint64_t seed = 1;
  bool drain = false;
};

struct Live {
  OrderRef ref;
  Locate loc;
  Side side;
  PxE4 px;
  Qty qty;
};

class Writer {
 public:
  explicit Writer(std::FILE* f) : f_(f) { buf_.reserve(kCap + 64); }
  ~Writer() { flush(); }
  template <class M>
  void put(const M& m) {
    std::byte tmp[2 + itch50::kMaxMsgLen];
    store_be16(tmp, static_cast<std::uint16_t>(M::kLen));
    itch50::encode_unchecked(tmp + 2, m);
    buf_.insert(buf_.end(), tmp, tmp + 2 + M::kLen);
    ++count_;
    if (buf_.size() >= kCap) flush();
  }
  void flush() {
    if (!buf_.empty() && std::fwrite(buf_.data(), 1, buf_.size(), f_) != buf_.size()) ok_ = false;
    buf_.clear();
  }
  [[nodiscard]] std::uint64_t count() const noexcept { return count_; }
  [[nodiscard]] bool ok() const noexcept { return ok_; }

 private:
  static constexpr std::size_t kCap = std::size_t{1} << 20;
  std::FILE* f_;
  std::vector<std::byte> buf_;
  std::uint64_t count_ = 0;
  bool ok_ = true;
};

Symbol8 symbol_for(Locate loc) {
  char s[9];
  std::snprintf(s, sizeof s, "SYN%04u", static_cast<unsigned>(loc));
  return Symbol8(s);
}

class Synth {
 public:
  Synth(const Args& a, Writer& w) : a_(a), w_(w), rng_(a.seed), mid_(a.symbols + 1u, 0) {}

  void run() {
    constexpr Nanos kOpen = 9 * 3600 * kNsPerSec + 30 * 60 * kNsPerSec;
    constexpr Nanos kClose = 16 * 3600 * kNsPerSec;
    system_event(3 * 3600 * kNsPerSec, itch50::EventCode::StartOfMessages);
    for (Locate loc = 1; loc <= a_.symbols; ++loc) directory(3 * 3600 * kNsPerSec + loc, loc);
    system_event(4 * 3600 * kNsPerSec, itch50::EventCode::StartOfSystemHours);
    for (Locate loc = 1; loc <= a_.symbols; ++loc) trading_action(4 * 3600 * kNsPerSec + loc, loc);
    system_event(kOpen, itch50::EventCode::StartOfMarketHours);

    const std::uint64_t fixed = w_.count() + 3;
    const std::uint64_t body = a_.messages > fixed ? a_.messages - fixed : 0;
    const Nanos step = body == 0 ? 1 : std::max<Nanos>(1, (kClose - kOpen - kNsPerSec) / static_cast<Nanos>(body));
    now_ = kOpen;
    for (std::uint64_t i = 0; i < body; ++i) {
      now_ += static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(2 * step) + 1));
      if (now_ >= kClose - kNsPerSec) now_ = kClose - kNsPerSec;
      one();
    }
    if (a_.drain) {
      while (!live_.empty()) remove_at(live_.size() - 1);
    }
    system_event(kClose, itch50::EventCode::EndOfMarketHours);
    system_event(20 * 3600 * kNsPerSec, itch50::EventCode::EndOfSystemHours);
    system_event(20 * 3600 * kNsPerSec + 5 * 60 * kNsPerSec, itch50::EventCode::EndOfMessages);
  }

 private:
  template <class M>
  void header(M& m, Locate loc, Nanos t) {
    m.stock_locate = loc;
    m.tracking_number = 0;
    m.timestamp = static_cast<std::uint64_t>(t);
  }

  void system_event(Nanos t, itch50::EventCode c) {
    itch50::SystemEvent m{};
    header(m, 0, t);
    m.event_code = c;
    w_.put(m);
  }

  void directory(Nanos t, Locate loc) {
    itch50::StockDirectory m{};
    header(m, loc, t);
    m.stock = symbol_for(loc);
    m.market_category = itch50::MarketCategory::NasdaqGlobalSelect;
    m.financial_status = itch50::FinancialStatus::Normal;
    m.round_lot_size = 100;
    m.round_lots_only = itch50::YesNo::No;
    m.issue_classification = itch50::IssueClassification::CommonStock;
    m.issue_sub_type = Alpha<2>("Z");
    m.authenticity = itch50::Authenticity::Test;
    m.short_sale_threshold = itch50::YesNoBlank::No;
    m.ipo_flag = itch50::IpoFlag::NotNewIpo;
    m.luld_tier = itch50::LuldTier::Tier2;
    m.etp_flag = itch50::YesNoBlank::No;
    m.etp_leverage_factor = 0;
    m.inverse_indicator = itch50::YesNo::No;
    w_.put(m);
    // $5 .. $500 mid, on the $0.01 grid.
    mid_[loc] = static_cast<PxE4>(500 + rng_.below(49'500)) * 100;
  }

  void trading_action(Nanos t, Locate loc) {
    itch50::StockTradingAction m{};
    header(m, loc, t);
    m.stock = symbol_for(loc);
    m.trading_state = itch50::TradingState::Trading;
    m.reserved = ' ';
    m.reason = Alpha<4>("");
    w_.put(m);
  }

  Locate pick_locate() {
    // Skewed: a few symbols carry most of the flow, as on a real day.
    const std::uint64_t u = rng_.below(a_.symbols);
    const std::uint64_t v = rng_.below(a_.symbols);
    return static_cast<Locate>(1 + std::min(u, v));
  }

  PxE4 price_for(Locate loc, Side s) {
    if (rng_.chance(1, 50)) mid_[loc] = std::max<PxE4>(200, mid_[loc] + (rng_.chance(1, 2) ? 100 : -100));
    const PxE4 away = static_cast<PxE4>(rng_.below(20)) * 100;
    return s == Side::Buy ? std::max<PxE4>(100, mid_[loc] - 100 - away) : mid_[loc] + 100 + away;
  }

  void add() {
    const Locate loc = pick_locate();
    const Side s = rng_.chance(1, 2) ? Side::Buy : Side::Sell;
    const PxE4 px = price_for(loc, s);
    const Qty q = static_cast<Qty>(rng_.chance(4, 5) ? 100 * (1 + rng_.below(5)) : 1 + rng_.below(2'000));
    const OrderRef ref = next_ref_++;
    if (rng_.chance(1, 40)) {
      itch50::AddOrderMpid m{};
      header(m, loc, now_);
      m.order_ref = ref;
      m.side = s;
      m.shares = q;
      m.stock = symbol_for(loc);
      m.price = px;
      m.attribution = Mpid4("SYNT");
      w_.put(m);
    } else {
      itch50::AddOrder m{};
      header(m, loc, now_);
      m.order_ref = ref;
      m.side = s;
      m.shares = q;
      m.stock = symbol_for(loc);
      m.price = px;
      w_.put(m);
    }
    live_.push_back({ref, loc, s, px, q});
  }

  void remove_at(std::size_t i) {
    itch50::OrderDelete m{};
    header(m, live_[i].loc, now_);
    m.order_ref = live_[i].ref;
    w_.put(m);
    erase(i);
  }

  void erase(std::size_t i) {
    live_[i] = live_.back();
    live_.pop_back();
  }

  void replace_at(std::size_t i) {
    Live& o = live_[i];
    itch50::OrderReplace m{};
    header(m, o.loc, now_);
    m.original_order_ref = o.ref;
    m.new_order_ref = next_ref_++;
    m.shares = static_cast<Qty>(100 * (1 + rng_.below(5)));
    m.price = price_for(o.loc, o.side);
    w_.put(m);
    o.ref = m.new_order_ref;
    o.qty = m.shares;
    o.px = m.price;
  }

  void reduce_at(std::size_t i, char kind) {
    Live& o = live_[i];
    const Qty q = static_cast<Qty>(1 + rng_.below(o.qty));
    if (kind == 'X') {
      itch50::OrderCancel m{};
      header(m, o.loc, now_);
      m.order_ref = o.ref;
      m.cancelled_shares = q;
      w_.put(m);
    } else if (kind == 'E') {
      itch50::OrderExecuted m{};
      header(m, o.loc, now_);
      m.order_ref = o.ref;
      m.executed_shares = q;
      m.match_number = next_match_++;
      w_.put(m);
    } else {
      itch50::OrderExecutedWithPrice m{};
      header(m, o.loc, now_);
      m.order_ref = o.ref;
      m.executed_shares = q;
      m.match_number = next_match_++;
      m.printable = rng_.chance(1, 2) ? itch50::YesNo::Yes : itch50::YesNo::No;
      m.execution_price = o.px;
      w_.put(m);
    }
    o.qty -= q;
    if (o.qty == 0) erase(i);
  }

  void trade() {
    const Locate loc = pick_locate();
    itch50::Trade m{};
    header(m, loc, now_);
    m.order_ref = 0;
    m.side = Side::Buy;
    m.shares = static_cast<Qty>(100 * (1 + rng_.below(3)));
    m.stock = symbol_for(loc);
    m.price = mid_[loc];
    m.match_number = next_match_++;
    w_.put(m);
  }

  void one() {
    // Weights per 1,000, leaning towards adds when the book is below target.
    const unsigned add_w = live_.size() < a_.live ? 520 : 400;
    const std::uint64_t r = rng_.below(1000);
    if (live_.empty() || r < add_w) return add();
    const std::size_t i = static_cast<std::size_t>(rng_.below(live_.size()));
    const std::uint64_t x = r - add_w;
    const std::uint64_t rest = 1000 - add_w;  // split: D 72%, U 15%, X 5%, E 6%, C 0.5%, P 1.5%
    if (x < rest * 720 / 1000) return remove_at(i);
    if (x < rest * 870 / 1000) return replace_at(i);
    if (x < rest * 920 / 1000) return reduce_at(i, 'X');
    if (x < rest * 980 / 1000) return reduce_at(i, 'E');
    if (x < rest * 985 / 1000) return reduce_at(i, 'C');
    return trade();
  }

  const Args& a_;
  Writer& w_;
  Prng rng_;
  std::vector<PxE4> mid_;
  std::vector<Live> live_;
  Nanos now_ = 0;
  OrderRef next_ref_ = 1;
  MatchNo next_match_ = 1;
};

[[noreturn]] void usage(const char* msg) {
  if (msg) std::fprintf(stderr, "itch_synth: %s\n", msg);
  std::fprintf(stderr,
               "usage: itch_synth --out FILE [--messages N] [--symbols K (1..65535)] [--live L] [--seed S] [--drain]\n");
  std::exit(2);
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    const std::string_view k = argv[i];
    auto val = [&]() -> const char* {
      if (i + 1 >= argc) usage("missing value");
      return argv[++i];
    };
    if (k == "--out") a.out = val();
    else if (k == "--messages") a.messages = std::strtoull(val(), nullptr, 0);
    else if (k == "--symbols") a.symbols = static_cast<unsigned>(std::strtoul(val(), nullptr, 0));
    else if (k == "--live") a.live = std::strtoull(val(), nullptr, 0);
    else if (k == "--seed") a.seed = std::strtoull(val(), nullptr, 0);
    else if (k == "--drain") a.drain = true;
    else usage("unknown option");
  }
  if (a.out.empty()) usage("--out is required");
  if (a.symbols == 0 || a.symbols > 65'535) usage("--symbols must be 1..65535");
  std::FILE* f = std::fopen(a.out.c_str(), "wb");
  if (f == nullptr) {
    std::perror(a.out.c_str());
    return 1;
  }
  std::uint64_t written = 0;
  bool ok = true;
  {
    Writer w(f);
    Synth s(a, w);
    s.run();
    w.flush();
    written = w.count();
    ok = w.ok();
  }
  if (std::fclose(f) != 0 || !ok) {
    std::fprintf(stderr, "itch_synth: write failed\n");
    return 1;
  }
  std::fprintf(stderr, "itch_synth: %" PRIu64 " messages -> %s\n", written, a.out.c_str());
  return 0;
}
