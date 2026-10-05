#include "client/loadgen.h"

#include <hdr/hdr_histogram.h>

#include <algorithm>
#include <cmath>
#include <deque>
#include <limits>
#include <map>

#include "client/histogram.h"
#include "client/poisson.h"
#include "common/assert.h"
#include "common/endian.h"
#include "common/hash.h"
#include "common/int128.h"
#include "common/prng.h"

namespace lle::client::lg {

Symbol8 symbol_name(std::uint32_t index) {
  char b[5] = {'S', '0', '0', '0', '0'};
  std::uint32_t v = index + 1;
  for (int i = 4; i >= 1; --i) {
    b[i] = static_cast<char>('0' + v % 10);
    v /= 10;
  }
  return Symbol8(std::string_view(b, 5));
}

PxE4 symbol_mid(std::uint64_t seed, std::uint32_t index) {
  return static_cast<PxE4>(10 + mix64(seed ^ (0x4D49'4400'0000'0000ull + index)) % 190) * kPxScale;
}

namespace {

struct MOrder {
  std::uint32_t urn = 0, qty = 0, exec = 0, price = 0, live_pos = 0;
  std::uint16_t symbol = 0, session = 0;
  char side = 'B';
  bool alive = false;
};

struct SymBook {
  std::map<std::uint32_t, std::deque<std::uint32_t>, std::greater<>> bids;
  std::map<std::uint32_t, std::deque<std::uint32_t>> asks;
};

// The symbols schedule thread t of T trades: those whose session (symbol mod K) is t's.
std::vector<std::uint16_t> owned_symbols(const ScheduleConfig& c) {
  std::vector<std::uint16_t> v;
  for (std::uint32_t sym = 0; sym < c.symbols; ++sym)
    if (session_of_thread(sym % c.sessions, c.thread_index, c.threads)) v.push_back(static_cast<std::uint16_t>(sym));
  return v;
}

class Model {
 public:
  Model(const ScheduleConfig& c, Schedule& s)
      : c_(c), s_(s), books_(c.symbols), rng_(mix64(c.seed ^ 0x5348'4544'0000'0001ull ^ thread_salt(c))),
        owned_(owned_symbols(c)), dup_(c.sessions), acct_(c.shared_account ? 1 : c.sessions), sym_open_(c.symbols, 0),
        port_(c.sessions), symb_(c.symbols) {
    s_.urns_per_session.assign(c.sessions, 0);
    LLE_ASSERT(!owned_.empty(), "this schedule thread owns no symbol");
    if (c.dup_guard != 0)
      for (auto& d : dup_) d.assign(c.dup_guard, 0);
    if (c.risk.dup_window_sec > 0 && c.dup_guard < RiskDupSlots) ++s_.risk.dup_guard_short;
  }

  static constexpr std::uint32_t RiskDupSlots = 8;  // engine RiskGate::kDupSlots
  static std::uint64_t thread_salt(const ScheduleConfig& c) noexcept {
    return c.threads <= 1 ? 0 : mix64(0x5448'5245'4144'0000ull + c.thread_index);
  }

  void enter(Nanos t, bool warmup) {
    const std::uint16_t sym = owned_[rng_.below(owned_.size())];
    const char side = rng_.below(2) == 0 ? 'B' : 'S';
    const std::uint32_t px = price_for(sym, side);
    std::uint32_t qty = c_.lot * static_cast<std::uint32_t>(c_.lots_min + rng_.below(c_.lots_max - c_.lots_min + 1));
    const auto session = static_cast<std::uint16_t>(sym % c_.sessions);
    qty = unique_size(session, sym, side, px, qty, false, c_.lot);
    check_order(t, sym, session, qty, px, 0, i128{qty} * px);
    const std::uint32_t id = add_order(sym, side, px, qty);
    push(Item{t, orders_[id].urn, 0, qty, px, sym, orders_[id].session, Kind::Enter, side, warmup});
  }

  bool cancel(Nanos t) {
    if (live_.empty()) return false;
    const std::uint32_t id = live_[rng_.below(live_.size())];
    MOrder& o = orders_[id];
    push(Item{t, o.urn, 0, 0, o.price, o.symbol, o.session, Kind::Cancel, o.side, false});
    remove_from_level(id);
    release_open(o);
    kill(id);
    return true;
  }

  bool replace(Nanos t) {
    if (live_.empty()) return false;
    const std::uint32_t id = live_[rng_.below(live_.size())];
    const MOrder old = orders_[id];
    remove_from_level(id);
    const std::uint32_t px = price_for(old.symbol, old.side);
    const auto open = c_.lot * static_cast<std::uint32_t>(c_.lots_min + rng_.below(c_.lots_max - c_.lots_min + 1));
    check_order(t, old.symbol, old.session, old.exec + open, px, i128{old.qty} * old.price, i128{open} * px);
    release_open(orders_[id]);
    kill(id);
    const std::uint32_t nid = add_order(old.symbol, old.side, px, open);
    orders_[nid].exec = old.exec;  // the chain's executions (OUCH 5.0 §2.2: quantity is the chain total)
    push(Item{t, orders_[nid].urn, old.urn, old.exec + open, px, old.symbol, old.session, Kind::Replace, old.side, false});
    return true;
  }

  bool ioc(Nanos t) {
    if (live_.empty()) return false;
    // A random live order picks the symbol and the side to hit, so liquidity exists.
    const MOrder& seed_order = orders_[live_[rng_.below(live_.size())]];
    const std::uint16_t sym = seed_order.symbol;
    const char hit = seed_order.side;
    SymBook& b = books_[sym];
    std::deque<std::uint32_t>* level = nullptr;
    std::uint32_t px = 0;
    if (hit == 'B') {
      level = &b.bids.begin()->second;
      px = b.bids.begin()->first;
    } else {
      level = &b.asks.begin()->second;
      px = b.asks.begin()->first;
    }
    std::uint64_t total = 0;
    for (std::uint32_t id : *level) total += orders_[id].qty;
    const std::uint64_t draw = std::uint64_t{c_.ioc_unit} * (c_.ioc_min + rng_.below(c_.ioc_max - c_.ioc_min + 1));
    const std::uint16_t session = static_cast<std::uint16_t>(sym % c_.sessions);
    auto want = static_cast<std::uint32_t>(std::min<std::uint64_t>(total, draw));
    want = unique_size(session, sym, hit == 'B' ? 'S' : 'B', px, want, true, 0, static_cast<std::uint32_t>(total));
    check_order(t, sym, session, want, px, 0, i128{want} * px);
    // FIFO fills, as the engine's price-time priority will do.
    std::uint32_t left = want;
    while (left > 0) {
      const std::uint32_t id = level->front();
      MOrder& o = orders_[id];
      const std::uint32_t f = std::min(left, o.qty);
      o.qty -= f;
      o.exec += f;
      left -= f;
      on_fill(o, f);
      ++s_.stats.passive_fills;
      if (o.qty == 0) {
        level->pop_front();
        kill(id);
      }
    }
    if (level->empty()) {
      if (hit == 'B') b.bids.erase(px);
      else b.asks.erase(px);
    }
    const std::uint32_t urn = ++s_.urns_per_session[session];
    s_.stats.ioc_shares += want;
    push(Item{t, urn, 0, want, px, sym, session, Kind::Ioc, hit == 'B' ? 'S' : 'B', false});
    return true;
  }

  [[nodiscard]] std::size_t live() const noexcept { return live_.size(); }

 private:
  // ---- duplicate guard (Enter contents per session) ----
  static std::uint64_t content(std::uint16_t sym, char side, std::uint32_t px, std::uint32_t qty, bool ioc) noexcept {
    return mix64((std::uint64_t{sym} << 48) ^ (std::uint64_t{static_cast<unsigned char>(side)} << 40) ^
                 (std::uint64_t{px} << 1) ^ (std::uint64_t{qty} * 0x9E37'79B9'7F4A'7C15ull) ^ (ioc ? 1u : 0u));
  }
  // The size, changed by `step` (Enter) or by one share downwards (IOC, which must stay
  // within the level's `cap`) until the content is not among the session's last N.
  std::uint32_t unique_size(std::uint16_t session, std::uint16_t sym, char side, std::uint32_t px, std::uint32_t qty,
                            bool ioc, std::uint32_t step, std::uint32_t cap = 0) {
    if (c_.dup_guard == 0) return qty;
    auto& ring = dup_[session];
    auto seen = [&](std::uint64_t h) { return std::find(ring.begin(), ring.end(), h) != ring.end(); };
    std::uint32_t q = qty;
    std::uint64_t h = content(sym, side, px, q, ioc);
    for (std::uint32_t tries = 0; seen(h) && tries <= c_.dup_guard; ++tries) {
      if (ioc) {
        q = q > 1 ? q - 1 : std::min<std::uint32_t>(cap, qty + tries + 1);
      } else {
        const std::uint32_t lo = c_.lot * c_.lots_min, hi = c_.lot * c_.lots_max;
        q = q + step > hi ? lo : q + step;
      }
      h = content(sym, side, px, q, ioc);
      ++s_.dup_bumps;
    }
    if (seen(h)) {
      ++s_.risk.dup_unresolved;
      if (c_.risk.dup_window_sec > 0) ++s_.risk.dup_unresolved_rejects;
    }
    auto& at = dup_pos_[session];
    ring[at % ring.size()] = h;
    ++at;
    return q;
  }

  // ---- pre-trade risk budget (engine RiskGate rules on schedule time) ----
  struct Acct {
    i128 open = 0, executed = 0;
    bool killed = false;
  };
  struct Bucket {
    Nanos last = std::numeric_limits<Nanos>::min();
    std::int64_t level = 0;
  };
  Acct& acct(std::uint16_t session) noexcept { return acct_[c_.shared_account ? 0 : session]; }
  static bool take(Bucket& b, std::int64_t rate, Nanos now) noexcept {
    const std::int64_t cap = rate * kNsPerSec;
    std::int64_t level = cap;
    if (b.last != std::numeric_limits<Nanos>::min()) {
      const Nanos el = std::min<Nanos>(kNsPerSec, now > b.last ? now - b.last : 0);
      level = std::min(cap, b.level + el * rate);
    }
    b.last = now;
    if (level < kNsPerSec) {
      b.level = level;
      return false;
    }
    b.level = level - kNsPerSec;
    return true;
  }
  void check_order(Nanos t, std::uint16_t sym, std::uint16_t session, std::uint32_t qty, std::uint32_t px, i128 old_open,
                   i128 add) {
    RiskCheck& r = s_.risk;
    const RiskLimits& L = c_.risk;
    ++r.checked;
    if (L.port_rate > 0 && !take(port_[session], L.port_rate, t)) ++r.over_port_rate;
    if (L.symbol_rate > 0 && !take(symb_[sym], L.symbol_rate, t)) ++r.over_symbol_rate;
    if (L.max_qty > 0 && qty > L.max_qty) ++r.over_qty;
    if (L.max_notional > 0 && i128{qty} * px > L.max_notional) ++r.over_notional;
    const Acct& a = acct(session);
    const i128 sym_after = sym_open_[sym] - old_open + add;
    const i128 gross_after = a.open - old_open + add + a.executed;
    if (L.symbol_notional > 0 && sym_after > L.symbol_notional) ++r.over_symbol_notional;
    if (L.gross > 0 && gross_after > L.gross) ++r.over_gross;
    r.peak_symbol_notional = std::max(r.peak_symbol_notional, sym_after);
    r.peak_gross = std::max(r.peak_gross, gross_after);
  }
  void add_open(const MOrder& o) noexcept {
    const i128 v = i128{o.qty} * o.price;
    acct(o.session).open += v;
    sym_open_[o.symbol] += v;
  }
  void release_open(const MOrder& o) noexcept {
    const i128 v = i128{o.qty} * o.price;
    acct(o.session).open -= v;
    sym_open_[o.symbol] -= v;
  }
  // A passive fill of f shares on o: the aggressor (same symbol, so same session and
  // account) executes the same notional.
  void on_fill(const MOrder& o, std::uint32_t f) noexcept {
    const i128 v = i128{f} * o.price;
    Acct& a = acct(o.session);
    a.open -= v;
    sym_open_[o.symbol] -= v;
    a.executed += 2 * v;
    s_.risk.peak_executed = std::max(s_.risk.peak_executed, a.executed);
    if (c_.risk.kill_exposure > 0 && !a.killed && a.executed > c_.risk.kill_exposure) {
      a.killed = true;
      ++s_.risk.over_kill;
    }
  }

  std::uint32_t price_for(std::uint16_t sym, char side) {
    // Nearer ticks are more likely: k = 1 + floor(u1 * u2 / L) for u1, u2 in [0, L).
    const std::uint64_t L = c_.depth_ticks;
    const std::uint64_t k = 1 + rng_.below(L) * rng_.below(L) / L;
    const PxE4 mid = symbol_mid(c_.seed, sym);
    const PxE4 px = side == 'B' ? mid - static_cast<PxE4>(k) * c_.tick : mid + static_cast<PxE4>(k) * c_.tick;
    return static_cast<std::uint32_t>(px);
  }

  std::uint32_t add_order(std::uint16_t sym, char side, std::uint32_t px, std::uint32_t qty) {
    const auto id = static_cast<std::uint32_t>(orders_.size());
    MOrder o;
    o.session = static_cast<std::uint16_t>(sym % c_.sessions);
    o.urn = ++s_.urns_per_session[o.session];
    o.qty = qty;
    o.price = px;
    o.symbol = sym;
    o.side = side;
    o.alive = true;
    o.live_pos = static_cast<std::uint32_t>(live_.size());
    orders_.push_back(o);
    add_open(o);
    live_.push_back(id);
    if (side == 'B') books_[sym].bids[px].push_back(id);
    else books_[sym].asks[px].push_back(id);
    return id;
  }

  void remove_from_level(std::uint32_t id) {
    const MOrder& o = orders_[id];
    SymBook& b = books_[o.symbol];
    auto erase_in = [&](auto& side_map) {
      auto it = side_map.find(o.price);
      LLE_ASSERT(it != side_map.end());
      auto& q = it->second;
      q.erase(std::find(q.begin(), q.end(), id));
      if (q.empty()) side_map.erase(it);
    };
    if (o.side == 'B') erase_in(b.bids);
    else erase_in(b.asks);
  }

  void kill(std::uint32_t id) {
    MOrder& o = orders_[id];
    o.alive = false;
    const std::uint32_t pos = o.live_pos;
    const std::uint32_t last = live_.back();
    live_[pos] = last;
    orders_[last].live_pos = pos;
    live_.pop_back();
  }

  void push(const Item& it) {
    ++s_.stats.kinds[static_cast<std::size_t>(it.kind)];
    s_.items.push_back(it);
  }

  const ScheduleConfig& c_;
  Schedule& s_;
  std::vector<MOrder> orders_;
  std::vector<std::uint32_t> live_;
  std::vector<SymBook> books_;
  Prng rng_;
  std::vector<std::uint16_t> owned_;
  std::vector<std::vector<std::uint64_t>> dup_;
  std::vector<std::uint64_t> dup_pos_ = std::vector<std::uint64_t>(c_.sessions, 0);
  std::vector<Acct> acct_;
  std::vector<i128> sym_open_;
  std::vector<Bucket> port_, symb_;
};

}  // namespace

Schedule build_schedule(const ScheduleConfig& cfg) {
  LLE_ASSERT(cfg.sessions >= 1 && cfg.symbols >= 1 && cfg.symbols <= 9999 && cfg.rate >= 1);
  LLE_ASSERT(cfg.mix.enter_pct + cfg.mix.cancel_pct + cfg.mix.replace_pct + cfg.mix.ioc_pct == 100, "mix must sum to 100");
  LLE_ASSERT(cfg.threads >= 1 && cfg.thread_index < cfg.threads && cfg.threads <= cfg.sessions);
  LLE_ASSERT(!cfg.shared_account || cfg.threads == 1, "a shared account is checked by one schedule thread");
  LLE_ASSERT(cfg.lot >= 1 && cfg.lots_min >= 1 && cfg.lots_max >= cfg.lots_min && cfg.ioc_unit >= 1 && cfg.ioc_min >= 1 &&
             cfg.ioc_max >= cfg.ioc_min);
  Schedule s;
  s.cfg = cfg;
  // This thread's share: its symbols' fraction of the rate and of the prefill.
  const auto owned = static_cast<std::uint64_t>(owned_symbols(cfg).size());
  const std::uint64_t rate = std::max<std::uint64_t>(1, static_cast<std::uint64_t>(static_cast<u128>(cfg.rate) * owned / cfg.symbols));
  const std::uint64_t prefill_all = cfg.prefill != 0 ? cfg.prefill : std::uint64_t{cfg.symbols} * 8;
  const std::uint64_t prefill = cfg.threads <= 1 ? prefill_all : prefill_all * owned / cfg.symbols;
  const auto measured = static_cast<std::uint64_t>(static_cast<u128>(rate) * static_cast<std::uint64_t>(cfg.duration) /
                                                   static_cast<std::uint64_t>(kNsPerSec));
  s.items.reserve(prefill + measured);
  Model m(cfg, s);
  const std::uint64_t salt = Model::thread_salt(cfg);
  Arrivals arrivals(mix64(cfg.seed ^ 0x4152'5249'5645'0001ull ^ salt), rate, cfg.poisson);
  Prng kinds(mix64(cfg.seed ^ 0x4B49'4E44'0000'0001ull ^ salt));
  for (std::uint64_t i = 0; i < prefill + measured; ++i) {
    const Nanos t = arrivals.next();
    if (i < prefill) {
      m.enter(t, true);
      ++s.stats.prefill;
      continue;
    }
    const std::uint64_t r = kinds.below(100);
    bool ok = true;
    if (r < cfg.mix.enter_pct) {
      m.enter(t, false);
    } else if (r < cfg.mix.enter_pct + cfg.mix.cancel_pct) {
      ok = m.cancel(t);
    } else if (r < cfg.mix.enter_pct + cfg.mix.cancel_pct + cfg.mix.replace_pct) {
      ok = m.replace(t);
    } else {
      ok = m.ioc(t);
    }
    if (!ok) {
      ++s.stats.fallbacks;
      m.enter(t, false);
    }
  }
  s.stats.live_at_end = m.live();
  if (cfg.warmup > 0)
    for (Item& it : s.items)
      if (it.t < cfg.warmup) it.warmup = true;
  return s;
}

std::size_t encode_item(const Item& it, std::span<std::byte> out) {
  switch (it.kind) {
    case Kind::Enter:
    case Kind::Ioc: {
      ouch50::in::EnterOrder e;
      e.user_ref_num = it.urn;
      e.side = static_cast<ouch50::Side>(it.side);
      e.quantity = it.qty;
      e.symbol = symbol_name(it.symbol);
      e.price = it.price;
      e.time_in_force = it.kind == Kind::Ioc ? ouch50::TimeInForce::Ioc : ouch50::TimeInForce::Day;
      e.display = ouch50::Display::Visible;
      e.capacity = ouch50::Capacity::Agency;
      e.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
      e.cross_type = ouch50::CrossType::Continuous;
      return ouch50::encode(out, e);
    }
    case Kind::Cancel: {
      ouch50::in::CancelOrder c;
      c.user_ref_num = it.urn;
      c.quantity = 0;
      return ouch50::encode(out, c);
    }
    case Kind::Replace: {
      ouch50::in::ReplaceOrder r;
      r.orig_user_ref_num = it.orig;
      r.user_ref_num = it.urn;
      r.quantity = it.qty;
      r.price = it.price;
      r.time_in_force = ouch50::TimeInForce::Day;
      r.display = ouch50::Display::Visible;
      r.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
      return ouch50::encode(out, r);
    }
  }
  return 0;
}

// --- latency histograms ------------------------------------------------------------------
Latency::Latency() { hdr_init(1, 60 * kNsPerSec, 3, &h); }
Latency::~Latency() { hdr_close(h); }
void Latency::record(Nanos v) noexcept { hdr_record_value(h, v < 1 ? 1 : std::min<Nanos>(v, 60 * kNsPerSec)); }
std::int64_t Latency::percentile(double p) const noexcept { return hdr_value_at_percentile(h, p); }
std::int64_t Latency::max() const noexcept { return hdr_max(h); }
std::int64_t Latency::count() const noexcept { return h->total_count; }

// --- accounting -----------------------------------------------------------------------------
Accounting::Accounting(const Schedule& s) : s_(s), tracks_(s.cfg.sessions) {
  for (std::size_t i = 0; i < tracks_.size(); ++i) tracks_[i].resize(std::size_t{s.urns_per_session[i]} + 1);
}

void Accounting::on_sent(std::size_t i, Nanos t0, Nanos sent) noexcept {
  const Item& it = s_.items[i];
  const Nanos sched = t0 + it.t;
  ++st_.sent;
  ++sent_target_;
  if (!it.warmup) late_.record(sent - sched);
  Track& t = tracks_[it.session][it.urn];
  if (it.kind == Kind::Cancel) {
    t.cancel_sched = sched;
    t.cancel_item = static_cast<std::uint32_t>(i);
    t.cancel_awaiting = true;
    t.cancel_warmup = it.warmup;
    return;
  }
  t.sched = sched;
  t.item = static_cast<std::uint32_t>(i);
  t.kind = it.kind;
  t.awaiting = true;
  t.warmup = it.warmup;
  t.ioc_left = it.kind == Kind::Ioc ? it.qty : 0;
}

void Accounting::ack(std::uint32_t item, Nanos sched, bool warmup, Kind k, Nanos now) noexcept {
  last_acked_ = item;
  ++st_.acked;
  ++acked_;
  ++st_.acked_by_kind[static_cast<std::size_t>(k)];
  if (!warmup) {
    all_.record(now - sched);
    by_kind_[static_cast<std::size_t>(k)].record(now - sched);
    if (!intervals_.empty()) {
      const Nanos rel = sched - interval_t0_;
      std::size_t idx = rel <= 0 ? 0 : static_cast<std::size_t>(rel / kNsPerSec);
      if (idx >= intervals_.size()) idx = intervals_.size() - 1;
      intervals_[idx]->record(now - sched);
    }
  }
}

void Accounting::on_response(std::uint16_t s, std::span<const std::byte> m, Nanos now) noexcept {
  if (m.empty()) return;
  const char type = static_cast<char>(m[0]);
  if (type == 'S') {
    ++st_.system_events;
    return;
  }
  if (m.size() < 13 || s >= tracks_.size()) {
    unexpected(st_.other);
    return;
  }
  auto& tr = tracks_[s];
  const std::uint32_t u9 = load_be32(m.data() + 9);
  auto track = [&](std::uint32_t u) -> Track* { return u < tr.size() ? &tr[u] : nullptr; };
  switch (type) {
    case 'A': {
      Track* t = track(u9);
      if (t == nullptr || !t->awaiting || (t->kind != Kind::Enter && t->kind != Kind::Ioc)) {
        unexpected(t == nullptr ? st_.unknown_urn : st_.duplicate_ack);
        return;
      }
      t->awaiting = false;
      constexpr std::size_t kState = ouch50::layout::out::OrderAccepted::kOrderStateOff;
      const auto state = static_cast<char>(m.size() > kState ? m[kState] : std::byte{0});
      if (t->kind == Kind::Ioc && state == 'D') unexpected(st_.ioc_dead);
      if (t->kind == Kind::Enter && state != 'L') unexpected(st_.wrong_state);
      ack(t->item, t->sched, t->warmup, t->kind, now);
      return;
    }
    case 'U': {
      const std::uint32_t u13 = m.size() >= 17 ? load_be32(m.data() + 13) : 0;
      Track* t = track(u13);
      if (t == nullptr || !t->awaiting || t->kind != Kind::Replace) {
        unexpected(t == nullptr ? st_.unknown_urn : st_.duplicate_ack);
        return;
      }
      t->awaiting = false;
      ack(t->item, t->sched, t->warmup, Kind::Replace, now);
      return;
    }
    case 'C': {
      Track* t = track(u9);
      if (t != nullptr && t->cancel_awaiting) {
        t->cancel_awaiting = false;
        ack(t->cancel_item, t->cancel_sched, t->cancel_warmup, Kind::Cancel, now);
        return;
      }
      if (t != nullptr && t->kind == Kind::Ioc) {
        unexpected(st_.ioc_remainder);
        return;
      }
      unexpected(t == nullptr ? st_.unknown_urn : st_.other);
      return;
    }
    case 'E': {
      Track* t = track(u9);
      constexpr std::size_t kQty = ouch50::layout::out::OrderExecuted::kQuantityOff;
      const std::uint32_t q = m.size() >= kQty + 4 ? load_be32(m.data() + kQty) : 0;
      if (t == nullptr) {
        unexpected(st_.unknown_urn);
        return;
      }
      if (t->kind == Kind::Ioc) {
        ++st_.ioc_fills;
        st_.ioc_shares += q;
        t->ioc_left = t->ioc_left >= q ? t->ioc_left - q : 0;
      } else {
        ++st_.passive_fills;
        st_.passive_shares += q;
      }
      return;
    }
    case 'J': {
      constexpr std::size_t kReason = ouch50::layout::out::Rejected::kReasonOff;
      ++st_.reject_reasons_low[m.size() >= kReason + 2 ? std::to_integer<std::uint8_t>(m[kReason + 1]) : 0];
      Track* t = track(u9);
      if (t != nullptr && t->awaiting) {
        t->awaiting = false;  // answered, but not as expected
        ++missing_counted_;
      }
      unexpected(st_.rejected);
      return;
    }
    case 'I': {
      Track* t = track(u9);
      if (t != nullptr && t->cancel_awaiting) {
        t->cancel_awaiting = false;
        ++missing_counted_;
      }
      unexpected(st_.cancel_rejects);
      return;
    }
    default: unexpected(st_.other); return;
  }
}

void Accounting::finish() noexcept {
  for (auto& tr : tracks_) {
    for (Track& t : tr) {
      if (t.awaiting) ++st_.missing;
      if (t.cancel_awaiting) ++st_.missing;
      t.awaiting = t.cancel_awaiting = false;
    }
  }
}

}  // namespace lle::client::lg
