#include "engine/risk/risk_gate.h"

#include <algorithm>

#include "common/hash.h"

namespace lle::engine {

namespace {
using RR = ouch50::RejectReason;
constexpr std::uint16_t code(RR r) noexcept { return static_cast<std::uint16_t>(r); }
constexpr std::int64_t kNano = 1'000'000'000;
constexpr std::uint32_t kKnownPerms = kNoPreMarket | kNoPostMarket | kNoShortSell | kNoShortExempt |
                                      kNoMarketOrders | kNoIpoMarketBuy | kNoThroughBand;
bool is_short(Marking m) noexcept { return m == Marking::SellShort || m == Marking::SellShortExempt; }
}  // namespace

std::uint64_t dup_content(Locate l, Marking m, Qty q, std::uint64_t price, Tif tif, Display d, CrossType c) noexcept {
  Fnv1a64 h;
  h.u(l);
  h.u(static_cast<std::uint8_t>(m));
  h.u(q);
  h.u(price);
  h.u(static_cast<std::uint8_t>(tif));
  h.u(static_cast<std::uint8_t>(d));
  h.u(static_cast<std::uint8_t>(c));
  return h.value();
}

void RiskGate::configure(std::uint32_t accounts, std::span<const std::uint32_t> session_account,
                         std::uint32_t symbols) {
  limits_.assign(accounts, Limits{});
  accts_.assign(accounts, AcctState{});
  session_account_.assign(session_account.begin(), session_account.end());
  rules_.clear();
  has_rules_.assign(accounts, 0);
  port_.assign(session_account.size(), Bucket{});
  sym_bucket_slot_.assign(session_account.size(), kNone);
  sym_buckets_.clear();
  sym_open_slot_.assign(accounts, kNone);
  sym_open_.clear();
  dup_slot_.assign(accounts, kNone);
  dups_.clear();
  pending_.clear();
  pending_.reserve(accounts);
  stride_ = std::size_t{symbols} + 1;
  rebuild_ = kNone;
}

const RiskGate::SymbolRule* RiskGate::rule(std::uint32_t account, Locate l) const noexcept {
  if (has_rules_[account] == 0) return nullptr;
  const auto it = std::lower_bound(rules_.begin(), rules_.end(), std::pair{account, l},
                                   [](const SymbolRule& r, const std::pair<std::uint32_t, Locate>& k) {
                                     return r.account != k.first ? r.account < k.first : r.locate < k.second;
                                   });
  return it != rules_.end() && it->account == account && it->locate == l ? &*it : nullptr;
}

RiskGate::SymbolRule& RiskGate::rule_mut(std::uint32_t account, Locate l) {
  const auto it = std::lower_bound(rules_.begin(), rules_.end(), std::pair{account, l},
                                   [](const SymbolRule& r, const std::pair<std::uint32_t, Locate>& k) {
                                     return r.account != k.first ? r.account < k.first : r.locate < k.second;
                                   });
  if (it != rules_.end() && it->account == account && it->locate == l) return *it;
  has_rules_[account] = 1;
  SymbolRule r;
  r.account = account;
  r.locate = l;
  return *rules_.insert(it, r);
}

void RiskGate::ensure_sym_open(std::uint32_t account) {
  if (sym_open_slot_[account] != kNone) return;
  sym_open_slot_[account] = static_cast<std::uint32_t>(sym_open_.size() / stride_);
  sym_open_.resize(sym_open_.size() + stride_, 0);
  rebuild_ = account;
}

void RiskGate::ensure_sym_buckets(std::uint32_t account) {
  for (std::size_t s = 0; s < session_account_.size(); ++s) {
    if (session_account_[s] != account || sym_bucket_slot_[s] != kNone) continue;
    sym_bucket_slot_[s] = static_cast<std::uint32_t>(sym_buckets_.size() / stride_);
    sym_buckets_.resize(sym_buckets_.size() + stride_, Bucket{});
  }
}

void RiskGate::ensure_dup(std::uint32_t account) {
  if (dup_slot_[account] != kNone) return;
  dup_slot_[account] = static_cast<std::uint32_t>(dups_.size());
  DupFilter f;
  f.account = account;
  dups_.push_back(f);
}

bool RiskGate::set(std::uint32_t account, RiskKind kind, std::int64_t value, Locate l) {
  if (account >= limits_.size() || value < 0 || l >= stride_) return false;
  const bool per_symbol =
      kind == RiskKind::Restricted || kind == RiskKind::HardToBorrow || kind == RiskKind::SymbolNotional;
  if (l != 0 && !per_symbol) return false;
  Limits& lim = limits_[account];
  switch (kind) {
    case RiskKind::Permissions:
      if ((static_cast<std::uint64_t>(value) & ~std::uint64_t{kKnownPerms}) != 0) return false;
      lim.perms = static_cast<std::uint32_t>(value);
      return true;
    case RiskKind::MaxOrderQty: lim.max_qty = value; return true;
    case RiskKind::MaxOrderNotional: lim.max_notional = value; return true;
    case RiskKind::FatFingerBps: lim.ff_bps = value; return true;
    case RiskKind::FatFingerAbs: lim.ff_abs = value; return true;
    case RiskKind::Lop:
      if (value > 1) return false;
      lim.lop = value;
      return true;
    case RiskKind::DupWindowSec:
      if (value > kMaxDupWindow) return false;
      lim.dup_window = value;
      ensure_dup(account);
      return true;
    case RiskKind::PortRate:
      if (value > kMaxRate) return false;
      lim.port_rate = value;
      return true;
    case RiskKind::SymbolRate:
      if (value > kMaxRate) return false;
      lim.symbol_rate = value;
      ensure_sym_buckets(account);
      return true;
    case RiskKind::GrossExposure: lim.gross = value; return true;
    case RiskKind::SymbolNotional:
      ensure_sym_open(account);
      if (l == 0) {
        lim.symbol_notional = value;
      } else {
        rule_mut(account, l).notional = value;
      }
      return true;
    case RiskKind::AdvPct: lim.adv_pct = value; return true;
    case RiskKind::Restricted:
    case RiskKind::HardToBorrow:
      if (l == 0 || value > 1) return false;
      (kind == RiskKind::Restricted ? rule_mut(account, l).restricted : rule_mut(account, l).hard_to_borrow) =
          value == 1;
      return true;
    case RiskKind::KillExposure: lim.kill_exposure = value; return true;
  }
  return false;
}

bool RiskGate::take(Bucket& b, std::int64_t rate, std::int64_t now) noexcept {
  const std::int64_t cap = rate * kNano;
  std::int64_t level = cap;
  if (b.last != kNever) {
    std::int64_t el = 0;  // elapsed ns, at most a second (a full second refills the whole bucket)
    if (now > b.last) {
      const std::uint64_t d = static_cast<std::uint64_t>(now) - static_cast<std::uint64_t>(b.last);
      el = d > static_cast<std::uint64_t>(kNano) ? kNano : static_cast<std::int64_t>(d);
    }
    level = std::min(cap, b.level + el * rate);
  }
  b.last = now;
  if (level < kNano) {
    b.level = level;
    return false;
  }
  b.level = level - kNano;
  return true;
}

RiskGate::Bucket& RiskGate::sym_bucket(std::uint32_t session, Locate l) {
  if (sym_bucket_slot_[session] == kNone) {
    sym_bucket_slot_[session] = static_cast<std::uint32_t>(sym_buckets_.size() / stride_);
    sym_buckets_.resize(sym_buckets_.size() + stride_, Bucket{});
  }
  return sym_buckets_[std::size_t{sym_bucket_slot_[session]} * stride_ + l];
}

bool RiskGate::dup_hit(const DupFilter& f, std::uint64_t key, std::int64_t sec, std::int64_t window) const noexcept {
  for (std::int64_t s = sec - window + 1; s <= sec; ++s) {
    if (s < 0) continue;
    const DupBucket& b = f.b[static_cast<std::size_t>(s) % kDupBuckets];
    if (b.sec != s) continue;
    const std::uint32_t k = b.n < kDupSlots ? b.n : static_cast<std::uint32_t>(kDupSlots);
    for (std::uint32_t j = 0; j < k; ++j)
      if (b.h[j] == key) return true;
  }
  return false;
}

void RiskGate::dup_insert(DupFilter& f, std::uint64_t key, std::int64_t sec) noexcept {
  DupBucket& b = f.b[static_cast<std::size_t>(sec) % kDupBuckets];
  if (b.sec != sec) {
    b.sec = sec;
    b.n = 0;
  }
  b.h[b.n % kDupSlots] = key;
  ++b.n;
  f.last = sec;
}

std::uint16_t RiskGate::check(const RiskRequest& r, const RiskQuote& q, std::int64_t now, PxE4* risk_px) {
  const Limits& L = limits_[r.account];
  const AcctState& st = accts_[r.account];
  // 1-2. Message rates on record time.
  if (L.port_rate > 0 && !take(port_[r.session], L.port_rate, now)) return code(RR::RiskPortMsgRateRestriction);
  if (L.symbol_rate > 0 && !take(sym_bucket(r.session, r.locate), L.symbol_rate, now))
    return code(RR::RiskSymbolMsgRateRestriction);
  // 3. Permissions.
  const std::uint32_t p = L.perms;
  const bool buy = r.marking == Marking::Buy;
  if ((p & kNoPreMarket) != 0 && q.session == Session::PreMarket) return code(RR::RiskPreMarketNotAllowed);
  if ((p & kNoPostMarket) != 0 && q.session == Session::PostMarket) return code(RR::RiskPostMarketNotAllowed);
  if ((p & kNoShortSell) != 0 && r.marking == Marking::SellShort) return code(RR::RiskShortSellNotAllowed);
  if ((p & kNoShortExempt) != 0 && r.marking == Marking::SellShortExempt)
    return code(RR::RiskShortSellExemptNotAllowed);
  if ((p & kNoMarketOrders) != 0 && r.market) return code(RR::RiskMarketOrderNotAllowed);
  if ((p & kNoIpoMarketBuy) != 0 && r.market && buy && q.ipo) return code(RR::RiskIpoMarketBuyNotAllowed);
  // 4-5. Symbol lists.
  const SymbolRule* sr = rule(r.account, r.locate);
  if (sr != nullptr && sr->restricted) return code(RR::RiskRestrictedStock);
  if (sr != nullptr && sr->hard_to_borrow && is_short(r.marking) && !r.located) return code(RR::RiskLocateRequired);
  // 6-7. Size.
  if (L.max_qty > 0 && r.qty > L.max_qty) return code(RR::RiskMaxQuantityExceeded);
  if (L.adv_pct > 0 && q.adv > 0 && i128{r.qty} * 100 > i128{q.adv} * L.adv_pct) return code(RR::RiskExceedsAdvLimit);
  // Price-protection reference: the NBO for a buy (NBB for a sell), else the
  // last sale. Market orders are valued at it, else at the prior close.
  const PxE4 near = buy ? q.ask : q.bid;
  const PxE4 ref = near > 0 ? near : q.last;
  const PxE4 rp = r.market ? (ref > 0 ? ref : q.prior) : r.px;
  *risk_px = rp;
  // 8. Order notional.
  if (L.max_notional > 0 && i128{r.qty} * rp > L.max_notional) return code(RR::RiskSingleOrderNotionalExceeded);
  // 9-11. Price protection for continuous limit orders of a trading symbol.
  if (!r.market && !r.cross && !q.halted) {
    if (ref > 0) {
      const PxE4 through = buy ? r.px - ref : ref - r.px;
      if (L.lop != 0 && through > std::max<PxE4>(ref / 10, 5'000)) return code(RR::FatFinger);
      if (L.ff_bps > 0 && i128{through} * 10'000 > i128{ref} * L.ff_bps) return code(RR::RiskFatFinger);
      if (L.ff_abs > 0 && through > L.ff_abs) return code(RR::RiskFatFinger);
    }
    if ((p & kNoThroughBand) != 0 && q.luld_hi > 0 && (buy ? r.px > q.luld_hi : r.px < q.luld_lo))
      return code(RR::RiskMarketImpact);
  }
  // 12-13. Exposure.
  const i128 add = i128{r.open} * rp;
  const std::int64_t sym_lim = sr != nullptr && sr->notional >= 0 ? sr->notional : L.symbol_notional;
  if (sym_lim > 0 && symbol_open(r.account, r.locate) - r.old_open + add > sym_lim)
    return code(RR::ExceedsMaxAllowedNotional);
  if (L.gross > 0 && st.open - r.old_open + add + st.executed > L.gross) return code(RR::RiskAggregateExposureExceeded);
  // 14. Duplicates (Enter Orders), by record second.
  if (!r.replace && dup_slot_[r.account] != kNone) {
    DupFilter& f = dups_[dup_slot_[r.account]];
    const std::int64_t sec = now / kNano;
    if (L.dup_window > 0 && dup_hit(f, r.content, sec, L.dup_window)) return code(RR::RiskDuplicateMsgRateRestriction);
    if (L.dup_window > 0) dup_insert(f, r.content, sec);
  }
  return 0;
}

void RiskGate::on_execution(std::uint32_t account, Qty q, PxE4 px) noexcept {
  AcctState& s = accts_[account];
  s.executed += i128{q} * px;
  const std::int64_t k = limits_[account].kill_exposure;
  if (k > 0 && !s.killed && !s.pending && s.executed > k) {
    s.pending = true;
    pending_.push_back(account);
  }
}

void RiskGate::take_pending(std::vector<std::uint32_t>& out) {
  out.clear();
  std::sort(pending_.begin(), pending_.end());
  for (std::uint32_t a : pending_) {
    accts_[a].pending = false;
    out.push_back(a);
  }
  pending_.clear();
}

bool RiskGate::restore(ByteReader& rd) {
  auto i128r = [&] {
    const std::uint64_t lo = rd.u64();
    const std::uint64_t hi = rd.u64();
    return static_cast<i128>((static_cast<u128>(hi) << 64) | lo);
  };
  const std::uint32_t na = rd.u32();
  if (rd.fail() || na != limits_.size()) return false;
  for (std::uint32_t a = 0; a < na; ++a) {
    Limits& l = limits_[a];
    l.perms = rd.u32();
    for (std::int64_t* x : {&l.max_qty, &l.max_notional, &l.ff_bps, &l.ff_abs, &l.lop, &l.dup_window, &l.port_rate,
                            &l.symbol_rate, &l.gross, &l.symbol_notional, &l.adv_pct, &l.kill_exposure})
      *x = static_cast<std::int64_t>(rd.u64());
    accts_[a].open = i128r();
    accts_[a].executed = i128r();
    accts_[a].killed = rd.u8() != 0;
    if (accts_[a].open < 0 || accts_[a].executed < 0) return false;
    if (rd.u8() != 0) ensure_sym_open(a);
    if (l.symbol_rate > 0) ensure_sym_buckets(a);
    if ((l.perms & ~kKnownPerms) != 0 || l.lop < 0 || l.lop > 1 || l.dup_window < 0 || l.dup_window > kMaxDupWindow ||
        l.port_rate < 0 || l.port_rate > kMaxRate || l.symbol_rate < 0 || l.symbol_rate > kMaxRate)
      return false;
  }
  rebuild_ = kNone;
  const std::uint32_t nr = rd.u32();
  if (rd.fail() || nr > rd.remaining() / 16) return false;
  for (std::uint32_t i = 0; i < nr; ++i) {
    SymbolRule r;
    r.account = rd.u32();
    r.locate = rd.u16();
    r.restricted = rd.u8() != 0;
    r.hard_to_borrow = rd.u8() != 0;
    r.notional = static_cast<std::int64_t>(rd.u64());
    if (rd.fail() || r.account >= na || r.locate == 0 || r.locate >= stride_) return false;
    if (!rules_.empty() && !(rules_.back().account < r.account ||
                             (rules_.back().account == r.account && rules_.back().locate < r.locate)))
      return false;
    has_rules_[r.account] = 1;
    rules_.push_back(r);
  }
  const std::uint32_t ns = rd.u32();
  if (rd.fail() || ns != port_.size()) return false;
  for (Bucket& b : port_) {
    b.level = static_cast<std::int64_t>(rd.u64());
    b.last = static_cast<std::int64_t>(rd.u64());
    if (b.level < 0 || b.level > kMaxRate * kNano) return false;  // never above the largest capacity
  }
  const std::uint32_t nb = rd.u32();
  if (rd.fail() || nb > rd.remaining() / 22) return false;
  for (std::uint32_t i = 0; i < nb; ++i) {
    const std::uint32_t s = rd.u32();
    const Locate l = rd.u16();
    if (rd.fail() || s >= port_.size() || l == 0 || l >= stride_) return false;
    Bucket& b = sym_bucket(s, l);
    b.level = static_cast<std::int64_t>(rd.u64());
    b.last = static_cast<std::int64_t>(rd.u64());
    if (b.last == kNever || b.level < 0 || b.level > kMaxRate * kNano) return false;
  }
  const std::uint32_t nf = rd.u32();
  if (rd.fail() || nf > na) return false;
  std::uint32_t prev = 0;
  for (std::uint32_t i = 0; i < nf; ++i) {
    const std::uint32_t a = rd.u32();
    if (rd.fail() || a >= na || (i > 0 && a <= prev)) return false;
    prev = a;
    ensure_dup(a);
    DupFilter& f = dups_[dup_slot_[a]];
    f.last = static_cast<std::int64_t>(rd.u64());
    const std::uint32_t n = rd.u32();
    if (rd.fail() || n > kDupBuckets) return false;
    for (std::uint32_t j = 0; j < n; ++j) {
      const auto sec = static_cast<std::int64_t>(rd.u64());
      const std::uint32_t k = rd.u32();
      if (rd.fail() || sec < 0 || sec > f.last || sec <= f.last - static_cast<std::int64_t>(kDupBuckets) || k == 0 ||
          k > kDupSlots)
        return false;
      DupBucket& b = f.b[static_cast<std::size_t>(sec) % kDupBuckets];
      if (b.n != 0) return false;
      b.sec = sec;
      for (std::uint32_t x = 0; x < k; ++x) b.h[x] = rd.u64();
      b.n = k;
    }
  }
  return !rd.fail();
}

}  // namespace lle::engine
