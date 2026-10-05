#include "engine/cross.h"

#include <algorithm>

namespace lle::engine {

std::uint64_t cross_volume(std::uint64_t rb, std::uint64_t rs, std::uint64_t ib, std::uint64_t is) noexcept {
  if (rb >= rs) return rs + std::min(is, rb - rs);
  return rb + std::min(ib, rs - rb);
}

CrossResult evaluate(const CrossTotals& t, PxE4 p, CrossKind kind) noexcept {
  CrossResult r;
  r.valid = true;
  r.price = p;
  r.volume = cross_volume(t.rb, t.rs, t.ib, t.is);
  const bool buy_excess = t.rb > r.volume;
  const bool sell_excess = t.rs > r.volume;
  if (kind == CrossKind::Halt) {
    r.imbalance = t.rb >= t.rs ? t.rb - t.rs : t.rs - t.rb;
    r.side = t.rb > t.rs ? 'B' : (t.rs > t.rb ? 'S' : 'N');
  } else {
    // Cross orders execute first on their side: only the excess side leaves any unmatched.
    const std::uint64_t ub = buy_excess && t.xb > r.volume ? t.xb - r.volume : 0;
    const std::uint64_t us = sell_excess && t.xs > r.volume ? t.xs - r.volume : 0;
    r.imbalance = ub + us;
    r.side = ub > 0 ? 'B' : (us > 0 ? 'S' : 'N');
  }
  r.market_unexecuted = t.mb > r.volume || t.ms > r.volume;
  return r;
}

bool better_candidate(const CrossResult& a, bool ca, const CrossResult& b, bool cb, PxE4 ref) noexcept {
  if (a.volume != b.volume) return a.volume > b.volume;            // A
  if (a.imbalance != b.imbalance) return a.imbalance < b.imbalance;  // B
  if (ca != cb) return ca;                                         // C
  if (ref > 0) {                                                   // D
    const PxE4 da = a.price >= ref ? a.price - ref : ref - a.price;
    const PxE4 db = b.price >= ref ? b.price - ref : ref - b.price;
    if (da != db) return da < db;
  }
  return a.price < b.price;  // final: the lower price
}

CrossResult CrossCalculator::compute(std::span<const CrossInterest> interest, const CrossParams& params) {
  pts_.clear();
  market_ = CrossTotals{};
  for (const CrossInterest& c : interest) {
    if (c.qty == 0) continue;
    if (c.market) {
      if (c.buy) {
        market_.rb += c.qty;
        market_.mb += c.qty;
        if (c.cross_order) market_.xb += c.qty;
      } else {
        market_.rs += c.qty;
        market_.ms += c.qty;
        if (c.cross_order) market_.xs += c.qty;
      }
      continue;
    }
    Point p{c.px, 0, 0, 0, 0, 0, 0, false, false};
    if (c.imbalance_only) {
      (c.buy ? p.buy_io : p.sell_io) = c.qty;
    } else {
      (c.buy ? p.buy_reg : p.sell_reg) = c.qty;
      (c.buy ? p.limit_b : p.limit_s) = true;
      if (c.cross_order) (c.buy ? p.buy_x : p.sell_x) = c.qty;
    }
    pts_.push_back(p);
  }
  std::sort(pts_.begin(), pts_.end(), [](const Point& a, const Point& b) { return a.px < b.px; });
  // Merge equal prices.
  std::size_t w = 0;
  for (std::size_t i = 0; i < pts_.size(); ++i) {
    if (w > 0 && pts_[w - 1].px == pts_[i].px) {
      Point& d = pts_[w - 1];
      d.buy_reg += pts_[i].buy_reg;
      d.sell_reg += pts_[i].sell_reg;
      d.buy_io += pts_[i].buy_io;
      d.sell_io += pts_[i].sell_io;
      d.buy_x += pts_[i].buy_x;
      d.sell_x += pts_[i].sell_x;
      d.limit_b = d.limit_b || pts_[i].limit_b;
      d.limit_s = d.limit_s || pts_[i].limit_s;
    } else {
      pts_[w++] = pts_[i];
    }
  }
  pts_.resize(w);
  cands_.clear();
  for (const Point& p : pts_) cands_.push_back(p.px);
  if (params.ref > 0) cands_.push_back(params.ref);
  if (params.hi > 0) {
    cands_.push_back(params.lo);
    cands_.push_back(params.hi);
  }
  std::sort(cands_.begin(), cands_.end());
  cands_.erase(std::unique(cands_.begin(), cands_.end()), cands_.end());
  if (params.hard && params.hi > 0) return best_of(params, true);
  CrossResult r = best_of(params, false);
  if (r.valid && params.hi > 0 && (r.price < params.lo || r.price > params.hi)) r = best_of(params, true);
  return r;
}

CrossResult CrossCalculator::best_of(const CrossParams& params, bool inside_only) {
  // Sweep candidates ascending: sells at or below p accumulate; buys at or above p are
  // the suffix, so start from the total and remove points as they fall below p.
  std::uint64_t buy_reg = 0, buy_io = 0, buy_x = 0;
  for (const Point& p : pts_) {
    buy_reg += p.buy_reg;
    buy_io += p.buy_io;
    buy_x += p.buy_x;
  }
  std::uint64_t sell_reg = 0, sell_io = 0, sell_x = 0;
  std::size_t below = 0;  // points with px < candidate (removed from the buy suffix)
  std::size_t upto = 0;   // points with px <= candidate (added to the sell prefix)
  CrossResult best;
  bool best_c = false;
  for (const PxE4 c : cands_) {
    while (below < pts_.size() && pts_[below].px < c) {
      buy_reg -= pts_[below].buy_reg;
      buy_io -= pts_[below].buy_io;
      buy_x -= pts_[below].buy_x;
      ++below;
    }
    while (upto < pts_.size() && pts_[upto].px <= c) {
      sell_reg += pts_[upto].sell_reg;
      sell_io += pts_[upto].sell_io;
      sell_x += pts_[upto].sell_x;
      ++upto;
    }
    if (inside_only && (c < params.lo || c > params.hi)) continue;
    CrossTotals t = market_;
    t.rb += buy_reg;
    t.rs += sell_reg;
    t.ib += buy_io;
    t.is += sell_io;
    t.xb += buy_x;
    t.xs += sell_x;
    const bool at = below < pts_.size() && pts_[below].px == c;
    t.limit_b = at && pts_[below].limit_b;
    t.limit_s = at && pts_[below].limit_s;
    const CrossResult r = evaluate(t, c, params.kind);
    const bool cr = (t.rb > r.volume && t.limit_b) || (t.rs > r.volume && t.limit_s);
    if (!best.valid || better_candidate(r, cr, best, best_c, params.ref)) {
      best = r;
      best_c = cr;
    }
  }
  return best;
}

}  // namespace lle::engine
