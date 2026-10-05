#pragma once
// Brute-force cross price determination (05-matching-engine §5, E-08): for
// every candidate price, scan every order and re-derive the totals, then pick
// the winner with steps A-D and the threshold rule of step E. O(P * N),
// written independently of src/engine/cross.cpp (shares only the I/O structs);
// the two must agree exactly on every input (cross_diff, cross_test).
#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

#include "engine/cross.h"

namespace lle::engine::ref {

struct BruteCandidate {
  CrossResult r;
  bool entered_remaining = false;  // step C
};

inline BruteCandidate brute_eval(std::span<const CrossInterest> v, PxE4 p, CrossKind kind) {
  std::uint64_t rb = 0, rs = 0, ib = 0, is = 0, xb = 0, xs = 0, mb = 0, ms = 0;
  bool lb = false, ls = false;
  for (const CrossInterest& o : v) {
    if (o.qty == 0) continue;
    const bool eligible = o.market || (o.buy ? o.px >= p : o.px <= p);
    if (!eligible) continue;
    if (o.imbalance_only) {
      (o.buy ? ib : is) += o.qty;
      continue;
    }
    (o.buy ? rb : rs) += o.qty;
    if (o.cross_order) (o.buy ? xb : xs) += o.qty;
    if (o.market) (o.buy ? mb : ms) += o.qty;
    if (!o.market && o.px == p) (o.buy ? lb : ls) = true;
  }
  BruteCandidate c;
  c.r.valid = true;
  c.r.price = p;
  std::uint64_t vol;
  if (rb >= rs) {
    vol = rs + std::min(is, rb - rs);
  } else {
    vol = rb + std::min(ib, rs - rb);
  }
  c.r.volume = vol;
  if (kind == CrossKind::Halt) {
    c.r.imbalance = rb > rs ? rb - rs : rs - rb;
    c.r.side = rb > rs ? 'B' : (rs > rb ? 'S' : 'N');
  } else {
    std::uint64_t ub = 0, us = 0;
    if (rb > vol && xb > vol) ub = xb - vol;
    if (rs > vol && xs > vol) us = xs - vol;
    c.r.imbalance = ub + us;
    c.r.side = ub != 0 ? 'B' : (us != 0 ? 'S' : 'N');
  }
  c.r.market_unexecuted = mb > vol || ms > vol;
  c.entered_remaining = (rb > vol && lb) || (rs > vol && ls);
  return c;
}

// a beats b?
inline bool brute_better(const BruteCandidate& a, const BruteCandidate& b, PxE4 ref) {
  if (a.r.volume > b.r.volume) return true;
  if (a.r.volume < b.r.volume) return false;
  if (a.r.imbalance < b.r.imbalance) return true;
  if (a.r.imbalance > b.r.imbalance) return false;
  if (a.entered_remaining && !b.entered_remaining) return true;
  if (!a.entered_remaining && b.entered_remaining) return false;
  if (ref > 0) {
    const PxE4 da = a.r.price > ref ? a.r.price - ref : ref - a.r.price;
    const PxE4 db = b.r.price > ref ? b.r.price - ref : ref - b.r.price;
    if (da < db) return true;
    if (da > db) return false;
  }
  return a.r.price < b.r.price;
}

inline CrossResult brute_cross(std::span<const CrossInterest> v, const CrossParams& prm) {
  std::vector<PxE4> cands;
  for (const CrossInterest& o : v)
    if (o.qty != 0 && !o.market) cands.push_back(o.px);
  if (prm.ref > 0) cands.push_back(prm.ref);
  const bool window = prm.hi > 0;
  if (window) {
    cands.push_back(prm.lo);
    cands.push_back(prm.hi);
  }
  std::sort(cands.begin(), cands.end());
  cands.erase(std::unique(cands.begin(), cands.end()), cands.end());
  auto pick = [&](bool inside) {
    BruteCandidate best;
    bool have = false;
    for (const PxE4 p : cands) {
      if (inside && (p < prm.lo || p > prm.hi)) continue;
      const BruteCandidate c = brute_eval(v, p, prm.kind);
      if (!have || brute_better(c, best, prm.ref)) {
        best = c;
        have = true;
      }
    }
    return have ? best.r : CrossResult{};
  };
  if (window && prm.hard) return pick(true);
  CrossResult r = pick(false);
  if (r.valid && window && (r.price < prm.lo || r.price > prm.hi)) r = pick(true);
  return r;
}

}  // namespace lle::engine::ref
