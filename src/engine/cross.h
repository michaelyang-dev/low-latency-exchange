#pragma once
// Cross price determination (05-matching-engine §5, E-08; R2 D2.3).
//
// CrossCalculator::compute(interest, params) applies the shared NASDAQ
// algorithm to a set of buy and sell interest:
//   A  maximize the executable shares V(p);
//   B  minimize the unmatched cross-order shares (open/close) or the
//      imbalance |buy - sell| (halt);
//   C  prefer an entered price at which shares remain unexecuted;
//   D  minimize the distance to the reference price;
//   then the lower price (a documented final tie-break);
//   E  a soft window (the open/close threshold): when the winner lies outside
//      it, the choice is repeated among the candidates inside it. A hard
//      window (the Current Reference Price, limited to the BBO) restricts the
//      candidates from the start. Halt collars are checked by the caller.
// Candidates: every distinct limit price of the interest, the reference price
// (when non-zero) and the window bounds (when set), filtered by a hard window.
//
// V(p): R_B and R_S are the regular buy and sell shares eligible at p (market,
// or limit >= p for buys and <= p for sells); imbalance-only (OIO/IO) shares
// I_B and I_S only offset the regular imbalance:
//   V = R_S + min(I_S, R_B - R_S) when R_B >= R_S, else R_B + min(I_B, R_S - R_B).
// Cross orders (MOO/LOO/MOC/LOC) execute first on their side, so the
// unmatched cross-order shares are max(0, X - V) on the side with excess.
//
// cross_bruteforce.h computes the same result independently (O(P*N)); the
// two must agree exactly (tests/unit/engine/cross_test.cpp, fuzz harness).
#include <cstdint>
#include <span>
#include <vector>

#include "common/types.h"

namespace lle::engine {

enum class CrossKind : std::uint8_t { Open = 'O', Close = 'C', Halt = 'H' };

struct CrossInterest {
  PxE4 px = 0;  // limit (effective, after IO repricing); ignored for market interest
  Qty qty = 0;
  bool buy = true;
  bool market = false;
  bool cross_order = false;     // MOO/LOO/MOC/LOC: counted in the cross-order imbalance
  bool imbalance_only = false;  // OIO/IO: only offsets the regular imbalance
};

struct CrossParams {
  CrossKind kind = CrossKind::Open;
  PxE4 ref = 0;  // step D reference; 0 = none
  PxE4 lo = 0;   // window [lo, hi]; hi == 0 means no window
  PxE4 hi = 0;
  bool hard = false;  // hard window: candidates restricted from the start
};

struct CrossResult {
  bool valid = false;  // a candidate price exists
  PxE4 price = 0;
  std::uint64_t volume = 0;     // paired shares V(price)
  std::uint64_t imbalance = 0;  // B's measure at price
  char side = 'N';              // side with unexecuted shares: 'B', 'S' or 'N'
  bool market_unexecuted = false;  // some market interest does not execute at price
  friend bool operator==(const CrossResult&, const CrossResult&) = default;
};

// Aggregates at one price (shared by the calculator and the brute force).
struct CrossTotals {
  std::uint64_t rb = 0, rs = 0;  // regular interest eligible at p
  std::uint64_t ib = 0, is = 0;  // imbalance-only interest eligible at p
  std::uint64_t xb = 0, xs = 0;  // cross-order interest eligible at p
  std::uint64_t mb = 0, ms = 0;  // market interest
  bool limit_b = false;          // a regular buy limit order priced exactly at p
  bool limit_s = false;
};

[[nodiscard]] CrossResult evaluate(const CrossTotals& t, PxE4 p, CrossKind kind) noexcept;

// True if candidate a beats candidate b by steps A-D and the final tie-break.
[[nodiscard]] bool better_candidate(const CrossResult& a, bool ca, const CrossResult& b, bool cb, PxE4 ref) noexcept;

class CrossCalculator {
 public:
  // `scratch` buffers are reused across calls (no allocation once they have grown).
  [[nodiscard]] CrossResult compute(std::span<const CrossInterest> interest, const CrossParams& params);
  // Pre-sizes the scratch buffers for `n` interest entries (no allocation below that).
  void reserve(std::size_t n) {
    pts_.reserve(n);
    cands_.reserve(n + 3);
  }

 private:
  struct Point {
    PxE4 px;
    std::uint64_t buy_reg, sell_reg, buy_io, sell_io, buy_x, sell_x;
    bool limit_b, limit_s;
  };
  CrossResult best_of(const CrossParams& params, bool inside_only);
  std::vector<Point> pts_;
  std::vector<PxE4> cands_;
  CrossTotals market_{};
};

// The executable shares at price `p` for this interest (helper for allocation).
[[nodiscard]] std::uint64_t cross_volume(std::uint64_t rb, std::uint64_t rs, std::uint64_t ib, std::uint64_t is) noexcept;

}  // namespace lle::engine
