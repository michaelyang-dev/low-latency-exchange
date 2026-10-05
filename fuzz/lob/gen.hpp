#pragma once
// Structure-aware swarm generator for the book differential fuzzers
// (04-order-book §8 "Generators", R4b §5.2).
//
// Each seed draws its own feature mix ("swarm testing": some op kinds
// disabled, the rest at wildly different weights) and then emits a stream of
// ITCH-semantics book operations that are valid by construction: the
// generator tracks the live orders it created, so reduce/remove/replace name
// live refs and executions hit any queue position. Invalid operations (refs a
// real feed would never send, zero shares, bad prices or sides, duplicates,
// over-reduce) are a separate, per-seed optional weight; both books must
// reject them identically.
//
// Features: ITCH-like and U-storm mixes (U 7.4% / ~23%), executions at any
// queue position, halts with crossed and locked prices, stub and far prices
// ($0.0001..$0.01, $199,999.99, 2^32-1), more than 3,000 levels on a side,
// more than 10,000 orders at one level, refs dense / interleaved
// (non-monotonic) / sparse / above 2^32 and near 2^64, ref reuse after
// delete, sub-dollar books, duplicate stock-directory messages, adds on
// undeclared locates, and an end-of-day drain to an empty book.
//
// Deterministic: lle::Prng only; the unordered_map is used for lookup only.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/prng.h"
#include "common/types.h"

namespace lle::lobfuzz {

struct Op {
  enum class Kind : std::uint8_t { kDeclare, kAdd, kReduce, kRemove, kReplace };
  Kind kind = Kind::kDeclare;
  Side side = Side::Buy;
  Locate loc = 0;
  OrderRef ref = 0;
  OrderRef new_ref = 0;
  PxE4 px = 0;
  Qty qty = 0;
};

inline std::string to_string(const Op& op) {
  static constexpr const char* kNames[] = {"declare", "add", "reduce", "remove", "replace"};
  std::string s = kNames[static_cast<int>(op.kind)];
  s += " loc=" + std::to_string(op.loc);
  s += " side=";
  s += static_cast<char>(op.side);
  s += " ref=" + std::to_string(op.ref) + " new_ref=" + std::to_string(op.new_ref);
  s += " px=" + std::to_string(op.px) + " qty=" + std::to_string(op.qty);
  return s;
}

enum class RefMode : std::uint8_t { kDense, kInterleaved, kSparse, kHigh };

struct Swarm {
  // Operation weights (relative).
  std::uint32_t w_add = 0, w_exec = 0, w_cancel = 0, w_delete = 0, w_replace = 0;
  std::uint32_t w_declare = 0, w_invalid = 0;
  // Shape.
  std::uint32_t n_locates = 1;
  bool sparse_locates = false;
  bool auto_declare = false;  // some adds name locates never declared
  RefMode refs = RefMode::kDense;
  OrderRef ref_base = 0;
  std::uint32_t sparse_bits = 32;
  std::uint32_t live_target = 1000;
  bool deep_queue = false;  // most adds at one hot price: >10K orders at a level
  bool wide = false;        // offsets over 6,000 ticks: >3,000 levels per side
  bool stubs = false;       // stub and far prices
  bool halts = false;       // crossed/locked prices while halted
  bool storms = false;      // bursts of U
  bool sub_dollar = false;  // $0.0001 tick books
  bool odd_ticks = false;   // sub-penny prices above $1
  bool huge_qty = false;    // shares near 2^32
  bool drain = true;        // end-of-day drain to empty
  // Book-configuration hints (swarm over book parameters).
  std::uint64_t max_direct_ref = 1ull << 32;
  std::size_t reserve_orders = 1 << 16;
  std::size_t levels_per_side = 0;

  [[nodiscard]] std::string describe() const {
    static constexpr const char* kRef[] = {"dense", "interleaved", "sparse", "high"};
    std::string s = "w=" + std::to_string(w_add) + "/" + std::to_string(w_exec) + "/" + std::to_string(w_cancel) + "/" +
                    std::to_string(w_delete) + "/" + std::to_string(w_replace) + "/" + std::to_string(w_declare) + "/" +
                    std::to_string(w_invalid);
    s += " locates=" + std::to_string(n_locates) + (sparse_locates ? "s" : "");
    s += " refs=";
    s += kRef[static_cast<int>(refs)];
    s += " base=" + std::to_string(ref_base) + " live=" + std::to_string(live_target);
    if (deep_queue) s += " deep";
    if (wide) s += " wide";
    if (stubs) s += " stubs";
    if (halts) s += " halts";
    if (storms) s += " storms";
    if (sub_dollar) s += " subdollar";
    if (odd_ticks) s += " oddticks";
    if (huge_qty) s += " hugeqty";
    if (auto_declare) s += " autodecl";
    if (drain) s += " drain";
    s += " max_direct=" + std::to_string(max_direct_ref);
    return s;
  }
};

class Gen {
 public:
  explicit Gen(std::uint64_t seed) : rng_(seed ^ 0x6C6F'6266'757A'7A31ull), sym_idx_(65536, -1) {
    draw_swarm();
    init_symbols();
  }

  [[nodiscard]] const Swarm& swarm() const { return sw_; }
  [[nodiscard]] std::size_t live() const { return live_.size(); }

  // Next operation of the main phase. The first operations declare every
  // initial locate.
  Op next() {
    while (pending_declares_ < syms_.size()) {
      const Sym& s = syms_[pending_declares_++];
      if (!s.undeclared) return declare(s.loc);
    }
    tick_state();
    return pick_op();
  }

  // End-of-day drain (R1a Q6 pitfall 9): removes, executions and cancels
  // until no order is left. Returns false once the book is empty.
  bool next_drain(Op& op) {
    if (live_.empty()) return false;
    const std::size_t i = pick_live();
    const std::uint64_t r = rng_.below(100);
    if (r < 60) {
      op = make_remove(i);
    } else if (r < 85) {
      op = make_reduce(i, live_[i].qty);  // full execution
    } else {
      op = make_reduce(i, live_[i].qty > 1 ? static_cast<Qty>(rng_.range(1, live_[i].qty - 1)) : 1);
    }
    return true;
  }

 private:
  struct Live {
    OrderRef ref;
    PxE4 px;
    Qty qty;
    Locate loc;
    Side side;
  };
  struct Sym {
    Locate loc;
    PxE4 mid;
    PxE4 tick;
    PxE4 hot[2];  // deep-queue price per side
    bool halted = false;
    bool undeclared = false;
  };

  static constexpr PxE4 kMaxPx = 0xFFFF'FFFFll;

  // ---- swarm -------------------------------------------------------------------
  void draw_swarm() {
    const std::uint64_t preset = rng_.below(8);
    if (preset <= 1) {
      // 01302019 mix (A+F 44.7, D 43.0, U 7.4, E+C 2.2, X 1.3).
      sw_.w_add = 447, sw_.w_delete = 430, sw_.w_replace = 74, sw_.w_exec = 22, sw_.w_cancel = 13;
    } else if (preset == 2) {
      // 2025-style U storm share (~23%).
      sw_.w_add = 380, sw_.w_delete = 350, sw_.w_replace = 230, sw_.w_exec = 25, sw_.w_cancel = 15;
    } else {
      auto w = [&]() -> std::uint32_t { return rng_.chance(1, 4) ? 0 : static_cast<std::uint32_t>(rng_.range(1, 100)); };
      sw_.w_add = static_cast<std::uint32_t>(rng_.range(1, 100));
      sw_.w_exec = w(), sw_.w_cancel = w(), sw_.w_delete = w(), sw_.w_replace = w();
    }
    sw_.w_declare = rng_.chance(1, 2) ? static_cast<std::uint32_t>(rng_.range(1, 3)) : 0;
    sw_.w_invalid = rng_.chance(1, 3) ? static_cast<std::uint32_t>(rng_.range(1, 30)) : 0;

    static constexpr std::uint32_t kLive[] = {20, 200, 1000, 5000, 20000, 100000};
    sw_.live_target = kLive[rng_.below(rng_.chance(1, 8) ? 6 : 5)];
    static constexpr std::uint32_t kLocates[] = {1, 2, 3, 8, 40, 300};
    sw_.n_locates = kLocates[rng_.below(6)];
    sw_.sparse_locates = rng_.chance(1, 3);
    sw_.auto_declare = rng_.chance(1, 6);

    sw_.refs = static_cast<RefMode>(rng_.below(4));
    switch (sw_.refs) {
      case RefMode::kDense:
      case RefMode::kInterleaved: {
        static constexpr OrderRef kBase[] = {0, 1, 92, 8191, 1u << 20, 300'000'000};
        sw_.ref_base = kBase[rng_.below(6)];
        break;
      }
      case RefMode::kSparse: {
        static constexpr std::uint32_t kBits[] = {14, 20, 28, 33, 40, 64};
        sw_.sparse_bits = kBits[rng_.below(6)];
        break;
      }
      case RefMode::kHigh: {
        static constexpr OrderRef kBase[] = {(1ull << 32) - 4000, (1ull << 32), (1ull << 33) + 12345,
                                             (1ull << 63) - 5000, ~0ull - (1ull << 40)};
        sw_.ref_base = kBase[rng_.below(5)];
        break;
      }
    }

    sw_.deep_queue = rng_.chance(1, 10);
    sw_.wide = !sw_.deep_queue && rng_.chance(1, 10);
    if (sw_.deep_queue) {  // ~85% of each side's adds at one price: >10K orders there
      sw_.n_locates = 1;
      sw_.live_target = 26000 + static_cast<std::uint32_t>(rng_.below(10000));
    }
    if (sw_.wide) {  // ~7K+ orders per side over 6,000 ticks: >3,000 distinct levels
      sw_.n_locates = 1;
      sw_.live_target = 14000 + static_cast<std::uint32_t>(rng_.below(6000));
    }
    if (sw_.refs == RefMode::kSparse && sw_.sparse_bits < 20 && sw_.live_target > 4096) sw_.live_target = 4096;
    sw_.stubs = rng_.chance(1, 3);
    sw_.halts = rng_.chance(1, 3);
    sw_.storms = rng_.chance(1, 4);
    sw_.sub_dollar = rng_.chance(1, 5);
    sw_.odd_ticks = rng_.chance(1, 8);
    sw_.huge_qty = rng_.chance(1, 8);
    sw_.drain = !rng_.chance(1, 8);

    static constexpr std::uint64_t kDirect[] = {1ull << 13, 1ull << 16, 1ull << 20, 1ull << 24, 1ull << 30, 1ull << 32};
    sw_.max_direct_ref = kDirect[rng_.below(6)];
    static constexpr std::size_t kReserve[] = {1, 64, 4096, 1 << 16};
    sw_.reserve_orders = kReserve[rng_.below(4)];
    static constexpr std::size_t kPerSide[] = {0, 8, 128};
    sw_.levels_per_side = kPerSide[rng_.below(3)];
  }

  void init_symbols() {
    for (std::uint32_t i = 0; i < sw_.n_locates; ++i) {
      const Locate l = fresh_locate();
      sym_idx_[l] = static_cast<std::int32_t>(syms_.size());
      syms_.push_back(new_sym(l));
    }
    if (sw_.auto_declare) {
      for (std::size_t i = 1; i < syms_.size(); i += 3) syms_[i].undeclared = true;
    }
  }

  Locate fresh_locate() {
    for (;;) {
      Locate l;
      if (sw_.sparse_locates) {
        const std::uint64_t r = rng_.below(8);
        l = r == 0 ? 0 : (r == 1 ? 65535 : static_cast<Locate>(rng_.below(65536)));
      } else {
        l = static_cast<Locate>(syms_.size() + 1);
      }
      if (sym_idx_[l] < 0) return l;
    }
  }

  Sym new_sym(Locate loc) {
    Sym s{};
    s.loc = loc;
    if (sw_.sub_dollar && rng_.chance(1, 2)) {
      s.tick = 1;
      s.mid = rng_.range(50, 9'900);  // $0.0050 .. $0.99
    } else {
      s.tick = 100;
      const std::uint64_t r = rng_.below(10);
      const PxE4 dollars = r < 7 ? rng_.range(1, 500) : (r < 9 ? rng_.range(500, 5'000) : rng_.range(10'000, 150'000));
      s.mid = dollars * 10'000 + rng_.range(0, 99) * 100;
    }
    s.hot[0] = clamp_px(s.mid - s.tick * rng_.range(1, 4));
    s.hot[1] = clamp_px(s.mid + s.tick * rng_.range(1, 4));
    return s;
  }

  // ---- per-op state --------------------------------------------------------------
  void tick_state() {
    ++step_;
    if (sw_.storms) {
      if (storm_left_ > 0) {
        --storm_left_;
      } else if (rng_.chance(1, 5000)) {
        storm_left_ = static_cast<std::uint32_t>(rng_.range(200, 4000));
      }
    }
    if (sw_.halts && rng_.chance(1, 1500)) {
      Sym& s = syms_[rng_.below(syms_.size())];
      s.halted = !s.halted;
    }
  }

  Op pick_op() {
    std::uint64_t wa = sw_.w_add, we = sw_.w_exec, wc = sw_.w_cancel, wd = sw_.w_delete, wr = sw_.w_replace;
    const std::uint64_t wdecl = sw_.w_declare, winv = sw_.w_invalid;
    if (storm_left_ > 0) wr = (wa + wd + 1) * 2;
    const std::size_t n = live_.size();
    if (n >= sw_.live_target) {
      wa = wa / 8;
      if (wd + we + wc + wr == 0) wd = 1;
    } else {
      wa = wa * 2 + 1;  // climb to the target quickly, then hover around it
    }
    if (n == 0) we = wc = wd = wr = 0;
    if (wa + we + wc + wd + wr + wdecl + winv == 0) wa = 1;
    std::uint64_t r = rng_.below(wa + we + wc + wd + wr + wdecl + winv);
    if (r < wa) return make_add();
    r -= wa;
    if (r < we) {  // E/C: most executions fill the order (78% on 01302019)
      const std::size_t i = pick_live();
      const Qty q = live_[i].qty;
      return make_reduce(i, rng_.chance(78, 100) || q == 1 ? q : static_cast<Qty>(rng_.range(1, q - 1)));
    }
    r -= we;
    if (r < wc) {  // X: partial cancel
      const std::size_t i = pick_live();
      const Qty q = live_[i].qty;
      return make_reduce(i, q == 1 ? 1 : static_cast<Qty>(rng_.range(1, q - 1)));
    }
    r -= wc;
    if (r < wd) return make_remove(pick_live());
    r -= wd;
    if (r < wr) return make_replace(pick_live());
    r -= wr;
    if (r < wdecl) return declare(syms_[rng_.below(syms_.size())].loc);
    return make_invalid();
  }

  // ---- valid operations -------------------------------------------------------------
  Op declare(Locate loc) {
    Op op;
    op.kind = Op::Kind::kDeclare;
    op.loc = loc;
    sym_of(loc).undeclared = false;
    return op;
  }

  Op make_add() {
    Sym& s = syms_[rng_.below(syms_.size())];
    const Side side = rng_.chance(1, 2) ? Side::Buy : Side::Sell;
    Op op;
    op.kind = Op::Kind::kAdd;
    op.loc = s.loc;
    op.side = side;
    op.ref = fresh_ref();
    op.px = add_price(s, side);
    op.qty = draw_qty();
    track_add(op.ref, op.loc, side, op.px, op.qty);
    return op;
  }

  Op make_reduce(std::size_t i, Qty q) {
    Op op;
    op.kind = Op::Kind::kReduce;
    op.ref = live_[i].ref;
    op.qty = q;
    if (q >= live_[i].qty) {
      untrack(i);
    } else {
      live_[i].qty -= q;
    }
    return op;
  }

  Op make_remove(std::size_t i) {
    Op op;
    op.kind = Op::Kind::kRemove;
    op.ref = live_[i].ref;
    untrack(i);
    return op;
  }

  Op make_replace(std::size_t i) {
    const Live old = live_[i];
    Op op;
    op.kind = Op::Kind::kReplace;
    op.ref = old.ref;
    op.new_ref = rng_.chance(1, 500) ? old.ref : fresh_ref();  // new == old is legal: same as D + A
    Sym& s = sym_of(old.loc);
    const std::uint64_t r = rng_.below(100);
    if (r < 2) {
      op.px = old.px;  // MEAS: 1.6% of U keep the price
    } else if (r < 90 && !sw_.deep_queue) {
      const PxE4 step = s.tick * rng_.range(1, 5);
      op.px = clamp_px(rng_.chance(1, 2) ? old.px + step : old.px - step);
    } else {
      op.px = add_price(s, old.side);
    }
    op.qty = rng_.chance(98, 100) ? old.qty : draw_qty();
    untrack(i);
    track_add(op.new_ref, old.loc, old.side, op.px, op.qty);
    return op;
  }

  // ---- invalid operations (no state change, except over-reduce removes) ----------------
  Op make_invalid() {
    Op op;
    const std::uint64_t r = rng_.below(9);
    if (live_.empty() && r >= 4 && r != 8) return unknown_ref_op();
    switch (r) {
      case 0:
      case 1:
      case 2:
      case 3:
        return unknown_ref_op();
      case 4: {  // duplicate add of a live ref
        const Live& l = live_[pick_live()];
        op.kind = Op::Kind::kAdd;
        op.ref = l.ref;
        op.loc = l.loc;
        op.side = rng_.chance(1, 2) ? Side::Buy : Side::Sell;
        op.px = l.px;
        op.qty = draw_qty();
        return op;
      }
      case 5: {  // replace onto another live ref
        const Live& a = live_[pick_live()];
        const Live& b = live_[pick_live()];
        op.kind = Op::Kind::kReplace;
        op.ref = a.ref;
        op.new_ref = b.ref;
        op.px = a.px;
        op.qty = a.qty;
        if (a.ref == b.ref) op.qty = 0;  // keep it invalid: zero shares
        return op;
      }
      case 6: {  // over-reduce: removes the order, reported as such
        const std::size_t i = pick_live();
        const Qty q = live_[i].qty;
        const Qty over = q > std::numeric_limits<Qty>::max() - 100 ? std::numeric_limits<Qty>::max()
                                                                  : q + static_cast<Qty>(rng_.range(1, 100));
        if (over == q) return make_reduce(i, q);
        return make_reduce(i, over);
      }
      case 7: {  // zero shares or a bad price on a live order
        const Live& l = live_[pick_live()];
        op.kind = rng_.chance(1, 2) ? Op::Kind::kReduce : Op::Kind::kReplace;
        op.ref = l.ref;
        op.new_ref = fresh_unused_ref();
        op.px = l.px;
        op.qty = 0;
        if (op.kind == Op::Kind::kReplace && rng_.chance(1, 2)) {
          op.qty = l.qty;
          op.px = bad_price();
        }
        return op;
      }
      default: {  // malformed add: zero shares, bad price, or bad side
        Sym& s = syms_[rng_.below(syms_.size())];
        op.kind = Op::Kind::kAdd;
        op.loc = s.loc;
        op.ref = fresh_unused_ref();
        op.side = Side::Buy;
        op.px = s.mid;
        op.qty = draw_qty();
        const std::uint64_t k = rng_.below(3);
        if (k == 0) op.qty = 0;
        if (k == 1) op.px = bad_price();
        if (k == 2) op.side = static_cast<Side>('X');
        return op;
      }
    }
  }

  Op unknown_ref_op() {
    Op op;
    const std::uint64_t k = rng_.below(3);
    op.kind = k == 0 ? Op::Kind::kReduce : (k == 1 ? Op::Kind::kRemove : Op::Kind::kReplace);
    op.ref = fresh_unused_ref();
    op.new_ref = fresh_unused_ref();
    op.qty = draw_qty();
    op.px = syms_[0].mid;
    return op;
  }

  PxE4 bad_price() {
    static constexpr PxE4 kBad[] = {-1, kMaxPx + 1, std::numeric_limits<PxE4>::max(), std::numeric_limits<PxE4>::min()};
    return kBad[rng_.below(4)];
  }

  // ---- prices and quantities ---------------------------------------------------------
  PxE4 add_price(Sym& s, Side side) {
    if (rng_.chance(1, 50)) {  // the touch drifts
      s.mid = clamp_px(s.mid + (rng_.chance(1, 2) ? s.tick : -s.tick));
      if (s.mid < 4 * s.tick) s.mid = 4 * s.tick;
    }
    if (sw_.stubs && rng_.chance(1, 40)) {
      static constexpr PxE4 kStub[] = {1, 100, 1'999'999'900, 2'000'000'000, kMaxPx, 0};
      const std::uint64_t r = rng_.below(8);
      return r < 6 ? kStub[r] : rng_.range(1, kMaxPx);
    }
    const int si = side == Side::Buy ? 0 : 1;
    if (sw_.deep_queue && rng_.chance(85, 100)) return s.hot[si];
    PxE4 off;
    if (sw_.wide) {
      off = rng_.range(0, 6'000);
    } else {
      off = 0;
      while (off < 60 && rng_.chance(1, 2)) ++off;  // ~half at the touch, geometric tail
      if (rng_.chance(1, 30)) off += rng_.range(16, 400);
    }
    const PxE4 half = 1 + static_cast<PxE4>(rng_.below(2));
    if (s.halted && rng_.chance(1, 2)) off = -half - static_cast<PxE4>(rng_.below(6));  // crossed / locked
    PxE4 px = side == Side::Buy ? s.mid - (half + off) * s.tick : s.mid + (half + off) * s.tick;
    if (sw_.odd_ticks && s.tick == 100 && rng_.chance(1, 20)) px += rng_.range(1, 99);
    return clamp_px(px);
  }

  static PxE4 clamp_px(PxE4 px) { return px < 0 ? 0 : (px > kMaxPx ? kMaxPx : px); }

  Qty draw_qty() {
    const std::uint64_t r = rng_.below(100);
    if (r < 50) return static_cast<Qty>(100 * rng_.range(1, 10));
    if (r < 80) return static_cast<Qty>(rng_.range(1, 99));
    if (r < 95) return static_cast<Qty>(rng_.range(100, 5'000));
    if (r < 99) return rng_.chance(1, 2) ? 999'999 : static_cast<Qty>(rng_.range(1, 999'999));
    if (sw_.huge_qty) return std::numeric_limits<Qty>::max() - static_cast<Qty>(rng_.below(10));
    return 1;
  }

  // ---- refs -----------------------------------------------------------------------
  OrderRef fresh_ref() {
    switch (sw_.refs) {
      case RefMode::kDense:
      case RefMode::kHigh: {
        const OrderRef r = sw_.ref_base + counter_;
        counter_ += rng_.chance(3, 4) ? 4 : 1 + rng_.below(3);  // MEAS: delta 4 dominates
        return r;
      }
      case RefMode::kInterleaved: {
        // Disjoint ranges consumed in random order: globally non-monotonic
        // (79% of adds on 01302019), unique by construction.
        const std::uint64_t lane = rng_.below(3);
        const OrderRef r = sw_.ref_base + lane * (1ull << 26) + lanes_[lane];
        lanes_[lane] += 1 + rng_.below(4);
        return r;
      }
      case RefMode::kSparse:
        break;
    }
    for (int tries = 0; tries < 64; ++tries) {  // sparse: a dead ref may be reused, a live one may not
      const OrderRef r = sw_.sparse_bits >= 64 ? rng_.next_u64() : rng_.below(1ull << sw_.sparse_bits);
      if (pos_.find(r) == pos_.end()) return r;
    }
    // The sparse range is (nearly) full of live refs: continue densely above it.
    for (;;) {
      const OrderRef r = (sw_.sparse_bits >= 64 ? 0 : (1ull << sw_.sparse_bits)) + overflow_++;
      if (pos_.find(r) == pos_.end()) return r;
    }
  }

  OrderRef fresh_unused_ref() {
    for (;;) {
      const std::uint64_t k = rng_.below(4);
      const OrderRef r = k == 0 ? rng_.next_u64() : (k == 1 ? (1ull << 32) + rng_.below(1 << 16) : rng_.below(1 << 16));
      if (pos_.find(r) == pos_.end()) return r;
    }
  }

  // ---- live-order tracking --------------------------------------------------------
  void track_add(OrderRef ref, Locate loc, Side side, PxE4 px, Qty qty) {
    pos_[ref] = live_.size();
    live_.push_back(Live{ref, px, qty, loc, side});
  }

  void untrack(std::size_t i) {
    pos_.erase(live_[i].ref);
    if (i + 1 != live_.size()) {
      live_[i] = live_.back();
      pos_[live_[i].ref] = i;
    }
    live_.pop_back();
  }

  std::size_t pick_live() { return static_cast<std::size_t>(rng_.below(live_.size())); }

  Sym& sym_of(Locate loc) { return syms_[static_cast<std::size_t>(sym_idx_[loc])]; }

  Prng rng_;
  Swarm sw_;
  std::vector<Sym> syms_;
  std::vector<std::int32_t> sym_idx_;  // locate -> index in syms_, -1 if none
  std::vector<Live> live_;
  std::unordered_map<OrderRef, std::size_t> pos_;
  std::size_t pending_declares_ = 0;
  std::uint64_t step_ = 0;
  std::uint64_t counter_ = 0;
  std::uint64_t lanes_[3] = {0, 0, 0};
  std::uint64_t overflow_ = 0;
  std::uint32_t storm_left_ = 0;
};

}  // namespace lle::lobfuzz
