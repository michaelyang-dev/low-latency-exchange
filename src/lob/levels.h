#pragma once
// Level containers: the price levels of one book side (04-order-book §3).
//
// Every container keeps levels ordered by a goodness order `Better` over keys
// (Higher for bids; Lower for asks, or Higher on negated ask prices, X11) and
// hands out Level pointers that stay valid until that level is erased, so an
// order can point straight at its level. Interface (Level, Better, Pool):
//
//   Level* find_or_insert(PxE4 key, Pool&, bool& created)
//   Level* find(PxE4 key) const
//   void   erase(PxE4 key, Level*, Pool&)        level must be empty
//   Level* best() const                          nullptr when the side is empty
//   void   for_each(f(PxE4 key, const Level&))   best to worst
//   size(), reserve(n), clear(Pool&), check(err)
//
//   MapSide     std::map<key, Level>; levels live in the map nodes (B0).
//   VecSide     sorted keys (SoA) + level pointers, best at the back, linear
//               scan from the touch (X06, X10); levels come from a SlabPool.
//   WindowSide  2^kBits-slot price window with a two-level tzcnt/lzcnt
//               bitmap around the touch, and a VecSide for far prices (X20).
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "common/assert.h"
#include "lob/types.h"

namespace lle::lob {

// ---------------------------------------------------------------------------
// MapSide (B0)
// ---------------------------------------------------------------------------
template <class Level, class Better>
class MapSide {
  struct Cmp {
    bool operator()(PxE4 a, PxE4 b) const noexcept { return Better::better(a, b); }
  };

 public:
  template <class Pool>
  Level* find_or_insert(PxE4 key, Pool& /*pool*/, bool& created) {
    auto [it, inserted] = m_.try_emplace(key);
    created = inserted;
    return &it->second;
  }

  [[nodiscard]] Level* find(PxE4 key) const noexcept {
    auto it = m_.find(key);
    return it == m_.end() ? nullptr : const_cast<Level*>(&it->second);
  }

  template <class Pool>
  void erase(PxE4 key, Level* /*lv*/, Pool& /*pool*/) noexcept {
    m_.erase(key);
  }

  [[nodiscard]] Level* best() const noexcept {
    return m_.empty() ? nullptr : const_cast<Level*>(&m_.begin()->second);
  }

  template <class F>
  void for_each(F&& f) const {
    for (const auto& [k, lv] : m_) f(k, lv);
  }

  [[nodiscard]] std::size_t size() const noexcept { return m_.size(); }
  void reserve(std::size_t) noexcept {}
  template <class Pool>
  void clear(Pool& /*pool*/) noexcept {
    m_.clear();
  }
  [[nodiscard]] bool check(std::string*) const { return true; }  // ordered by construction

 private:
  std::map<PxE4, Level, Cmp> m_;
};

// ---------------------------------------------------------------------------
// VecSide: sorted vector, best at the back (Gross, CppCon 2024; itch-book)
// ---------------------------------------------------------------------------
template <class Level, class Better>
class VecSide {
 public:
  template <class Pool>
  Level* find_or_insert(PxE4 key, Pool& pool, bool& created) {
    bool found;
    const std::size_t i = scan(key, found);
    if (found) {
      created = false;
      return lv_[i];
    }
    Level* lv = new_level(pool);
    insert_at(i, key, lv);
    created = true;
    return lv;
  }

  [[nodiscard]] Level* find(PxE4 key) const noexcept {
    bool found;
    const std::size_t i = scan(key, found);
    return found ? lv_[i] : nullptr;
  }

  template <class Pool>
  void erase(PxE4 key, Level* lv, Pool& pool) noexcept {
    bool found;
    const std::size_t i = scan(key, found);
    LLE_DASSERT(found && lv_[i] == lv, "VecSide::erase of a missing level");
    keys_.erase(keys_.begin() + static_cast<std::ptrdiff_t>(i));
    lv_.erase(lv_.begin() + static_cast<std::ptrdiff_t>(i));
    pool.free(lv->self);
  }

  [[nodiscard]] Level* best() const noexcept { return lv_.empty() ? nullptr : lv_.back(); }
  [[nodiscard]] PxE4 best_key() const noexcept { return keys_.back(); }
  [[nodiscard]] PxE4 key_at(std::size_t i) const noexcept { return keys_[i]; }
  [[nodiscard]] Level* level_at(std::size_t i) const noexcept { return lv_[i]; }

  template <class F>
  void for_each(F&& f) const {
    for (std::size_t i = keys_.size(); i-- > 0;) f(keys_[i], *lv_[i]);
  }

  [[nodiscard]] std::size_t size() const noexcept { return keys_.size(); }
  // Pre-sizes both vectors. A side whose level count later grows past the
  // reserve reallocates them inside find_or_insert(): an allocation on the hot
  // path. Users that must not allocate after startup (the matching engine:
  // EngineConfig::book.levels_per_side) reserve for the deepest book they accept.
  void reserve(std::size_t n) {
    keys_.reserve(n);
    lv_.reserve(n);
  }
  template <class Pool>
  void clear(Pool& pool) noexcept {
    for (Level* lv : lv_) pool.free(lv->self);
    keys_.clear();
    lv_.clear();
  }

  [[nodiscard]] bool check(std::string* err) const {
    if (keys_.size() != lv_.size()) {
      if (err) *err = "vec levels: key/level arrays differ in size";
      return false;
    }
    for (std::size_t i = 1; i < keys_.size(); ++i) {
      if (!Better::better(keys_[i], keys_[i - 1])) {
        if (err) *err = "vec levels: keys not strictly improving toward the back";
        return false;
      }
    }
    for (const Level* lv : lv_) {
      if (lv == nullptr) {
        if (err) *err = "vec levels: null level";
        return false;
      }
    }
    return true;
  }

  // --- used by WindowSide ---------------------------------------------------
  template <class Pool>
  static Level* new_level(Pool& pool) {
    const Handle32 h = pool.alloc();
    Level* lv = pool.ptr(h);
    lv->self = h;
    return lv;
  }

  // Merges n (key, level) pairs sorted in ascending goodness and disjoint
  // from the current keys, in place from the back: O(size + n).
  void merge_sorted(const PxE4* keys, Level* const* lvs, std::size_t n) {
    std::size_t i = keys_.size();
    std::size_t j = n;
    std::size_t w = i + n;
    keys_.resize(w);
    lv_.resize(w);
    while (j > 0) {
      if (i > 0 && Better::better(keys_[i - 1], keys[j - 1])) {
        --i;
        --w;
        keys_[w] = keys_[i];
        lv_[w] = lv_[i];
      } else {
        --j;
        --w;
        keys_[w] = keys[j];
        lv_[w] = lvs[j];
      }
    }
  }

  // Removes every entry whose key satisfies pred, handing it to sink;
  // keeps the rest in order.
  template <class Pred, class Sink>
  void extract_if(Pred&& pred, Sink&& sink) {
    std::size_t w = 0;
    for (std::size_t r = 0; r < keys_.size(); ++r) {
      if (pred(keys_[r])) {
        sink(keys_[r], lv_[r]);
      } else {
        keys_[w] = keys_[r];
        lv_[w] = lv_[r];
        ++w;
      }
    }
    keys_.resize(w);
    lv_.resize(w);
  }

 private:
  // Linear scan from the touch (the back). Returns the index of key when
  // found, else the insertion point that keeps the order.
  [[nodiscard]] std::size_t scan(PxE4 key, bool& found) const noexcept {
    const PxE4* k = keys_.data();
    std::size_t i = keys_.size();
    while (i > 0) {
      const PxE4 x = k[i - 1];
      if (x == key) {
        found = true;
        return i - 1;
      }
      if (Better::better(key, x)) break;
      --i;
    }
    found = false;
    return i;
  }

  void insert_at(std::size_t i, PxE4 key, Level* lv) {
    keys_.insert(keys_.begin() + static_cast<std::ptrdiff_t>(i), key);
    lv_.insert(lv_.begin() + static_cast<std::ptrdiff_t>(i), lv);
  }

  std::vector<PxE4> keys_;  // ascending goodness: back() is the best price
  std::vector<Level*> lv_;
};

// ---------------------------------------------------------------------------
// WindowSide: price window + two-level bitmap, far prices in a VecSide
// ---------------------------------------------------------------------------
//
// A flat price array per book is infeasible (a day spans ~20M ticks, R5
// D5.1), so only a window of 2^kBits slots around the touch is direct-mapped.
// Keys are mapped to a goodness scale g = kSign * key (higher is better);
// slot = (g - gbase) / tick for keys inside the window and on its tick grid
// (tick = $0.01 for prices >= $1 on whole cents, else $0.0001). Every other
// key lives in the far VecSide; a key that maps into the window is never in
// the far side. When a newly created level becomes the side's best price
// outside the window, the window is re-based around it (3/4 of the slots
// below the touch, 1/4 above) and levels migrate in O(levels).
template <class Level, class Better, std::uint32_t kBits>
class WindowSide {
  static_assert(kBits >= 6 && kBits <= 12, "window of 64..4096 slots (one L1 word)");
  static constexpr std::uint32_t kW = 1u << kBits;
  static constexpr std::uint32_t kWords = kW / 64;
  static constexpr PxE4 kTop = static_cast<PxE4>(kW) * 3 / 4;  // touch slot after a re-base
  static constexpr PxE4 kPenny = 100;                          // $0.01 in PxE4

 public:
  WindowSide() = default;
  WindowSide(WindowSide&&) noexcept = default;
  WindowSide& operator=(WindowSide&&) noexcept = default;

  template <class Pool>
  Level* find_or_insert(PxE4 key, Pool& pool, bool& created) {
    if (tick_ == 0) [[unlikely]]
      init(key);
    std::uint32_t idx;
    if (slot_of(key, idx)) {
      Level*& s = slots_[idx];
      if (s != nullptr) {
        created = false;
        return s;
      }
      s = Far::new_level(pool);
      set_bit(idx);
      ++n_;
      created = true;
      return s;
    }
    Level* lv = far_.find_or_insert(key, pool, created);
    if (created && far_.best_key() == key && (n_ == 0 || Better::better(key, window_best_key()))) rebase(key);
    return lv;
  }

  [[nodiscard]] Level* find(PxE4 key) const noexcept {
    std::uint32_t idx;
    if (slot_of(key, idx)) return slots_[idx];
    return far_.find(key);
  }

  template <class Pool>
  void erase(PxE4 key, Level* lv, Pool& pool) noexcept {
    std::uint32_t idx;
    if (slot_of(key, idx)) {
      LLE_DASSERT(slots_[idx] == lv, "WindowSide::erase of a missing level");
      slots_[idx] = nullptr;
      clear_bit(idx);
      --n_;
      pool.free(lv->self);
      return;
    }
    far_.erase(key, lv, pool);
  }

  [[nodiscard]] Level* best() const noexcept {
    Level* f = far_.best();
    if (l1_ == 0) return f;
    const std::uint32_t idx = top_slot();
    Level* w = slots_[idx];
    if (f == nullptr) return w;
    return Better::better(far_.best_key(), key_of(idx)) ? f : w;
  }

  template <class F>
  void for_each(F&& f) const {
    std::int64_t wi = l1_ == 0 ? -1 : static_cast<std::int64_t>(top_slot());
    std::size_t fi = far_.size();
    while (wi >= 0 || fi > 0) {
      if (wi >= 0) {
        const auto idx = static_cast<std::uint32_t>(wi);
        const PxE4 wk = key_of(idx);
        if (fi == 0 || Better::better(wk, far_.key_at(fi - 1))) {
          f(wk, *slots_[idx]);
          wi = prev_set(idx);
          continue;
        }
      }
      --fi;
      f(far_.key_at(fi), *far_.level_at(fi));
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return n_ + far_.size(); }

  void reserve(std::size_t n) {
    far_.reserve(n);
    ensure_storage();
  }

  template <class Pool>
  void clear(Pool& pool) noexcept {
    if (slots_) {
      for (std::uint32_t w = 0; w < kWords; ++w) {
        for (std::uint64_t word = l0_[w]; word != 0; word &= word - 1) {
          const std::uint32_t idx = w * 64 + static_cast<std::uint32_t>(std::countr_zero(word));
          pool.free(slots_[idx]->self);
          slots_[idx] = nullptr;
        }
        l0_[w] = 0;
      }
    }
    l1_ = 0;
    n_ = 0;
    tick_ = 0;
    far_.clear(pool);
  }

  [[nodiscard]] bool check(std::string* err) const {
    auto fail = [&](const char* m) {
      if (err) *err = m;
      return false;
    };
    if (!far_.check(err)) return false;
    if (tick_ == 0) {
      if (n_ != 0 || l1_ != 0) return fail("window: levels in an uninitialized window");
      return true;
    }
    std::uint32_t pop = 0;
    for (std::uint32_t w = 0; w < kWords; ++w) {
      pop += static_cast<std::uint32_t>(std::popcount(l0_[w]));
      if (((l1_ >> w) & 1u) != (l0_[w] != 0 ? 1u : 0u)) return fail("window: L1 bit disagrees with L0 word");
    }
    if (pop != n_) return fail("window: bitmap population != level count");
    for (std::uint32_t i = 0; i < kW; ++i) {
      const bool bit = ((l0_[i / 64] >> (i % 64)) & 1u) != 0;
      if (bit != (slots_[i] != nullptr)) return fail("window: slot occupancy disagrees with bitmap");
    }
    for (std::size_t i = 0; i < far_.size(); ++i) {
      std::uint32_t idx;
      if (slot_of(far_.key_at(i), idx)) return fail("window: far level maps into the window");
    }
    return true;
  }

  // Diagnostics for tests and experiments.
  [[nodiscard]] std::size_t window_levels() const noexcept { return n_; }
  [[nodiscard]] std::size_t far_levels() const noexcept { return far_.size(); }
  [[nodiscard]] std::uint64_t rebases() const noexcept { return rebases_; }

 private:
  using Far = VecSide<Level, Better>;

  static constexpr PxE4 goodness(PxE4 key) noexcept { return Better::kSign * key; }
  static constexpr PxE4 choose_tick(PxE4 key) noexcept {
    const PxE4 px = key < 0 ? -key : key;
    return (px >= 10'000 && px % kPenny == 0) ? kPenny : 1;
  }

  [[nodiscard]] bool slot_of(PxE4 key, std::uint32_t& idx) const noexcept {
    if (tick_ == 0) return false;
    PxE4 d = goodness(key) - gbase_;
    if (d < 0) return false;
    if (tick_ != 1) {
      if (d % kPenny != 0) return false;
      d /= kPenny;
    }
    if (d >= static_cast<PxE4>(kW)) return false;
    idx = static_cast<std::uint32_t>(d);
    return true;
  }

  [[nodiscard]] PxE4 key_of(std::uint32_t idx) const noexcept {
    return Better::kSign * (gbase_ + static_cast<PxE4>(idx) * tick_);
  }

  [[nodiscard]] std::uint32_t top_slot() const noexcept {
    const auto w = static_cast<std::uint32_t>(63 - std::countl_zero(l1_));
    return w * 64 + static_cast<std::uint32_t>(63 - std::countl_zero(l0_[w]));
  }
  [[nodiscard]] PxE4 window_best_key() const noexcept { return key_of(top_slot()); }

  // Highest occupied slot strictly below idx, or -1.
  [[nodiscard]] std::int64_t prev_set(std::uint32_t idx) const noexcept {
    const std::uint32_t w = idx / 64;
    const std::uint32_t b = idx % 64;
    const std::uint64_t below = b == 0 ? 0 : (l0_[w] & ((std::uint64_t{1} << b) - 1));
    if (below != 0) return static_cast<std::int64_t>(w * 64 + static_cast<std::uint32_t>(63 - std::countl_zero(below)));
    const std::uint64_t words = w == 0 ? 0 : (l1_ & ((std::uint64_t{1} << w) - 1));
    if (words == 0) return -1;
    const auto w2 = static_cast<std::uint32_t>(63 - std::countl_zero(words));
    return static_cast<std::int64_t>(w2 * 64 + static_cast<std::uint32_t>(63 - std::countl_zero(l0_[w2])));
  }

  void set_bit(std::uint32_t idx) noexcept {
    l0_[idx / 64] |= std::uint64_t{1} << (idx % 64);
    l1_ |= std::uint64_t{1} << (idx / 64);
  }
  void clear_bit(std::uint32_t idx) noexcept {
    std::uint64_t& word = l0_[idx / 64];
    word &= ~(std::uint64_t{1} << (idx % 64));
    if (word == 0) l1_ &= ~(std::uint64_t{1} << (idx / 64));
  }

  void ensure_storage() {
    if (!slots_) {
      slots_ = std::make_unique<Level*[]>(kW);  // value-initialized: all nullptr
      scratch_keys_.reserve(kW);
      scratch_lv_.reserve(kW);
    }
  }

  void init(PxE4 key) {
    ensure_storage();
    tick_ = choose_tick(key);
    gbase_ = goodness(key) - kTop * tick_;
  }

  // Moves every window level to the far side, re-centers the window on
  // `center`, then pulls far levels that now map into the window back in.
  void rebase(PxE4 center) {
    ++rebases_;
    scratch_keys_.clear();
    scratch_lv_.clear();
    for (std::uint32_t w = 0; w < kWords; ++w) {
      for (std::uint64_t word = l0_[w]; word != 0; word &= word - 1) {
        const std::uint32_t idx = w * 64 + static_cast<std::uint32_t>(std::countr_zero(word));
        scratch_keys_.push_back(key_of(idx));  // ascending slot == ascending goodness
        scratch_lv_.push_back(slots_[idx]);
        slots_[idx] = nullptr;
      }
      l0_[w] = 0;
    }
    l1_ = 0;
    n_ = 0;
    far_.merge_sorted(scratch_keys_.data(), scratch_lv_.data(), scratch_keys_.size());
    tick_ = choose_tick(center);
    gbase_ = goodness(center) - kTop * tick_;
    far_.extract_if(
        [this](PxE4 k) {
          std::uint32_t idx;
          return slot_of(k, idx);
        },
        [this](PxE4 k, Level* lv) {
          std::uint32_t idx = 0;
          const bool in = slot_of(k, idx);
          LLE_DASSERT(in, "extracted level must map into the window");
          static_cast<void>(in);
          slots_[idx] = lv;
          set_bit(idx);
          ++n_;
        });
  }

  std::uint64_t l1_ = 0;        // bit w set iff l0_[w] != 0
  std::uint64_t l0_[kWords]{};  // bit i set iff slot i holds a level
  PxE4 gbase_ = 0;              // goodness of slot 0
  PxE4 tick_ = 0;               // 0 = window not initialized
  std::uint32_t n_ = 0;         // levels in the window
  std::uint64_t rebases_ = 0;
  std::unique_ptr<Level*[]> slots_;
  Far far_;
  std::vector<PxE4> scratch_keys_;
  std::vector<Level*> scratch_lv_;
};

// ---------------------------------------------------------------------------
// Level policies
// ---------------------------------------------------------------------------
struct MapLevels {
  static constexpr bool kPooled = false;
  template <class Level, class Better>
  using Side = MapSide<Level, Better>;
};

struct VecLevels {
  static constexpr bool kPooled = true;
  template <class Level, class Better>
  using Side = VecSide<Level, Better>;
};

template <std::uint32_t kBits = 10>
struct WindowLevels {
  static constexpr bool kPooled = true;
  template <class Level, class Better>
  using Side = WindowSide<Level, Better, kBits>;
};

}  // namespace lle::lob
