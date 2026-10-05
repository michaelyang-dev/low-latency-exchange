#pragma once
// Order-reference indexes: u64 ref -> u32 record handle (04-order-book §3,
// X04, X05, X28). ITCH refs are 64-bit, day-unique, non-monotonic, and reach
// ~1.1e9 in 2025 (R1a Q6 pitfall 6), so every index takes full 64-bit keys.
//
//   StdIndex    std::unordered_map<u64, u32>
//   FlatIndex   open addressing, linear probing, Robin Hood insertion,
//               backward-shift deletion (no tombstones)
//   PagedIndex  direct array over refs < max_direct_ref, in lazily allocated
//               pages of 8 Ki refs; refs above the maximum go to a fallback
//               (FlatIndex by default), so refs >= 2^32 still work
//
// Interface: find(k) -> handle or kNil32; insert(k, v) -> false if k is
// present (no change); erase(k) -> removed handle or kNil32; size();
// prefetch(k); check(err). Handles must not equal kNil32.
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "common/hash.h"
#include "lob/arena.h"
#include "lob/types.h"

namespace lle::lob {

struct IndexConfig {
  std::size_t capacity = 1 << 16;               // expected peak live keys (pre-sizing)
  std::uint64_t max_direct_ref = 1ull << 32;    // PagedIndex: refs >= this use the fallback
};

// ---------------------------------------------------------------------------
// Hashes: bucket(k, bits) in [0, 2^bits).
// ---------------------------------------------------------------------------
struct FibonacciHash {  // multiplicative: high bits of k * 2^64/phi
  [[nodiscard]] static constexpr std::uint64_t bucket(std::uint64_t k, std::uint32_t bits) noexcept {
    return (k * 0x9E37'79B9'7F4A'7C15ull) >> (64 - bits);
  }
};
struct IdentityHash {  // low bits: dense refs land in consecutive slots
  [[nodiscard]] static constexpr std::uint64_t bucket(std::uint64_t k, std::uint32_t bits) noexcept {
    return k & ((std::uint64_t{1} << bits) - 1);
  }
};
struct MixHash {  // SplitMix64 finalizer
  [[nodiscard]] static constexpr std::uint64_t bucket(std::uint64_t k, std::uint32_t bits) noexcept {
    return mix64(k) >> (64 - bits);
  }
};

// ---------------------------------------------------------------------------
// StdIndex
// ---------------------------------------------------------------------------
class StdIndex {
 public:
  explicit StdIndex(const IndexConfig& c = {}) { m_.reserve(c.capacity); }

  [[nodiscard]] Handle32 find(std::uint64_t k) const noexcept {
    auto it = m_.find(k);
    return it == m_.end() ? kNil32 : it->second;
  }
  bool insert(std::uint64_t k, Handle32 v) { return m_.try_emplace(k, v).second; }
  Handle32 erase(std::uint64_t k) noexcept {
    auto it = m_.find(k);
    if (it == m_.end()) return kNil32;
    const Handle32 v = it->second;
    m_.erase(it);
    return v;
  }
  [[nodiscard]] std::size_t size() const noexcept { return m_.size(); }
  void prefetch(std::uint64_t) const noexcept {}
  [[nodiscard]] bool check(std::string*) const { return true; }

 private:
  std::unordered_map<std::uint64_t, Handle32> m_;
};

// ---------------------------------------------------------------------------
// FlatIndex: Robin Hood with backward-shift deletion
// ---------------------------------------------------------------------------
//
// Each slot stores its probe distance + 1 (0 = empty). Insertion displaces
// any resident that is closer to its home than the incoming key ("steal from
// the rich"), which bounds probe-length variance; lookups stop as soon as a
// resident is closer to home than the probe. Deletion shifts the following
// cluster back by one instead of leaving tombstones, so lookups never slow
// down as the table churns (R1a Q6 pitfall 6). Max load 3/4, power-of-two
// capacity; growth (a rehash) only happens past the pre-sized capacity.
template <class Hash = FibonacciHash, class Backing = HeapBacking>
class FlatIndex {
  struct Slot {
    std::uint64_t key;
    Handle32 val;
    std::uint32_t dist;  // probe distance + 1; 0 = empty
  };
  static_assert(sizeof(Slot) == 16);

 public:
  explicit FlatIndex(const IndexConfig& c = {}) {
    std::size_t want = c.capacity < 8 ? 8 : c.capacity;
    std::size_t slots = std::bit_ceil(want + want / 3 + 1);
    allocate(slots);
  }
  FlatIndex(const FlatIndex&) = delete;
  FlatIndex& operator=(const FlatIndex&) = delete;
  ~FlatIndex() { Backing::deallocate(slots_, cap() * sizeof(Slot), alignof(Slot) < 64 ? 64 : alignof(Slot)); }

  [[nodiscard]] Handle32 find(std::uint64_t k) const noexcept {
    std::uint64_t i = Hash::bucket(k, bits_);
    for (std::uint32_t d = 1;; ++d) {
      const Slot& s = slots_[i];
      if (s.dist < d) return kNil32;
      if (s.key == k) return s.val;
      i = (i + 1) & mask_;
    }
  }

  bool insert(std::uint64_t k, Handle32 v) {
    if (size_ >= grow_at_) [[unlikely]]
      grow();
    Slot cur{k, v, 1};
    std::uint64_t i = Hash::bucket(k, bits_);
    bool displaced = false;
    for (;;) {
      Slot& s = slots_[i];
      if (s.dist == 0) {
        s = cur;
        ++size_;
        return true;
      }
      // Until the first displacement the probe walks k's own sequence, where
      // an existing copy of k must sit before any closer-to-home resident.
      if (!displaced && s.key == k) return false;
      if (s.dist < cur.dist) {
        std::swap(s, cur);
        displaced = true;
      }
      i = (i + 1) & mask_;
      ++cur.dist;
    }
  }

  Handle32 erase(std::uint64_t k) noexcept {
    std::uint64_t i = Hash::bucket(k, bits_);
    for (std::uint32_t d = 1;; ++d) {
      const Slot& s = slots_[i];
      if (s.dist < d) return kNil32;
      if (s.key == k) break;
      i = (i + 1) & mask_;
    }
    const Handle32 v = slots_[i].val;
    for (;;) {
      const std::uint64_t j = (i + 1) & mask_;
      if (slots_[j].dist <= 1) break;  // empty, or already at its home slot
      slots_[i] = slots_[j];
      --slots_[i].dist;
      i = j;
    }
    slots_[i].dist = 0;
    --size_;
    return v;
  }

  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return grow_at_; }
  [[nodiscard]] std::size_t rehashes() const noexcept { return rehashes_; }
  void prefetch(std::uint64_t k) const noexcept { __builtin_prefetch(&slots_[Hash::bucket(k, bits_)]); }

  [[nodiscard]] bool check(std::string* err) const {
    auto fail = [&](const char* m) {
      if (err) *err = m;
      return false;
    };
    std::size_t n = 0;
    for (std::uint64_t i = 0; i < cap(); ++i) {
      const Slot& s = slots_[i];
      const Slot& nx = slots_[(i + 1) & mask_];
      if (nx.dist > s.dist + 1) return fail("flat index: Robin Hood invariant broken");
      if (s.dist == 0) continue;
      ++n;
      const std::uint64_t home = Hash::bucket(s.key, bits_);
      if (((i - home) & mask_) != s.dist - 1) return fail("flat index: stored distance != distance from home");
      if (find(s.key) != s.val) return fail("flat index: key not findable");
    }
    if (n != size_) return fail("flat index: occupancy != size");
    return true;
  }

 private:
  [[nodiscard]] std::uint64_t cap() const noexcept { return mask_ + 1; }

  void allocate(std::size_t slots) {
    slots_ = static_cast<Slot*>(allocate_zeroed<Backing>(slots * sizeof(Slot), alignof(Slot) < 64 ? 64 : alignof(Slot)));
    bits_ = static_cast<std::uint32_t>(std::countr_zero(slots));
    mask_ = slots - 1;
    grow_at_ = slots / 4 * 3;
    size_ = 0;
  }

  void grow() {
    Slot* old = slots_;
    const std::uint64_t old_cap = cap();
    allocate(old_cap * 2);
    for (std::uint64_t i = 0; i < old_cap; ++i) {
      if (old[i].dist != 0) insert(old[i].key, old[i].val);
    }
    Backing::deallocate(old, old_cap * sizeof(Slot), alignof(Slot) < 64 ? 64 : alignof(Slot));
    ++rehashes_;
  }

  Slot* slots_ = nullptr;
  std::uint64_t mask_ = 0;
  std::uint32_t bits_ = 0;
  std::size_t size_ = 0;
  std::size_t grow_at_ = 0;
  std::size_t rehashes_ = 0;
};

// ---------------------------------------------------------------------------
// PagedIndex: paged direct index with a hash fallback
// ---------------------------------------------------------------------------
//
// A page covers 8 Ki consecutive refs and stores handle + 1 per ref (0 =
// absent), so fresh zeroed memory is an empty page. Pages are allocated on
// first use from 2 MiB chunks, and a page whose last entry is erased goes to
// a free list for reuse, so memory tracks the spread of live refs and a
// steady state allocates nothing. Refs >= max_direct_ref (rounded up to a
// page) use the fallback index, which bounds the page table (4 MiB for 2^32).
template <class Fallback = FlatIndex<>, class Backing = HeapBacking>
class PagedIndex {
 public:
  static constexpr std::uint32_t kPageBits = 13;
  static constexpr std::uint64_t kPageRefs = std::uint64_t{1} << kPageBits;  // 8 Ki refs
  static constexpr std::uint64_t kPageMask = kPageRefs - 1;
  static constexpr std::size_t kPageBytes = kPageRefs * sizeof(std::uint32_t);  // 32 KiB
  static constexpr std::size_t kChunkPages = kHugePageBytes / kPageBytes;        // 64

  explicit PagedIndex(const IndexConfig& c = {})
      : max_direct_((c.max_direct_ref + kPageMask) & ~kPageMask), far_(fallback_config(c)) {
    LLE_ASSERT(max_direct_ / kPageRefs <= (std::uint64_t{1} << 32), "max_direct_ref too large");
    pages_.assign(static_cast<std::size_t>(max_direct_ / kPageRefs), nullptr);
    page_live_.assign(pages_.size(), 0);
  }
  PagedIndex(const PagedIndex&) = delete;
  PagedIndex& operator=(const PagedIndex&) = delete;
  ~PagedIndex() {
    for (void* ch : chunks_) Backing::deallocate(ch, kHugePageBytes, 64);
  }

  [[nodiscard]] Handle32 find(std::uint64_t k) const noexcept {
    if (k < max_direct_) [[likely]] {
      const std::uint32_t* p = pages_[static_cast<std::size_t>(k >> kPageBits)];
      return p != nullptr ? p[k & kPageMask] - 1u : kNil32;  // stored 0 wraps to kNil32
    }
    return far_.find(k);
  }

  bool insert(std::uint64_t k, Handle32 v) {
    LLE_DASSERT(v != kNil32, "kNil32 is not a storable handle");
    if (k < max_direct_) [[likely]] {
      const auto pi = static_cast<std::size_t>(k >> kPageBits);
      std::uint32_t* p = pages_[pi];
      if (p == nullptr) [[unlikely]] {
        p = new_page();
        pages_[pi] = p;
      }
      std::uint32_t& e = p[k & kPageMask];
      if (e != 0) return false;
      e = v + 1u;
      ++page_live_[pi];
      ++direct_;
      return true;
    }
    return far_.insert(k, v);
  }

  Handle32 erase(std::uint64_t k) noexcept {
    if (k < max_direct_) [[likely]] {
      const auto pi = static_cast<std::size_t>(k >> kPageBits);
      std::uint32_t* p = pages_[pi];
      if (p == nullptr) return kNil32;
      std::uint32_t& e = p[k & kPageMask];
      if (e == 0) return kNil32;
      const Handle32 v = e - 1u;
      e = 0;
      --direct_;
      if (--page_live_[pi] == 0) {
        pages_[pi] = nullptr;
        free_page(p);
      }
      return v;
    }
    return far_.erase(k);
  }

  [[nodiscard]] std::size_t size() const noexcept { return direct_ + far_.size(); }
  [[nodiscard]] std::size_t direct_size() const noexcept { return direct_; }
  [[nodiscard]] std::size_t fallback_size() const noexcept { return far_.size(); }
  [[nodiscard]] std::size_t pages_in_use() const noexcept { return pages_used_; }
  [[nodiscard]] std::size_t chunks() const noexcept { return chunks_.size(); }
  [[nodiscard]] std::uint64_t max_direct_ref() const noexcept { return max_direct_; }

  void prefetch(std::uint64_t k) const noexcept {
    if (k < max_direct_) {
      const std::uint32_t* p = pages_[static_cast<std::size_t>(k >> kPageBits)];
      if (p != nullptr) __builtin_prefetch(p + (k & kPageMask));
    } else {
      far_.prefetch(k);
    }
  }

  [[nodiscard]] bool check(std::string* err) const {
    auto fail = [&](const char* m) {
      if (err) *err = m;
      return false;
    };
    std::size_t total = 0, used = 0;
    for (std::size_t pi = 0; pi < pages_.size(); ++pi) {
      const std::uint32_t* p = pages_[pi];
      if (p == nullptr) {
        if (page_live_[pi] != 0) return fail("paged index: live count on an absent page");
        continue;
      }
      ++used;
      std::uint32_t n = 0;
      for (std::uint64_t i = 0; i < kPageRefs; ++i) n += p[i] != 0 ? 1u : 0u;
      if (n == 0) return fail("paged index: empty page not released");
      if (n != page_live_[pi]) return fail("paged index: page live count wrong");
      total += n;
    }
    if (total != direct_) return fail("paged index: direct size wrong");
    if (used != pages_used_) return fail("paged index: pages-in-use count wrong");
    return far_.check(err);
  }

 private:
  static IndexConfig fallback_config(const IndexConfig& c) {
    IndexConfig f = c;
    f.capacity = c.capacity / 16 < 64 ? 64 : c.capacity / 16;  // refs above the max are rare
    return f;
  }

  std::uint32_t* new_page() {
    ++pages_used_;
    if (free_ != nullptr) {
      std::uint32_t* p = free_;
      std::memcpy(&free_, p, kLinkBytes);  // free pages link through their first word
      std::memset(p, 0, kLinkBytes);
      return p;
    }
    if (carve_left_ == 0) {
      carve_ = static_cast<std::uint32_t*>(allocate_zeroed<Backing>(kHugePageBytes, 64));
      chunks_.push_back(carve_);
      carve_left_ = kChunkPages;
    }
    std::uint32_t* p = carve_;
    carve_ += kPageRefs;
    --carve_left_;
    return p;
  }

  void free_page(std::uint32_t* p) noexcept {
    --pages_used_;
    std::memcpy(p, &free_, kLinkBytes);  // the rest of the page is already zero
    free_ = p;
  }

  std::uint64_t max_direct_;
  std::vector<std::uint32_t*> pages_;    // page table
  std::vector<std::uint32_t> page_live_;  // live entries per page
  std::size_t direct_ = 0;
  std::size_t pages_used_ = 0;
  static constexpr std::size_t kLinkBytes = sizeof(std::uint32_t*);
  std::uint32_t* free_ = nullptr;   // free-page list
  std::uint32_t* carve_ = nullptr;  // next unused page of the newest chunk
  std::size_t carve_left_ = 0;
  std::vector<void*> chunks_;
  Fallback far_;
};

}  // namespace lle::lob
