#pragma once
// Order stores: order records with stable addresses plus the ref index
// (04-order-book §3 "Order index", "Order record", "Memory").
//
// A store policy exposes `handle<Rec>` (the handle type for a record type,
// usable while Rec is still incomplete) and `Impl<Rec>`:
//
//   Handle find(OrderRef)          kNil when absent
//   Handle emplace(OrderRef)       default-constructed record; kNil if present
//   void   erase(OrderRef, Handle) after the record is no longer referenced
//   Rec&   rec(Handle)
//   size(), check(err)
//
//   StdStore            std::unordered_map<u64, Rec>: the record lives in the
//                       map node, handle = Rec* (the B0 design)
//   PoolStore<Index,B>  records in a SlabPool (32-bit handles), Index maps
//                       ref -> handle (StdIndex, FlatIndex, PagedIndex)
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "lob/arena.h"
#include "lob/index.h"
#include "lob/slab_pool.h"
#include "lob/types.h"

namespace lle::lob {

struct StoreConfig {
  std::size_t reserve_orders = 1 << 16;  // pre-sized record capacity
  IndexConfig index{};
  bool prefault = false;  // touch pooled memory at startup
};

struct StdStore {
  template <class Rec>
  using handle = Rec*;

  template <class Rec>
  class Impl {
   public:
    using Handle = Rec*;
    static constexpr Handle kNil = nullptr;

    explicit Impl(const StoreConfig& c = {}) { m_.reserve(c.reserve_orders); }

    [[nodiscard]] Handle find(OrderRef r) const noexcept {
      auto it = m_.find(r);
      return it == m_.end() ? nullptr : const_cast<Rec*>(&it->second);
    }
    [[nodiscard]] Handle emplace(OrderRef r) {
      auto [it, inserted] = m_.try_emplace(r);
      return inserted ? &it->second : nullptr;
    }
    // Pointers to unordered_map elements survive rehashing, so handles held
    // across an emplace stay valid.
    void erase(OrderRef r, Handle) noexcept { m_.erase(r); }
    [[nodiscard]] Rec& rec(Handle h) noexcept { return *h; }
    [[nodiscard]] const Rec& rec(Handle h) const noexcept { return *h; }
    [[nodiscard]] std::size_t size() const noexcept { return m_.size(); }
    [[nodiscard]] bool check(std::string*) const { return true; }

   private:
    std::unordered_map<OrderRef, Rec> m_;
  };
};

template <class Index, class Backing = HeapBacking>
struct PoolStore {
  template <class Rec>
  using handle = Handle32;

  template <class Rec>
  class Impl {
   public:
    using Handle = Handle32;
    static constexpr Handle kNil = kNil32;

    explicit Impl(const StoreConfig& c = {}) : pool_(c.reserve_orders, c.prefault), idx_(index_config(c)) {}

    [[nodiscard]] Handle find(OrderRef r) const noexcept { return idx_.find(r); }
    [[nodiscard]] Handle emplace(OrderRef r) {
      const Handle h = pool_.alloc();
      if (!idx_.insert(r, h)) [[unlikely]] {
        pool_.free(h);
        return kNil;
      }
      return h;
    }
    void erase(OrderRef r, Handle h) noexcept {
      idx_.erase(r);
      pool_.free(h);
    }
    [[nodiscard]] Rec& rec(Handle h) noexcept { return pool_[h]; }
    [[nodiscard]] const Rec& rec(Handle h) const noexcept { return pool_[h]; }
    [[nodiscard]] std::size_t size() const noexcept { return idx_.size(); }
    [[nodiscard]] bool check(std::string* err) const {
      if (idx_.size() != pool_.live()) {
        if (err) *err = "store: index size != live records";
        return false;
      }
      return idx_.check(err);
    }

    void prefetch(OrderRef r) const noexcept { idx_.prefetch(r); }
    [[nodiscard]] const SlabPool<Rec, Backing>& pool() const noexcept { return pool_; }
    [[nodiscard]] const Index& index() const noexcept { return idx_; }

   private:
    static IndexConfig index_config(const StoreConfig& c) {
      IndexConfig i = c.index;
      if (i.capacity < c.reserve_orders) i.capacity = c.reserve_orders;
      return i;
    }

    SlabPool<Rec, Backing> pool_;
    Index idx_;
  };
};

}  // namespace lle::lob
