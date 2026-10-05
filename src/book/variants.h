#pragma once
// Named ItchBook variants (04-order-book §4, §7). Every variant must produce
// identical BBO-stream and final-books digests for identical input.
//
// The ladder follows the published step sequence for comparable designs (R5
// D5.4: naive map + unordered_map -> vectors + intrusive FIFO + pools ->
// flat hash -> paged index), changing one component per step so each step
// can be measured as its own experiment.
#include <string_view>
#include <tuple>

#include "book/itch_book.h"
#include "book/listener.h"
#include "lob/arena.h"
#include "lob/fifo.h"
#include "lob/index.h"
#include "lob/levels.h"
#include "lob/store.h"

namespace lle::book {

// B0, the pre-registered textbook baseline (04 §4): std::map<PxE4, Level>
// per side, std::list FIFO per level, std::unordered_map<u64, Order> with the
// record (level pointer + list iterator + shares) in the map node, default
// allocator, separate bid/ask comparators, virtual BookListener.
using B0Policies = Policies<lob::MapLevels, lob::ListFifo, lob::StdStore, lob::HeapBacking, false>;
using B0Book = ItchBook<B0Policies, VirtualListener>;

// X06 alone: sorted-vector levels, everything else as B0.
using VecListStdPolicies = Policies<lob::VecLevels, lob::ListFifo, lob::StdStore, lob::HeapBacking, false>;

// + intrusive FIFO, slab-pooled records and levels, negated asks; index
// still std::unordered_map (itch-book's "unordered_map" step).
using VecIntrStdPolicies =
    Policies<lob::VecLevels, lob::IntrusiveFifo, lob::PoolStore<lob::StdIndex>, lob::HeapBacking, true>;

// + Robin Hood flat map (X04).
using VecIntrFlatPolicies =
    Policies<lob::VecLevels, lob::IntrusiveFifo, lob::PoolStore<lob::FlatIndex<>>, lob::HeapBacking, true>;

// + paged direct index with flat-map fallback (X05): the optimized variant.
using OptPolicies =
    Policies<lob::VecLevels, lob::IntrusiveFifo, lob::PoolStore<lob::PagedIndex<>>, lob::HeapBacking, true>;

// Optimized on huge-page arenas (X12): records, levels, index pages.
using HugeArena = lob::ArenaBacking<lob::HugePages::kTransparent, false>;
using OptHugePolicies =
    Policies<lob::VecLevels, lob::IntrusiveFifo,
             lob::PoolStore<lob::PagedIndex<lob::FlatIndex<lob::FibonacciHash, HugeArena>, HugeArena>, HugeArena>,
             HugeArena, true>;

// Price window + bitmap levels instead of sorted vectors (X20).
using WinPolicies =
    Policies<lob::WindowLevels<10>, lob::IntrusiveFifo, lob::PoolStore<lob::PagedIndex<>>, lob::HeapBacking, true>;

// Cross-combinations, kept so every policy is fuzzed in other pairings:
// map levels with pooled intrusive records and an identity-hash flat map;
// a small window with separate comparators (Lower for asks), std::list
// FIFOs over pooled records, and a mixing-hash flat map.
using MapIntrFlatPolicies = Policies<lob::MapLevels, lob::IntrusiveFifo,
                                     lob::PoolStore<lob::FlatIndex<lob::IdentityHash>>, lob::HeapBacking, false>;
using WinListFlatPolicies = Policies<lob::WindowLevels<7>, lob::ListFifo, lob::PoolStore<lob::FlatIndex<lob::MixHash>>,
                                     lob::HeapBacking, false>;

template <class L = NullListener>
using OptBook = ItchBook<OptPolicies, L>;

// --- variant registry for harnesses -----------------------------------------
template <class P, bool kVirtual>
struct VariantTag {
  using Policies = P;
  static constexpr bool kVirtualListener = kVirtual;  // B0 reports through BookListener
};

struct VarB0 : VariantTag<B0Policies, true> {
  static constexpr std::string_view kName = "b0";
  static constexpr std::string_view kDesc = "std::map levels, std::list FIFO, unordered_map<u64,Order>, virtual listener";
};
struct VarVecListStd : VariantTag<VecListStdPolicies, false> {
  static constexpr std::string_view kName = "vec_list_std";
  static constexpr std::string_view kDesc = "sorted-vector levels, std::list FIFO, unordered_map<u64,Order>";
};
struct VarVecIntrStd : VariantTag<VecIntrStdPolicies, false> {
  static constexpr std::string_view kName = "vec_intr_std";
  static constexpr std::string_view kDesc = "sorted-vector levels, intrusive FIFO, slab pools, unordered_map index, neg asks";
};
struct VarVecIntrFlat : VariantTag<VecIntrFlatPolicies, false> {
  static constexpr std::string_view kName = "vec_intr_flat";
  static constexpr std::string_view kDesc = "sorted-vector levels, intrusive FIFO, slab pools, Robin Hood index, neg asks";
};
struct VarOpt : VariantTag<OptPolicies, false> {
  static constexpr std::string_view kName = "opt";
  static constexpr std::string_view kDesc = "sorted-vector levels, intrusive FIFO, slab pools, paged index, neg asks";
};
struct VarOptHuge : VariantTag<OptHugePolicies, false> {
  static constexpr std::string_view kName = "opt_huge";
  static constexpr std::string_view kDesc = "opt on huge-page arenas (MADV_HUGEPAGE on Linux, plain mmap on macOS)";
};
struct VarWin : VariantTag<WinPolicies, false> {
  static constexpr std::string_view kName = "win";
  static constexpr std::string_view kDesc = "1024-slot price window + tzcnt bitmap levels, intrusive FIFO, paged index";
};
struct VarMapIntrFlat : VariantTag<MapIntrFlatPolicies, false> {
  static constexpr std::string_view kName = "map_intr_flat";
  static constexpr std::string_view kDesc = "std::map levels, intrusive FIFO, slab pools, identity-hash Robin Hood index";
};
struct VarWinListFlat : VariantTag<WinListFlatPolicies, false> {
  static constexpr std::string_view kName = "win_list_flat";
  static constexpr std::string_view kDesc = "128-slot window (no negation), std::list FIFO, pooled records, mix-hash index";
};

using AllVariants = std::tuple<VarB0, VarVecListStd, VarVecIntrStd, VarVecIntrFlat, VarOpt, VarOptHuge, VarWin,
                               VarMapIntrFlat, VarWinListFlat>;

// Calls f.template operator()<V>() for the variant named `name`.
template <class F>
bool visit_variant(std::string_view name, F&& f) {
  return [&]<class... V>(std::tuple<V...>*) {
    return ((V::kName == name ? (f.template operator()<V>(), true) : false) || ...);
  }(static_cast<AllVariants*>(nullptr));
}

// Calls f.template operator()<V>() for every variant in registry order.
template <class F>
void for_each_variant(F&& f) {
  [&]<class... V>(std::tuple<V...>*) { (f.template operator()<V>(), ...); }(static_cast<AllVariants*>(nullptr));
}

static_assert(ItchEventSink<B0Book>);
static_assert(ItchEventSink<OptBook<>>);
static_assert(sizeof(Order<OptPolicies>) == 32, "hot order record is 32 bytes (X09)");

}  // namespace lle::book
