#pragma once
// GLIMPSE-style snapshot server core (03-protocols §8): turns a caller-provided
// view of replica state at journal position P into the spin payloads
//   S..., R..., H..., Y..., h..., A/F..., G(S(P)+1)
// handed one by one to `sink(std::span<const std::byte>)` (each becomes one
// SoupBinTCP sequenced message; the session that carries them is another
// track's). Deterministic: the order is fixed by category, then by the order in
// which the state view visits items.
//
// State view (any type):
//   SeqNo snapshot_next_seq() const;          // S(P)+1
//   void visit_system_events(F&&) const;      // F(const itch50::SystemEvent&)
//   void visit_stock_directory(F&&) const;    // F(const itch50::StockDirectory&)
//   void visit_trading_actions(F&&) const;    // F(const itch50::StockTradingAction&)
//   void visit_reg_sho(F&&) const;            // F(const itch50::RegShoRestriction&)
//   void visit_operational_halts(F&&) const;  // F(const itch50::OperationalHalt&)
//   void visit_orders(F&&) const;             // F(const itch50::AddOrder&) or F(const itch50::AddOrderMpid&)
#include <array>
#include <concepts>
#include <cstdint>
#include <span>
#include <type_traits>

#include "common/types.h"
#include "proto/glimpse/glimpse.h"
#include "proto/itch50/itch50.h"

namespace lle::glimpse {

namespace detail {
// Archetype used only to check the state-view concept.
struct AnyMessageFn {
  template <class M>
  void operator()(const M&) const noexcept {}
};

template <class M>
inline constexpr bool kSnapshotMessage =
    std::is_same_v<M, itch50::SystemEvent> || std::is_same_v<M, itch50::StockDirectory> ||
    std::is_same_v<M, itch50::StockTradingAction> || std::is_same_v<M, itch50::RegShoRestriction> ||
    std::is_same_v<M, itch50::OperationalHalt> || std::is_same_v<M, itch50::AddOrder> ||
    std::is_same_v<M, itch50::AddOrderMpid>;
}  // namespace detail

template <class S>
concept SnapshotStateLike = requires(const S& s, detail::AnyMessageFn f) {
  { s.snapshot_next_seq() } -> std::convertible_to<SeqNo>;
  s.visit_system_events(f);
  s.visit_stock_directory(f);
  s.visit_trading_actions(f);
  s.visit_reg_sho(f);
  s.visit_operational_halts(f);
  s.visit_orders(f);
};

struct SpinStats {
  std::uint64_t messages = 0;  // including the final G
  std::array<std::uint64_t, 256> by_type{};
  SeqNo next_seq = 0;
};

class SnapshotServer {
 public:
  template <SnapshotStateLike State, class Sink>
  SpinStats emit(const State& state, Sink&& sink) const {
    SpinStats st;
    std::array<std::byte, itch50::kMaxMsgLen> buf{};
    const auto put = [&](const auto& m) {
      using M = std::decay_t<decltype(m)>;
      static_assert(detail::kSnapshotMessage<M>, "GLIMPSE spin carries only S, R, H, Y, h, A and F");
      const std::size_t n = itch50::encode(buf, m);
      ++st.messages;
      ++st.by_type[static_cast<unsigned char>(M::kType)];
      sink(std::span<const std::byte>(buf.data(), n));
    };
    state.visit_system_events(put);
    state.visit_stock_directory(put);
    state.visit_trading_actions(put);
    state.visit_reg_sho(put);
    state.visit_operational_halts(put);
    state.visit_orders(put);
    st.next_seq = static_cast<SeqNo>(state.snapshot_next_seq());
    std::array<std::byte, kEndOfSnapshotLen> g{};
    (void)encode_end_of_snapshot(g, st.next_seq);
    ++st.messages;
    ++st.by_type[static_cast<unsigned char>(kEndOfSnapshotType)];
    sink(std::span<const std::byte>(g.data(), g.size()));
    return st;
  }
};

}  // namespace lle::glimpse
