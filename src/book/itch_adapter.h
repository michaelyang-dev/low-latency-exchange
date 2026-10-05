#pragma once
// ITCH 5.0 -> book dispatch (04-order-book §5): the thin sans-I/O adapter that
// lob_replay and itch_replay_diff put between BinaryFILE framing and a book.
//
// Book semantics follow R1a Q6: R declares the locate; A/F add; E, C and X
// reduce (C is applied whatever its Printable flag; the execution price is not
// a book input); D removes; U replaces. Every other message type changes no
// book and is only counted. Locate is used as given, as an array index.
#include <cstddef>
#include <cstdint>

#include "book/itch_book.h"
#include "proto/itch50/itch50.h"

namespace lle::book {

enum class ItchKind : std::uint8_t {
  kDirectory,  // R
  kAdd,        // A, F
  kExecute,    // E
  kExecPrice,  // C
  kCancel,     // X
  kDelete,     // D
  kReplace,    // U
  kOther,      // no book effect
  kMalformed,  // length does not match the type's spec length (never in NASDAQ files)
};
inline constexpr std::size_t kItchKinds = 9;

[[nodiscard]] constexpr const char* to_string(ItchKind k) noexcept {
  constexpr const char* kNames[kItchKinds] = {"R", "AF", "E", "C", "X", "D", "U", "other", "malformed"};
  return kNames[static_cast<std::size_t>(k)];
}

struct ItchResult {
  ItchKind kind;
  Status status;
};

// One book event decoded from a message, for harnesses that need the operands
// (itch_replay_diff feeds them to both books).
struct ItchEvent {
  ItchKind kind = ItchKind::kOther;
  Side side = Side::Buy;
  Locate loc = 0;
  OrderRef ref = 0;
  OrderRef new_ref = 0;  // U only
  PxE4 px = 0;           // A/F/U
  Qty qty = 0;           // shares added, removed, or the replacement size
};

[[nodiscard]] inline ItchEvent decode_book_event(const std::byte* m, std::size_t n) noexcept {
  ItchEvent e;
  if (n == 0 || n != itch50::kMsgLen[static_cast<unsigned char>(m[0])]) {
    e.kind = ItchKind::kMalformed;
    return e;
  }
  e.loc = itch50::MessageHeaderView(m).stock_locate();
  switch (static_cast<char>(m[0])) {
    case 'R': e.kind = ItchKind::kDirectory; break;
    case 'A': {
      const itch50::AddOrderView v(m);
      e = {ItchKind::kAdd, v.side(), e.loc, v.order_ref(), 0, v.price(), v.shares()};
      break;
    }
    case 'F': {
      const itch50::AddOrderMpidView v(m);
      e = {ItchKind::kAdd, v.side(), e.loc, v.order_ref(), 0, v.price(), v.shares()};
      break;
    }
    case 'E': {
      const itch50::OrderExecutedView v(m);
      e.kind = ItchKind::kExecute;
      e.ref = v.order_ref();
      e.qty = v.executed_shares();
      break;
    }
    case 'C': {
      const itch50::OrderExecutedWithPriceView v(m);
      e.kind = ItchKind::kExecPrice;
      e.ref = v.order_ref();
      e.qty = v.executed_shares();
      break;
    }
    case 'X': {
      const itch50::OrderCancelView v(m);
      e.kind = ItchKind::kCancel;
      e.ref = v.order_ref();
      e.qty = v.cancelled_shares();
      break;
    }
    case 'D':
      e.kind = ItchKind::kDelete;
      e.ref = itch50::OrderDeleteView(m).order_ref();
      break;
    case 'U': {
      const itch50::OrderReplaceView v(m);
      e.kind = ItchKind::kReplace;
      e.ref = v.original_order_ref();
      e.new_ref = v.new_order_ref();
      e.px = v.price();
      e.qty = v.shares();
      break;
    }
    default: break;
  }
  return e;
}

// Applies one message (type byte first, `n` bytes) to the book.
template <ItchEventSink Book>
[[gnu::always_inline]] inline ItchResult apply_itch(Book& b, const std::byte* m, std::size_t n) {
  if (n == 0 || n != itch50::kMsgLen[static_cast<unsigned char>(m[0])]) [[unlikely]]
    return {ItchKind::kMalformed, Status::kOk};
  switch (static_cast<char>(m[0])) {
    case 'A': {
      const itch50::AddOrderView v(m);
      return {ItchKind::kAdd, b.add(v.order_ref(), v.stock_locate(), v.side(), v.price(), v.shares())};
    }
    case 'D': return {ItchKind::kDelete, b.remove(itch50::OrderDeleteView(m).order_ref())};
    case 'U': {
      const itch50::OrderReplaceView v(m);
      return {ItchKind::kReplace, b.replace(v.original_order_ref(), v.new_order_ref(), v.price(), v.shares())};
    }
    case 'E': {
      const itch50::OrderExecutedView v(m);
      return {ItchKind::kExecute, b.reduce(v.order_ref(), v.executed_shares())};
    }
    case 'X': {
      const itch50::OrderCancelView v(m);
      return {ItchKind::kCancel, b.reduce(v.order_ref(), v.cancelled_shares())};
    }
    case 'F': {
      const itch50::AddOrderMpidView v(m);
      return {ItchKind::kAdd, b.add(v.order_ref(), v.stock_locate(), v.side(), v.price(), v.shares())};
    }
    case 'C': {
      const itch50::OrderExecutedWithPriceView v(m);
      return {ItchKind::kExecPrice, b.reduce(v.order_ref(), v.executed_shares())};
    }
    case 'R': b.stock_directory(itch50::MessageHeaderView(m).stock_locate()); return {ItchKind::kDirectory, Status::kOk};
    default: return {ItchKind::kOther, Status::kOk};
  }
}

// Lookahead hint for the message `D` records ahead (04 §6 "Prefetch disclosure":
// at most 16). Every book message type carries its order reference at offset 11;
// U also inserts its new reference at offset 19.
template <class Book>
[[gnu::always_inline]] inline void prefetch_itch(const Book& b, const std::byte* m) noexcept {
  switch (static_cast<char>(m[0])) {
    case 'U': b.prefetch(load_be64(m + 19)); [[fallthrough]];
    case 'A': case 'F': case 'E': case 'C': case 'X': case 'D': b.prefetch(load_be64(m + 11)); break;
    default: break;
  }
}

}  // namespace lle::book
