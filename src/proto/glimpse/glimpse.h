#pragma once
// GLIMPSE-style snapshot payloads (03-protocols §8; R1b D5).
//
// A spin is a sequence of payloads, one per SoupBinTCP sequenced-data message
// (the SoupBinTCP framing is another track): ITCH 5.0 messages of the types
// below, then End of Snapshot:
//   'G' Message Type @0/1, Sequence Number @1/20 (ASCII numeric)   = 21 bytes.
// Decision (NASDAQ's wording is ambiguous, R1b Risk 8): the sequence number is
// S(P)+1, the next MoldUDP64/ITCH sequence to apply after the snapshot. It is
// emitted right-justified and space padded (the SoupBinTCP numeric convention);
// left/right padding and leading zeros are accepted on input.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "common/alpha.h"
#include "common/types.h"

namespace lle::glimpse {

inline constexpr char kEndOfSnapshotType = 'G';
inline constexpr std::size_t kSequenceDigits = 20;
inline constexpr std::size_t kEndOfSnapshotLen = 1 + kSequenceDigits;

// ITCH 5.0 types a snapshot may carry: system events, directory, trading
// action, Reg SHO, operational halt, and resting displayed orders.
[[nodiscard]] constexpr bool is_snapshot_type(char t) noexcept {
  return t == 'S' || t == 'R' || t == 'H' || t == 'Y' || t == 'h' || t == 'A' || t == 'F';
}

inline std::size_t encode_end_of_snapshot(std::span<std::byte> out, SeqNo next_seq) noexcept {
  if (out.size() < kEndOfSnapshotLen) return 0;
  out[0] = static_cast<std::byte>(kEndOfSnapshotType);
  format_padded_decimal(reinterpret_cast<char*>(out.data() + 1), kSequenceDigits, next_seq);
  return kEndOfSnapshotLen;
}

enum class EndOfSnapshotError : std::uint8_t { NotEndOfSnapshot, BadLength, BadNumber };

[[nodiscard]] inline std::expected<SeqNo, EndOfSnapshotError> decode_end_of_snapshot(
    std::span<const std::byte> in) noexcept {
  if (in.empty() || static_cast<char>(in[0]) != kEndOfSnapshotType)
    return std::unexpected(EndOfSnapshotError::NotEndOfSnapshot);
  if (in.size() != kEndOfSnapshotLen) return std::unexpected(EndOfSnapshotError::BadLength);
  const std::string_view s(reinterpret_cast<const char*>(in.data() + 1), kSequenceDigits);
  std::size_t b = 0, e = s.size();
  while (b < e && s[b] == ' ') ++b;
  while (e > b && s[e - 1] == ' ') --e;
  if (b == e) return std::unexpected(EndOfSnapshotError::BadNumber);
  SeqNo v = 0;
  for (std::size_t i = b; i < e; ++i) {
    const char c = s[i];
    if (c < '0' || c > '9') return std::unexpected(EndOfSnapshotError::BadNumber);
    const auto d = static_cast<SeqNo>(c - '0');
    if (v > (~SeqNo{0} - d) / 10) return std::unexpected(EndOfSnapshotError::BadNumber);  // > 2^64-1
    v = v * 10 + d;
  }
  return v;
}

}  // namespace lle::glimpse
