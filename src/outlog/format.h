#pragma once
// Output log on-disk format (06 §8, ADR-029).
//
// Data file: NASDAQ BinaryFILE framing, records of
//   [u16 big-endian length][message bytes]
// with length 1..65535. The writer never emits the zero-length end-of-session
// record, so a zero length prefix inside a data file marks the end of valid
// data (typically a zero-filled tail after a crash). The sequence number of a
// message is its 1-based position in the file: the MoldUDP64 sequence for
// itch.bin, the SoupBinTCP sequence for soup-<session>.bin.
//
// Sparse index `<data>.idx`: a 32-byte header, then u64 little-endian entries.
// Entry k is the byte offset of the length prefix of message k*4096 + 1, so
// entry 0 is 0. Header layout (little-endian):
//   [0, 8)   magic "LLEOIDX1"
//   [8, 12)  version = 1
//   [12, 16) interval = 4096
//   [16, 24) reserved = 0
//   [24, 28) reserved = 0
//   [28, 32) CRC32C of bytes [0, 28)
// The index is derived from the data file, which is itself derived from the
// journal: every consumer validates it against the data and rebuilds it by
// scanning when it is missing, short or inconsistent.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "common/types.h"

namespace lle::outlog {

inline constexpr std::size_t kLengthPrefixBytes = 2;
inline constexpr std::size_t kMaxMessageBytes = 65'535;  // largest u16 length
inline constexpr std::size_t kMinRecordBytes = kLengthPrefixBytes + 1;
inline constexpr std::size_t kMaxRecordBytes = kLengthPrefixBytes + kMaxMessageBytes;

inline constexpr std::uint32_t kIndexInterval = 4096;  // messages per index entry (06 §8)
inline constexpr std::uint32_t kIndexVersion = 1;
inline constexpr std::size_t kIndexHeaderBytes = 32;
inline constexpr std::size_t kIndexEntryBytes = 8;
inline constexpr std::size_t kIndexCrcOffset = 28;
inline constexpr std::string_view kIndexMagic = "LLEOIDX1";

enum class Error : std::uint8_t {
  NotOpen,          // the writer or reader is not open
  EmptyMessage,     // zero-length messages are BinaryFILE end-of-session markers; never written
  MessageTooLarge,  // longer than 65,535 bytes: does not fit the u16 length prefix
  Io,               // a system call failed; a writer stays failed afterwards
  OutOfRange,       // sequence number outside [1, count] (or count larger than the log)
  ScratchTooSmall,  // the caller's buffer is shorter than the message
  Corrupt,          // the data changed underneath an open reader (truncated or rewritten)
  Locked,           // another writer holds the data file
};

[[nodiscard]] const char* to_string(Error e) noexcept;

[[nodiscard]] std::array<std::byte, kIndexHeaderBytes> encode_index_header() noexcept;
[[nodiscard]] bool index_header_valid(std::span<const std::byte> header) noexcept;

// `<data path>.idx`.
[[nodiscard]] std::string index_path(const std::string& data_path);

// Number of index entries for a file that holds `count` messages.
[[nodiscard]] constexpr std::uint64_t index_entries_for(SeqNo count) noexcept {
  return (count + kIndexInterval - 1) / kIndexInterval;
}

}  // namespace lle::outlog
