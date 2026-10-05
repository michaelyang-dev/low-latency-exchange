#pragma once
// L3 segment files (06 §6): `journal/<day>/<epoch:04>-<first_index:020>.seg`, 1 GiB by
// default, starting with a 4 KiB header block. Records follow from offset 4096; every
// write is a whole number of 4 KiB blocks (each batch is padded with a Pad record), so
// appends are pure overwrites of pre-zeroed space.
//
// Header block layout (little-endian):
//    0 char[8] magic "LLEJRNL1"
//    8 u32 version (1)
//   12 u32 header_bytes (4096)
//   16 u32 day (YYYYMMDD)
//   20 u32 epoch (epoch of the first record; 0 while unassigned)
//   24 u64 first_index (0: prepared, not yet assigned to a position in the journal)
//   32 u64 nonce (seeds every record seal in this segment; fresh on each preparation)
//   40 u32 prev_last_crc (content crc of the previous segment's last record; 0 first of day)
//   44 u32 reserved (0)
//   48 u64 segment_bytes (file size including the header)
//   56 ... zeros
// 4092 u32 header_crc = CRC32C(bytes [0, 4092))
//
// Segments are identified by their header, not their file name: recovery reads every
// *.seg file in the directory, so a crash between assigning a segment and renaming it
// to its canonical name loses nothing.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace lle::journal {

inline constexpr std::uint32_t kBlockBytes = 4096;
inline constexpr std::uint32_t kSegmentHeaderBytes = 4096;
inline constexpr std::uint32_t kSegmentVersion = 1;
inline constexpr std::array<char, 8> kSegmentMagic = {'L', 'L', 'E', 'J', 'R', 'N', 'L', '1'};
inline constexpr std::uint64_t kDefaultSegmentBytes = std::uint64_t{1} << 30;
// Group commit (06 §6): batches of up to 64 KiB, queue depth <= 4.
inline constexpr std::uint32_t kBatchBytes = 64 * 1024;
inline constexpr std::uint32_t kQueueDepth = 4;
// The in-flight window of recovery (06 §7): QD x 64 KiB beyond the last valid record.
inline constexpr std::uint64_t kInflightWindow = std::uint64_t{kQueueDepth} * kBatchBytes;

struct SegmentHeader {
  std::uint32_t version = kSegmentVersion;
  std::uint32_t day = 0;
  std::uint32_t epoch = 0;
  std::uint64_t first_index = 0;
  std::uint64_t nonce = 0;
  std::uint32_t prev_last_crc = 0;
  std::uint64_t segment_bytes = 0;

  [[nodiscard]] bool assigned() const noexcept { return first_index != 0; }
  friend constexpr bool operator==(const SegmentHeader&, const SegmentHeader&) = default;
};

enum class HeaderError : std::uint8_t {
  Truncated,   // fewer than 4096 bytes
  BadMagic,
  BadVersion,
  BadCrc,
  BadNonce,    // 0 or a nonce whose seed is 0
  BadSize,     // segment_bytes not a multiple of 4 KiB or too small for one batch
};
[[nodiscard]] std::string_view to_string(HeaderError e) noexcept;

// Smallest legal segment: the header plus one full batch.
inline constexpr std::uint64_t kMinSegmentBytes = kSegmentHeaderBytes + kBatchBytes;

// Writes the 4096-byte header block.
void encode_segment_header(std::span<std::byte, kSegmentHeaderBytes> out, const SegmentHeader& h) noexcept;
[[nodiscard]] std::expected<SegmentHeader, HeaderError> decode_segment_header(std::span<const std::byte> block) noexcept;

// "<epoch:04>-<first_index:020>.seg"
[[nodiscard]] std::string segment_file_name(std::uint32_t epoch, std::uint64_t first_index);
// Name of a prepared (unassigned) segment in the pool: "prep-<n:06>.seg".
[[nodiscard]] std::string prepared_file_name(std::uint64_t n);

[[nodiscard]] constexpr std::uint64_t align_down_block(std::uint64_t v) noexcept { return v & ~std::uint64_t{kBlockBytes - 1}; }
[[nodiscard]] constexpr std::uint64_t align_up_block(std::uint64_t v) noexcept {
  return (v + (kBlockBytes - 1)) & ~std::uint64_t{kBlockBytes - 1};
}

// Bytes a batch of `used` bytes occupies once padded to the next 4 KiB boundary with a
// Pad record. A Pad needs at least a header, so a gap of 8..32 bytes takes one more
// block.
[[nodiscard]] constexpr std::uint64_t padded_batch_bytes(std::uint64_t used) noexcept {
  const std::uint64_t up = align_up_block(used);
  const std::uint64_t gap = up - used;
  return (gap == 0 || gap >= 40) ? up : up + kBlockBytes;
}

}  // namespace lle::journal
