#include "journal/segment.h"

#include <cstdio>
#include <cstring>

#include "common/crc32c.h"
#include "common/endian.h"
#include "journal/record.h"

namespace lle::journal {

namespace {
constexpr std::size_t kOffVersion = 8;
constexpr std::size_t kOffHeaderBytes = 12;
constexpr std::size_t kOffDay = 16;
constexpr std::size_t kOffEpoch = 20;
constexpr std::size_t kOffFirstIndex = 24;
constexpr std::size_t kOffNonce = 32;
constexpr std::size_t kOffPrevLastCrc = 40;
constexpr std::size_t kOffSegmentBytes = 48;
constexpr std::size_t kOffHeaderCrc = kSegmentHeaderBytes - 4;
// A Pad record must fit in the smallest gap padded_batch_bytes() leaves.
static_assert(kHeaderBytes == 40);
}  // namespace

std::string_view to_string(HeaderError e) noexcept {
  switch (e) {
    case HeaderError::Truncated: return "truncated";
    case HeaderError::BadMagic: return "bad magic";
    case HeaderError::BadVersion: return "bad version";
    case HeaderError::BadCrc: return "bad header crc";
    case HeaderError::BadNonce: return "bad nonce";
    case HeaderError::BadSize: return "bad segment size";
  }
  return "unknown";
}

void encode_segment_header(std::span<std::byte, kSegmentHeaderBytes> out, const SegmentHeader& h) noexcept {
  std::memset(out.data(), 0, out.size());
  std::memcpy(out.data(), kSegmentMagic.data(), kSegmentMagic.size());
  store_le32(out.data() + kOffVersion, h.version);
  store_le32(out.data() + kOffHeaderBytes, kSegmentHeaderBytes);
  store_le32(out.data() + kOffDay, h.day);
  store_le32(out.data() + kOffEpoch, h.epoch);
  store_le64(out.data() + kOffFirstIndex, h.first_index);
  store_le64(out.data() + kOffNonce, h.nonce);
  store_le32(out.data() + kOffPrevLastCrc, h.prev_last_crc);
  store_le64(out.data() + kOffSegmentBytes, h.segment_bytes);
  store_le32(out.data() + kOffHeaderCrc, crc32c(out.data(), kOffHeaderCrc));
}

std::expected<SegmentHeader, HeaderError> decode_segment_header(std::span<const std::byte> block) noexcept {
  if (block.size() < kSegmentHeaderBytes) return std::unexpected(HeaderError::Truncated);
  if (std::memcmp(block.data(), kSegmentMagic.data(), kSegmentMagic.size()) != 0) {
    return std::unexpected(HeaderError::BadMagic);
  }
  if (crc32c(block.data(), kOffHeaderCrc) != load_le32(block.data() + kOffHeaderCrc)) {
    return std::unexpected(HeaderError::BadCrc);
  }
  SegmentHeader h;
  h.version = load_le32(block.data() + kOffVersion);
  if (h.version != kSegmentVersion || load_le32(block.data() + kOffHeaderBytes) != kSegmentHeaderBytes) {
    return std::unexpected(HeaderError::BadVersion);
  }
  h.day = load_le32(block.data() + kOffDay);
  h.epoch = load_le32(block.data() + kOffEpoch);
  h.first_index = load_le64(block.data() + kOffFirstIndex);
  h.nonce = load_le64(block.data() + kOffNonce);
  h.prev_last_crc = load_le32(block.data() + kOffPrevLastCrc);
  h.segment_bytes = load_le64(block.data() + kOffSegmentBytes);
  if (!usable_nonce(h.nonce)) return std::unexpected(HeaderError::BadNonce);
  if (h.segment_bytes < kMinSegmentBytes || h.segment_bytes % kBlockBytes != 0) {
    return std::unexpected(HeaderError::BadSize);
  }
  return h;
}

std::string segment_file_name(std::uint32_t epoch, std::uint64_t first_index) {
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%04u-%020llu.seg", epoch, static_cast<unsigned long long>(first_index));
  return buf;
}

std::string prepared_file_name(std::uint64_t n) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "prep-%06llu.seg", static_cast<unsigned long long>(n));
  return buf;
}

}  // namespace lle::journal
