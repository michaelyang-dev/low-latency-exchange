#include "snapshot/format.h"

#include <charconv>
#include <cstring>
#include <format>
#include <limits>

#include "common/crc32c.h"
#include "common/endian.h"

namespace lle::snap {

bool sessions_canonical(std::span<const SessionSeq> sessions) noexcept {
  for (std::size_t i = 1; i < sessions.size(); ++i) {
    if (sessions[i - 1].session_id >= sessions[i].session_id) return false;
  }
  return true;
}

std::optional<SnapshotLayout> compute_layout(std::uint64_t chunk_bytes, std::uint32_t session_count,
                                             std::uint64_t payload_bytes) noexcept {
  if (!valid_chunk_bytes(chunk_bytes)) return std::nullopt;
  // Division first: payload_bytes + chunk_bytes - 1 could wrap for hostile headers.
  const std::uint64_t full = payload_bytes / chunk_bytes;
  const std::uint64_t tail = payload_bytes % chunk_bytes;
  const std::uint64_t count = full + (tail != 0 ? 1 : 0);
  if (count > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
  // Bounded now: full < 2^32 and chunk_bytes <= 2^30, so the sum stays below 2^63.
  SnapshotLayout l;
  l.chunk_bytes = static_cast<std::uint32_t>(chunk_bytes);
  l.chunk_count = static_cast<std::uint32_t>(count);
  l.session_count = session_count;
  l.payload_bytes = payload_bytes;
  l.payload_offset = std::uint64_t{kHeaderBytes} + std::uint64_t{kSessionEntryBytes} * session_count +
                     kSessionTableTailBytes;
  l.file_bytes = l.payload_offset + full * chunk_frame_bytes(chunk_bytes) + (tail != 0 ? chunk_frame_bytes(tail) : 0) +
                 kTrailerBytes;
  return l;
}

std::uint32_t chunk_crc(std::uint64_t chunk_index, std::span<const std::byte> data) noexcept {
  std::byte seed[8];
  store_le64(seed, chunk_index);
  return crc32c_extend(crc32c(seed, sizeof(seed)), data.data(), data.size());
}

std::array<std::byte, kHeaderBytes> encode_header(const SnapshotMeta& meta, const SnapshotLayout& layout) noexcept {
  std::array<std::byte, kHeaderBytes> h{};
  std::byte* p = h.data();
  std::memcpy(p + hdr::kMagic, kMagic.data(), kMagic.size());
  store_le32(p + hdr::kVersion, kVersion);
  store_le32(p + hdr::kHeaderBytes, kHeaderBytes);
  store_le32(p + hdr::kDay, meta.day);
  store_le32(p + hdr::kEpoch, meta.epoch);
  store_le64(p + hdr::kIndex, meta.index);
  store_le64(p + hdr::kSnapshotId, meta.snapshot_id);
  store_le64(p + hdr::kMoldSeq, meta.mold_seq);
  store_le64(p + hdr::kStateHash, meta.state_hash);
  store_le64(p + hdr::kBuildId, meta.build_id);
  store_le32(p + hdr::kChunkBytes, layout.chunk_bytes);
  store_le32(p + hdr::kSessionCount, layout.session_count);
  store_le64(p + hdr::kPayloadBytes, layout.payload_bytes);
  store_le32(p + hdr::kChunkCount, layout.chunk_count);
  // flags and reserved stay zero in v1.
  store_le32(p + hdr::kHeaderCrc, crc32c(p, hdr::kHeaderCrc));
  return h;
}

std::array<std::byte, kTrailerBytes> encode_trailer(std::uint64_t file_bytes, std::uint32_t header_crc,
                                                    std::uint32_t sections_crc) noexcept {
  std::array<std::byte, kTrailerBytes> t{};
  std::byte* p = t.data();
  std::memcpy(p + trl::kMagic, kTrailerMagic.data(), kTrailerMagic.size());
  store_le64(p + trl::kFileBytes, file_bytes);
  store_le32(p + trl::kHeaderCrc, header_crc);
  store_le32(p + trl::kSectionsCrc, sections_crc);
  store_le32(p + trl::kTrailerCrc, crc32c(p, trl::kTrailerCrc));
  return t;
}

namespace {

const char* code_name(ErrorCode c) noexcept {
  switch (c) {
    case ErrorCode::InvalidArgument:
      return "invalid argument";
    case ErrorCode::UnsortedSessions:
      return "sessions not strictly ascending";
    case ErrorCode::TooLarge:
      return "payload too large";
    case ErrorCode::OutOfMemory:
      return "out of memory";
    case ErrorCode::Io:
      return "i/o error";
    case ErrorCode::Closed:
      return "writer closed";
  }
  return "unknown";
}

}  // namespace

std::string to_string(const Error& e) {
  std::string s = code_name(e.code);
  if (e.op != nullptr && e.op[0] != '\0') {
    s += ": ";
    s += e.op;
  }
  if (e.sys_errno != 0) {
    s += ": ";
    s += std::strerror(e.sys_errno);
  }
  return s;
}

std::string_view to_string(LoadError e) noexcept {
  switch (e) {
    case LoadError::Truncated:
      return "truncated";
    case LoadError::BadMagic:
      return "bad magic";
    case LoadError::UnsupportedVersion:
      return "unsupported version";
    case LoadError::BadHeader:
      return "bad header";
    case LoadError::BadHeaderCrc:
      return "bad header crc";
    case LoadError::BadChunkSize:
      return "bad chunk size";
    case LoadError::BadChunkCount:
      return "bad chunk count";
    case LoadError::BadLength:
      return "bad length";
    case LoadError::BadTrailer:
      return "bad trailer";
    case LoadError::BadSessionTable:
      return "bad session table";
    case LoadError::UnsortedSessions:
      return "unsorted sessions";
    case LoadError::BadChunkCrc:
      return "bad chunk crc";
    case LoadError::BadPadding:
      return "bad padding";
    case LoadError::Io:
      return "i/o error";
  }
  return "unknown";
}

std::string snapshot_day_dir(const std::string& data_root, std::uint32_t day) {
  return std::format("{}{}snap/{:08}", data_root, data_root.empty() || data_root.back() == '/' ? "" : "/", day);
}

std::string snapshot_file_name(std::uint64_t index) { return std::format("{:020}{}", index, kSnapshotSuffix); }

namespace {

std::string join(const std::string& dir, std::string_view name) {
  std::string s = dir;
  if (!s.empty() && s.back() != '/') s += '/';
  s += name;
  return s;
}

}  // namespace

std::string snapshot_path(const std::string& day_dir, std::uint64_t index) {
  return join(day_dir, snapshot_file_name(index));
}

std::string snapshot_temp_path(const std::string& day_dir, std::uint64_t index) {
  return join(day_dir, std::format("{:020}{}", index, kTempSuffix));
}

std::optional<std::uint64_t> parse_snapshot_file_name(std::string_view file_name) noexcept {
  if (file_name.size() != kIndexDigits + kSnapshotSuffix.size()) return std::nullopt;
  if (file_name.substr(kIndexDigits) != kSnapshotSuffix) return std::nullopt;
  const std::string_view digits = file_name.substr(0, kIndexDigits);
  std::uint64_t v = 0;
  // from_chars on an unsigned type accepts digits only (no sign, no space), so
  // consuming all 20 characters means all are digits; values above u64 max give
  // result_out_of_range.
  const auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), v);
  if (ec != std::errc{} || ptr != digits.data() + digits.size()) return std::nullopt;
  return v;
}

}  // namespace lle::snap
