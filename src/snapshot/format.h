#pragma once
// Snapshot container format v1 (06 §9, ADR-007).
//
// `snapshotd` replays the journal in its own process and, at every SnapshotMark
// record, asks its engine to serialize itself into a Writer. The engine owns the
// payload bytes (a canonical, sorted serialization of books, orders, risk, dedupe,
// auction/halt state, counters and timers); this module owns the container around
// them: identity, the values recovery needs before it can touch the payload (the
// MoldUDP64 output sequence S(P) and the SoupBinTCP next sequence per session),
// integrity (CRC32C per chunk, 06 §9) and atomic publication.
//
// Files live at `snap/<day>/<index:020>.snap`. All integers are little-endian.
// Every section starts at an 8-byte-aligned offset. The format is canonical: all
// reserved fields and padding must be zero, so an image the loader accepts
// re-encodes to exactly the same bytes (the fuzz harness checks this).
//
// Header (128 bytes, offset 0):
//   off  size  field
//     0     8  magic          "LLESNAP1"
//     8     4  version        1
//    12     4  header_bytes   128
//    16     4  day            trading date, YYYYMMDD
//    20     4  epoch          replication epoch of record P
//    24     8  index          P: the state after applying journal records 1..P
//    32     8  snapshot_id    from the SnapshotMark record
//    40     8  mold_seq       S(P): ITCH messages derived from records <= P
//    48     8  state_hash     engine state_hash() at P (primary/backup cross-check)
//    56     8  build_id
//    64     4  chunk_bytes    payload chunk size: power of two in [4 KiB, 1 GiB]
//    68     4  session_count  entries in the session table
//    72     8  payload_bytes  engine payload length
//    80     4  chunk_count    == ceil(payload_bytes / chunk_bytes)
//    84     4  flags          0 in v1
//    88    36  reserved       zero
//   124     4  header_crc     CRC32C of bytes [0, 124)
//
// Session table (offset 128): session_count entries of 16 bytes, session_id
// strictly ascending (canonical order, so equal states give equal bytes):
//     0     4  session_id
//     4     4  reserved       zero
//     8     8  next_seq       SoupBinTCP next sequence number for the session
// followed by
//     0     4  table_crc      CRC32C of the 16 * session_count entry bytes
//     4     4  pad            zero
// so the table occupies 16 * session_count + 8 bytes.
//
// Payload chunks (from offset 128 + 16 * session_count + 8): the payload split
// into chunk_count chunks of chunk_bytes, the last one shorter. Chunk k is
//     data (len bytes) | chunk_crc (4) | zero pad up to the next 8-byte boundary
// where chunk_crc = crc32c_extend(crc32c(le64(k)), data). Seeding with the chunk
// index makes a swapped, duplicated or misdirected chunk fail its CRC. A full
// chunk therefore occupies chunk_bytes + 8 bytes; the last one round_up8(len + 4).
//
// Trailer (32 bytes, last in the file); detects truncation and binds the
// sections together, so chunks spliced in from another snapshot with the same
// layout fail even though their own CRCs verify:
//     0     8  magic          "LLESEND1"
//     8     8  file_bytes     total file length, trailer included
//    16     4  header_crc     copy of the header's header_crc
//    20     4  sections_crc   CRC32C of le32(table_crc) || le32(chunk_crc[0]) || ...
//    24     4  trailer_crc    CRC32C of trailer bytes [0, 24)
//    28     4  pad            zero
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace lle::snap {

inline constexpr std::array<char, 8> kMagic = {'L', 'L', 'E', 'S', 'N', 'A', 'P', '1'};
inline constexpr std::array<char, 8> kTrailerMagic = {'L', 'L', 'E', 'S', 'E', 'N', 'D', '1'};
inline constexpr std::uint32_t kVersion = 1;

inline constexpr std::uint32_t kHeaderBytes = 128;
inline constexpr std::uint32_t kSessionEntryBytes = 16;
inline constexpr std::uint32_t kSessionTableTailBytes = 8;  // table_crc + pad
inline constexpr std::uint32_t kTrailerBytes = 32;

// 06 §9 fixes 1 MiB chunks; smaller sizes exist so tests can cross many chunk
// boundaries cheaply. The upper bound keeps every layout computation inside u64.
inline constexpr std::uint32_t kDefaultChunkBytes = std::uint32_t{1} << 20;
inline constexpr std::uint32_t kMinChunkBytes = std::uint32_t{1} << 12;
inline constexpr std::uint32_t kMaxChunkBytes = std::uint32_t{1} << 30;

// Header field offsets (see the table above).
namespace hdr {
inline constexpr std::size_t kMagic = 0;
inline constexpr std::size_t kVersion = 8;
inline constexpr std::size_t kHeaderBytes = 12;
inline constexpr std::size_t kDay = 16;
inline constexpr std::size_t kEpoch = 20;
inline constexpr std::size_t kIndex = 24;
inline constexpr std::size_t kSnapshotId = 32;
inline constexpr std::size_t kMoldSeq = 40;
inline constexpr std::size_t kStateHash = 48;
inline constexpr std::size_t kBuildId = 56;
inline constexpr std::size_t kChunkBytes = 64;
inline constexpr std::size_t kSessionCount = 68;
inline constexpr std::size_t kPayloadBytes = 72;
inline constexpr std::size_t kChunkCount = 80;
inline constexpr std::size_t kFlags = 84;
inline constexpr std::size_t kReserved = 88;
inline constexpr std::size_t kHeaderCrc = 124;
}  // namespace hdr

// Trailer field offsets, relative to the start of the trailer.
namespace trl {
inline constexpr std::size_t kMagic = 0;
inline constexpr std::size_t kFileBytes = 8;
inline constexpr std::size_t kHeaderCrc = 16;
inline constexpr std::size_t kSectionsCrc = 20;
inline constexpr std::size_t kTrailerCrc = 24;
inline constexpr std::size_t kPad = 28;
}  // namespace trl

// Identity of the state a snapshot captures; written by the caller, returned by
// the loader.
struct SnapshotMeta {
  std::uint32_t day = 0;          // YYYYMMDD
  std::uint32_t epoch = 0;
  std::uint64_t index = 0;        // P
  std::uint64_t snapshot_id = 0;
  std::uint64_t mold_seq = 0;     // S(P)
  std::uint64_t state_hash = 0;
  std::uint64_t build_id = 0;
  friend bool operator==(const SnapshotMeta&, const SnapshotMeta&) = default;
};

// Primary and backup snapshots at the same mark must agree on these (06 §9); a
// mismatch is a determinism bug and raises an alarm.
[[nodiscard]] constexpr bool same_state(const SnapshotMeta& a, const SnapshotMeta& b) noexcept {
  return a.index == b.index && a.state_hash == b.state_hash && a.mold_seq == b.mold_seq;
}

struct SessionSeq {
  std::uint32_t session_id = 0;
  std::uint64_t next_seq = 0;
  friend bool operator==(const SessionSeq&, const SessionSeq&) = default;
};

// Strictly ascending session ids: the only order the format accepts.
[[nodiscard]] bool sessions_canonical(std::span<const SessionSeq> sessions) noexcept;

// Where everything sits in a file; derived from the header's size fields.
struct SnapshotLayout {
  std::uint32_t chunk_bytes = 0;
  std::uint32_t chunk_count = 0;
  std::uint32_t session_count = 0;
  std::uint64_t payload_bytes = 0;
  std::uint64_t payload_offset = 0;  // first chunk
  std::uint64_t file_bytes = 0;      // trailer included
  friend bool operator==(const SnapshotLayout&, const SnapshotLayout&) = default;
};

[[nodiscard]] constexpr bool valid_chunk_bytes(std::uint64_t chunk_bytes) noexcept {
  return chunk_bytes >= kMinChunkBytes && chunk_bytes <= kMaxChunkBytes && (chunk_bytes & (chunk_bytes - 1)) == 0;
}

// Bytes a chunk of `data_len` payload bytes occupies: data, CRC, zero pad to 8.
[[nodiscard]] constexpr std::uint64_t chunk_frame_bytes(std::uint64_t data_len) noexcept {
  return (data_len + 4 + 7) & ~std::uint64_t{7};
}

// Computes the layout, or nullopt if chunk_bytes is invalid or the payload would
// need more than 2^32 - 1 chunks. Never overflows for any argument values.
[[nodiscard]] std::optional<SnapshotLayout> compute_layout(std::uint64_t chunk_bytes, std::uint32_t session_count,
                                                           std::uint64_t payload_bytes) noexcept;

// CRC of chunk `chunk_index`: crc32c_extend(crc32c(le64(chunk_index)), data).
[[nodiscard]] std::uint32_t chunk_crc(std::uint64_t chunk_index, std::span<const std::byte> data) noexcept;

// Header bytes for `meta` and `layout`, header_crc included.
[[nodiscard]] std::array<std::byte, kHeaderBytes> encode_header(const SnapshotMeta& meta,
                                                                const SnapshotLayout& layout) noexcept;

// Trailer bytes, trailer_crc included.
[[nodiscard]] std::array<std::byte, kTrailerBytes> encode_trailer(std::uint64_t file_bytes, std::uint32_t header_crc,
                                                                  std::uint32_t sections_crc) noexcept;

// Errors are values: writer and loader never throw (conventions).
enum class ErrorCode : std::uint8_t {
  InvalidArgument,   // bad chunk size, wrong writer mode
  UnsortedSessions,  // session ids not strictly ascending
  TooLarge,          // more than 2^32 - 1 chunks
  OutOfMemory,       // chunk buffer allocation failed
  Io,                // a system call failed; see sys_errno and op
  Closed,            // already committed, finished or aborted
};

struct Error {
  ErrorCode code = ErrorCode::Io;
  int sys_errno = 0;    // errno for Io, else 0
  const char* op = "";  // static string naming the failed step, e.g. "fsync(dir)"
  friend bool operator==(const Error&, const Error&) = default;
};

[[nodiscard]] std::string to_string(const Error& e);

enum class LoadError : std::uint8_t {
  Truncated,           // shorter than the header or than its layout requires
  BadMagic,
  UnsupportedVersion,
  BadHeader,           // header_bytes, flags or reserved bytes
  BadHeaderCrc,
  BadChunkSize,
  BadChunkCount,       // chunk_count != ceil(payload_bytes / chunk_bytes), or too many chunks
  BadLength,           // longer than the layout says
  BadTrailer,          // magic, length, header CRC copy, sections CRC, trailer CRC or pad
  BadSessionTable,     // table CRC, reserved field or pad
  UnsortedSessions,
  BadChunkCrc,
  BadPadding,          // non-zero padding after a chunk CRC
  Io,                  // the file could not be opened, sized or mapped
};

[[nodiscard]] std::string_view to_string(LoadError e) noexcept;

// --- File naming: snap/<day>/<index:020>.snap (06 §9) ---

inline constexpr std::string_view kSnapshotSuffix = ".snap";
inline constexpr std::string_view kTempSuffix = ".snap.tmp";
inline constexpr std::size_t kIndexDigits = 20;  // enough for any u64

// "<data_root>/snap/<day:08>"
[[nodiscard]] std::string snapshot_day_dir(const std::string& data_root, std::uint32_t day);
// "<index:020>.snap"
[[nodiscard]] std::string snapshot_file_name(std::uint64_t index);
// "<day_dir>/<index:020>.snap"
[[nodiscard]] std::string snapshot_path(const std::string& day_dir, std::uint64_t index);
// "<day_dir>/<index:020>.snap.tmp": the writer's temporary file.
[[nodiscard]] std::string snapshot_temp_path(const std::string& day_dir, std::uint64_t index);
// Index from a bare file name of exactly 20 decimal digits + ".snap"; nullopt
// for anything else (temporary files, other names, values above u64).
[[nodiscard]] std::optional<std::uint64_t> parse_snapshot_file_name(std::string_view file_name) noexcept;

}  // namespace lle::snap
