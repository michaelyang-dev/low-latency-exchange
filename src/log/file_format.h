#pragma once
// nlog file format v1 (docs/design/nlog-format.md): constants and the writer-side encoders shared
// by the backend, the tests and the fuzz seed generator.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "log/arg_value.h"
#include "log/format_spec.h"

namespace lle::nlog::file {

inline constexpr std::array<char, 8> kFileMagic = {'L', 'L', 'E', 'N', 'L', 'O', 'G', '\0'};
inline constexpr std::uint16_t kVersionMajor = 1;
inline constexpr std::uint16_t kVersionMinor = 0;
inline constexpr std::uint32_t kFileHeaderBytes = 64;
inline constexpr std::size_t kNodeBytes = 24;  // NUL-padded, so at most 23 significant bytes

inline constexpr std::uint32_t kChunkMagic = 0x4B434C4Eu;  // bytes "NLCK"
inline constexpr std::uint32_t kChunkHeaderBytes = 16;
inline constexpr std::uint32_t kMaxChunkPayload = 64u << 20;

enum class ChunkType : std::uint16_t {
  kDict = 1,
  kCalib = 2,
  kThread = 3,
  kExtent = 4,
  kDrops = 5,
  kEnd = 6,
  kThreadEnd = 7,
};

inline constexpr std::uint32_t kExtentHeaderBytes = 16;  // thread_id, record_count, base_tsc
inline constexpr std::uint32_t kCalibPayloadBytes = 32;
inline constexpr std::uint32_t kDropsPayloadBytes = 24;
inline constexpr std::uint32_t kEndPayloadBytes = 32;
inline constexpr std::uint32_t kThreadEndPayloadBytes = 16;

// Compacted record header: varint((site_idx << 2) | (flags & kRecFlagMask)).
inline constexpr std::uint64_t kRecFlagMask = 0x3;

struct FileHeader {
  std::int64_t created_realtime_ns = 0;
  std::uint64_t tsc_hz = 0;
  std::string_view node;
  std::uint32_t flags = 0;
};

struct DictEntry {
  std::uint32_t idx = 0;
  std::uint8_t level = 0;
  std::uint8_t nargs = 0;
  ArgKinds kinds{};
  std::uint32_t line = 0;
  std::string_view file;
  std::string_view fmt;
};

struct Calibration {
  std::uint64_t tsc = 0;
  std::int64_t realtime_ns = 0;
  std::uint64_t tsc_hz = 0;
  std::uint32_t window_ticks = 0;
};

void append_file_header(std::vector<std::byte>& out, const FileHeader& h);

// Chunk framing: begin_chunk reserves the 16-byte header and returns its offset;
// end_chunk fills type, length and CRC32C over header bytes [0,12) + payload.
[[nodiscard]] std::size_t begin_chunk(std::vector<std::byte>& out);
void end_chunk(std::vector<std::byte>& out, std::size_t at, ChunkType type);

void append_dict_chunk(std::vector<std::byte>& out, std::span<const DictEntry> entries);
void append_calib_chunk(std::vector<std::byte>& out, const Calibration& c);
void append_thread_chunk(std::vector<std::byte>& out, std::uint32_t thread_id, std::uint64_t ring_bytes,
                         std::string_view name);
void append_drops_chunk(std::vector<std::byte>& out, std::uint32_t thread_id, std::uint64_t tsc,
                        std::uint64_t total_drops);
void append_thread_end_chunk(std::vector<std::byte>& out, std::uint32_t thread_id, std::uint64_t tsc);
void append_end_chunk(std::vector<std::byte>& out, std::uint64_t tsc, std::uint64_t total_records,
                      std::uint64_t total_drops, std::uint64_t unregistered_drops);

// Accumulates one thread's compacted records and emits them as an EXTENT chunk.
class ExtentBuilder {
 public:
  // Largest compacted record: two header varints plus 8 arguments of a length
  // varint and 64 string bytes.
  static constexpr std::size_t kMaxCompactRecord = 2 * 10 + kMaxArgs * (10 + kMaxStringBytes);

  void reset(std::uint32_t thread_id) noexcept;
  [[nodiscard]] bool empty() const noexcept { return count_ == 0; }
  [[nodiscard]] std::size_t bytes() const noexcept { return len_; }
  [[nodiscard]] std::uint32_t count() const noexcept { return count_; }
  [[nodiscard]] std::uint32_t thread_id() const noexcept { return thread_id_; }
  void reserve(std::size_t bytes) { ensure(bytes); }

  // Compacts the arguments of one raw ring record (record.h layout) laid out per
  // `kinds`. Returns false (and adds nothing) if the raw bytes do not match.
  bool add_raw(std::uint32_t site_idx, std::uint16_t flags, std::uint64_t tsc, const ArgKinds& kinds,
               std::uint8_t nargs, const std::byte* args, const std::byte* args_end);

  // Same from decoded values (tests, fuzz seeds). Strings longer than 64 bytes are cut.
  void add_values(std::uint32_t site_idx, std::uint16_t flags, std::uint64_t tsc, std::span<const ArgValue> args);

  // Appends the EXTENT chunk to `out` (no-op when empty) and clears the builder.
  void finish_into(std::vector<std::byte>& out);

 private:
  void ensure(std::size_t extra);                                            // grows the buffer (rare)
  std::byte* put_header(std::byte* w, std::uint32_t site_idx, std::uint16_t flags, std::uint64_t tsc) noexcept;

  std::uint32_t thread_id_ = 0;
  std::uint32_t count_ = 0;
  std::uint64_t base_tsc_ = 0;
  std::uint64_t prev_tsc_ = 0;
  std::size_t len_ = 0;           // bytes of compacted records in body_
  std::vector<std::byte> body_;  // writable capacity (size() is the capacity in use)
};

}  // namespace lle::nlog::file
