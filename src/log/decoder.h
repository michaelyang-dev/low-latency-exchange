#pragma once
// nlog file decoder (11-logging-observability §1): validates the chunk stream,
// collects the dictionary, calibrations and per-thread extents, then k-way merges
// the threads' record streams by TSC with a heap. TSC is converted to wall time by
// interpolating between calibration records. Input is untrusted: every read is
// bounds-checked and a truncated or corrupt file decodes up to its last valid
// chunk. Used by apps/nlog_decode, the tests and the fuzz harness.
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "log/arg_value.h"
#include "log/file_format.h"
#include "log/format_spec.h"

namespace lle::nlog::decode {

struct SiteInfo {
  std::uint32_t idx = 0;
  std::uint8_t level = 0;
  std::uint8_t nargs = 0;
  ArgKinds kinds{};
  std::uint32_t line = 0;
  std::string_view file;  // views into the file bytes
  std::string_view fmt;
};

struct ThreadInfo {
  std::uint32_t id = 0;
  std::uint64_t ring_bytes = 0;
  std::string_view name;
  std::uint64_t drops = 0;  // latest total reported
  bool ended = false;
};

enum class Status : std::uint8_t {
  kOk,                  // every byte belongs to a valid chunk
  kTruncated,           // the file ends inside a chunk (e.g. crash while writing)
  kCorrupt,             // bad chunk magic, length or CRC: decoding stopped there
  kBadHeader,           // not an nlog file
  kUnsupportedVersion,  // major version != 1
};

[[nodiscard]] std::string_view status_name(Status s) noexcept;

struct ScanInfo {
  Status status = Status::kOk;
  std::size_t valid_bytes = 0;  // prefix made of the header and valid chunks
  std::size_t chunks = 0;
  std::size_t extents = 0;
  std::size_t unknown_chunks = 0;    // skipped (newer minor version)
  std::size_t malformed_chunks = 0;  // CRC-valid but structurally wrong (ignored)
  bool clean_end = false;            // END chunk present
  std::uint16_t version_major = 0;
  std::uint16_t version_minor = 0;
  std::string node;
  std::int64_t created_realtime_ns = 0;
  std::uint64_t header_tsc_hz = 0;
  std::uint64_t end_total_records = 0;
  std::uint64_t end_total_drops = 0;
  std::uint64_t end_unregistered_drops = 0;
};

struct Record {
  std::uint32_t thread_id = 0;
  std::uint64_t tsc = 0;
  std::optional<std::int64_t> wall_ns;
  std::uint32_t site_idx = 0;
  const SiteInfo* site = nullptr;
  std::uint16_t flags = 0;  // kFlagTruncated | kFlagEventTs (record.h)
  std::uint8_t nargs = 0;
  std::array<ArgValue, kMaxArgs> args{};
};

struct ParseOptions {
  bool verify_crc = true;  // the fuzz harness turns this off to reach the extent parser
};

struct MergeStats {
  std::size_t records = 0;
  std::size_t bad_extents = 0;  // extents whose records stopped parsing early
};

class LogFile {
 public:
  // Never throws on bad input. The span must outlive the LogFile.
  [[nodiscard]] static LogFile parse(std::span<const std::byte> bytes, const ParseOptions& opts = {});

  [[nodiscard]] const ScanInfo& info() const noexcept { return info_; }
  [[nodiscard]] const std::map<std::uint32_t, SiteInfo>& sites() const noexcept { return sites_; }
  [[nodiscard]] const SiteInfo* site(std::uint32_t idx) const noexcept;
  [[nodiscard]] const std::vector<file::Calibration>& calibrations() const noexcept { return calibs_; }
  [[nodiscard]] const std::map<std::uint32_t, ThreadInfo>& threads() const noexcept { return threads_; }

  // Wall time (ns since the UNIX epoch) for a counter value; nullopt without a
  // usable calibration.
  [[nodiscard]] std::optional<std::int64_t> to_wall_ns(std::uint64_t tsc) const noexcept;

  // Visits records merged across threads by (tsc, thread id); within a thread the
  // file (program) order is kept. Return false from `f` to stop early.
  MergeStats for_each(const std::function<bool(const Record&)>& f) const;

 private:
  struct ExtentRef {
    std::size_t offset;  // payload offset in bytes_
    std::size_t len;
  };
  struct Cursor;
  bool advance(Cursor& c, MergeStats& ms) const;
  bool decode_record(Cursor& c, Record& r) const;
  void parse_dict(std::span<const std::byte> p);

  std::span<const std::byte> bytes_;
  ScanInfo info_;
  std::map<std::uint32_t, SiteInfo> sites_;
  std::vector<file::Calibration> calibs_;
  std::map<std::uint32_t, ThreadInfo> threads_;
  std::map<std::uint32_t, std::vector<ExtentRef>> extents_;
};

struct Filter {
  std::optional<std::uint8_t> min_level;
  std::vector<std::uint32_t> sites;    // empty: all
  std::vector<std::uint32_t> threads;  // empty: all
  std::optional<std::int64_t> from_ns, to_ns;     // wall-clock range [from, to)
  std::optional<std::uint64_t> from_tsc, to_tsc;  // counter range [from, to)
  [[nodiscard]] bool matches(const Record& r) const noexcept;
};

enum class OutputFormat : std::uint8_t { kText, kJsonl };
enum class TimeMode : std::uint8_t { kWall, kTsc, kNone };

struct RenderOptions {
  OutputFormat format = OutputFormat::kText;
  TimeMode time = TimeMode::kWall;
  Filter filter;
  bool full_paths = false;  // default: source file basename only
};

struct RenderStats {
  MergeStats merge;
  std::size_t records_out = 0;
};

// Appends one record as a '\n'-terminated text or JSONL line.
void render_record(std::string& out, const Record& r, const RenderOptions& opts);

// Renders every record that passes the filter; `sink` receives one line at a time.
RenderStats render(const LogFile& f, const RenderOptions& opts, const std::function<void(std::string_view)>& sink);
[[nodiscard]] std::string render_to_string(const LogFile& f, const RenderOptions& opts);

// Human-readable summaries for --stats and --dict.
[[nodiscard]] std::string describe(const LogFile& f);
[[nodiscard]] std::string dictionary_text(const LogFile& f);

}  // namespace lle::nlog::decode
