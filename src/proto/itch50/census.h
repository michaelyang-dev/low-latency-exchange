#pragma once
// Whole-stream ITCH 5.0 census behind apps/itch_census (03-protocols §3, P-03).
//
// print_report() writes the framing, per-type, timestamp, system-event, burst,
// hourly and enumeration sections in exactly the format of the research
// analyzer (docs/plan/research/tools/itch/itch_stats.cpp), so its output can be
// diffed line by line against docs/plan/research/data/01302019.stats.txt. The
// research tool's order-book sections are out of scope here (they belong to the
// order-book track). Counting semantics mirror that tool: every record counts
// as a message (including zero-length ones), per-type counts include
// length-mismatched messages, and timestamps are only taken from well-formed
// messages.
//
// Memory: one u32 bucket per millisecond of the day (86.4M buckets, ~330 MiB of
// zero-initialized virtual memory, committed only where touched), as in the
// research tool, so burst maxima are exact even for unordered input.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <span>
#include <string>

namespace lle::itch50 {

class Census {
 public:
  static constexpr std::uint64_t kMsPerDay = 86'400'000ull;

  Census();
  ~Census();
  Census(const Census&) = delete;
  Census& operator=(const Census&) = delete;

  // One BinaryFILE record (message bytes after the length prefix; empty for a
  // zero-length record).
  void add(std::span<const std::byte> msg) noexcept;

  void print_report(std::FILE* out) const;
  // Which of the 23 types appeared in this stream ("real bytes") and which did not.
  void print_coverage(std::FILE* out) const;

  [[nodiscard]] std::uint64_t messages() const noexcept { return nmsg_; }
  [[nodiscard]] std::uint64_t bytes() const noexcept { return nbytes_; }
  [[nodiscard]] std::uint64_t zero_length() const noexcept { return zero_len_; }
  [[nodiscard]] std::uint64_t unknown_type() const noexcept { return unknown_; }
  [[nodiscard]] std::uint64_t bad_length() const noexcept { return bad_len_; }
  [[nodiscard]] std::uint64_t count(char type) const noexcept { return cnt_[static_cast<unsigned char>(type)]; }
  [[nodiscard]] std::uint64_t locate_zero(char type) const noexcept {
    return loc0_[static_cast<unsigned char>(type)];
  }
  [[nodiscard]] std::uint64_t timestamp_decreases() const noexcept { return ts_decreases_; }
  [[nodiscard]] std::uint64_t first_timestamp() const noexcept { return first_ts_; }
  [[nodiscard]] std::uint64_t last_timestamp() const noexcept { return last_ts_; }
  [[nodiscard]] std::uint32_t max_in_1ms() const noexcept;
  [[nodiscard]] std::uint64_t max_in_1s() const noexcept;

  // Enumeration histogram for one field label (e.g. "S.event"): value -> count.
  [[nodiscard]] std::map<std::string, std::uint64_t> enum_values(const std::string& label) const;

 private:
  struct SysEvent {
    char code;
    std::uint64_t ts;
  };
  struct EnumHistograms;

  std::uint64_t nmsg_ = 0, nbytes_ = 0, zero_len_ = 0, unknown_ = 0, bad_len_ = 0;
  std::array<std::uint64_t, 256> cnt_{}, lenmis_{}, loc0_{};
  std::uint64_t first_ts_ = UINT64_MAX, last_ts_ = 0, prev_ts_ = 0, ts_decreases_ = 0, max_ts_decrease_ = 0;
  std::uint64_t ts_over_day_ = 0;
  std::uint32_t* per_ms_ = nullptr;  // kMsPerDay + 1 buckets
  static constexpr std::size_t kMaxSysEvents = 64;
  std::array<SysEvent, kMaxSysEvents> sys_events_{};
  std::size_t num_sys_events_ = 0;
  std::unique_ptr<EnumHistograms> enums_;
};

}  // namespace lle::itch50
