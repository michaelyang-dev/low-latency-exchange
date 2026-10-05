#pragma once
// In-memory nlog consumer for the deterministic simulator and tests
// (11-logging-observability §1 "In the simulator"). drain() is called explicitly
// on the caller's thread; rings are visited in registration-slot order and each
// ring in program order, so with a single-threaded simulator (and NLOG_EV or the
// LLE_SIM virtual clock for timestamps) the record sequence, text and hash are
// deterministic. It replaces the file backend: only one consumer may be active.
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "log/arg_value.h"
#include "log/format_spec.h"
#include "log/site.h"

namespace lle::nlog {

namespace detail {
struct ThreadBuffer;
}

struct MemRecord {
  std::uint32_t thread_id = 0;
  std::uint64_t tsc = 0;
  std::uint32_t site_idx = 0;
  const LogSite* site = nullptr;
  std::uint16_t flags = 0;
  std::uint8_t nargs = 0;
  std::array<ArgValue, kMaxArgs> raw{};      // string payloads live in `strings`
  std::array<std::string, kMaxArgs> strings;

  // The argument as a view (strings point into this record).
  [[nodiscard]] ArgValue arg(std::size_t i) const noexcept {
    ArgValue a = raw[i];
    if (a.kind == ArgKind::kStr) a.s = strings[i];
    return a;
  }
};

class MemorySink {
 public:
  MemorySink() = default;
  ~MemorySink();
  MemorySink(const MemorySink&) = delete;
  MemorySink& operator=(const MemorySink&) = delete;

  // Claims the consumer role (false if a backend or another sink is active).
  [[nodiscard]] bool attach() noexcept;
  void detach() noexcept;
  [[nodiscard]] bool attached() const noexcept { return attached_; }

  // Moves every committed record of every ring into records(). Returns the count.
  std::size_t drain();

  [[nodiscard]] const std::vector<MemRecord>& records() const noexcept { return records_; }
  void clear() noexcept { records_.clear(); }
  [[nodiscard]] std::uint64_t bad_records() const noexcept { return bad_records_; }
  [[nodiscard]] std::uint64_t drops(std::uint32_t thread_id) const noexcept;

  // "<tsc> <LEVEL> t<id> <file>:<line> <message>" (file basename).
  [[nodiscard]] static std::string format(const MemRecord& r);
  [[nodiscard]] std::string text() const;  // all records, one per line

  // FNV-1a over (tsc, thread, format string, file basename, line, arguments): stable
  // across builds of the same source, unlike site IDs which depend on link order.
  // Thread IDs are deterministic only if threads register in a fixed order.
  [[nodiscard]] std::uint64_t hash(bool include_thread_ids = true) const noexcept;

  // poll_rings handler interface.
  void on_thread(const detail::ThreadBuffer&) noexcept {}
  void on_record(const detail::ThreadBuffer& b, const std::byte* p, std::uint32_t len);
  void on_drops(const detail::ThreadBuffer& b, std::uint64_t total);
  void on_thread_end(const detail::ThreadBuffer&) noexcept {}

 private:
  bool attached_ = false;
  std::vector<MemRecord> records_;
  std::vector<std::pair<std::uint32_t, std::uint64_t>> drops_;
  std::uint64_t bad_records_ = 0;
};

}  // namespace lle::nlog
