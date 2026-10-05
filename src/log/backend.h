#pragma once
// nlog file backend (11-logging-observability §1): one housekeeping thread that
// drains every registered thread ring round-robin, compacts the records
// (varint/zigzag, TSC deltas) into per-thread extents and appends them to a log
// file with periodic {tsc, CLOCK_REALTIME, tsc_hz} calibration chunks. The site
// dictionary is written once at startup by walking the nlog section. File
// format: docs/design/nlog-format.md.
//
// Only one consumer (this backend or a MemorySink) may run at a time.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

namespace lle::nlog {

struct BackendOptions {
  std::string path;                                       // output file (truncated)
  std::string node = "lle";                               // stored in the file header (<= 23 bytes kept)
  std::uint64_t calibration_interval_ns = 1'000'000'000;  // periodic CALIB chunks
  std::size_t extent_flush_bytes = 64 * 1024;             // emit a thread's extent past this size
  std::size_t write_buffer_bytes = 1 << 20;               // write(2) once this much is buffered
  std::size_t drain_batch = 1024;                         // records per ring per round
  std::uint32_t idle_sleep_us = 50;                       // sleep when a round finds nothing (0: spin)
  std::uint64_t poll_interval_ns = 20'000;                // min time between polls once caught up
  int pin_cpu = -1;                                       // Linux only: pin the backend thread
};

struct BackendStats {
  std::uint64_t records = 0;       // records written to extents
  std::uint64_t bad_records = 0;   // raw records rejected (unknown site, bad length)
  std::uint64_t extents = 0;
  std::uint64_t bytes_written = 0;
  std::uint64_t write_errors = 0;
  std::uint64_t calibrations = 0;
  std::uint64_t drops_seen = 0;    // sum of the latest drop totals reported per thread
  std::uint64_t threads_seen = 0;
};

class Backend {
 public:
  Backend();
  ~Backend();  // stops if running
  Backend(const Backend&) = delete;
  Backend& operator=(const Backend&) = delete;

  // Opens the file, writes header, dictionary and a first calibration, then
  // starts the drain thread. Fails if another consumer is active.
  std::expected<void, std::string> start(BackendOptions opts);

  // Drains everything committed before the call, writes the final drop counts,
  // a last calibration and the END chunk, closes the file and joins the thread.
  void stop();

  [[nodiscard]] bool running() const noexcept;
  [[nodiscard]] BackendStats stats() const noexcept;  // exact after stop()

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace lle::nlog
