#pragma once
// Metrics segment (11-logging-observability §3): a fixed-layout shared-memory
// region `/lle-stats-<node>` (POSIX shm; /dev/shm on Linux) holding named
// counters/gauges and HDR latency histograms.
//
// - Single writer per value: each counter/histogram is updated only by its owning
//   thread with relaxed atomic loads and stores (no read-modify-write), so the hot
//   path is a few plain instructions. Readers (lle-top, exporters) are cold-path,
//   possibly in another process, and see each value tear-free.
// - Histograms use HdrHistogram_c's bucket layout. The writer computes the bucket
//   index inline (same arithmetic as counts_index_for) and bumps a count in the
//   segment; the reader copies the counts into a private hdr_histogram for
//   percentiles.
// - The layout is described by a Schema fixed at creation; the creator publishes
//   the segment by storing the magic number last (release).
//
// Layout v1 (offsets from the base, every block 64-byte aligned):
//   SegmentHeader | CounterSlot[counter_count] | HistogramSlot[histogram_count] |
//   int64 counts[] per histogram
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct hdr_histogram;

namespace lle::metrics {

inline constexpr std::uint64_t kMagic = 0x3153544154534C4CULL;  // bytes "LLSTATS1"
inline constexpr std::uint32_t kVersion = 1;
inline constexpr std::size_t kNameBytes = 48;
inline constexpr std::size_t kNodeBytes = 32;
inline constexpr std::size_t kUnitBytes = 8;
inline constexpr std::size_t kMaxNodeName = 20;  // "/lle-stats-" + node fits macOS's 31-byte shm names

enum class CounterKind : std::uint32_t { kCounter = 0, kGauge = 1 };

struct CounterSpec {
  std::string_view name;
  CounterKind kind = CounterKind::kCounter;
};

struct HistogramSpec {
  std::string_view name;
  std::int64_t lowest = 1;                   // smallest discernible value (>= 1)
  std::int64_t highest = 3'600'000'000'000;  // largest trackable value; larger values are clamped and counted
  int significant_figures = 3;               // 1..5
  std::string_view unit = "ns";
};

struct Schema {
  std::vector<CounterSpec> counters;
  std::vector<HistogramSpec> histograms;
};

static_assert(std::atomic<std::uint64_t>::is_always_lock_free && std::atomic<std::int64_t>::is_always_lock_free,
              "cross-process atomics must be lock-free");

struct SegmentHeader {
  std::atomic<std::uint64_t> magic;  // kMagic once the segment is fully initialized
  std::uint32_t version;
  std::uint32_t header_bytes;
  std::uint64_t total_bytes;
  char node[kNodeBytes];
  std::uint32_t counter_count;
  std::uint32_t histogram_count;
  std::uint64_t counters_offset;
  std::uint64_t histograms_offset;
  std::int64_t created_realtime_ns;
  std::uint32_t writer_pid;
  std::uint32_t reserved;
  std::atomic<std::uint64_t> heartbeat;  // bumped by the owner (liveness for readers)
};

struct CounterSlot {
  char name[kNameBytes];
  CounterKind kind;
  std::uint32_t reserved;
  std::atomic<std::uint64_t> value;
};
static_assert(sizeof(CounterSlot) == 64);

struct HistogramSlot {
  char name[kNameBytes];
  char unit[kUnitBytes];
  std::int64_t lowest;
  std::int64_t highest;
  std::int32_t significant_figures;
  std::int32_t counts_len;
  std::int32_t unit_magnitude;
  std::int32_t sub_bucket_half_count_magnitude;
  std::int32_t sub_bucket_half_count;
  std::int32_t reserved;
  std::int64_t sub_bucket_mask;
  std::uint64_t counts_offset;
  std::atomic<std::int64_t> total_count;
  std::atomic<std::int64_t> overflow;  // values above `highest` (recorded as `highest`)
  std::atomic<std::int64_t> sum;       // of recorded (clamped) values, for the mean
};

// Writer handle for one counter or gauge. Use only from the owning thread.
class Counter {
 public:
  Counter() = default;
  explicit Counter(CounterSlot* s) noexcept : v_(&s->value) {}
  void add(std::uint64_t n = 1) noexcept {
    v_->store(v_->load(std::memory_order_relaxed) + n, std::memory_order_relaxed);
  }
  void set(std::uint64_t v) noexcept { v_->store(v, std::memory_order_relaxed); }
  [[nodiscard]] std::uint64_t value() const noexcept { return v_->load(std::memory_order_relaxed); }
  [[nodiscard]] bool valid() const noexcept { return v_ != nullptr; }

 private:
  std::atomic<std::uint64_t>* v_ = nullptr;
};

// Writer handle for one histogram. Use only from the owning thread.
class Histogram {
 public:
  Histogram() = default;
  Histogram(HistogramSlot* slot, std::int64_t* counts) noexcept;

  void record(std::int64_t value) noexcept {
    if (value < 0) value = 0;
    if (value > highest_) {
      bump(slot_->overflow, 1);
      value = highest_;
    }
    // Relaxed single-writer increment of a plain int64 in the segment (__atomic
    // builtins: Apple libc++ has no std::atomic_ref).
    std::int64_t* c = &counts_[index_for(value)];
    __atomic_store_n(c, __atomic_load_n(c, __ATOMIC_RELAXED) + 1, __ATOMIC_RELAXED);
    bump(slot_->total_count, 1);
    bump(slot_->sum, value);
  }

  // HdrHistogram_c's counts_index_for (value already clamped to [0, highest]).
  [[nodiscard]] std::int32_t index_for(std::int64_t value) const noexcept {
    const std::int32_t pow2ceiling = 64 - __builtin_clzll(static_cast<std::uint64_t>(value | sub_bucket_mask_));
    const std::int32_t bucket = pow2ceiling - unit_magnitude_ - (sub_bucket_half_count_magnitude_ + 1);
    const auto sub_bucket = static_cast<std::int32_t>(value >> (bucket + unit_magnitude_));
    return ((bucket + 1) << sub_bucket_half_count_magnitude_) + (sub_bucket - sub_bucket_half_count_);
  }

  [[nodiscard]] bool valid() const noexcept { return slot_ != nullptr; }

 private:
  static void bump(std::atomic<std::int64_t>& a, std::int64_t n) noexcept {
    a.store(a.load(std::memory_order_relaxed) + n, std::memory_order_relaxed);
  }
  HistogramSlot* slot_ = nullptr;
  std::int64_t* counts_ = nullptr;
  std::int64_t highest_ = 0;
  std::int64_t sub_bucket_mask_ = 0;
  std::int32_t unit_magnitude_ = 0;
  std::int32_t sub_bucket_half_count_magnitude_ = 0;
  std::int32_t sub_bucket_half_count_ = 0;
};

// The writer side: creates (and owns) the segment.
class Segment {
 public:
  // Bytes needed for `schema`, or an error for an invalid histogram spec.
  [[nodiscard]] static std::expected<std::size_t, std::string> required_bytes(const Schema& schema);
  // Lays the segment out in caller memory (tests, simulator, in-process use).
  [[nodiscard]] static std::expected<Segment, std::string> create_in(std::span<std::byte> mem, std::string_view node,
                                                                     const Schema& schema);
  // Creates /lle-stats-<node> (replacing a stale one) and maps it read-write.
  [[nodiscard]] static std::expected<Segment, std::string> create_shm(std::string_view node, const Schema& schema);
  [[nodiscard]] static std::string shm_name(std::string_view node);

  Segment(Segment&& o) noexcept;
  Segment& operator=(Segment&& o) noexcept;
  Segment(const Segment&) = delete;
  Segment& operator=(const Segment&) = delete;
  ~Segment();

  [[nodiscard]] Counter counter(std::size_t i) const noexcept;
  [[nodiscard]] Histogram histogram(std::size_t i) const noexcept;
  // Lookup by name (cold; linear). Invalid handle if absent.
  [[nodiscard]] Counter counter(std::string_view name) const noexcept;
  [[nodiscard]] Histogram histogram(std::string_view name) const noexcept;

  void heartbeat() noexcept;
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return {base_, size_}; }
  // Removes the shm name (the mapping stays valid until destruction).
  bool unlink() noexcept;

 private:
  Segment() = default;
  std::byte* base_ = nullptr;
  std::size_t size_ = 0;
  bool mapped_ = false;
  std::string shm_name_;
};

struct CounterValue {
  std::string_view name;
  CounterKind kind = CounterKind::kCounter;
  std::uint64_t value = 0;
};

struct HdrDeleter {
  void operator()(hdr_histogram* h) const noexcept;
};

struct HistogramSnapshot {
  std::string name;
  std::string unit;
  std::int64_t count = 0;
  std::int64_t overflow = 0;
  std::int64_t min = 0;
  std::int64_t max = 0;
  double mean = 0.0;
  std::unique_ptr<hdr_histogram, HdrDeleter> hdr;  // private copy of the counts
  [[nodiscard]] std::int64_t value_at_percentile(double p) const noexcept;
};

// The reader side (cold path, any process).
class Reader {
 public:
  [[nodiscard]] static std::expected<Reader, std::string> attach(std::span<const std::byte> mem);
  [[nodiscard]] static std::expected<Reader, std::string> open_shm(std::string_view node);

  Reader(Reader&& o) noexcept;
  Reader& operator=(Reader&& o) noexcept;
  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;
  ~Reader();

  [[nodiscard]] std::string_view node() const noexcept;
  [[nodiscard]] std::uint32_t writer_pid() const noexcept;
  [[nodiscard]] std::uint64_t heartbeat() const noexcept;
  [[nodiscard]] std::size_t counter_count() const noexcept;
  [[nodiscard]] std::size_t histogram_count() const noexcept;
  [[nodiscard]] CounterValue counter(std::size_t i) const noexcept;
  [[nodiscard]] std::optional<std::size_t> find_counter(std::string_view name) const noexcept;
  [[nodiscard]] std::optional<std::size_t> find_histogram(std::string_view name) const noexcept;
  // Copies histogram i (counts are read one by one; a concurrent writer may make
  // the copy slightly inconsistent across buckets, never torn within one).
  [[nodiscard]] std::expected<HistogramSnapshot, std::string> histogram(std::size_t i) const;

 private:
  Reader() = default;
  const std::byte* base_ = nullptr;
  std::size_t size_ = 0;
  bool mapped_ = false;
};

// lle-top style one-shot text view of a segment (the interactive TUI comes later).
[[nodiscard]] std::string dump_text(const Reader& r);

}  // namespace lle::metrics
