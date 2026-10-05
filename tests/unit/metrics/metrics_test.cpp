// Metrics segment: layout, single-writer counters, HDR histograms (bit-exact
// against HdrHistogram_c), POSIX shm round trip, concurrent reader, validation.
#include "metrics/segment.h"

#include <unistd.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <hdr/hdr_histogram.h>

#include "common/prng.h"
#include "metrics/probe.h"

namespace lle::metrics {
namespace {

struct AlignedBuffer {
  explicit AlignedBuffer(std::size_t n) : size(n), p(static_cast<std::byte*>(std::aligned_alloc(64, (n + 63) & ~std::size_t{63}))) {}
  ~AlignedBuffer() { std::free(p); }
  AlignedBuffer(const AlignedBuffer&) = delete;
  AlignedBuffer& operator=(const AlignedBuffer&) = delete;
  std::span<std::byte> span() const { return {p, size}; }
  std::size_t size;
  std::byte* p;
};

Schema test_schema() {
  Schema s;
  s.counters = {{"orders_in"}, {"fills"}, {"book_levels", CounterKind::kGauge}};
  s.histograms = {{"engine_apply_ns", 1, 10'000'000, 3, "ns"}, {"batch_size", 1, 4096, 2, "msgs"}};
  return s;
}

TEST(Metrics, CountersAndHistogramsRoundTripInMemory) {
  const Schema schema = test_schema();
  const auto bytes = Segment::required_bytes(schema);
  ASSERT_TRUE(bytes.has_value());
  AlignedBuffer buf(*bytes);
  auto seg = Segment::create_in(buf.span(), "gw0", schema);
  ASSERT_TRUE(seg.has_value()) << seg.error();
  Counter orders = seg->counter("orders_in");
  Counter levels = seg->counter("book_levels");
  ASSERT_TRUE(orders.valid());
  EXPECT_FALSE(seg->counter("missing").valid());
  orders.add();
  orders.add(41);
  levels.set(17);
  levels.set(9);
  Histogram apply = seg->histogram("engine_apply_ns");
  for (std::int64_t v = 1; v <= 1000; ++v) apply.record(v);
  seg->heartbeat();

  auto r = Reader::attach(seg->bytes());
  ASSERT_TRUE(r.has_value()) << r.error();
  EXPECT_EQ(r->node(), "gw0");
  EXPECT_EQ(r->heartbeat(), 1u);
  ASSERT_EQ(r->counter_count(), 3u);
  EXPECT_EQ(r->counter(0).name, "orders_in");
  EXPECT_EQ(r->counter(0).value, 42u);
  EXPECT_EQ(r->counter(1).value, 0u);
  EXPECT_EQ(r->counter(2).kind, CounterKind::kGauge);
  EXPECT_EQ(r->counter(2).value, 9u);
  EXPECT_EQ(r->find_counter("fills"), std::optional<std::size_t>{1});
  EXPECT_EQ(r->find_histogram("batch_size"), std::optional<std::size_t>{1});
  EXPECT_FALSE(r->find_histogram("nope").has_value());

  const auto h = r->histogram(0);
  ASSERT_TRUE(h.has_value()) << h.error();
  EXPECT_EQ(h->name, "engine_apply_ns");
  EXPECT_EQ(h->unit, "ns");
  EXPECT_EQ(h->count, 1000);
  EXPECT_EQ(h->min, 1);
  EXPECT_EQ(h->max, 1000);
  EXPECT_DOUBLE_EQ(h->mean, 500.5);
  EXPECT_EQ(h->value_at_percentile(50.0), 500);
  EXPECT_EQ(h->value_at_percentile(99.0), 990);

  const std::string text = dump_text(*r);
  EXPECT_NE(text.find("lle-stats node=gw0"), std::string::npos) << text;
  EXPECT_NE(text.find("orders_in"), std::string::npos);
  EXPECT_NE(text.find("gauge"), std::string::npos);
  EXPECT_NE(text.find("engine_apply_ns"), std::string::npos);
}

TEST(Metrics, HistogramBucketsMatchHdrHistogramC) {
  struct Spec {
    std::int64_t lowest, highest;
    int sig;
  };
  for (const Spec sp : {Spec{1, 3'600'000'000'000, 3}, Spec{1, 1000, 1}, Spec{16, 1'000'000, 2}, Spec{1, 1 << 20, 5}}) {
    Schema schema;
    schema.histograms = {{"h", sp.lowest, sp.highest, sp.sig, "ns"}};
    AlignedBuffer buf(*Segment::required_bytes(schema));
    auto seg = Segment::create_in(buf.span(), "x", schema);
    ASSERT_TRUE(seg.has_value());
    Histogram ours = seg->histogram(0);
    hdr_histogram* ref = nullptr;
    ASSERT_EQ(hdr_init(sp.lowest, sp.highest, sp.sig, &ref), 0);
    Prng rng(0xC0FFEE + static_cast<std::uint64_t>(sp.sig));
    for (int i = 0; i < 20000; ++i) {
      // Log-uniform values across the whole trackable range.
      const auto bits = static_cast<unsigned>(rng.below(63));
      const auto v = static_cast<std::int64_t>(rng.below(std::uint64_t{1} << bits)) % (sp.highest + 1);
      ours.record(v);
      ASSERT_TRUE(hdr_record_value(ref, v));
    }
    auto r = Reader::attach(seg->bytes());
    ASSERT_TRUE(r.has_value());
    const auto snap = r->histogram(0);
    ASSERT_TRUE(snap.has_value());
    ASSERT_EQ(snap->hdr->counts_len, ref->counts_len);
    for (std::int32_t k = 0; k < ref->counts_len; ++k) ASSERT_EQ(snap->hdr->counts[k], ref->counts[k]) << k;
    for (const double p : {0.0, 50.0, 90.0, 99.0, 99.9, 100.0}) {
      EXPECT_EQ(snap->value_at_percentile(p), hdr_value_at_percentile(ref, p)) << p;
    }
    EXPECT_EQ(snap->count, ref->total_count);
    hdr_close(ref);
  }
}

TEST(Metrics, OutOfRangeValuesAreClampedAndCounted) {
  Schema schema;
  schema.histograms = {{"h", 1, 1000, 3, "us"}};
  AlignedBuffer buf(*Segment::required_bytes(schema));
  auto seg = Segment::create_in(buf.span(), "x", schema);
  ASSERT_TRUE(seg.has_value());
  Histogram h = seg->histogram(0);
  h.record(-5);
  h.record(5000);
  h.record(1'000'000);
  auto r = Reader::attach(seg->bytes());
  const auto snap = r->histogram(0);
  ASSERT_TRUE(snap.has_value());
  EXPECT_EQ(snap->count, 3);
  EXPECT_EQ(snap->overflow, 2);
  EXPECT_EQ(snap->min, 0);
  EXPECT_EQ(snap->max, hdr_max(snap->hdr.get()));
  EXPECT_GE(snap->max, 1000);
}

TEST(Metrics, SharedMemorySegmentIsVisibleToAReader) {
  const std::string node = "t" + std::to_string(::getpid());
  auto seg = Segment::create_shm(node, test_schema());
  ASSERT_TRUE(seg.has_value()) << seg.error();
  seg->counter(0).add(7);
  seg->histogram(1).record(32);
  {
    auto r = Reader::open_shm(node);
    ASSERT_TRUE(r.has_value()) << r.error();
    EXPECT_EQ(r->counter(0).value, 7u);
    EXPECT_EQ(r->writer_pid(), static_cast<std::uint32_t>(::getpid()));
    seg->counter(0).add(1);  // live view, not a copy
    EXPECT_EQ(r->counter(0).value, 8u);
    const auto h = r->histogram(1);
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(h->count, 1);
    EXPECT_EQ(h->unit, "msgs");
  }
  EXPECT_TRUE(seg->unlink());
  EXPECT_FALSE(Reader::open_shm(node).has_value());
}

TEST(Metrics, ReaderSeesMonotonicValuesFromAConcurrentWriter) {
  AlignedBuffer buf(*Segment::required_bytes(test_schema()));
  auto seg = Segment::create_in(buf.span(), "x", test_schema());
  ASSERT_TRUE(seg.has_value());
  constexpr std::uint64_t kN = 200'000;
  std::atomic<bool> done{false};
  std::thread writer([&] {
    Counter c = seg->counter(0);
    Histogram h = seg->histogram(0);
    for (std::uint64_t i = 1; i <= kN; ++i) {
      c.add();
      h.record(static_cast<std::int64_t>(i % 5000));
    }
    done.store(true, std::memory_order_release);
  });
  auto r = Reader::attach(seg->bytes());
  ASSERT_TRUE(r.has_value());
  std::uint64_t last = 0;
  while (!done.load(std::memory_order_acquire)) {
    const std::uint64_t v = r->counter(0).value;
    ASSERT_GE(v, last);
    ASSERT_LE(v, kN);
    last = v;
    const auto snap = r->histogram(0);
    ASSERT_TRUE(snap.has_value());
    ASSERT_LE(snap->count, static_cast<std::int64_t>(kN));
  }
  writer.join();
  EXPECT_EQ(r->counter(0).value, kN);
  EXPECT_EQ(r->histogram(0)->count, static_cast<std::int64_t>(kN));
}

TEST(Metrics, Validation) {
  Schema bad;
  bad.histograms = {{"h", 1, 1000, 0, "ns"}};  // significant figures must be 1..5
  EXPECT_FALSE(Segment::required_bytes(bad).has_value());
  Schema unnamed;
  unnamed.counters = {{""}};
  EXPECT_FALSE(Segment::required_bytes(unnamed).has_value());

  const Schema s = test_schema();
  AlignedBuffer small(64);
  EXPECT_FALSE(Segment::create_in(small.span(), "x", s).has_value());
  AlignedBuffer buf(*Segment::required_bytes(s) + 64);
  EXPECT_FALSE(Segment::create_in(buf.span().subspan(8), "x", s).has_value()) << "unaligned";
  EXPECT_FALSE(Segment::create_shm("bad/name", s).has_value());
  EXPECT_FALSE(Segment::create_shm("much-too-long-node-name-x", s).has_value());

  std::memset(buf.p, 0, buf.size);
  EXPECT_FALSE(Reader::attach(buf.span()).has_value()) << "no magic";
  auto seg = Segment::create_in(buf.span(), "x", s);
  ASSERT_TRUE(seg.has_value());
  auto* h = static_cast<SegmentHeader*>(static_cast<void*>(buf.p));
  h->counters_offset = 1u << 30;
  EXPECT_FALSE(Reader::attach(buf.span()).has_value()) << "offset out of range";
}

TEST(Metrics, StageProbeSamplesOneInNAndConvertsTicksToNanoseconds) {
  Schema schema;
  schema.histograms = {{"stage_ns", 1, 1'000'000'000, 3, "ns"}};
  AlignedBuffer buf(*Segment::required_bytes(schema));
  auto seg = Segment::create_in(buf.span(), "x", schema);
  ASSERT_TRUE(seg.has_value());
  StageProbe probe(seg->histogram(0), 50, 24'000'000);  // 50 -> every 64th event; 24 MHz counter
  EXPECT_EQ(probe.to_ns(24), 1000);                      // 24 ticks = 1 us
  EXPECT_EQ(probe.to_ns(24'000'000), 1'000'000'000);
  EXPECT_EQ(probe.to_ns(0), 0);
  EXPECT_EQ(probe.to_ns(1), 42);  // 41.67 ns rounds to 42
  for (int i = 0; i < 640; ++i) probe.record_span(1000, 1000 + 240);  // 10 us each
  probe.record_span(500, 100);                                        // backwards: 0 if sampled
  EXPECT_EQ(probe.events(), 641u);
  auto r = Reader::attach(seg->bytes());
  const auto h = r->histogram(0);
  ASSERT_TRUE(h.has_value());
  EXPECT_EQ(h->count, 11);  // events 0, 64, ..., 640
  EXPECT_EQ(h->min, 0);
  EXPECT_TRUE(hdr_values_are_equivalent(h->hdr.get(), h->value_at_percentile(50.0), 10'000));
  StageProbe every(seg->histogram(0), 1, 1'000'000'000);
  EXPECT_TRUE(every.sample());
  EXPECT_TRUE(every.sample());
  EXPECT_EQ(every.to_ns(123), 123);
}

}  // namespace
}  // namespace lle::metrics
