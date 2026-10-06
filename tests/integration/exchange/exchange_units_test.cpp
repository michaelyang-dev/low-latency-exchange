// In-process checks of exchanged's own pieces (apps/exchanged), next to the end-to-end
// tests: the input SCQs' single-consumer guard, the ring-occupancy gauges, the record
// log's L3 window.
#include <gtest/gtest.h>

#include <filesystem>
#include <thread>

#include "../../unit/journal/journal_test_util.h"
#include "concurrent/mpsc_scq.h"
#include "exchanged/consumer_guard.h"
#include "exchanged/record_log.h"
#include "exchanged/restart_guard.h"
#include "exchanged/ring_gauge.h"
#include "journal/mem_journal_device.h"

namespace lle::exch {
namespace {

// RecordLog's L3 reads over an in-memory journal: a view of the shared directory, as
// the opener returns one per window.
struct MemDirView {
  using Device = journal::MemJournalDevice;
  journal::MemSegmentDir* d;
  [[nodiscard]] std::size_t count() const { return d->count(); }
  Device& device(std::size_t i) { return d->device(i); }
  [[nodiscard]] std::string_view name(std::size_t i) const { return d->name(i); }
  std::optional<std::size_t> create(std::string_view n, std::uint64_t sz) { return d->create(n, sz); }
  bool rename(std::size_t i, std::string_view n) { return d->rename(i, n); }
  bool sync_dir() { return d->sync_dir(); }
};
struct MemOpener {
  journal::MemSegmentDir* d = nullptr;
  [[nodiscard]] std::expected<MemDirView, std::string> operator()(const std::string&) const { return MemDirView{d}; }
};
using MemRecordLog = BasicRecordLog<MemOpener>;

struct JournalOf {
  journal::MemSegmentDir dir;
  journal::testing::MemWriter w{journal::testing::writer_options()};
  journal::testing::RecordStream s{21, journal::testing::RecordStream::Mix{140, 40, 6000}};
  explicit JournalOf(std::uint64_t segment_bytes = journal::kSegmentHeaderBytes + 128 * 1024) {
    w.start(journal::ChainState{});
    for (const auto& p : journal::testing::prepare_segments(dir, 8, segment_bytes))
      EXPECT_TRUE(w.add_prepared(dir.device(p.handle), p.handle, p.header));
  }
  void journal(std::uint64_t n) {
    for (std::uint64_t i = 0; i < n; ++i) journal::testing::append_one(w, s.next(), s.sealer());
    journal::testing::drain(w);
  }
};

bool same_record(std::span<const std::byte> got, std::span<const std::byte> want) {
  return journal::same_content(journal::RecordView(got), journal::RecordView(want));
}

// A catch-up reads old records in order and rewinds to its oldest unacknowledged one:
// every record comes back exact, across segments and window slides (more than the
// window's 4 MiB), with an arena far smaller than the day.
TEST(RecordLogL3, InOrderReadsWithRewindsReturnEveryRecord) {
  JournalOf j(journal::kSegmentHeaderBytes + (std::uint64_t{1} << 20));
  constexpr std::uint64_t kDayRecords = 20'000;
  j.journal(kDayRecords);
  ASSERT_GE(j.w.stats().segments, 4u);
  MemRecordLog log(std::size_t{1} << 16, 128, "journal", journal::testing::kDay, MemOpener{&j.dir});
  ASSERT_TRUE(log.load(kDayRecords));
  ASSERT_GT(log.lowest(), kDayRecords - 1000) << "the arena should hold only the newest records";
  std::vector<std::byte> buf(journal::kMaxRecordBytes);
  std::uint64_t i = 1;
  for (int step = 0; i <= kDayRecords; ++step) {
    const std::uint32_t n = log.read(i, buf);
    ASSERT_NE(n, 0u) << "record " << i;
    ASSERT_TRUE(same_record(std::span<const std::byte>(buf.data(), n), j.s.at(i))) << "record " << i;
    // Every 97 reads, go back 60 records (a go-back-N rewind), then on.
    if (step % 97 == 96 && i > 60) {
      i -= 60;
    } else {
      ++i;
    }
  }
}

// A record the arena evicted before the io stage made it durable is in neither place: the
// read fails at once (no journal walk per attempt) until durability passes it.
TEST(RecordLogL3, ARecordNotYetInL3IsReadOnceDurable) {
  JournalOf j;
  j.journal(1000);
  MemRecordLog log(std::size_t{1} << 16, 128, "journal", journal::testing::kDay, MemOpener{&j.dir});
  ASSERT_TRUE(log.load(1000));
  std::vector<std::byte> buf(journal::kMaxRecordBytes);
  ASSERT_NE(log.read(500, buf), 0u);  // in L3
  // 1,000 more records reach the log (sequenced) before any is durable.
  std::vector<std::vector<std::byte>> more;
  for (int k = 0; k < 1000; ++k) {
    const std::span<const std::byte> r = j.s.next();
    more.emplace_back(r.begin(), r.end());
    ASSERT_TRUE(log.append_from(r.data(), static_cast<std::uint32_t>(r.size()), j.s.sealer()));
  }
  ASSERT_GT(log.lowest(), 1500u);
  log.note_durable(1000);
  EXPECT_EQ(log.read(1200, buf), 0u) << "neither in the arena nor durable";
  for (const auto& r : more) journal::testing::append_one(j.w, r, j.s.sealer());
  journal::testing::drain(j.w);
  log.note_durable(2000);
  const std::uint32_t n = log.read(1200, buf);
  ASSERT_NE(n, 0u);
  EXPECT_TRUE(same_record(std::span<const std::byte>(buf.data(), n), j.s.at(1200)));
}

TEST(ScqConsumerGuard, HandOversBetweenTheTwoConsumersPass) {
  ScqConsumerGuard g;
  for (int i = 0; i < 3; ++i) {
    { const ScqConsumerScope s(g, ScqConsumerGuard::kSeq); }
    { const ScqConsumerScope s(g, ScqConsumerGuard::kRepl); }
  }
  // Re-entering as the same consumer is fine (nested scopes on one thread).
  const ScqConsumerScope a(g, ScqConsumerGuard::kSeq);
  const ScqConsumerScope b(g, ScqConsumerGuard::kSeq);
}

TEST(ScqConsumerGuardDeathTest, OverlappingConsumersAreCaughtInDebugBuilds) {
#if defined(NDEBUG)
  GTEST_SKIP() << "the guard is compiled out without debug assertions";
#else
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  EXPECT_DEATH(
      {
        ScqConsumerGuard g;
        const ScqConsumerScope seq(g, ScqConsumerGuard::kSeq);
        std::thread t([&] { const ScqConsumerScope repl(g, ScqConsumerGuard::kRepl); });
        t.join();
      },
      "two consumers of the input SCQs");
#endif
}

// ring_<R>_{used,hwm,peak,window} (ring_gauge.h): peak is the largest sample of the last
// completed 1 s window, window counts completed windows, hwm never drops.
TEST(RingGauge, PeaksPerCompletedWindowAndAHighWaterMark) {
  constexpr Nanos s = RingGauge::kWindow;
  RingGauge g;
  g.cap = 100;
  g.sample(10, 5 * s);
  g.sample(40, 5 * s + s / 2);
  g.sample(20, 5 * s + s - 1);
  EXPECT_EQ(g.used, 20u);
  EXPECT_EQ(g.hwm, 40u);
  EXPECT_EQ(g.window, 0u) << "the first window is still open";
  EXPECT_EQ(g.peak, 0u);
  g.sample(5, 6 * s);  // window 1 closes with its largest sample
  EXPECT_EQ(g.window, 1u);
  EXPECT_EQ(g.peak, 40u);
  EXPECT_EQ(g.used, 5u);
  g.sample(7, 6 * s + 1);
  g.sample(3, 7 * s);
  EXPECT_EQ(g.window, 2u);
  EXPECT_EQ(g.peak, 7u) << "the second window's peak, not the high-water mark";
  EXPECT_EQ(g.hwm, 40u);
  // Nothing sampled for 3 s: the counter jumps (readers see the gap).
  g.sample(9, 10 * s + 3);
  EXPECT_EQ(g.window, 5u);
  EXPECT_EQ(g.peak, 3u);
  g.sample(1, 11 * s);
  EXPECT_EQ(g.window, 6u);
  EXPECT_EQ(g.peak, 9u);
}

// The input queues' occupancy as the seq stage samples it (MpscScqRing::size_approx).
TEST(RingGauge, ScqSizeFollowsPushesAndPops) {
  conc::MpscScqRing<int, 8> q;
  EXPECT_EQ(q.size_approx(), 0u);
  for (int i = 0; i < 5; ++i) ASSERT_TRUE(q.try_push(i));
  EXPECT_EQ(q.size_approx(), 5u);
  int v = 0;
  ASSERT_TRUE(q.try_pop(v));
  ASSERT_TRUE(q.try_pop(v));
  EXPECT_EQ(q.size_approx(), 3u);
  for (int i = 0; i < 5; ++i) ASSERT_TRUE(q.try_push(i));
  EXPECT_EQ(q.size_approx(), 8u);
  EXPECT_FALSE(q.try_push(9));
  EXPECT_EQ(q.size_approx(), 8u) << "never above the capacity";
  while (q.try_pop(v)) {
  }
  EXPECT_EQ(q.size_approx(), 0u);
  EXPECT_FALSE(q.try_pop(v));
  EXPECT_EQ(q.size_approx(), 0u) << "an empty poll does not move it";
}

}  // namespace
// The restart-loop guard (restart_guard.h): consecutive exits at the same point from the
// same journal count up; a different point, target or journal starts again; the start is
// refused at the limit, and only for the journal that recorded it.
TEST(RestartGuard, CountsIdenticalExitsAndRefusesAtTheLimit) {
  std::optional<RestartRecord> rec;
  for (std::uint32_t k = 1; k <= 3; ++k) {
    rec = next_restart_record(rec, "truncate the journal to", 0, 517);
    EXPECT_EQ(rec->count, k);
  }
  EXPECT_TRUE(restart_refused(rec, 517, 3));
  EXPECT_FALSE(restart_refused(rec, 517, 4));
  EXPECT_FALSE(restart_refused(rec, 0, 3)) << "the *.seg files were moved aside: another journal";
  EXPECT_FALSE(restart_refused(rec, 517, 0)) << "limit 0: never";
  EXPECT_FALSE(restart_refused(std::nullopt, 517, 3));
  EXPECT_EQ(next_restart_record(rec, "truncate the journal to", 1, 517).count, 1u);
  EXPECT_EQ(next_restart_record(rec, "reload the engine to", 0, 517).count, 1u);
  EXPECT_EQ(next_restart_record(rec, "truncate the journal to", 0, 518).count, 1u);
  const std::string msg = restart_refusal(*rec);
  EXPECT_NE(msg.find("*.seg"), std::string::npos) << msg;
  EXPECT_NE(msg.find("truncate the journal to 0"), std::string::npos) << msg;
}

TEST(RestartGuard, TheRecordRoundTripsThroughItsFile) {
  const RestartRecord r{"reload the engine to", 42, 4096, 2};
  const auto back = parse_restart_record(format_restart_record(r));
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(back->what, r.what);
  EXPECT_EQ(back->target, 42u);
  EXPECT_EQ(back->recovered, 4096u);
  EXPECT_EQ(back->count, 2u);
  for (const char* bad : {"", "exit5", "exit5 0 1 2 x", "exit4 1 1 2 x", "exit5 1 1 2"}) EXPECT_FALSE(parse_restart_record(bad)) << bad;
  const auto path = (std::filesystem::temp_directory_path() / ("lle-restart-guard-" + std::to_string(::getpid()))).string();
  EXPECT_FALSE(read_restart_record(path).has_value());
  ASSERT_TRUE(write_restart_record(path, r));
  const auto read = read_restart_record(path);
  ASSERT_TRUE(read.has_value());
  EXPECT_EQ(read->count, 2u);
  clear_restart_record(path);
  EXPECT_FALSE(std::filesystem::exists(path));
}

}  // namespace lle::exch
