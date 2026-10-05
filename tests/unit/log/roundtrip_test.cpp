// End to end: hot path -> backend thread -> file -> decoder.
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdio>
#include <format>
#include <limits>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "common/endian.h"
#include "log/backend.h"
#include "log/decoder.h"
#include "log/file_format.h"
#include "log/nlog.h"
#include "log/record.h"
#include "test_util.h"

namespace lle::nlog {
namespace {

using decode::LogFile;
using decode::Record;
using decode::RenderOptions;
using decode::Status;
using decode::TimeMode;

enum class Side : char { kBuy = 'B', kSell = 'S' };

class NlogRoundTrip : public ::testing::Test {
 protected:
  void SetUp() override {
    test::drain_and_discard();
    path_ = test::temp_path(::testing::UnitTest::GetInstance()->current_test_info()->name());
  }
  void TearDown() override { std::remove(path_.c_str()); }

  BackendOptions opts() const {
    BackendOptions o;
    o.path = path_;
    o.node = "unit";
    o.idle_sleep_us = 20;
    return o;
  }
  std::string path_;
};

TEST_F(NlogRoundTrip, GoldenText) {
  ThreadScope scope({.ring_bytes = 1 << 16, .name = "golden"});
  ASSERT_TRUE(scope.ok());
  Backend be;
  ASSERT_TRUE(be.start(opts()).has_value());
  const std::uint64_t ref = 42;
  const std::int64_t px = -1500;
  const std::uint32_t qty = 100;
  const std::uint8_t side = 66;
  const std::string_view sym = "AAPL";
  // One call per line: __LINE__ of a call spanning lines is implementation-defined.
  const int l1 = __LINE__ + 1;
  NLOG_EV(1000, "order {} accepted px {} qty {} side {}", ref, px, qty, side);
  const int l2 = __LINE__ + 1;
  NLOG_EV_AT(Level::kWarn, 1001, "sym {} halted={} code {:c} side {:c}", sym, true, 'H', Side::kSell);
  const int l3 = __LINE__ + 1;
  NLOG_EV_AT(Level::kError, 1003, "px {:.4f} hex {:#x} pad [{:>5}] {{literal}}", 101.25, 255u, 7);
  const int l4 = __LINE__ + 1;
  NLOG_EV_AT(Level::kDebug, 900, "no args");
  be.stop();

  const auto bytes = test::read_file(path_);
  const LogFile f = LogFile::parse(bytes);
  ASSERT_EQ(f.info().status, Status::kOk);
  EXPECT_TRUE(f.info().clean_end);
  EXPECT_EQ(f.info().node, "unit");
  // NDEBUG builds default LLE_NLOG_MIN_LEVEL to INFO, which compiles the DEBUG call out.
  constexpr bool kDebugOn = LLE_NLOG_MIN_LEVEL <= 0;
  EXPECT_EQ(f.info().end_total_records, kDebugOn ? 4u : 3u);
  RenderOptions ro;
  ro.time = TimeMode::kTsc;
  const std::uint32_t t = scope.thread_id();
  const std::string expected =
      std::format("1000 INFO  t{0} roundtrip_test.cpp:{1} order 42 accepted px -1500 qty 100 side 66\n"
                  "1001 WARN  t{0} roundtrip_test.cpp:{2} sym AAPL halted=true code H side S\n"
                  "1003 ERROR t{0} roundtrip_test.cpp:{3} px 101.2500 hex 0xff pad [    7] {{literal}}\n"
                  "{5}",
                  t, l1, l2, l3, l4, kDebugOn ? std::format("900 DEBUG t{} roundtrip_test.cpp:{} no args\n", t, l4) : "");
  // The merge orders threads by TSC but keeps each thread's program order, so the
  // DEBUG record stamped 900 but logged last stays last.
  EXPECT_EQ(decode::render_to_string(f, ro), expected);

  std::uint32_t warn_site = ~0u;
  for (const auto& [idx, s] : f.sites()) {
    if (s.line == static_cast<std::uint32_t>(l2) && s.file.ends_with("roundtrip_test.cpp")) warn_site = idx;
  }
  ro.format = decode::OutputFormat::kJsonl;
  ro.time = TimeMode::kNone;
  ro.filter.min_level = static_cast<std::uint8_t>(Level::kWarn);
  ro.filter.to_tsc = 1002;
  EXPECT_EQ(decode::render_to_string(f, ro),
            std::format("{{\"tsc\":1001,\"level\":\"WARN\",\"thread\":{},\"site\":{},\"file\":\"roundtrip_test.cpp\","
                        "\"line\":{},\"msg\":\"sym AAPL halted=true code H side S\",\"args\":[\"AAPL\",true,\"H\",\"S\"],"
                        "\"ev\":true}}\n",
                        t, warn_site, l2));
}

TEST_F(NlogRoundTrip, EveryKindMatchesStdFormatOfTheSameValues) {
  ThreadScope scope({.ring_bytes = 1 << 16});
  Backend be;
  ASSERT_TRUE(be.start(opts()).has_value());
  const std::string long_str(80, 'q');
  NLOG_EV(1, "{} {} {} {}", std::uint8_t{0}, std::uint16_t{65535}, std::uint32_t{4000000000u},
          std::numeric_limits<std::uint64_t>::max());
  NLOG_EV(2, "{} {} {} {}", std::int8_t{-128}, std::int16_t{32767}, std::int32_t{-2147483647 - 1},
          std::numeric_limits<std::int64_t>::min());
  NLOG_EV(3, "{} {} {} {:e} {}", true, 'x', 3.0, -2.5e300, 1.0 / 3.0);
  NLOG_EV(4, "[{}] [{}] [{:>4}]", long_str, std::string_view{""}, "ab");
  be.stop();
  const auto bytes = test::read_file(path_);
  const LogFile f = LogFile::parse(bytes);
  ASSERT_EQ(f.info().status, Status::kOk);
  std::vector<std::string> msgs;
  f.for_each([&](const Record& r) {
    std::string line;
    RenderOptions ro;
    ro.time = TimeMode::kNone;
    decode::render_record(line, r, ro);
    msgs.push_back(line.substr(line.find(' ', line.find(".cpp:")) + 1));
    return true;
  });
  ASSERT_EQ(msgs.size(), 4u);
  EXPECT_EQ(msgs[0], std::format("{} {} {} {}\n", std::uint8_t{0}, std::uint16_t{65535}, std::uint32_t{4000000000u},
                                 std::numeric_limits<std::uint64_t>::max()));
  EXPECT_EQ(msgs[1], std::format("{} {} {} {}\n", std::int8_t{-128}, std::int16_t{32767},
                                 std::int32_t{-2147483647 - 1}, std::numeric_limits<std::int64_t>::min()));
  EXPECT_EQ(msgs[2], std::format("{} {} {} {:e} {}\n", true, 'x', 3.0, -2.5e300, 1.0 / 3.0));
  EXPECT_EQ(msgs[3], "[" + std::string(64, 'q') + "...] [] [  ab]\n");
}

TEST_F(NlogRoundTrip, ThreadsAreMergedByTimestamp) {
  constexpr int kThreads = 4;
  constexpr std::uint64_t kPerThread = 5000;
  Backend be;
  ASSERT_TRUE(be.start(opts()).has_value());
  std::atomic<int> ready{0};
  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([t, &ready] {
      ThreadScope scope({.ring_bytes = 1 << 14, .policy = FullPolicy::kBlock});
      ready.fetch_add(1);
      while (ready.load() < kThreads) {
      }
      // Phase 1: event times i*kThreads + t interleave the threads deterministically.
      for (std::uint64_t i = 0; i < kPerThread; ++i) {
        NLOG_EV(i * kThreads + static_cast<std::uint64_t>(t), "mt-ev t {} i {}", t, i);
      }
      // Phase 2: real counter stamps (each thread's stream stays sorted).
      for (std::uint64_t i = 0; i < kPerThread; ++i) NLOG_INFO("mt-now t {} i {}", t, i);
    });
  }
  for (auto& th : threads) th.join();
  be.stop();
  EXPECT_EQ(be.stats().drops_seen, 0u);

  const auto bytes = test::read_file(path_);
  const LogFile f = LogFile::parse(bytes);
  ASSERT_EQ(f.info().status, Status::kOk);
  std::uint64_t next_ev = 0;
  std::uint64_t prev_now_tsc = 0;
  std::map<std::uint32_t, std::uint64_t> next_now;
  std::uint64_t now_count = 0;
  std::map<std::uint32_t, std::uint64_t> tids;
  const auto ms = f.for_each([&](const Record& r) {
    const std::string_view fmt = r.site->fmt;
    if (fmt == "mt-ev t {} i {}") {
      // Event times 0..N-1 sort before every real counter value.
      EXPECT_EQ(r.tsc, next_ev);
      EXPECT_EQ(r.args[1].u * kThreads + static_cast<std::uint64_t>(r.args[0].i), next_ev);
      EXPECT_EQ(prev_now_tsc, 0u);
      ++next_ev;
    } else if (fmt == "mt-now t {} i {}") {
      EXPECT_GE(r.tsc, prev_now_tsc) << "merged output must be ordered by TSC";
      prev_now_tsc = r.tsc;
      EXPECT_EQ(r.args[1].u, next_now[r.thread_id]++) << "per-thread program order";
      ++now_count;
    }
    return true;
  });
  EXPECT_EQ(ms.bad_extents, 0u);
  EXPECT_EQ(next_ev, kThreads * kPerThread);
  EXPECT_EQ(now_count, kThreads * kPerThread);
  EXPECT_EQ(next_now.size(), static_cast<std::size_t>(kThreads));
  EXPECT_EQ(f.info().end_total_records, 2 * kThreads * kPerThread);
  for (const auto& [id, info] : f.threads()) EXPECT_TRUE(info.ended) << "thread " << id;
}

TEST_F(NlogRoundTrip, DropsAreReportedInTheFile) {
  ThreadScope scope({.ring_bytes = 4096});
  std::uint64_t accepted = 0;
  while (thread_drops() == 0) {
    NLOG_INFO("file-drop {}", accepted);
    if (thread_drops() == 0) ++accepted;
  }
  for (int i = 0; i < 9; ++i) NLOG_INFO("file-drop {}", std::uint64_t{0});
  Backend be;
  ASSERT_TRUE(be.start(opts()).has_value());
  be.stop();
  const auto bytes = test::read_file(path_);
  const LogFile f = LogFile::parse(bytes);
  ASSERT_EQ(f.info().status, Status::kOk);
  ASSERT_EQ(f.threads().count(scope.thread_id()), 1u);
  EXPECT_EQ(f.threads().at(scope.thread_id()).drops, 10u);
  EXPECT_EQ(f.info().end_total_drops, 10u);
  EXPECT_EQ(f.info().end_total_records, accepted);
  std::uint64_t n = 0;
  f.for_each([&](const Record& r) {
    EXPECT_EQ(r.args[0].u, n++);
    return true;
  });
  EXPECT_EQ(n, accepted);
}

TEST_F(NlogRoundTrip, CalibrationGivesWallClockTimes) {
  ThreadScope scope({.ring_bytes = 1 << 16});
  Backend be;
  ASSERT_TRUE(be.start(opts()).has_value());
  NLOG_INFO("calibrated {}", 1);
  be.stop();
  const auto bytes = test::read_file(path_);
  const LogFile f = LogFile::parse(bytes);
  ASSERT_GE(f.calibrations().size(), 2u);  // start and stop
  std::optional<std::int64_t> wall;
  f.for_each([&](const Record& r) {
    wall = r.wall_ns;
    return true;
  });
  ASSERT_TRUE(wall.has_value());
  // The record lies between the first and last calibration samples.
  EXPECT_GE(*wall, f.calibrations().front().realtime_ns);
  EXPECT_LE(*wall, f.calibrations().back().realtime_ns);
}

// Writes a file with many small extents and returns (bytes, chunk end offsets,
// records complete at each chunk end).
struct ExtentFile {
  std::vector<std::byte> bytes;
  std::vector<std::pair<std::size_t, std::size_t>> boundaries;  // (offset, records before it)
  std::size_t records = 0;
};

ExtentFile make_extent_file(const std::string& path, BackendOptions o) {
  ExtentFile out;
  {
    ThreadScope scope({.ring_bytes = 1 << 16, .policy = FullPolicy::kBlock});
    o.extent_flush_bytes = 200;
    Backend be;
    if (!be.start(o)) return out;
    for (std::uint64_t i = 0; i < 400; ++i) NLOG_INFO("extent-seq {} sq {}", i, i * i);
    be.stop();
  }
  out.bytes = test::read_file(path);
  // Walk the valid chunk chain to learn where extents end.
  std::size_t off = file::kFileHeaderBytes;
  std::size_t recs = 0;
  out.boundaries.emplace_back(off, 0);
  while (off + file::kChunkHeaderBytes <= out.bytes.size()) {
    const std::uint32_t len = load_le32(out.bytes.data() + off + 8);
    const std::uint16_t type = load_le16(out.bytes.data() + off + 4);
    if (type == static_cast<std::uint16_t>(file::ChunkType::kExtent)) {
      recs += load_le32(out.bytes.data() + off + file::kChunkHeaderBytes + 4);
    }
    off += file::kChunkHeaderBytes + len;
    out.boundaries.emplace_back(off, recs);
  }
  out.records = recs;
  return out;
}

void expect_prefix(const LogFile& f, std::size_t n, const std::string& what) {
  std::uint64_t i = 0;
  f.for_each([&](const Record& r) {
    EXPECT_EQ(r.args[0].u, i) << what;
    EXPECT_EQ(r.args[1].u, i * i) << what;
    ++i;
    return true;
  });
  EXPECT_EQ(i, n) << what;
}

TEST_F(NlogRoundTrip, TruncatedFileDecodesUpToLastCompleteExtent) {
  const ExtentFile ef = make_extent_file(path_, opts());
  ASSERT_EQ(ef.records, 400u);
  ASSERT_GT(ef.boundaries.size(), 10u);
  std::size_t b = 0;
  for (std::size_t cut = 0; cut <= ef.bytes.size(); ++cut) {
    const LogFile f = LogFile::parse({ef.bytes.data(), cut});
    if (cut < file::kFileHeaderBytes) {
      ASSERT_EQ(f.info().status, Status::kBadHeader) << cut;
      continue;
    }
    while (b + 1 < ef.boundaries.size() && ef.boundaries[b + 1].first <= cut) ++b;
    const bool at_boundary = ef.boundaries[b].first == cut;
    ASSERT_EQ(f.info().status, at_boundary ? Status::kOk : Status::kTruncated) << cut;
    ASSERT_EQ(f.info().valid_bytes, ef.boundaries[b].first) << cut;
    expect_prefix(f, ef.boundaries[b].second, "cut at " + std::to_string(cut));
  }
}

TEST_F(NlogRoundTrip, CorruptExtentStopsDecodingThere) {
  ExtentFile ef = make_extent_file(path_, opts());
  ASSERT_GT(ef.boundaries.size(), 12u);
  // Flip one payload byte in the chunk that starts at boundary 10.
  const auto [at, before] = ef.boundaries[10];
  ef.bytes[at + file::kChunkHeaderBytes + 3] ^= std::byte{0x40};
  const LogFile f = LogFile::parse(ef.bytes);
  EXPECT_EQ(f.info().status, Status::kCorrupt);
  EXPECT_EQ(f.info().valid_bytes, at);
  EXPECT_FALSE(f.info().clean_end);
  expect_prefix(f, before, "corrupt chunk 10");
}

TEST_F(NlogRoundTrip, KilledWriterLeavesDecodablePrefix) {
  // A child process logs continuously and is SIGKILLed while the backend is
  // writing; whatever reached the file must decode as a valid prefix.
  const pid_t pid = ::fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    if (!register_thread({.ring_bytes = 1 << 16, .policy = FullPolicy::kBlock})) ::_exit(3);
    BackendOptions o = opts();
    o.extent_flush_bytes = 512;
    o.write_buffer_bytes = 1024;
    Backend be;
    if (!be.start(o)) ::_exit(4);
    for (std::uint64_t i = 0;; ++i) {
      NLOG_INFO("crash-seq {} sq {}", i, i * i);
      if (i % 1000 == 999) {
        struct stat st {};
        if (::stat(path_.c_str(), &st) == 0 && st.st_size > 64 * 1024) ::kill(::getpid(), SIGKILL);
      }
    }
  }
  int status = 0;
  ASSERT_EQ(::waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFSIGNALED(status)) << "child exit status " << WEXITSTATUS(status);
  EXPECT_EQ(WTERMSIG(status), SIGKILL);
  const auto bytes = test::read_file(path_);
  const LogFile f = LogFile::parse(bytes);
  EXPECT_TRUE(f.info().status == Status::kOk || f.info().status == Status::kTruncated);
  EXPECT_FALSE(f.info().clean_end);
  std::uint64_t i = 0;
  const auto ms = f.for_each([&](const Record& r) {
    EXPECT_EQ(r.args[0].u, i);
    EXPECT_EQ(r.args[1].u, i * i);
    ++i;
    return true;
  });
  EXPECT_EQ(ms.bad_extents, 0u);
  EXPECT_GT(i, 1000u);
}

TEST_F(NlogRoundTrip, SecondConsumerIsRejected) {
  Backend a;
  ASSERT_TRUE(a.start(opts()).has_value());
  Backend b;
  BackendOptions o = opts();
  o.path += ".second";
  EXPECT_FALSE(b.start(o).has_value());
  MemorySink sink;
  EXPECT_FALSE(sink.attach());
  a.stop();
  EXPECT_TRUE(sink.attach());
}

TEST_F(NlogRoundTrip, StartFailsOnUnwritablePath) {
  Backend be;
  BackendOptions o = opts();
  o.path = "/nonexistent-dir-nlog/x.nlog";
  const auto r = be.start(o);
  ASSERT_FALSE(r.has_value());
  EXPECT_NE(r.error().find("open"), std::string::npos);
  MemorySink sink;
  EXPECT_TRUE(sink.attach()) << "a failed start must release the consumer role";
}

}  // namespace
}  // namespace lle::nlog
