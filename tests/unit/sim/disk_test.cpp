#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <vector>

#include "env/concepts.h"
#include "sim/disk.h"
#include "sim/dist.h"
#include "sim/fault_atlas.h"
#include "sim/node.h"
#include "sim/world.h"
#include "test_util.h"

namespace lle::sim {
namespace {

static_assert(env::DiskFileLike<DiskFile>);

std::vector<std::byte> fill(std::size_t n, std::uint8_t v) { return std::vector<std::byte>(n, std::byte{v}); }

struct Completions {
  std::vector<env::DiskCompletion> all;
  std::size_t drain(DiskFile& f) {
    return f.poll([&](const env::DiskCompletion& c) { all.push_back(c); });
  }
};

struct DiskFixture {
  World w;
  Node& n;
  std::unique_ptr<DiskFile> f;
  Completions cq;
  explicit DiskFixture(std::uint64_t seed, const DiskParams& p = DiskParams{})
      : w(seed, base_fault_config()), n(w.add_node("n")) {
    n.disk().set_params(p);
    f = std::make_unique<DiskFile>(n, "data");
  }
  void settle(Nanos d = 100 * kMs) {
    const Nanos end = w.now() + d;
    while (w.pending_events() > 0 && w.next_event_time() <= end) {
      w.step();
      if (f) cq.drain(*f);
    }
    w.run_until_time(end);
  }
  std::uint32_t fid() { return n.disk().open("data"); }
  std::vector<std::byte> durable() {
    const auto s = n.disk().durable_image(fid());
    return {s.begin(), s.end()};
  }
  std::vector<std::byte> visible() {
    const auto s = n.disk().cache_image(fid());
    return {s.begin(), s.end()};
  }
};

TEST(Disk, WritesAreVisibleOnCompletionAndDurableOnlyAfterSync) {
  DiskFixture d(1);
  ASSERT_TRUE(d.f->submit_write(0, fill(1000, 0xAA), false, 7));
  d.settle();
  ASSERT_EQ(d.cq.all.size(), 1u);
  EXPECT_EQ(d.cq.all[0].tag, 7u);
  EXPECT_EQ(d.cq.all[0].result, 1000);
  EXPECT_EQ(d.visible(), fill(1000, 0xAA));
  EXPECT_TRUE(d.durable().empty());
  std::vector<std::byte> out(1000);
  EXPECT_EQ(d.f->read(0, out), 1000u);
  EXPECT_EQ(out, fill(1000, 0xAA));
  ASSERT_TRUE(d.f->submit_sync(8));
  d.settle();
  ASSERT_EQ(d.cq.all.size(), 2u);
  EXPECT_EQ(d.cq.all[1].result, 0);
  EXPECT_EQ(d.durable(), fill(1000, 0xAA));
}

TEST(Disk, SyncCoversOnlyWritesCompletedBeforeIt) {
  DiskParams p;
  p.write_min_ns = 10 * kMs;  // the write completes after the sync
  p.sync_min_ns = 1 * kMs;
  DiskFixture d(2, p);
  d.f->submit_write(0, fill(100, 1), false, 1);
  d.f->submit_sync(2);
  d.settle();
  EXPECT_EQ(d.cq.all[0].tag, 2u);  // sync completed first: out-of-order completion
  EXPECT_TRUE(d.durable().empty());
  EXPECT_EQ(d.visible(), fill(100, 1));
}

TEST(Disk, HostCrashLosesUnsyncedAndKeepsSynced) {
  DiskFixture d(3);
  d.f->submit_write(0, fill(512, 1), false, 1);
  d.settle();
  d.f->submit_sync(2);
  d.settle();
  d.f->submit_write(512, fill(512, 2), false, 3);  // completed, not synced
  d.settle();
  d.f->submit_write(1024, fill(512, 3), false, 4);  // still in flight at the crash
  d.f.reset();
  d.n.boot();
  d.n.crash(CrashKind::Host);
  EXPECT_EQ(d.durable(), fill(512, 1));
  EXPECT_EQ(d.visible(), fill(512, 1));
  EXPECT_EQ(d.w.stats().disk_lost_unsynced, 2u);
  EXPECT_EQ(d.w.probes().hits("disk.crash_between_write_and_fsync"), 1u);
  d.settle();  // the in-flight completion is discarded
  EXPECT_EQ(d.visible(), fill(512, 1));
}

TEST(Disk, ProcessCrashKeepsPageCacheAndInFlightWritesLand) {
  DiskFixture d(4);
  d.f->submit_write(0, fill(100, 9), false, 1);
  d.settle();
  d.f->submit_write(100, fill(100, 8), false, 2);  // in flight
  d.n.boot();
  d.f.reset();  // process memory gone: handle closed
  d.n.crash(CrashKind::Process);
  d.settle();
  std::vector<std::byte> want = fill(100, 9);
  const auto tail = fill(100, 8);
  want.insert(want.end(), tail.begin(), tail.end());
  EXPECT_EQ(d.visible(), want);
  EXPECT_TRUE(d.durable().empty());
  // A new incarnation's fsync makes the old dirty pages durable.
  d.f = std::make_unique<DiskFile>(d.n, "data");
  d.f->submit_sync(3);
  d.settle();
  EXPECT_EQ(d.durable(), want);
}

bool sector_granular(const std::vector<std::byte>& img, std::size_t g, std::byte old_v, std::byte new_v,
                     std::size_t len, int& partial) {
  int new_sectors = 0;
  int sectors = 0;
  for (std::size_t s = 0; s < len; s += g) {
    const std::byte first = s < img.size() ? img[s] : old_v;
    for (std::size_t i = s; i < s + g; ++i) {
      const std::byte b = i < img.size() ? img[i] : old_v;
      if (b != first) return false;
    }
    if (first != old_v && first != new_v) return false;
    new_sectors += first == new_v ? 1 : 0;
    ++sectors;
  }
  if (new_sectors > 0 && new_sectors < sectors) ++partial;
  return true;
}

TEST(Disk, TornWritesTearAtSectorGranularity) {
  for (const std::uint32_t g : {512u, 4096u}) {
    int partial = 0;
    for (std::uint64_t seed = 1; seed <= 40; ++seed) {
      DiskParams p;
      p.crash_torn_ppm = 1'000'000;
      p.tear_bytes = g;
      DiskFixture d(seed, p);
      d.f->submit_write(0, fill(8 * g, 0x11), false, 1);
      d.settle();
      d.f->submit_sync(2);
      d.settle();
      d.f->submit_write(0, fill(8 * g, 0x22), false, 3);  // overwrite, never synced
      d.settle();
      d.f.reset();
      d.n.boot();
      d.n.crash(CrashKind::Host);
      ASSERT_TRUE(sector_granular(d.durable(), g, std::byte{0x11}, std::byte{0x22}, 8 * g, partial)) << g;
      EXPECT_EQ(d.w.stats().disk_torn, 1u);
    }
    EXPECT_GT(partial, 20) << "granularity " << g;
  }
}

TEST(Disk, InFlightWritesMayPersistOutOfOrderAtCrash) {
  std::uint64_t ooo = 0;
  std::uint64_t probe_hits = 0;
  for (std::uint64_t seed = 1; seed <= 30; ++seed) {
    DiskParams p;
    p.crash_keep_ppm = 500'000;
    p.write_min_ns = 50 * kMs;  // all still in flight at the crash
    DiskFixture d(seed, p);
    for (std::uint64_t i = 0; i < 16; ++i) d.f->submit_write(i * 100, fill(100, static_cast<std::uint8_t>(i + 1)), false, i);
    d.f.reset();
    d.n.boot();
    d.n.crash(CrashKind::Host);
    const auto img = d.durable();
    // Some record i persisted while an earlier record j < i did not.
    bool found = false;
    for (std::size_t i = 1; i < 16 && !found; ++i) {
      const bool later = img.size() >= (i + 1) * 100 && img[i * 100] == std::byte(static_cast<std::uint8_t>(i + 1));
      for (std::size_t j = 0; j < i && later && !found; ++j) {
        found = img.size() < (j + 1) * 100 || img[j * 100] != std::byte(static_cast<std::uint8_t>(j + 1));
      }
    }
    ooo += found ? 1u : 0u;
    EXPECT_EQ(found, d.w.stats().disk_ooo_persist > 0);
    probe_hits += d.w.probes().hits("disk.ooo_persist_at_crash");
  }
  EXPECT_GT(ooo, 10u);
  EXPECT_EQ(probe_hits > 0, true);
}

TEST(Disk, EioOnWriteAndFsyncgateOnSync) {
  DiskParams p;
  p.eio_write_ppm = 1'000'000;
  DiskFixture d(5, p);
  d.w.set_phase(Phase::Safety);
  d.f->submit_write(0, fill(10, 1), false, 1);
  d.settle();
  ASSERT_EQ(d.cq.all.size(), 1u);
  EXPECT_EQ(d.cq.all[0].result, -kEio);
  EXPECT_TRUE(d.visible().empty());

  DiskParams q;
  q.eio_sync_ppm = 1'000'000;
  DiskFixture e(6, q);
  e.w.set_phase(Phase::Safety);
  e.f->submit_write(0, fill(10, 1), false, 1);
  e.settle();
  e.f->submit_sync(2);
  e.settle();
  EXPECT_EQ(e.cq.all.back().result, -kEio);
  // A later successful fsync does not resurrect the doomed pages.
  DiskParams ok;
  e.n.disk().set_params(ok);
  e.f->submit_sync(3);
  e.settle();
  EXPECT_EQ(e.cq.all.back().result, 0);
  EXPECT_TRUE(e.durable().empty());
  EXPECT_EQ(e.visible(), fill(10, 1));  // still readable from the cache
  e.f.reset();
  e.n.boot();
  e.n.crash(CrashKind::Host);
  EXPECT_TRUE(e.visible().empty());
  EXPECT_EQ(e.w.stats().disk_eio, 1u);
}

TEST(Disk, StallsDelayCompletionsBetweenOneMsAndMax) {
  DiskParams p;
  p.stall_ppm = 1'000'000;
  p.stall_max_ns = 5 * kSec;
  p.heartbeat_ns = 100 * kMs;
  DiskFixture d(7, p);
  d.w.set_phase(Phase::Safety);
  std::vector<Nanos> latencies;
  for (int i = 0; i < 50; ++i) {
    const Nanos t0 = d.w.now();
    d.f->submit_write(0, fill(10, 1), false, 1);
    while (d.cq.all.size() < static_cast<std::size_t>(i + 1)) {
      d.w.step();
      d.cq.drain(*d.f);
    }
    latencies.push_back(d.w.now() - t0);
  }
  EXPECT_GE(*std::min_element(latencies.begin(), latencies.end()), kMs);
  EXPECT_LE(*std::max_element(latencies.begin(), latencies.end()), 5 * kSec + kMs);
  EXPECT_GT(*std::max_element(latencies.begin(), latencies.end()), 100 * kMs);
  EXPECT_EQ(d.w.stats().disk_stalls, 50u);
  EXPECT_GT(d.w.probes().hits("disk.stall_longer_than_heartbeat"), 0u);
}

TEST(Disk, QueueDepthIsBounded) {
  DiskParams p;
  p.max_queue_depth = 4;
  DiskFixture d(8, p);
  for (int i = 0; i < 4; ++i) EXPECT_TRUE(d.f->submit_write(0, fill(1, 1), false, 1));
  EXPECT_FALSE(d.f->submit_write(0, fill(1, 1), false, 1));
  EXPECT_FALSE(d.f->submit_sync(1));
}

TEST(FaultAtlas, NeverAllReplicasFaultyAndSingleCopyNeverFaulty) {
  const FaultAtlas atlas(99, 900'000);
  int faulty = 0;
  for (std::uint64_t key = 0; key < 50; ++key) {
    for (std::uint64_t area = 0; area < 200; ++area) {
      EXPECT_FALSE(atlas.faulty(key, area, 0, 1));
      for (std::uint32_t n = 2; n <= 4; ++n) {
        std::uint32_t bad = 0;
        for (std::uint32_t r = 0; r < n; ++r) bad += atlas.faulty(key, area, r, n) ? 1u : 0u;
        ASSERT_LT(bad, n);
        faulty += static_cast<int>(bad);
      }
    }
  }
  EXPECT_GT(faulty, 10'000);
  EXPECT_FALSE(FaultAtlas(1, 0).faulty(1, 1, 0, 3));
}

TEST(FaultAtlas, CorruptionStaysInsideFaultyAreasOnOneReplica) {
  FaultConfig f = base_fault_config();
  f.set(Param::DiskAtlasPpm, 500'000);
  World w(21, f);
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  DiskParams p;
  p.bitflip_ppm = 1'000'000;
  p.misdirect_ppm = 0;
  a.disk().set_params(p);
  b.disk().set_params(p);
  a.disk().set_atlas_replica(0, 2);
  b.disk().set_atlas_replica(1, 2);
  w.set_phase(Phase::Safety);
  DiskFile fa(a, "journal");
  DiskFile fb(b, "journal");
  const std::uint64_t area = w.atlas().area_bytes();
  const std::uint64_t key = FaultAtlas::file_key("journal", 7);
  const auto data = fill(static_cast<std::size_t>(area), 0x5A);
  for (std::uint64_t i = 0; i < 32; ++i) {
    fa.submit_write(i * area, data, true, i);
    fb.submit_write(i * area, data, true, i);
  }
  test::run_for(w, kSec);
  const auto ia = a.disk().durable_image(a.disk().open("journal"));
  const auto ib = b.disk().durable_image(b.disk().open("journal"));
  int corrupted = 0;
  for (std::uint64_t i = 0; i < 32; ++i) {
    const bool ca = !std::equal(data.begin(), data.end(), ia.begin() + static_cast<std::ptrdiff_t>(i * area));
    const bool cb = !std::equal(data.begin(), data.end(), ib.begin() + static_cast<std::ptrdiff_t>(i * area));
    EXPECT_EQ(ca, w.atlas().faulty(key, i, 0, 2));
    EXPECT_EQ(cb, w.atlas().faulty(key, i, 1, 2));
    EXPECT_FALSE(ca && cb) << "both copies of area " << i << " corrupted";
    corrupted += (ca ? 1 : 0) + (cb ? 1 : 0);
  }
  EXPECT_GT(corrupted, 5);
  EXPECT_EQ(w.stats().disk_bitflip, static_cast<std::uint64_t>(corrupted));
}

TEST(FaultAtlas, MisdirectedWritesLandOnlyInFaultyAreas) {
  FaultConfig f = base_fault_config();
  f.set(Param::DiskAtlasPpm, 700'000);
  World w(22, f);
  Node& a = w.add_node("a");
  DiskParams p;
  p.misdirect_ppm = 1'000'000;
  a.disk().set_params(p);
  a.disk().set_atlas_replica(0, 2);
  w.set_phase(Phase::Safety);
  DiskFile fa(a, "journal");
  const std::uint64_t area = w.atlas().area_bytes();
  const std::uint64_t key = FaultAtlas::file_key("journal", 7);
  for (std::uint64_t i = 0; i < 64; ++i) fa.submit_write(i * area + 1024, fill(512, 0x77), true, i);
  test::run_for(w, kSec);
  const auto img = a.disk().durable_image(a.disk().open("journal"));
  for (std::uint64_t i = 0; i < img.size(); ++i) {
    if (img[i] == std::byte{0x77}) {
      ASSERT_TRUE(w.atlas().faulty(key, i / area, 0, 2) || (i % area >= 1024 && i % area < 1536)) << i;
    }
  }
  EXPECT_GT(w.stats().disk_misdirect, 0u);
}

}  // namespace
}  // namespace lle::sim
