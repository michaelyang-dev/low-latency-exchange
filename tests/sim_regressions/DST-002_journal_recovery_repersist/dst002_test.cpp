// DST-002 regression test (scripted, seed-independent), on the simulated disk
// with the PosixJournalDevice model: the fdatasync of a batch fails (fsyncgate),
// the writer exits, recovery on restart finds the batch in the page cache and the
// resumed writer reports it durable. After a power cut it must still be there.
// Found by `exsim --seed=0x9 --world=journal`; see sim/ledger/bugs.yaml.
#include <gtest/gtest.h>

#include <vector>

#include "journal/journal_writer.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "sim/disk.h"
#include "sim/node.h"
#include "sim/world.h"
#include "sim/worlds/journal_device.h"

namespace lle::sim {
namespace {

namespace jr = lle::journal;
using worlds::SimJournalDevice;
using worlds::SimSegmentDir;
constexpr std::uint32_t kDay = 20261001;

struct Stream {
  jr::Sealer sealer;
  jr::RecordBuilder b{sealer};
  std::vector<std::byte> buf = std::vector<std::byte>(jr::kMaxRecordBytes);
  std::span<std::byte> next() {
    const jr::Timer t{static_cast<std::uint32_t>(b.chain().last_index + 1), jr::TimerKind::SystemEvent, 0};
    return b.append(buf, static_cast<Nanos>(b.chain().last_index + 1) * 1000, t);
  }
};

template <class Pred>
void step_until(World& w, jr::JournalWriter<SimJournalDevice>& wr, Pred done) {
  for (int i = 0; i < 100000 && !done(); ++i) {
    (void)wr.flush();
    (void)wr.poll();
    if (w.pending_events() == 0) {
      // Completions may unblock a flush that schedules new I/O.
      (void)wr.flush();
      (void)wr.poll();
      if (w.pending_events() == 0) break;
    }
    w.step();
  }
  (void)wr.poll();
}

TEST(DST002, RecordsTheResumedWriterReportsDurableSurviveAPowerCut) {
  World w(1, base_fault_config());
  Node& n = w.add_node("journal");
  w.set_phase(Phase::Safety);
  const jr::RecoveryOptions ro{kDay, jr::kBatchBytes, true};
  Stream s;
  {
    SimSegmentDir dir(n, "journal/");
    Rng rng(5);
    jr::SegmentPreparer<SimSegmentDir, Rng> prep(dir, rng, kDay, jr::kMinSegmentBytes);
    jr::JournalWriterOptions wo;
    wo.day = kDay;
    wo.queue_depth = 1;
    wo.buffers = 2;
    jr::JournalWriter<SimJournalDevice> wr(wo);
    wr.start(jr::ChainState{});
    const auto ps = prep.create();
    ASSERT_TRUE(ps.has_value());
    ASSERT_TRUE(wr.add_prepared(dir.device(ps->handle), ps->handle, ps->header));
    for (int i = 0; i < 20; ++i) ASSERT_EQ(wr.append(s.next(), s.sealer), jr::JournalWriter<SimJournalDevice>::Status::Ok);
    step_until(w, wr, [&] { return wr.durable_index() == 20; });
    ASSERT_EQ(wr.durable_index(), 20u);
    // The next batch's fdatasync fails: its pages stay readable, never durable.
    DiskParams bad;
    bad.eio_sync_ppm = 1'000'000;
    n.disk().set_params(bad);
    for (int i = 0; i < 5; ++i) ASSERT_EQ(wr.append(s.next(), s.sealer), jr::JournalWriter<SimJournalDevice>::Status::Ok);
    step_until(w, wr, [&] { return wr.failed(); });
    ASSERT_TRUE(wr.failed());  // fatal: the process exits
  }
  n.disk().set_params(DiskParams{});
  std::uint64_t claimed = 0;
  {
    SimSegmentDir dir(n, "journal/");
    const jr::RecoveryResult r = jr::recover(dir, ro);
    ASSERT_TRUE(r.usable()) << r.detail;
    claimed = r.chain.last_index;  // what a resumed writer reports as durable_index
    ASSERT_EQ(claimed, 25u);
  }
  n.disk().crash_host();
  SimSegmentDir dir(n, "journal/");
  const jr::RecoveryResult after = jr::recover(dir, ro);
  ASSERT_TRUE(after.usable()) << after.detail;
  EXPECT_EQ(after.chain.last_index, claimed) << "records reported durable after recovery were lost";
}

}  // namespace
}  // namespace lle::sim
