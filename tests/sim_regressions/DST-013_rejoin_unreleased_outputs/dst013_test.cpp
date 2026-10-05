// DST-013 regression test (scripted, seed-independent): a rejoin's reload must not put
// into the output log the outputs of records the primary may not have released. Found
// by `exsim --world=exchange_ha_split` (O-LIVE, in ci-sim's campaign); see
// sim/ledger/bugs.yaml.
//
// The output log holds released messages only (the io stage appends what egress
// releases), and the gateways' replay stores and the re-request server are built from it.
// A joiner copies records from its solo primary beyond the primary's release (they are
// not yet durable there, 10 §4), and a restart rejoins with them: the reload (reload_to)
// replays the journal through its end. At the found tree it regenerated the output log
// through that end, so the joiner's gateways replayed those outputs, executions among
// them, to clients that logged in. The primary then lost the records in a host crash and
// resumed without them: clients held fills the day never had, and asked for SoupBinTCP
// sequence numbers neither node would ever reach (no End of Session, O-LIVE). At the fix
// the reload keeps them for egress, which releases them in order with the rest.
//
// Production pieces: start_impl.h's reload_to (the rejoin hook) on a journal the
// production sequencer wrote, with an output log that holds nothing yet.
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "common/prng.h"
#include "concurrent/mpsc_scq.h"
#include "engine/engine.h"
#include "engine/scenario.h"
#include "exchanged/record_log.h"
#include "exchanged/recovery_impl.h"
#include "exchanged/shared.h"
#include "exchanged/start_impl.h"
#include "journal/journal_writer.h"
#include "journal/l2_ring.h"
#include "journal/mem_journal_device.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "outlog/day.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"

namespace lle {
namespace {

constexpr std::uint32_t kDay = 20261001;
constexpr Nanos kMidnight = 1'790'827'200'000'000'000;
constexpr std::uint64_t kRingNonce = 0x0DDBA11CAFEF00D5ull;

struct Clock {
  Nanos real = kMidnight;
  Nanos now_mono() const noexcept { return 0; }
  Nanos now_real() noexcept { return real += 1'000; }
  std::uint64_t tsc() const noexcept { return 0; }
};
struct Env {
  using Clock = lle::Clock;
  using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 64>;
  using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 16>;
  using AdminQueue = conc::MpscScqRing<seq::AdminMsg, 16>;
  using Ring = journal::L2Ring<2>;
};

struct Tables {
  std::vector<engine::SymbolEntry> syms{1};
  std::vector<engine::AccountEntry> accts{1};
  std::vector<engine::SessionEntry> sess{engine::SessionEntry{1, 100}};
  std::vector<engine::ScheduleEntry> sched = engine::standard_schedule(false, false);
  std::unique_ptr<seq::EngineDay> day;
  Tables() {
    syms[0].symbol = Symbol8("AAPL");
    syms[0].prior_close = 1'000'000;
    accts[0].account_id = 100;
    accts[0].firms[0] = Mpid4("FRMA");
    day = std::make_unique<seq::EngineDay>(seq::EngineTables{syms, accts, sess, {}, sched}, kMidnight);
  }
};

// The rejoin's storage: the node's POSIX output log and snapshots, no incarnation file.
struct TestIo : exch::PosixRecoveryIo {
  void note(const std::string&) {}
  void warn(const std::string& line) { ADD_FAILURE() << line; }
  std::vector<std::uint64_t> remove_snapshots_above(const std::string&, std::uint64_t) { return {}; }
};

using Writer = journal::JournalWriter<journal::MemJournalDevice>;
using Prep = journal::SegmentPreparer<journal::MemSegmentDir, Prng>;

// The day start and `orders` entered orders of session 1, sequenced by the production
// sequencer and written to `dir` by the journal writer. Returns the last index.
std::uint64_t journal_a_day(const Tables& t, journal::MemSegmentDir& dir, Prep& prep, int orders) {
  auto mem = std::make_unique<std::uint64_t[]>((std::size_t{1} << 20) / 8);
  journal::L2Ring<2> ring;
  ring.init(reinterpret_cast<std::byte*>(mem.get()), std::size_t{1} << 20, kRingNonce);
  Env::OuchQueue ouch;
  Env::SessionQueue events;
  Env::AdminQueue admin;
  Clock clock;
  seq::Sequencer<Env> sequencer(clock, ouch, events, admin, ring, t.day->timers(), seq::SequencerConfig{});
  journal::DayStart ds;
  ds.trading_date = kDay;
  ds.local_midnight_ns = kMidnight;
  EXPECT_TRUE(sequencer.start_day(ds, t.day->config(), 1, 0).has_value());
  for (int i = 0; i < orders; ++i) {
    seq::InboundMsg m;
    m.session_id = 1;
    m.account = 100;
    m.instance = 1;
    const auto b = engine::enter_msg({.urn = static_cast<UserRefNum>(i + 1), .qty = 100, .price = 1'000'000});
    m.len = static_cast<std::uint16_t>(b.size());
    std::memcpy(m.bytes, b.data(), b.size());
    EXPECT_TRUE(ouch.try_push(m));
  }
  for (int i = 0; i < 16; ++i) (void)sequencer.poll();

  journal::JournalWriterOptions wo;
  wo.day = kDay;
  Writer w(wo);
  w.start(journal::ChainState{});
  for (int i = 0; i < 2; ++i) {
    auto p = prep.create();
    EXPECT_TRUE(p.has_value());
    EXPECT_TRUE(w.add_prepared(dir.device(p->handle), p->handle, p->header));
  }
  const journal::Sealer ring_sealer(kRingNonce);
  std::uint64_t last = 0;
  (void)ring.drain(
      0,
      [&](const journal::RecordView& v) {
        for (int spins = 0;; ++spins) {
          const auto st = w.append(v.bytes(), ring_sealer);
          if (st == Writer::Status::Ok) break;
          EXPECT_EQ(st, Writer::Status::Busy);
          if (spins > 100000) return;
          (void)w.flush();
          (void)w.poll();
        }
        last = v.index();
      },
      1u << 20);
  for (int spins = 0; w.durable_index() < last && spins < 100000; ++spins) {
    (void)w.flush();
    (void)w.poll();
  }
  EXPECT_EQ(w.durable_index(), last);
  return last;
}

TEST(DST013, ARejoinReloadDoesNotWriteOutputsTheOutputLogDidNotHold) {
  const Tables t;
  journal::MemSegmentDir dir;
  Prng nonce(13);
  Prep prep(dir, nonce, kDay, journal::kSegmentHeaderBytes + 16 * journal::kBatchBytes);
  const std::uint64_t last = journal_a_day(t, dir, prep, 6);
  ASSERT_GT(last, 6u);

  const std::filesystem::path root =
      std::filesystem::temp_directory_path() /
      ("dst013-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
  std::filesystem::remove_all(root);
  const std::vector<std::uint32_t> ids{1};
  const exch::RecoveryLayout layout{(root / "outlog").string(), kDay, ids};
  outlog::OutlogDay out;
  std::filesystem::create_directories(root / "outlog");
  ASSERT_TRUE(out.open(layout.outlog_root, kDay, ids).has_value());  // nothing released yet: empty
  exch::RecordLog rlog(std::size_t{1} << 16, 1024, (root / "journal").string(), kDay);
  auto sh = std::make_unique<exch::Shared>();
  engine::Engine eng;
  exch::RecoveredDay recovered;
  std::uint64_t recovered_index = last;
  exch::RejoinParts<journal::MemSegmentDir, Prep, exch::RecordLog, outlog::OutlogDay> parts{
      .dir = dir,
      .prep = prep,
      .rlog = rlog,
      .sh = *sh,
      .engine = eng,
      .out = out,
      .recovered = recovered,
      .recovered_index = recovered_index,
      .date = kDay,
      .layout = layout,
      .config = t.day->config(),
      .snapshots_dir = (root / "snapshots").string(),
      .replay_snapshots = std::string(),
      .incarnation_path = (root / "journal" / "incarnation").string()};
  TestIo io;
  const exch::ReloadResult r = exch::reload_to(io, parts, last);
  const exch::OutlogPositions pos = exch::outlog_positions(out);
  const std::uint64_t itch_total = recovered.itch_total, soup_total = recovered.soup_total;
  (void)out.close();
  std::filesystem::remove_all(root);
  ASSERT_TRUE(r.ok);
  ASSERT_GT(soup_total, 0u) << "the orders must produce OUCH outputs";
  ASSERT_GT(itch_total, 0u);
  // The reload replayed every record into the engine, but the output log, which the
  // gateways replay and the re-request server serves, still holds only what was released.
  EXPECT_EQ(pos.itch_next, 1u) << "the reload wrote ITCH messages no one released into itch.bin";
  ASSERT_EQ(pos.soup_next.size(), 1u);
  EXPECT_EQ(pos.soup_next[0].second, 1u)
      << "the reload wrote OUCH messages no one released into the session's output log: the gateway replays them";
}

}  // namespace
}  // namespace lle
