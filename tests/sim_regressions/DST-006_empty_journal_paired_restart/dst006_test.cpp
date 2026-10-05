// DST-006 regression test (scripted, seed-independent): a paired node whose journal
// recovered empty after it had started the day must rejoin its partner, not start the
// day again. Found by `exsim --world=exchange_ha` (O-LINE); see sim/ledger/bugs.yaml.
//
// A journal write fails before the first batch is durable, the io stage stops the node,
// and the restart finds no record. Meanwhile the pair had released records: paired
// release needs only both L2s (10 §4). At the found tree exchanged decided "rejoin" only
// on a non-empty journal, so this node ran the day start again: incarnation 1 once more,
// start_paired(1, initial primary) while its partner ran the day. As the day's first
// primary it sequenced a second history from index 7. Its md sent line A bytes for
// sequence numbers its partner's line B had already carried with other bytes.
//
// Production pieces: start_impl.h's restart decision (restart_must_rejoin, which
// Node::open_journal and the simulator call) and begin_rejoin on an empty journal, which
// must find the day's configuration digest without an EpochStart.
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
#include "exchanged/record_log.h"
#include "exchanged/shared.h"
#include "exchanged/start_impl.h"
#include "journal/l2_ring.h"
#include "journal/record.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "outlog/day.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"

namespace lle {
namespace {

constexpr std::uint32_t kDay = 20261001;
constexpr Nanos kMidnight = 1'790'827'200'000'000'000;

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
  std::vector<engine::SymbolEntry> syms{2};
  std::vector<engine::AccountEntry> accts{1};
  std::vector<engine::SessionEntry> sess{engine::SessionEntry{1, 100}};
  std::vector<engine::ScheduleEntry> sched = engine::standard_schedule(false, false);
  std::unique_ptr<seq::EngineDay> day;
  Tables() {
    syms[0].symbol = Symbol8("AAPL");
    syms[0].prior_close = 1'000'000;
    syms[1].symbol = Symbol8("MSFT");
    syms[1].prior_close = 2'000'000;
    accts[0].account_id = 100;
    accts[0].firms[0] = Mpid4("FRMA");
    day = std::make_unique<seq::EngineDay>(seq::EngineTables{syms, accts, sess, {}, sched}, kMidnight);
  }
};

// The digest the day start stamps into its EpochStart, as the partner journaled it.
std::uint64_t day_start_digest(const Tables& t) {
  auto mem = std::make_unique<std::uint64_t[]>((std::size_t{1} << 20) / 8);
  journal::L2Ring<2> ring;
  ring.init(reinterpret_cast<std::byte*>(mem.get()), std::size_t{1} << 20, 0x0DDBA11CAFEF00D5ull);
  Env::OuchQueue ouch;
  Env::SessionQueue events;
  Env::AdminQueue admin;
  Clock clock;
  seq::Sequencer<Env> sequencer(clock, ouch, events, admin, ring, t.day->timers(), seq::SequencerConfig{});
  journal::DayStart ds;
  ds.trading_date = kDay;
  ds.local_midnight_ns = kMidnight;
  EXPECT_TRUE(sequencer.start_day(ds, t.day->config(), 1, 0).has_value());
  std::uint64_t digest = 0;
  (void)ring.drain(
      0,
      [&](const journal::RecordView& v) {
        if (v.type() == journal::RecordType::EpochStart) {
          if (const auto e = journal::decode_epoch_start(v)) digest = e->config_digest;
        }
      },
      1u << 20);
  return digest;
}

// The rejoin's storage (start_impl.h Io), in memory: the incarnation file exists.
struct TestIo {
  std::uint64_t incarnation = 1;  // written by the day start
  std::uint64_t read_incarnation(const std::string&) { return incarnation; }
  bool write_incarnation(const std::string&, std::uint64_t v) {
    incarnation = v;
    return true;
  }
};

TEST(DST006, AnEmptyJournalOfADayThatStartedHereRejoins) {
  // exchanged and the simulator decide with this: paired, journal recovered empty,
  // incarnation file present (written at the day start).
  EXPECT_TRUE(exch::restart_must_rejoin(true, 0, true)) << "an empty journal of a started day must rejoin";
  EXPECT_TRUE(exch::restart_must_rejoin(true, 42, true));
  EXPECT_TRUE(exch::restart_must_rejoin(true, 42, false));
  EXPECT_FALSE(exch::restart_must_rejoin(true, 0, false));  // the day's first start
  EXPECT_FALSE(exch::restart_must_rejoin(false, 0, true));  // solo: continue_day / day start
}

TEST(DST006, TheRejoinOfAnEmptyJournalJoinsUnderTheDaysDigest) {
  const Tables t;
  const std::uint64_t want = day_start_digest(t);
  ASSERT_NE(want, 0u);

  journal::MemSegmentDir dir;
  Prng nonce(7);
  journal::SegmentPreparer<journal::MemSegmentDir, Prng> prep(dir, nonce, kDay,
                                                             journal::kSegmentHeaderBytes + 4 * journal::kBatchBytes);
  const std::filesystem::path root =
      std::filesystem::temp_directory_path() /
      ("dst006-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
  std::filesystem::remove_all(root);
  exch::RecordLog rlog(std::size_t{1} << 16, 1024, (root / "journal").string(), kDay);
  auto sh = std::make_unique<exch::Shared>();
  engine::Engine eng;
  outlog::OutlogDay out;
  exch::RecoveredDay recovered;
  std::uint64_t recovered_index = 0;  // the journal recovered empty
  const std::vector<std::uint32_t> ids{1};
  exch::RejoinParts<journal::MemSegmentDir, journal::SegmentPreparer<journal::MemSegmentDir, Prng>, exch::RecordLog,
                    outlog::OutlogDay>
      parts{.dir = dir,
            .prep = prep,
            .rlog = rlog,
            .sh = *sh,
            .engine = eng,
            .out = out,
            .recovered = recovered,
            .recovered_index = recovered_index,
            .date = kDay,
            .layout = exch::RecoveryLayout{(root / "outlog").string(), kDay, ids},
            .config = t.day->config(),
            .snapshots_dir = (root / "snapshots").string(),
            .replay_snapshots = std::string(),
            .incarnation_path = (root / "journal" / "incarnation").string()};
  TestIo io;
  const auto begun = exch::begin_rejoin(io, parts);
  std::filesystem::remove_all(root);
  ASSERT_TRUE(begun.has_value()) << begun.error();
  EXPECT_EQ(begun->config_digest, want) << "the empty journal must join under the configuration the day started with";
  EXPECT_EQ(begun->incarnation, 2u);  // a new incarnation, never 1 again
  EXPECT_TRUE(sh->mirror.load());
}

}  // namespace
}  // namespace lle
