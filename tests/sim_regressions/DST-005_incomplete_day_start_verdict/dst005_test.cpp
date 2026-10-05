// DST-005 candidate (sim/ledger/bugs.yaml): a journal left with an incomplete day start
// (the process or the disk failed while the day-start records were being written:
// DayStart and some Config chunks, no EpochStart) is refused at restart with the wrong
// verdict. replay_day compared the journaled configuration with the configuration file
// (ADR-028) before checking that the day start was complete, so the operator was told
// to "restore the file the day was started with" instead of "the journal holds an
// incomplete day start ... move the journal directory aside", the documented remedy
// (exchange-node.md §8, recovery.h).
//
// Production pieces only: the sequencer emits the day start into an L2 ring, the
// journal writer persists the first records of it (DayStart and part of the Config),
// journal::recover establishes the prefix, and exch::basic_replay_day (the recovery
// exchanged runs, recovery_impl.h) gives the verdict.
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/prng.h"
#include "concurrent/mpsc_scq.h"
#include "engine/engine.h"
#include "engine/records.h"
#include "exchanged/recovery_impl.h"
#include "journal/journal_writer.h"
#include "journal/l2_ring.h"
#include "journal/recovery.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "outlog/day.h"
#include "outlog/reader.h"
#include "outlog/repair.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"
#include "snapshot/reader.h"
#include "snapshotd/out_digest.h"

namespace lle {
namespace {

constexpr std::uint32_t kDay = 20261001;
constexpr Nanos kMidnight = 1'790'827'200'000'000'000;
constexpr std::uint64_t kNonce = 0x0DDBA11CAFEF00D5ull;

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

// The storage recovery reads: POSIX output log, no snapshots.
struct TestIo {
  using Reader = outlog::OutlogReader;
  std::unique_ptr<Reader> make_reader() { return std::make_unique<Reader>(); }
  bool truncate_outlog(const std::string& path, SeqNo keep) { return outlog::truncate_to(path, keep).has_value(); }
  std::optional<snap::SnapshotInfo> find_snapshot(const std::string&, std::uint64_t) { return std::nullopt; }
  std::expected<snap::MappedSnapshot, snap::LoadError> open_snapshot(const std::string& path) {
    return snap::MappedSnapshot::open(path);
  }
  std::optional<snapd::OutDigests> read_sidecar(const std::string&) { return std::nullopt; }
  void note(const std::string&) {}
};

// The day's tables; `prior_close` varies the configuration.
struct Tables {
  std::vector<engine::SymbolEntry> syms{2};
  std::vector<engine::AccountEntry> accts{1};
  std::vector<engine::SessionEntry> sess{engine::SessionEntry{1, 100}};
  std::vector<engine::ScheduleEntry> sched = engine::standard_schedule(false, false);
  std::unique_ptr<seq::EngineDay> day;
  explicit Tables(PxE4 msft_prior_close = 2'000'000) {
    syms[0].symbol = Symbol8("AAPL");
    syms[0].prior_close = 1'000'000;
    syms[1].symbol = Symbol8("MSFT");
    syms[1].prior_close = msft_prior_close;
    accts[0].account_id = 100;
    accts[0].firms[0] = Mpid4("FRMA");
    day = std::make_unique<seq::EngineDay>(seq::EngineTables{syms, accts, sess, {}, sched}, kMidnight);
  }
};

// The day start of `t` as the sequencer emits it (DayStart, the Config chunks, EpochStart).
std::vector<std::vector<std::byte>> day_start_records(const Tables& t, const journal::Sealer** sealer,
                                                      journal::L2Ring<2>& ring) {
  static Env::OuchQueue ouch;
  static Env::SessionQueue events;
  static Env::AdminQueue admin;
  Clock clock;
  seq::Sequencer<Env> sequencer(clock, ouch, events, admin, ring, t.day->timers(), seq::SequencerConfig{});
  journal::DayStart ds;
  ds.trading_date = kDay;
  ds.local_midnight_ns = kMidnight;
  EXPECT_TRUE(sequencer.start_day(ds, t.day->config(), 1, 1).has_value());
  std::vector<std::vector<std::byte>> recs;
  (void)ring.drain(0, [&](const journal::RecordView& v) { recs.emplace_back(v.bytes().begin(), v.bytes().end()); },
                   1u << 20);
  *sealer = &ring.sealer();
  return recs;
}

// The first `n` records persisted, then the node's recovery on that journal: its verdict.
std::string verdict_after(const std::vector<std::vector<std::byte>>& recs, std::size_t n, const journal::Sealer& sealer,
                          std::span<const seq::ConfigBlob> expected_config) {
  journal::MemSegmentDir dir;
  Prng nonce(7);
  journal::SegmentPreparer prep(dir, nonce, kDay, journal::kSegmentHeaderBytes + 16 * journal::kBatchBytes);
  auto p = prep.create();
  EXPECT_TRUE(p.has_value());
  journal::JournalWriterOptions wo;
  wo.day = kDay;
  journal::JournalWriter<journal::MemJournalDevice> w(wo);
  EXPECT_TRUE(w.add_prepared(dir.device(p->handle), p->handle, p->header));
  for (std::size_t i = 0; i < n; ++i) {
    EXPECT_EQ(w.append(recs[i], sealer), journal::JournalWriter<journal::MemJournalDevice>::Status::Ok);
  }
  for (int spins = 0; w.batch_used() != 0 || w.in_flight() != 0; ++spins) {
    if (spins > 100000) break;
    (void)w.flush();
    (void)w.poll();
  }
  EXPECT_EQ(w.durable_index(), n);
  journal::RecoveryOptions ro;
  ro.day = kDay;
  ro.repair = false;
  const journal::RecoveryResult rr = journal::recover(dir, ro);
  EXPECT_TRUE(rr.usable()) << rr.detail;
  EXPECT_EQ(rr.chain.last_index, n);

  const std::filesystem::path root = std::filesystem::temp_directory_path() /
                                     ("dst005-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
                                      "-" + std::to_string(n));
  std::filesystem::remove_all(root);
  const std::vector<std::uint32_t> ids{1};
  outlog::OutlogDay out;
  EXPECT_TRUE(out.open(root.string(), kDay, ids).has_value());
  engine::Engine eng;
  TestIo io;
  const exch::RecoveryLayout layout{root.string(), kDay, ids};
  const auto rd = exch::basic_replay_day(io, dir, rr, eng, out, layout, expected_config, std::string());
  (void)out.close();
  std::filesystem::remove_all(root);
  return rd ? std::string() : rd.error();
}

// DayStart and the first Config chunk reached the journal: the process died (or the
// next write failed) before the rest of the day start. Refused, for the right reason:
// the day start is incomplete (nothing was released), not a configuration file that
// differs from the journal.
TEST(DST005, AnIncompleteDayStartIsReportedAsOne) {
  const Tables t;
  auto mem = std::make_unique<std::uint64_t[]>((std::size_t{1} << 20) / 8);
  journal::L2Ring<2> ring;
  ring.init(reinterpret_cast<std::byte*>(mem.get()), std::size_t{1} << 20, kNonce);
  const journal::Sealer* sealer = nullptr;
  const auto recs = day_start_records(t, &sealer, ring);
  ASSERT_GE(recs.size(), 4u);
  ASSERT_EQ(journal::RecordView(recs.back()).type(), journal::RecordType::EpochStart);
  const std::string why = verdict_after(recs, 2, *sealer, t.day->config());
  ASSERT_FALSE(why.empty());
  EXPECT_NE(why.find("incomplete day start"), std::string::npos) << why;
}

// The reorder must not mask a real mismatch: a complete day start whose journaled
// configuration differs from the configuration file still gets the ADR-028 verdict.
TEST(DST005, ACompleteDayStartWithAnotherConfigurationIsStillAMismatch) {
  const Tables journaled;
  const Tables file(2'100'000);  // the file was edited after the day started
  auto mem = std::make_unique<std::uint64_t[]>((std::size_t{1} << 20) / 8);
  journal::L2Ring<2> ring;
  ring.init(reinterpret_cast<std::byte*>(mem.get()), std::size_t{1} << 20, kNonce);
  const journal::Sealer* sealer = nullptr;
  const auto recs = day_start_records(journaled, &sealer, ring);
  const std::string why = verdict_after(recs, recs.size(), *sealer, file.day->config());
  ASSERT_FALSE(why.empty());
  EXPECT_NE(why.find("ADR-028"), std::string::npos) << why;
  // And the same journal with its own configuration recovers.
  EXPECT_EQ(verdict_after(recs, recs.size(), *sealer, journaled.day->config()), std::string());
}

}  // namespace
}  // namespace lle
