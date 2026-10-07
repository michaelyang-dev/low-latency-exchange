// DST-017 (sim/ledger/bugs.yaml): snapshotd continued from a snapshot whose record a
// rejoin had since replaced. A snapshot at P describes the history up to P; a rejoining
// node truncates its journal and writes its partner's records at the same indices.
// snapshotd, a process of its own, could load a snapshot of the old history (before the
// truncation, or one that exchanged's removal of snapshots above the truncation point
// missed), then follow the new journal from P + 1 without checking that record P was
// still the one it describes: every later snapshot carried the old history's state.
//
// The fix: the sidecar names record P by its content crc (LLEOUTD2); snapshotd removes
// a snapshot whose record P is gone from the journal, and its cursor checks record P
// when it resumes from one.
//
// Production pieces: the sequencer writes two histories (A, then B: the same day start
// and first orders, then other orders, more of them) into an L2 ring, the journal writer
// persists them as POSIX segment files, and snapshotd's BasicSnapshotter follows them.
// Every snapshot left on disk must hold the state a fresh engine reaches at its index
// of the journal it ends on (B).
#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/prng.h"
#include "concurrent/mpsc_scq.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "engine/records.h"
#include "engine/scenario.h"
#include "journal/journal_writer.h"
#include "journal/l2_ring.h"
#include "journal/posix_segment_dir.h"
#include "journal/replay.h"
#include "journal/segment_preparer.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"
#include "snapshot/engine_section.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshotd/out_digest.h"
#include "snapshotd/snapshotter.h"

namespace lle {
namespace {

namespace fs = std::filesystem;

constexpr std::uint32_t kDay = 20261001;
constexpr Nanos kMidnight = 1'790'827'200'000'000'000;
constexpr std::uint64_t kEvery = 16;  // a SnapshotMark after every 16th index

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

struct History {
  std::vector<std::vector<std::byte>> recs;
  std::unique_ptr<journal::L2Ring<2>> ring;  // its sealer seals recs
  std::unique_ptr<std::uint64_t[]> mem;
};

// The day start, the schedule's timers to 10:00, then `orders` Enter Orders of session 1:
// the first `common` priced the same in every history, the rest by `seed`; as the
// sequencer journals them.
History history(const Tables& t, std::size_t common, std::size_t orders, std::uint64_t seed) {
  History h;
  constexpr std::size_t kRing = std::size_t{1} << 22;
  h.mem.reset(new std::uint64_t[kRing / 8]());
  h.ring = std::make_unique<journal::L2Ring<2>>();
  h.ring->init(reinterpret_cast<std::byte*>(h.mem.get()), kRing, 0x5EA1ED00F00Dull + seed);
  Env::OuchQueue ouch;
  Env::SessionQueue events;
  Env::AdminQueue admin;
  Clock clock;
  seq::SequencerConfig sc;
  sc.snapshot_every = kEvery;
  seq::Sequencer<Env> sequencer(clock, ouch, events, admin, *h.ring, t.day->timers(), sc);
  journal::DayStart ds;
  ds.trading_date = kDay;
  ds.local_midnight_ns = kMidnight;
  EXPECT_TRUE(sequencer.start_day(ds, t.day->config(), 1, 1).has_value());
  // 10:00: the first poll journals the schedule's timers up to then (the open and the
  // opening cross), so the orders trade and the two histories' states differ.
  clock.real = kMidnight + Nanos{10} * 3600 * 1'000'000'000;
  Prng px(seed);
  for (std::size_t i = 0; i < orders; ++i) {
    const std::int64_t tick = i < common ? static_cast<std::int64_t>(i % 7) : static_cast<std::int64_t>(px.below(9));
    const std::vector<std::byte> b = engine::enter_msg({.urn = static_cast<UserRefNum>(i + 1),
                                                        .side = i % 2 == 0 ? ouch50::Side::Buy : ouch50::Side::Sell,
                                                        .qty = 100,
                                                        .symbol = "AAPL",
                                                        .price = static_cast<std::uint64_t>(990'000 + 1'000 * tick)});
    seq::InboundMsg m;
    m.session_id = 1;
    m.account = 100;
    m.len = static_cast<std::uint16_t>(b.size());
    std::memcpy(m.bytes, b.data(), b.size());
    EXPECT_TRUE(ouch.try_push(m));
    (void)sequencer.poll();
  }
  (void)h.ring->drain(0, [&](const journal::RecordView& v) { h.recs.emplace_back(v.bytes().begin(), v.bytes().end()); },
                      1u << 20);
  return h;
}

// The history as the node's journal: POSIX segment files in `dir` (whatever was there
// before is gone, as after a rejoin's truncation and catch-up).
void write_journal(const fs::path& dir, const History& h) {
  fs::remove_all(dir);
  fs::create_directories(dir);
  auto d = journal::PosixSegmentDir::open(dir.string());
  ASSERT_TRUE(d.has_value()) << d.error();
  Prng nonces(3);
  journal::SegmentPreparer prep(*d, nonces, kDay, journal::kSegmentHeaderBytes + 64 * journal::kBatchBytes);
  auto p = prep.create();
  ASSERT_TRUE(p.has_value());
  journal::JournalWriterOptions wo;
  wo.day = kDay;
  using Writer = journal::JournalWriter<journal::PosixJournalDevice>;
  Writer w(wo);
  w.start(journal::ChainState{});
  ASSERT_TRUE(w.add_prepared(d->device(p->handle), p->handle, p->header));
  for (const auto& r : h.recs) {
    for (int spins = 0;; ++spins) {
      const auto st = w.append(r, h.ring->sealer());
      if (st == Writer::Status::Ok) break;
      ASSERT_EQ(st, Writer::Status::Busy);
      ASSERT_LT(spins, 1'000'000);
      (void)w.flush();
      (void)w.poll();
    }
  }
  for (int spins = 0; (w.batch_used() != 0 || w.in_flight() != 0) && spins < 1'000'000; ++spins) {
    (void)w.flush();
    (void)w.poll();
  }
  ASSERT_EQ(w.durable_index(), h.recs.size());
}

// snapshotd's storage (apps/snapshotd/main.cpp's PosixSnapIo), its lines kept.
struct Io {
  std::vector<std::string>* lines;
  std::expected<journal::PosixSegmentDir, std::string> open_journal(const std::string& path) {
    return journal::PosixSegmentDir::open(path, false, journal::PosixDeviceOptions{.read_only = true});
  }
  std::optional<snap::SnapshotInfo> find_snapshot(const std::string& dir, std::uint64_t max_index) {
    return snap::find_latest(dir, max_index);
  }
  std::expected<snap::MappedSnapshot, snap::LoadError> open_snapshot(const std::string& path) {
    return snap::MappedSnapshot::open(path);
  }
  std::optional<snapd::OutDigests> read_sidecar(const std::string& path) { return snapd::read_sidecar(path); }
  std::expected<std::string, snap::Error> save_engine(const engine::Engine& e, const snap::EngineSnapshotIds& ids,
                                                      const std::string& dir) {
    return snap::save_engine(e, ids, dir);
  }
  bool write_sidecar(const std::string& path, const snapd::OutDigests& d) { return snapd::write_sidecar(path, d); }
  std::vector<std::string> list(const std::string& dir) {
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(dir, ec)) names.push_back(e.path().filename().string());
    return names;
  }
  void remove(const std::string& path) {
    std::error_code ec;
    fs::remove(path, ec);
  }
  void out(const std::string& line) { lines->push_back(line); }
  void err(const std::string& line) { lines->push_back(line); }
  void flush() {}
};
using Snapshotter = snapd::BasicSnapshotter<Io>;

// The state hash a fresh engine reaches after each record of `h`, by index.
std::map<std::uint64_t, std::uint64_t> states(const History& h) {
  struct Null {
    void itch(std::uint64_t, std::span<const std::byte>) {}
    void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte>) {}
    void audit(std::uint64_t, const engine::AuditEvent&) {}
  } sink;
  engine::Engine eng;
  std::map<std::uint64_t, std::uint64_t> out;
  for (const auto& r : h.recs) {
    const journal::RecordView v(r);
    eng.apply(engine::to_input(v), sink);
    out[v.index()] = eng.state_hash();
  }
  return out;
}

// The first index where the two histories hold different records.
std::uint64_t first_difference(const History& a, const History& b) {
  for (std::size_t i = 0; i < std::min(a.recs.size(), b.recs.size()); ++i) {
    if (journal::RecordView(a.recs[i]).content() != journal::RecordView(b.recs[i]).content()) return i + 1;
  }
  return std::min(a.recs.size(), b.recs.size()) + 1;
}

class DST017 : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = fs::temp_directory_path() / ("dst017-" + std::to_string(::getpid()) + "-" +
                                         ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(root_);
    fs::create_directories(root_ / "snapshots");
    a_ = history(t_, 40, 60, 1);
    b_ = history(t_, 40, 90, 2);  // longer: snapshotd finds records after A's snapshots
    diverge_ = first_difference(a_, b_);
    ASSERT_GT(diverge_, kEvery);  // a snapshot of the common history exists
    ASSERT_LT(diverge_ + kEvery, a_.recs.size());  // and one of A's own history
  }
  void TearDown() override { fs::remove_all(root_); }

  snapd::SnapshotterOptions options(bool follow) const {
    snapd::SnapshotterOptions o;
    o.journal = (root_ / "journal").string();
    o.snapshots = (root_ / "snapshots").string();
    o.day = kDay;
    o.build_id = 7;
    o.follow = follow;
    return o;
  }
  // Every snapshot on disk holds B's state at its index; returns how many there are.
  std::size_t check_snapshots_hold_b() {
    const auto want = states(b_);
    std::size_t n = 0;
    for (const auto& e : fs::directory_iterator(root_ / "snapshots")) {
      const auto idx = snap::parse_snapshot_file_name(e.path().filename().string());
      if (!idx) continue;
      auto m = snap::MappedSnapshot::open(e.path().string());
      EXPECT_TRUE(m.has_value()) << e.path();
      if (!m) continue;
      ++n;
      EXPECT_TRUE(want.count(*idx) != 0) << *idx;
      if (want.count(*idx) == 0) continue;
      EXPECT_EQ(m->reader().meta().state_hash, want.at(*idx))
          << "snapshot at " << *idx << " (B diverges from A at " << diverge_ << ") holds another history's state";
    }
    return n;
  }

  Tables t_;
  History a_, b_;
  std::uint64_t diverge_ = 0;
  fs::path root_;
};

// snapshotd starts on a journal that no longer holds the records of its newest
// snapshots: it removes them and continues from the newest one of the common history.
TEST_F(DST017, StartRemovesSnapshotsOfReplacedRecords) {
  std::vector<std::string> lines;
  write_journal(root_ / "journal", a_);
  {
    Snapshotter s0(options(false), Io{&lines});
    ASSERT_TRUE(s0.start(~std::uint64_t{0}));
    ASSERT_TRUE(s0.pass());
    ASSERT_GE(s0.written(), 3u);  // snapshots of the common history and of A's own
  }
  write_journal(root_ / "journal", b_);  // the rejoin: truncated, then the partner's records
  Snapshotter s1(options(false), Io{&lines});
  ASSERT_TRUE(s1.start(~std::uint64_t{0}));
  ASSERT_TRUE(s1.pass());
  EXPECT_EQ(s1.applied(), b_.recs.size());
  EXPECT_EQ(s1.engine().state_hash(), states(b_).at(b_.recs.size()));
  EXPECT_GE(check_snapshots_hold_b(), b_.recs.size() / kEvery);
}

// The race exsim found: snapshotd continues from its newest snapshot (of A's own
// history), then exchanged rejoins under it (truncation, the partner's records). Its
// next pass must not apply B's records on top of A's state.
TEST_F(DST017, ResumeChecksTheSnapshotsRecord) {
  std::vector<std::string> lines;
  write_journal(root_ / "journal", a_);
  {
    Snapshotter s0(options(false), Io{&lines});
    ASSERT_TRUE(s0.start(~std::uint64_t{0}));
    ASSERT_TRUE(s0.pass());
  }
  Snapshotter s1(options(true), Io{&lines});
  ASSERT_TRUE(s1.start(~std::uint64_t{0}));  // continues from A's newest snapshot, still valid here
  ASSERT_GE(s1.applied(), diverge_);         // a snapshot of A's own history
  write_journal(root_ / "journal", b_);
  for (int i = 0; i < 200 && s1.applied() != b_.recs.size(); ++i) ASSERT_TRUE(s1.pass());
  EXPECT_EQ(s1.applied(), b_.recs.size());
  EXPECT_EQ(s1.engine().state_hash(), states(b_).at(b_.recs.size()));
  check_snapshots_hold_b();
}

// Sidecars of the earlier format (no record crc) are still read; the cursor then has
// nothing to check record P against.
TEST(DST017Sidecar, BothVersionsDecode) {
  snapd::OutDigests d;
  d.index = 42;
  d.itch.add(std::vector<std::byte>(3, std::byte{1}));
  const auto v1 = snapd::encode_sidecar(d);
  ASSERT_EQ(std::memcmp(v1.data(), snapd::kSidecarMagicV1, 8), 0);
  const auto r1 = snapd::decode_sidecar(v1);
  ASSERT_TRUE(r1.has_value());
  EXPECT_FALSE(r1->record_crc.has_value());
  d.record_crc = 0xC0FFEEu;
  const auto v2 = snapd::encode_sidecar(d);
  ASSERT_EQ(std::memcmp(v2.data(), snapd::kSidecarMagic, 8), 0);
  const auto r2 = snapd::decode_sidecar(v2);
  ASSERT_TRUE(r2.has_value());
  EXPECT_EQ(r2->record_crc, std::optional<std::uint32_t>(0xC0FFEEu));
  EXPECT_EQ(r2->itch, d.itch);
}

}  // namespace
}  // namespace lle
