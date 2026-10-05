// Recovery steps 4-5 (06 §7; journal/engine_recovery.h): an engine recovered
// from the newest valid snapshot plus the journal suffix equals the engine
// that applied every record; without a usable snapshot it replays from 1.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "engine/engine.h"
#include "gen.hpp"
#include "journal/engine_recovery.h"
#include "journal_test_util.h"
#include "snapshot/engine_section.h"

namespace lle::journal::testing {

// An engine record payload as produced by the generator, journaled as is (the
// generator also produces deliberately malformed payloads, which the journal
// carries and the engine audits).
template <RecordType T>
struct Raw {
  static constexpr RecordType kType = T;
  std::span<const std::byte> bytes;
};
template <RecordType T>
constexpr std::uint32_t payload_size(const Raw<T>& r) noexcept {
  return static_cast<std::uint32_t>(r.bytes.size());
}
template <RecordType T>
void encode_payload(std::byte* p, const Raw<T>& r) noexcept {
  if (!r.bytes.empty()) std::memcpy(p, r.bytes.data(), r.bytes.size());
}

namespace {

struct Null {
  void itch(std::uint64_t, std::span<const std::byte>) {}
  void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte>) {}
  void audit(std::uint64_t, const engine::AuditEvent&) {}
};

class TempDir {
 public:
  TempDir() {
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    path_ = (std::filesystem::temp_directory_path() / (std::string("lle_engrec_") + info->name())).string();
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
    std::filesystem::create_directories(path_, ec);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  std::string path_;
};

// A journal of `n` generated engine records, a reference engine, and
// snapshots of it at the given journal indices.
struct Day {
  MemSegmentDir dir;
  std::uint64_t last = 0;
  std::uint64_t final_hash = 0, final_mold = 0;
  std::vector<std::uint64_t> hash_at;  // after index i

  Day(std::uint64_t seed, int n, const std::vector<std::uint64_t>& snap_at, const std::string& snap_dir) {
    auto prepared = prepare_segments(dir, 2, kSegmentHeaderBytes + 4 * 1024 * 1024, seed);
    MemWriter w(writer_options());
    w.start(ChainState{});
    for (const auto& p : prepared) EXPECT_TRUE(w.add_prepared(dir.device(p.handle), p.handle, p.header));
    const Sealer sealer(kL2Nonce);
    RecordBuilder b(sealer);
    b.set_epoch(1);
    std::vector<std::byte> buf(kMaxRecordBytes);
    engine::gen::Generator g(seed);
    engine::Engine ref;
    Null null;
    hash_at.assign(static_cast<std::size_t>(n) + 1, 0);
    for (int i = 0; i < n; ++i) {
      const engine::InputRecord& r = g.next();
      std::span<std::byte> rec;
      const std::span<std::byte> out(buf);
      switch (static_cast<RecordType>(r.type)) {
        case RecordType::DayStart: rec = b.append(out, r.ts_ns, Raw<RecordType::DayStart>{r.payload}, r.flags); break;
        case RecordType::Config: rec = b.append(out, r.ts_ns, Raw<RecordType::Config>{r.payload}, r.flags); break;
        case RecordType::SessionEvent:
          rec = b.append(out, r.ts_ns, Raw<RecordType::SessionEvent>{r.payload}, r.flags);
          break;
        case RecordType::OuchInbound:
          rec = b.append(out, r.ts_ns, Raw<RecordType::OuchInbound>{r.payload}, r.flags);
          break;
        case RecordType::Timer: rec = b.append(out, r.ts_ns, Raw<RecordType::Timer>{r.payload}, r.flags); break;
        case RecordType::Admin: rec = b.append(out, r.ts_ns, Raw<RecordType::Admin>{r.payload}, r.flags); break;
        default: continue;  // the generator's unknown record types cannot be journaled
      }
      append_one(w, rec, sealer);
      // The reference applies the journaled record (with its padding).
      ref.apply(engine::to_input(RecordView(rec)), null);
      last = b.chain().last_index;
      hash_at[static_cast<std::size_t>(last)] = ref.state_hash();
      for (std::uint64_t k : snap_at) {
        if (k != last) continue;
        snap::EngineSnapshotIds ids;
        ids.day = kDay;
        ids.epoch = 1;
        ids.index = last;
        ids.snapshot_id = last;
        EXPECT_TRUE(snap::save_engine(ref, ids, snap_dir).has_value());
      }
    }
    drain(w);
    final_hash = ref.state_hash();
    final_mold = ref.itch_count();
  }
};

TEST(EngineRecovery, SnapshotPlusSuffixEqualsFullReplay) {
  TempDir snaps;
  Day d(31, 3'000, {700, 1'900}, snaps.path());
  engine::Engine e;
  const EngineRecovery r = recover_engine(d.dir, snaps.path(), e);
  ASSERT_EQ(r.status, EngineRecoveryStatus::Ok);
  EXPECT_EQ(r.snapshot_index, 1'900u);
  EXPECT_FALSE(r.snapshot_rejected);
  EXPECT_EQ(r.replayed, d.last - 1'900);
  EXPECT_EQ(r.last_index, d.last);
  EXPECT_EQ(r.state_hash, d.final_hash);
  EXPECT_EQ(r.mold_seq, d.final_mold);
  std::string err;
  EXPECT_TRUE(e.check(&err)) << err;

  // Without snapshots: the whole day.
  engine::Engine f;
  const EngineRecovery full = recover_engine(d.dir, "", f);
  ASSERT_EQ(full.status, EngineRecoveryStatus::Ok);
  EXPECT_EQ(full.replayed, d.last);
  EXPECT_EQ(full.state_hash, d.final_hash);
}

TEST(EngineRecovery, SnapshotsBeyondTheJournalAreNotUsed) {
  TempDir snaps;
  Day d(32, 2'000, {500, 1'500}, snaps.path());
  // A snapshot newer than the journal's end (the journal lost its tail): find_latest
  // must pick the newest one at or below the last valid index.
  {
    Day longer(32, 2'500, {2'400}, snaps.path());
  }
  engine::Engine e;
  const EngineRecovery r = recover_engine(d.dir, snaps.path(), e);
  ASSERT_EQ(r.status, EngineRecoveryStatus::Ok);
  EXPECT_EQ(r.snapshot_index, 1'500u);
  EXPECT_EQ(r.state_hash, d.final_hash);
}

TEST(EngineRecovery, RejectedSnapshotFallsBackToFullReplay) {
  TempDir snaps;
  Day d(33, 1'500, {1'000}, snaps.path());
  // Overwrite the snapshot with a valid container whose engine payload does not
  // match its header (state hash): the engine section rejects it.
  engine::Engine other;
  snap::SnapshotMeta m;
  m.day = kDay;
  m.index = 1'000;
  m.state_hash = 1;
  std::vector<std::byte> payload;
  other.snapshot(payload);
  auto w = snap::Writer::create(snaps.path(), m, {});
  ASSERT_TRUE(w.has_value());
  w->write(payload);
  ASSERT_TRUE(w->commit().has_value());
  engine::Engine e;
  const EngineRecovery r = recover_engine(d.dir, snaps.path(), e);
  ASSERT_EQ(r.status, EngineRecoveryStatus::Ok);
  EXPECT_TRUE(r.snapshot_rejected);
  EXPECT_EQ(r.snapshot_index, 0u);
  EXPECT_EQ(r.replayed, d.last);
  EXPECT_EQ(r.state_hash, d.final_hash);
}

TEST(EngineRecovery, EmptyJournal) {
  MemSegmentDir dir;
  engine::Engine e;
  const EngineRecovery r = recover_engine(dir, "", e);
  EXPECT_EQ(r.status, EngineRecoveryStatus::Ok);
  EXPECT_EQ(r.last_index, 0u);
  EXPECT_EQ(e.live_orders(), 0u);
}

}  // namespace
}  // namespace lle::journal::testing
