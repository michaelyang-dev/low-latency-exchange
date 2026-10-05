// journal_replay --emit (06 §11): replaying a journal of engine records on disk
// regenerates exactly the ITCH the engine produced, as a BinaryFILE; from a
// snapshot it regenerates the messages after the snapshot's S(P).
#include <gtest/gtest.h>
#include <sys/wait.h>

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "gen.hpp"
#include "posix_test_util.h"
#include "proto/itch50/binary_file.h"
#include "snapshot/engine_section.h"

namespace lle::journal::testing {

template <RecordType T>
struct RawRec {
  static constexpr RecordType kType = T;
  std::span<const std::byte> bytes;
};
template <RecordType T>
constexpr std::uint32_t payload_size(const RawRec<T>& r) noexcept {
  return static_cast<std::uint32_t>(r.bytes.size());
}
template <RecordType T>
void encode_payload(std::byte* p, const RawRec<T>& r) noexcept {
  if (!r.bytes.empty()) std::memcpy(p, r.bytes.data(), r.bytes.size());
}

namespace {

struct Itch {
  std::vector<std::vector<std::byte>> msgs;
  void itch(std::uint64_t, std::span<const std::byte> b) { msgs.emplace_back(b.begin(), b.end()); }
  void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte>) {}
  void audit(std::uint64_t, const engine::AuditEvent&) {}
};

std::string run(const std::string& cmd) {
  std::string out;
  FILE* p = ::popen((cmd + " 2>&1").c_str(), "r");
  if (p == nullptr) return out;
  char buf[4096];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), p)) != 0) out.append(buf, n);
  const int st = ::pclose(p);
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) out += "\n<exit status != 0>";
  return out;
}

std::vector<std::vector<std::byte>> read_binary_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes(raw.size());
  if (!raw.empty()) std::memcpy(bytes.data(), raw.data(), raw.size());
  itch50::BinaryFileView v(bytes);
  std::vector<std::vector<std::byte>> out;
  for (;;) {
    const itch50::Record r = v.next();
    if (r.status != itch50::RecordStatus::Message) break;
    out.emplace_back(r.data.begin(), r.data.end());
  }
  return out;
}

TEST(JournalEmit, ReplayRegeneratesTheEnginesItch) {
  TempDir dir, snaps, outdir;
  // A journal of 4,000 generated engine records; the reference engine's ITCH;
  // a snapshot at index 2,000.
  auto d = PosixSegmentDir::open(dir.path.string());
  ASSERT_TRUE(d.has_value());
  Prng nonces(77);
  SegmentPreparer prep(*d, nonces, kDay, kSegmentHeaderBytes + 2 * 1024 * 1024);
  JournalWriterOptions o;
  o.day = kDay;
  PosixWriter w(o);
  w.start(ChainState{});
  for (int i = 0; i < 2; ++i) {
    auto p = prep.create();
    ASSERT_TRUE(p.has_value());
    ASSERT_TRUE(w.add_prepared(d->device(p->handle), p->handle, p->header));
  }
  const Sealer sealer(kL2Nonce);
  RecordBuilder b(sealer);
  b.set_epoch(1);
  std::vector<std::byte> buf(kMaxRecordBytes);
  engine::gen::Generator g(2026);
  engine::Engine ref;
  Itch itch;
  std::uint64_t snap_mold = 0, last = 0;
  constexpr std::uint64_t kSnapAt = 2'000;
  while (last < 4'000) {
    const engine::InputRecord& r = g.next();
    const std::span<std::byte> out(buf);
    std::span<std::byte> rec;
    switch (static_cast<RecordType>(r.type)) {
      case RecordType::DayStart: rec = b.append(out, r.ts_ns, RawRec<RecordType::DayStart>{r.payload}, r.flags); break;
      case RecordType::Config: rec = b.append(out, r.ts_ns, RawRec<RecordType::Config>{r.payload}, r.flags); break;
      case RecordType::SessionEvent:
        rec = b.append(out, r.ts_ns, RawRec<RecordType::SessionEvent>{r.payload}, r.flags);
        break;
      case RecordType::OuchInbound:
        rec = b.append(out, r.ts_ns, RawRec<RecordType::OuchInbound>{r.payload}, r.flags);
        break;
      case RecordType::Timer: rec = b.append(out, r.ts_ns, RawRec<RecordType::Timer>{r.payload}, r.flags); break;
      case RecordType::Admin: rec = b.append(out, r.ts_ns, RawRec<RecordType::Admin>{r.payload}, r.flags); break;
      default: continue;
    }
    for (;;) {
      const auto st = w.append(rec, sealer);
      if (st == PosixWriter::Status::Ok) break;
      ASSERT_EQ(st, PosixWriter::Status::Busy);
      (void)w.flush();
      (void)w.poll();
    }
    ref.apply(engine::to_input(RecordView(rec)), itch);
    last = b.chain().last_index;
    if (last == kSnapAt) {
      snap::EngineSnapshotIds ids;
      ids.day = kDay;
      ids.epoch = 1;
      ids.index = last;
      ASSERT_TRUE(snap::save_engine(ref, ids, snaps.path.string()).has_value());
      snap_mold = ref.itch_count();
    }
  }
  while (w.batch_used() != 0 || w.in_flight() != 0) {
    (void)w.flush();
    (void)w.poll();
  }
  PosixWriter::AssignedSegment a;
  while (w.take_assigned(a)) ASSERT_TRUE(d->rename(a.handle, segment_file_name(a.header.epoch, a.header.first_index)));
  ASSERT_TRUE(d->sync_dir());
  ASSERT_GT(itch.msgs.size(), 1'000u);
  char hash[32];
  std::snprintf(hash, sizeof(hash), "%016" PRIx64, ref.state_hash());

  const std::string tool = LLE_JOURNAL_REPLAY;
  const std::string full = (outdir.path / "full.itch").string();
  std::string out = run(tool + " " + dir.path.string() + " --emit " + full);
  EXPECT_NE(out.find("replayed 4000 records"), std::string::npos) << out;
  EXPECT_NE(out.find(std::string("state hash ") + hash), std::string::npos) << out;
  EXPECT_EQ(read_binary_file(full), itch.msgs);

  const std::string tail = (outdir.path / "tail.itch").string();
  out = run(tool + " " + dir.path.string() + " --snapshot-dir " + snaps.path.string() + " --emit " + tail +
            " --emit-ouch " + (outdir.path / "tail.ouch").string());
  EXPECT_NE(out.find("replayed 2000 records"), std::string::npos) << out;
  EXPECT_NE(out.find(std::string("state hash ") + hash), std::string::npos) << out;
  const auto got = read_binary_file(tail);
  ASSERT_EQ(got.size(), itch.msgs.size() - snap_mold);
  EXPECT_TRUE(std::equal(got.begin(), got.end(), itch.msgs.begin() + static_cast<std::ptrdiff_t>(snap_mold)));
}

}  // namespace
}  // namespace lle::journal::testing
