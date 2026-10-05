// "No allocation on append paths after startup" (conventions, 06 §2, §6): counts
// global operator new calls while the sequencer stamps into the L2 ring, the L3 writer
// batches, submits and reaps, and cursors drain. Its own executable, because the
// replacement operator new applies to the whole binary.
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

#include "journal/journal_writer.h"
#include "journal/mem_journal_device.h"
#include "journal/segment_preparer.h"
#include "sequencer_test_env.h"

namespace {
std::atomic<bool> g_counting{false};
std::atomic<std::uint64_t> g_allocs{0};

void* counted(std::size_t n, std::size_t align) {
  if (g_counting.load(std::memory_order_relaxed)) g_allocs.fetch_add(1, std::memory_order_relaxed);
  void* p = nullptr;
  if (align > alignof(std::max_align_t)) {
    if (::posix_memalign(&p, align, n == 0 ? align : n) != 0) p = nullptr;
  } else {
    p = std::malloc(n == 0 ? 1 : n);
  }
  if (p == nullptr) throw std::bad_alloc();
  return p;
}

void* counted_nothrow(std::size_t n, std::size_t align) noexcept {
  try {
    return counted(n, align);
  } catch (...) {
    return nullptr;
  }
}
}  // namespace

// Every form is replaced (docs/dev/conventions.md): with a partial set, memory the
// standard library allocates through an unreplaced form would be freed by this
// file's free(), which ASan with libstdc++ reports as alloc-dealloc-mismatch.
void* operator new(std::size_t n) { return counted(n, 0); }
void* operator new[](std::size_t n) { return counted(n, 0); }
void* operator new(std::size_t n, std::align_val_t a) { return counted(n, static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n, std::align_val_t a) { return counted(n, static_cast<std::size_t>(a)); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n, 0); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n, 0); }
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }

namespace lle::seq {
namespace {

using testing::Rig;
using Writer = journal::JournalWriter<journal::MemJournalDevice>;

TEST(NoAlloc, SequencerRingAndWriterHotPaths) {
  std::vector<ScheduleEntry> sched;
  for (std::uint32_t i = 0; i < 100; ++i) {
    sched.push_back(ScheduleEntry{1'790'000'000'000'000'000 + Nanos{i} * 10'000, journal::TimerKind::Noii, i});
  }
  SequencerConfig cfg;
  cfg.snapshot_every = 1000;
  Rig rig(std::size_t{1} << 20, sched, cfg);
  rig.clock.step = 37;
  journal::MemSegmentDir dir;
  Prng nonces(1);
  journal::SegmentPreparer prep(dir, nonces, 20260930, journal::kSegmentHeaderBytes + 4 * 1024 * 1024);
  journal::JournalWriterOptions wo;
  wo.day = 20260930;
  Writer w(wo);
  w.start(journal::ChainState{});
  for (int i = 0; i < 2; ++i) {
    auto p = prep.create();
    ASSERT_TRUE(p.has_value());
    ASSERT_TRUE(w.add_prepared(dir.device(p->handle), p->handle, p->header));
  }
  rig.start();
  rig.seq->reserve_first(4);  // cold: the list of session events that go first (ADR-032)
  rig.seq->reserve_ahead(4);  // cold: a promotion's re-injected input
  std::uint64_t engine_seen = 0;
  const auto run = [&](int rounds) {
    for (int round = 0; round < rounds; ++round) {
      for (std::uint8_t i = 0; i < 32; ++i) (void)rig.ouch->try_push(Rig::ouch_msg(i, i));
      (void)rig.sessions->try_push(SessionEventMsg{1, 1, journal::SessionEventKind::Login, 0});
      if (round % 7 == 0) {
        for (std::uint16_t k = 0; k < 3; ++k)
          (void)rig.seq->inject_first(SessionEventMsg{2, k, journal::SessionEventKind::InstanceDown, 0});
        for (std::uint8_t k = 0; k < 3; ++k) (void)rig.seq->inject_ahead(Rig::ouch_msg(3, k));
      }
      (void)rig.seq->poll();
      engine_seen += rig.ring.drain(1, [](const journal::RecordView&) {}, 1000);
      for (;;) {
        const journal::RecordView v = rig.ring.peek(0);
        if (v.empty() || w.append(v.bytes(), rig.ring.sealer()) != Writer::Status::Ok) break;
        rig.ring.release(0);
      }
      (void)w.flush();
      (void)w.poll();
    }
  };
  run(50);  // warm-up: segment assignment, first batches
  g_counting.store(true);
  run(2000);
  g_counting.store(false);
  EXPECT_EQ(g_allocs.load(), 0u);
  EXPECT_FALSE(w.failed());
  EXPECT_GT(w.durable_index(), 50'000u);
  EXPECT_GT(engine_seen, 50'000u);
  EXPECT_GT(rig.seq->stats().timers, 0u);
  EXPECT_GT(rig.seq->stats().snapshot_marks, 0u);
  EXPECT_GT(rig.seq->stats().first, 0u);
  EXPECT_GT(rig.seq->stats().ahead, 0u);
}

// The list of session events that go first (ADR-032): after reserve_first, injecting,
// emitting across polls (ouch_batch) and reusing emitted room never allocates.
TEST(NoAlloc, FirstEventsAfterReserve) {
  SequencerConfig cfg;
  cfg.ouch_batch = 2;
  Rig rig(std::size_t{1} << 20, {}, cfg);
  rig.start();
  rig.seq->reserve_first(5);
  const std::size_t cap = rig.seq->first_capacity();
  g_allocs.store(0);
  g_counting.store(true);
  std::uint64_t injected = 0;
  for (int round = 0; round < 1000; ++round) {
    while (rig.seq->inject_first(SessionEventMsg{3, 1, journal::SessionEventKind::InstanceDown, 0})) ++injected;
    (void)rig.seq->poll();  // two out: their room is reused on the next round
    (void)rig.ring.drain(0, [](const journal::RecordView&) {}, 1000);
    (void)rig.ring.drain(1, [](const journal::RecordView&) {}, 1000);
  }
  g_counting.store(false);
  EXPECT_EQ(g_allocs.load(), 0u);
  EXPECT_EQ(rig.seq->first_capacity(), cap);
  EXPECT_GT(injected, 1000u);
  EXPECT_EQ(rig.seq->stats().first + rig.seq->first_pending(), injected);
}

}  // namespace
}  // namespace lle::seq
