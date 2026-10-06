// DST-016 regression test (scripted, seed-independent): after the sequencer has filled the
// L2 ring to its back-pressure, the EpochStart of an epoch the witness granted must still
// fit. Found by `exsim --world=exchange_ha_split` (O-LIVE) once the world ran production's
// 1 Hz clock; see sim/ledger/bugs.yaml.
//
// A primary releases up to its backup's ACK (paired) or its durable index (solo), and a new
// primary releases nothing before its EpochStart is durable (10 §4). While release is held
// the engine fills the egress ring with outputs it may not send and stops applying, so its
// L2 cursor stops; the sequencer goes on until L2 is full (the 1 Hz clock's timer records
// do it quickly). In the seed the backup's ACKs stopped at 18,811, the primary sequenced on
// to 48,707 with a 1 MiB L2 holding 32 free bytes, and W granted it SOLO: the EpochStart did
// not fit, release could not move without it, the engine could not move without release,
// and L2 could not drain without the engine. The node never sequenced or released again;
// its partner's rejoin was refused at every attempt (no epoch end while the EpochStart is
// pending). At the fix the sequencer and replicated records leave room for one EpochStart.
//
// Production pieces: exchanged's sequencer ring adapter (seq_stage.h SeqRing) filling the
// L2 ring (journal::L2Ring), whose cursors do not move, and the replica's EpochStart
// reservation through L2Ring::try_reserve, as the replication stage makes it.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <memory>

#include "exchanged/seq_stage.h"
#include "exchanged/shared.h"
#include "journal/l2_ring.h"
#include "journal/record.h"

namespace lle::exch {
namespace {

constexpr std::uint64_t kNonce = 0x0DDBA11CAFEF00D5ull;

TEST(DST016, AnEpochStartFitsAfterTheSequencerFilledL2) {
  for (const std::size_t cap : {std::size_t{1} << 20, std::size_t{1} << 21}) {
    auto mem = std::make_unique<std::uint64_t[]>(cap / 8);
    L2 l2;
    l2.init(reinterpret_cast<std::byte*>(mem.get()), cap, kNonce);
    SeqRing seq(l2, nullptr);
    // Timer records until the ring pushes back: neither cursor moves (the engine waits on
    // a release, the io stage is irrelevant once the engine holds the ring).
    const std::uint32_t timer = journal::record_size(journal::Timer{});
    std::uint64_t n = 0;
    for (std::byte* p = seq.try_reserve(timer); p != nullptr; p = seq.try_reserve(timer)) {
      std::memset(p, 0, timer);
      seq.commit();
      ++n;
    }
    ASSERT_GT(n, cap / (2 * timer)) << "the sequencer stopped early";
    // W granted the primary a new epoch: its EpochStart goes in after every sequenced record.
    const std::uint32_t es = journal::record_size(journal::EpochStart{});
    EXPECT_NE(l2.try_reserve(es), nullptr)
        << "L2 (" << cap << " bytes) has no room for the EpochStart: release waits for it, the engine for release, "
        << "L2 for the engine";
  }
}

}  // namespace
}  // namespace lle::exch
