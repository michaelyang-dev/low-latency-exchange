#pragma once
// State shared by the stages of one exchanged process (01 §4, §7). Allocated once at
// start-up. Every watermark and flag has exactly one writing stage; queues are the
// verified lock-free rings of 08 (SCQ MPSC into the sequencer, the L2 broadcast ring,
// the egress broadcast ring, an SPSC for state-hash checkpoints).
//
//   gw0, gw1 --(SCQ: OUCH, session events)--> seq --(L2 ring)--> io (L3 journal)
//   lle-admin --(SCQ: admin)--------------------^              \-> engine --(egress ring)--> io (output log)
//                                                                                        \-> md, gw0, gw1
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "common/cache.h"
#include "concurrent/mpsc_scq.h"
#include "exchanged/consumer_guard.h"
#include "concurrent/spsc_byte_ring.h"
#include "concurrent/spsc_ring.h"
#include "journal/l2_ring.h"
#include "md/egress.h"
#include "md/publisher.h"
#include "sequencer/sequencer.h"

namespace lle::exch {

using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 4096>;
using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 1024>;
using AdminQueue = conc::MpscScqRing<seq::AdminMsg, 256>;

// L2 cursors (06 §5). The replicator reads the node's record log instead (repl_host.h).
using L2 = journal::L2Ring<2>;
inline constexpr std::size_t kL2Io = 0;
inline constexpr std::size_t kL2Engine = 1;

using md::Watermark;

struct StateHashMsg {
  std::uint64_t index = 0;
  std::uint64_t hash = 0;
};

struct alignas(kFalseSharingBytes) Flag {
  std::atomic<bool> v{false};
  [[nodiscard]] bool load() const noexcept { return v.load(std::memory_order_acquire); }
  void store(bool x) noexcept { v.store(x, std::memory_order_release); }
};

// Paired mode with the replica on its own thread (repl_stage.h, "split"): the hand-offs
// between the seq thread (sequencer) and the repl thread (replica).
//   - allowed: repl -> seq, sequencing allowed (Replica::sequencing_allowed);
//   - disallow_gen / parked: the replica appends to L2 only after the seq thread has
//     started a poll that saw allowed == false (so none of its appends is in flight);
//   - resync: what the sequencer continues from after the replica appended records
//     (written before allowed turns true);
//   - tee: every record the sequencer commits, for the repl thread's record log.
struct SplitRepl {
  struct Resync {
    journal::ChainState chain;
    std::size_t timers = 0;
    std::uint64_t next_snapshot_id = 1;
    std::uint64_t digest = 0;
    bool day_ended = false;  // the log holds the day's DayEnd: the sequencer stays stopped (DST-008)
  };
  alignas(kFalseSharingBytes) std::atomic<bool> allowed{false};
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> disallow_gen{0};
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> parked{0};
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> resync_gen{0};
  Resync resync;  // written by repl before resync_gen++, read by seq after
  conc::SpscByteRing tee;
  std::unique_ptr<std::uint64_t[]> tee_mem;
};

struct Shared {
  OuchQueue ouch;
  SessionQueue events;
  AdminQueue admin;
  L2 l2;
  std::atomic<bool> io_hold{false};  // control `io-hold on` (tests): io leaves L2 unjournaled
  md::EgressRing egress;
  md::EgressState egress_state;

  Watermark sequenced;    // seq: last index appended to L2
  Watermark durable;      // io: L3 durable_index
  Watermark apply_limit;  // seq/repl: the engine may apply records <= apply_limit
  Watermark itch_total;   // engine: ITCH messages emitted today, S(P)
  Watermark soup_total;   // engine: OUCH messages emitted today
  Watermark day_end_index;  // engine: index of the applied DayEnd record (0: none)

  std::atomic<bool> mirror{false};             // gateways: logins are mirror-attaches
  std::atomic<std::uint8_t> lines{md::kLineA | md::kLineB};  // md: lines to transmit

  // Control (control thread -> seq stage), dev and test only.
  std::atomic<Nanos> clock_target{0};
  Watermark clock_reached;
  std::atomic<std::uint64_t> sync_req{0};
  Watermark sync_ack;
  Watermark sync_index;
  Flag end_day_req;
  Flag stop;
  std::atomic<int> exit_code{0};

  // Replication status (seq/repl stage), for status and metrics.
  std::atomic<std::uint8_t> role{0};
  std::atomic<std::uint64_t> epoch{0};

  // engine -> seq/repl: state hashes at checkpoints (10 §3).
  conc::SpscRing<StateHashMsg, 256> hashes;

  SplitRepl split;  // used when the replica runs on its own thread
  ScqConsumerGuard scq_consumer;  // debug: one consumer of ouch/events at a time
};

}  // namespace lle::exch
