#pragma once
// One exchanged node as a simulated process image (09 §2; apps/exchanged/node.cpp,
// solo mode): the production stages seq, engine, io, gw0, gw1, md (MoldUDP64 lines
// and re-request server) and the GLIMPSE server over the shared queues and rings
// (apps/exchanged/shared.h), started on a fresh day or recovered from the journal
// through the production start-up and recovery steps (start_impl.h, recovery_impl.h),
// on the node's simulated clock, network and disk. snapshotd's follower
// (snapshotd/snapshotter.h) runs as one more stage of the image.
//
// Boot follows Node::start (solo): journal::recover -> refuse an unusable journal ->
// output log -> engine -> journal writer (resume_journal_writer) -> on a non-empty
// journal basic_replay_day (snapshots with output digests, or the whole day) ->
// sequencer and driver -> outlog_positions -> start_fresh_day | continue_day ->
// engine and io stages -> gateways, md, GLIMPSE (republish_from).
//
// Not modeled: threads and the core map (the scheduler interleaves the stages, one
// poll at a time), the admin and control ports (the world pushes Admin messages into
// the admin queue), metrics and nlog output (NLOG sites drop: no thread registers),
// the L2 file (the ring is process memory, ExchangeConfig.l2_path empty). A fatal
// stage error (IoStage) stops the node as Node::run does, and the supervisor
// restarts it: a process crash plus restart here.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "common/endian.h"
#include "engine/engine.h"
#include "engine/records.h"
#include "exchanged/engine_stage.h"
#include "exchanged/io_stage.h"
#include "exchanged/recovery.h"
#include "exchanged/seq_stage.h"
#include "exchanged/shared.h"
#include "gateway/credentials.h"
#include "gateway/gateway.h"
#include "gateway/session_table.h"
#include "journal/journal_writer.h"
#include "journal/segment_preparer.h"
#include "md/glimpse_server.h"
#include "md/publisher.h"
#include "outlog/day.h"
#include "outlog/reader.h"
#include "sequencer/engine_day.h"
#include "sim/exchange/sim_clock.h"
#include "sim/exchange/sim_net.h"
#include "sim/exchange/sim_storage.h"
#include "sim/node.h"
#include "sim/rng.h"
#include "sim/worlds/journal_device.h"
#include "snapshotd/snapshotter.h"

namespace lle::sim::exch {

using SimOutDay = outlog::BasicOutlogDay<SimNodeOutlogFs>;
using SimWriter = journal::JournalWriter<worlds::SimJournalDevice>;
using SimPreparer = journal::SegmentPreparer<worlds::SimSegmentDir, Rng>;
using SimSeqEnv = lle::exch::BasicSeqEnv<SimNodeClock>;
using SimSequencer = seq::Sequencer<SimSeqEnv>;
using SimSeqRing = lle::exch::BasicSeqRing<SimNodeClock>;
using SimSeqDriver = lle::exch::BasicSeqDriver<SimNodeClock, SimSequencer>;
using SimSeqStage = lle::exch::BasicSeqStage<SimSeqDriver>;
using SimEngineStage = lle::exch::BasicEngineStage<SimNodeClock>;
using SimIoStage = lle::exch::BasicIoStage<worlds::SimSegmentDir, SimWriter, SimPreparer, SimOutDay, SimNodeClock>;

// The gateways' input queues are the node's SCQs (shared.h), seen through taps that
// report every accepted push to the world: the gateway calls try_push only, and a tap
// forwards to the same ring the sequencer pops, so nothing the stages do changes.
struct NodeTaps {
  std::function<void(const seq::InboundMsg&)> ouch;        // pushed to the sequencer
  std::function<void(const seq::SessionEventMsg&)> event;  // pushed to the sequencer
};
struct TapOuchQueue {
  lle::exch::OuchQueue* q = nullptr;
  const NodeTaps* taps = nullptr;
  bool try_push(const seq::InboundMsg& m) noexcept {
    if (!q->try_push(m)) return false;
    if (taps == nullptr) return true;
    // Session events can travel in this queue, tagged (InboundMsg::reserved = 1, payload
    // u8 event + le64 requested sequence: seq::session_event_inbound, DST-004). Decoded
    // here from the wire layout so the harness builds with and without that change.
    if (m.reserved == 1 && m.len >= 9) {
      if (taps->event) {
        seq::SessionEventMsg e;
        e.session_id = m.session_id;
        e.instance = m.instance;
        e.event = static_cast<journal::SessionEventKind>(std::to_integer<std::uint8_t>(m.bytes[0]));
        e.requested_seq = load_le64(m.bytes + 1);
        taps->event(e);
      }
    } else if (taps->ouch) {
      taps->ouch(m);
    }
    return true;
  }
};
struct TapSessionQueue {
  lle::exch::SessionQueue* q = nullptr;
  const NodeTaps* taps = nullptr;
  bool try_push(const seq::SessionEventMsg& m) noexcept {
    if (!q->try_push(m)) return false;
    if (taps != nullptr && taps->event) taps->event(m);
    return true;
  }
};

struct SimGwEnv {
  using Net = SimNetStack;
  using OuchQueue = TapOuchQueue;
  using SessionQueue = TapSessionQueue;
  using Clock = SimNodeClock;
  using OutlogReader = outlog::BasicOutlogReader<SimBoundOutlogFs>;
};
struct SimMdEnv {
  using Net = SimNetStack;
  using Clock = SimNodeClock;
  using OutlogReader = outlog::BasicOutlogReader<SimBoundOutlogFs>;
};
using SimGateway = gw::Gateway<SimGwEnv>;
using SimMd = md::MdStage<SimMdEnv>;
using SimGlimpse = md::GlimpseServer<SimGwEnv>;
using SimSnapshotter = snapd::BasicSnapshotter<SimSnapIo>;

// The trading day: what exchanged reads from its configuration file (ADR-028: journaled
// at day start). Owned by the world, shared by its nodes and its oracles.
struct ExchangeDay {
  std::uint32_t date = 20261001;
  Nanos local_midnight = 0;
  std::string mold_session = "LLE0000001";
  std::string soup_session = "LLE0000001";
  std::vector<engine::SymbolEntry> symbols;
  std::vector<engine::AccountEntry> accounts;
  std::vector<engine::SessionEntry> sessions;
  std::vector<engine::RiskEntry> risk;
  std::vector<engine::ScheduleEntry> schedule;
  std::vector<gw::SessionSpec> specs;
  std::unique_ptr<seq::EngineDay> day;  // build() fills it and the table
  gw::SessionTable table;

  // Validates and builds the journaled tables and the gateways' session table.
  [[nodiscard]] std::expected<void, std::string> build();
  [[nodiscard]] std::vector<std::uint32_t> session_ids() const;  // sorted
};

struct NodeParams {
  std::uint16_t node_id = 1;
  std::string root;  // disk prefix of this node's files ("" = top level)
  // Journal (ExchangeConfig [journal]).
  std::uint64_t segment_bytes = std::uint64_t{1} << 20;
  std::size_t spares = 2;
  std::size_t l2_bytes = std::size_t{1} << 22;
  std::size_t egress_bytes = std::size_t{1} << 21;  // power of two >= 64 KiB
  std::uint64_t snapshot_every = 0;
  bool use_snapshots = true;
  // snapshotd beside the node.
  bool follower = true;
  Nanos follower_poll = 20'000'000;
  std::size_t follower_keep = 0;
  bool auto_end = true;
  // Network.
  env::Endpoint gw[2] = {};
  env::Endpoint line_a{};
  env::Endpoint line_b{};
  std::uint16_t rerequest_port = 30003;
  std::uint16_t glimpse_port = 0;  // 0: no GLIMPSE server
  std::string glimpse_user = "GLIMPS";
  gw::Credential glimpse_credential;
  Nanos soup_heartbeat = kNsPerSec;
  Nanos soup_idle_timeout = 15 * kNsPerSec;
  Nanos soup_login_timeout = 30 * kNsPerSec;
  std::uint32_t max_conns = 64;
  std::size_t replay_ring_msgs = std::size_t{1} << 16;
  std::size_t replay_ring_bytes = std::size_t{8} << 20;
  std::size_t md_ring_messages = std::size_t{1} << 18;
  std::size_t md_ring_bytes = std::size_t{16} << 20;
  std::size_t max_packet_a = 1472;
  std::size_t max_packet_b = 1000;
  Nanos md_heartbeat = kNsPerSec;
  Nanos md_eos_linger = 30 * kNsPerSec;

  [[nodiscard]] std::string journal_prefix(std::uint32_t date) const;
  [[nodiscard]] std::string outlog_root() const;
  [[nodiscard]] std::string snapshots_dir(std::uint32_t date) const;
};

// What the world observes of a process image.
struct NodeHooks {
  std::function<void(const std::string&)> log;                                 // progress lines (verbose runs)
  std::function<void(const std::string&)> boot_failed;                         // start-up refused (the process exits)
  std::function<void(const lle::exch::RecoveredDay&)> recovered;               // a restart replayed the journal
  std::function<void(int code)> stopped;                                       // a stage stopped the node (exit code)
  std::function<void(const engine::Engine&, std::uint64_t)> snapshot_written;  // snapshotd published one
  NodeTaps taps;                                                               // the gateways' pushes
  worlds::JournalDurableObserver* durable = nullptr;                           // journal writes made durable
};

class ExchangeProc final : public Process {
 public:
  ExchangeProc(Node& n, const ExchangeDay& day, const NodeParams& p, NodeHooks hooks);
  ~ExchangeProc() override;
  ExchangeProc(const ExchangeProc&) = delete;
  ExchangeProc& operator=(const ExchangeProc&) = delete;

  [[nodiscard]] bool started() const noexcept { return started_; }
  [[nodiscard]] const std::string& boot_error() const noexcept { return boot_error_; }
  [[nodiscard]] std::uint64_t recovered_index() const noexcept { return recovered_index_; }
  [[nodiscard]] const lle::exch::RecoveredDay& recovered() const noexcept { return recovered_; }

  [[nodiscard]] lle::exch::Shared& shared() noexcept { return *sh_; }
  [[nodiscard]] const lle::exch::Shared& shared() const noexcept { return *sh_; }
  [[nodiscard]] const SimGateway* gateway(std::size_t i) const noexcept { return gw_[i].get(); }
  [[nodiscard]] const SimMd* md() const noexcept { return md_.get(); }
  [[nodiscard]] const SimGlimpse* glimpse() const noexcept { return glimpse_.get(); }
  [[nodiscard]] const SimIoStage* io() const noexcept { return io_stage_.get(); }
  [[nodiscard]] const SimEngineStage* engine_stage() const noexcept { return engine_stage_.get(); }
  [[nodiscard]] const SimSnapshotter* follower() const noexcept { return follower_.get(); }
  [[nodiscard]] const SimSequencer* sequencer() const noexcept { return sequencer_.get(); }
  // Quiescent: everything sequenced is applied, durable, released and handed on by every
  // egress consumer (the control port's `sync` condition, node.cpp).
  [[nodiscard]] bool settled() const noexcept;

 private:
  struct Supervisor {
    ExchangeProc* p;
    bool poll() { return p->supervise(); }
  };
  struct Follower {
    ExchangeProc* p;
    bool poll() { return p->follow(); }
  };

  void fail(std::string why);
  bool supervise();
  bool follow();
  void start_follower();

  Node& node_;
  const ExchangeDay& d_;
  NodeParams p_;
  NodeHooks hooks_;
  Rng rng_;
  SimNodeClock clock_;
  EphemeralPorts eph_;
  std::unique_ptr<SimSnapStorage> snaps_;
  std::unique_ptr<lle::exch::Shared> sh_;
  std::unique_ptr<std::uint64_t[]> l2_mem_;
  std::unique_ptr<worlds::SimSegmentDir> dir_;
  std::unique_ptr<SimPreparer> prep_;
  std::unique_ptr<SimWriter> writer_;
  std::unique_ptr<SimOutDay> outlog_;
  std::unique_ptr<engine::Engine> engine_;
  std::unique_ptr<SimSeqRing> seq_ring_;
  std::unique_ptr<SimSequencer> sequencer_;
  std::unique_ptr<SimSeqDriver> driver_;
  std::unique_ptr<SimSeqStage> seq_stage_;
  std::unique_ptr<SimEngineStage> engine_stage_;
  std::unique_ptr<SimIoStage> io_stage_;
  TapOuchQueue tap_ouch_;
  TapSessionQueue tap_events_;
  std::unique_ptr<SimGateway> gw_[md::kGateways];
  std::unique_ptr<SimMd> md_;
  std::unique_ptr<SimGlimpse> glimpse_;
  std::unique_ptr<SimSnapshotter> follower_;
  Supervisor supervisor_{this};
  Follower follower_stage_{this};
  lle::exch::RecoveredDay recovered_;
  std::uint64_t recovered_index_ = 0;
  std::vector<std::pair<std::uint32_t, SeqNo>> soup_next_;
  SeqNo itch_next_ = 1;
  Nanos next_follow_ = 0;
  bool follower_failed_ = false;
  bool started_ = false;
  bool stopping_ = false;
  std::string boot_error_;
};

}  // namespace lle::sim::exch
