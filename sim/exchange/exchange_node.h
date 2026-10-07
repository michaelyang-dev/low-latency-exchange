#pragma once
// One exchanged node as a simulated process image (09 §2; apps/exchanged/node.cpp,
// solo or paired mode): the production stages seq, engine, io, gw0, gw1, md (MoldUDP64 lines
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
// Paired (10 §3-§5; NodeParams::paired): the record log (record_log.h on the node's
// disk), the replication stage (repl_stage.h, BasicReplStage, hosting the sequencer as
// Node does without repl_thread) talking to the peer and the witness over the simulated
// network. A fresh day starts both nodes from identical day-start records and the
// replica starts paired (Node::run); a restart mid-day rejoins through the production
// sequence (start_impl.h: begin_rejoin, the handshake with truncate_journal_to and
// reload_to as hooks, finish_rejoin), the handshake polled as the image's first stage
// as Node::rejoin polls it before any stage starts. Env::exit (a deposed node, a
// rejoin that must restart, a failed reload) ends the process image.
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

#include "env/buggify.h"
#include "common/endian.h"
#include "engine/engine.h"
#include "engine/records.h"
#include "exchanged/engine_stage.h"
#include "exchanged/io_stage.h"
#include "exchanged/record_log.h"
#include "exchanged/recovery.h"
#include "exchanged/repl_stage.h"
#include "exchanged/seq_stage.h"
#include "exchanged/start_impl.h"
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
#include "repl/types.h"
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
// The record log reads the node's journal back read-only (record_log.h, PosixL3Opener).
struct SimL3Opener {
  Node* node = nullptr;
  [[nodiscard]] std::expected<SimReadOnlySegmentDir, std::string> operator()(const std::string& dir) const {
    return SimReadOnlySegmentDir(*node, dir);
  }
};
// The record log, every append reported: what the node holds (its L2 and record log),
// sequenced here or replicated from the primary (the Output Rule's "held by both").
// The appends shadow the base's (BasicReplStage and BasicSeqRing call them on this type).
class SimRecordLog : public lle::exch::BasicRecordLog<SimL3Opener> {
 public:
  using Base = lle::exch::BasicRecordLog<SimL3Opener>;
  using Held = std::function<void(std::uint64_t index, std::uint32_t crc)>;
  SimRecordLog(std::size_t arena_bytes, std::size_t max_records, std::string l3_dir, std::uint32_t day,
               SimL3Opener open, const Held* held)
      : Base(arena_bytes, max_records, std::move(l3_dir), day, open), held_(held) {}
  bool append_from(const std::byte* rec, std::uint32_t len, const journal::Sealer& src) noexcept {
    if (!Base::append_from(rec, len, src)) return false;
    note();
    return true;
  }
  bool append_canonical(std::span<const std::byte> rec) noexcept {
    if (!Base::append_canonical(rec)) return false;
    note();
    return true;
  }

 private:
  void note() noexcept {
    if (held_ != nullptr && *held_) (*held_)(tail().last_index, tail().last_crc);
  }
  const Held* held_;
};
using SimSeqEnv = lle::exch::BasicSeqEnv<SimNodeClock, SimRecordLog>;
using SimSequencer = seq::Sequencer<SimSeqEnv>;
using SimSeqRing = lle::exch::BasicSeqRing<SimNodeClock, SimRecordLog>;
using SimSeqDriver = lle::exch::BasicSeqDriver<SimNodeClock, SimSequencer>;
using SimSeqStage = lle::exch::BasicSeqStage<SimSeqDriver>;
using SimEngineStage = lle::exch::BasicEngineStage<SimNodeClock>;
using SimIoStage = lle::exch::BasicIoStage<worlds::SimSegmentDir, SimWriter, SimPreparer, SimOutDay, SimNodeClock>;

// exchanged ends: std::_Exit in ReplEnv::exit. Here the process image ends (the stage
// that caught it requests the crash; the supervisor restarts the image).
struct ProcessExit {
  int code = 0;
};
// The metrics segment is not modeled (publish_metrics is never called).
struct SimMetrics {
  template <class... A>
  void set(A&&...) noexcept {}
  template <class... A>
  void set_work(A&&...) noexcept {}
};
struct SimReplEnv {
  using Clock = SimNodeClock;
  using Udp = SimUdpPort;
  using Metrics = SimMetrics;
  using Log = SimRecordLog;
  using Sequencer = SimSequencer;
  using Driver = SimSeqDriver;
  [[noreturn]] static void exit(int code) { throw ProcessExit{code}; }
};
using SimReplStage = lle::exch::BasicReplStage<SimReplEnv>;
using SimSeqSide = lle::exch::BasicSeqSide<SimReplEnv>;
using SimRejoinParts = lle::exch::RejoinParts<worlds::SimSegmentDir, SimPreparer, SimRecordLog, SimOutDay>;

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
    // A queue the sequencer has not drained yet (load): the gateway stages the message,
    // stops reading the connection and retries, its session events in a backlog behind.
    if (SIM_BUGGIFY("exchange.ouch_queue_full")) return false;
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

// exchanged's L2 in a file ([journal] l2_path; hugetlbfs in production): memory that
// outlives the process image and is lost with the host (a power loss). The world keeps
// one per data node and hands it to every image; a fresh image reopens it unless the
// host crashed since it was written.
struct L2File {
  std::unique_ptr<std::uint64_t[]> mem;
  std::size_t bytes = 0;
  std::uint64_t nonce = 0;
  std::uint64_t host_crashes = 0;  // Node::host_crashes() when it was created
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
  // Paired mode (ExchangeConfig [ha]): node ids 0 and 1.
  bool paired = false;
  std::uint16_t initial_primary = 0;
  env::Endpoint ha_bind{};  // this node's data-plane endpoint
  env::Endpoint ha_peer{};  // the partner's
  env::Endpoint witness{};  // witnessd
  Nanos ha_heartbeat = 1'000'000;
  Nanos t_d = 50'000'000;
  Nanos t_ack = 25'000'000;
  Nanos rejoin_retry = 5'000'000;
  Nanos ha_rto = 2'000'000;
  std::uint64_t hash_interval = 65'536;  // state-hash checkpoint every N records (node.cpp's value)
  std::shared_ptr<L2File> l2_file;      // [journal] l2_path; null: anonymous L2
  std::size_t repl_log_bytes = std::size_t{8} << 20;
  // [ha] repl_thread: the replica on its own stage ("thread"), the sequencer on the seq
  // stage (BasicSeqSide), its records reaching the record log through a tee of this size.
  bool repl_thread = false;
  std::size_t tee_bytes = std::size_t{16} << 20;

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
  std::function<void(int code)> exited;                                        // Env::exit (paired: deposed, rejoin)
  std::function<void(std::uint64_t incarnation)> rejoining;                    // a paired restart began its handshake
  std::function<void(repl::Role, std::uint64_t index, std::uint64_t truncated_from)> rejoined;  // ...finished it
  SimRecordLog::Held held;                                                     // paired: a record appended to L2
  std::function<void(repl::Alarm, std::uint64_t detail, std::uint64_t count)> alarm;  // replica ALARMs (10 §3)
  std::function<void(std::uint64_t records, std::uint64_t last)> l2_restored;  // a reopened L2 file's records
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
  [[nodiscard]] const engine::Engine* engine() const noexcept { return engine_.get(); }
  [[nodiscard]] const SimSnapshotter* follower() const noexcept { return follower_.get(); }
  [[nodiscard]] const SimSequencer* sequencer() const noexcept { return sequencer_.get(); }
  [[nodiscard]] const SimReplStage* repl() const noexcept { return repl_.get(); }
  [[nodiscard]] const SimRecordLog* record_log() const noexcept { return rlog_.get(); }
  [[nodiscard]] bool rejoining() const noexcept { return rejoin_ && !rejoined_; }
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
  // The seq thread of a paired node (Node::run hosts the ReplStage as "seq"), and before
  // it the rejoin handshake (Node::rejoin's loop).
  struct ReplHost {
    ExchangeProc* p;
    bool poll() { return p->repl_poll(); }
  };
  // Split mode (repl_thread): the seq thread runs the sequencer (BasicSeqSide), the
  // ReplHost is the repl thread.
  struct SeqSideHost {
    ExchangeProc* p;
    bool poll() { return p->seq_side_poll(); }
  };
  // The rejoin steps' storage (start_impl.h Io) on the node's disk.
  struct RejoinIo : SimRecoveryIo {
    std::uint64_t read_incarnation(const std::string& path);
    bool write_incarnation(const std::string& path, std::uint64_t v);
    std::vector<std::uint64_t> remove_snapshots_above(const std::string& dir, std::uint64_t t);
    void warn(const std::string& line) { note(line); }
  };

  void fail(std::string why);
  void note_alarms();
  bool supervise();
  bool follow();
  void start_follower();
  void open_journal();
  bool restore_l2(journal::RecoveryResult& rr);
  void recover_or_start();
  std::expected<void, std::string> open_writer(const journal::RecoveryResult& rr);
  void begin_rejoin();
  void complete_rejoin();
  void finish_boot();
  bool repl_poll();
  bool seq_side_poll();
  [[nodiscard]] bool split() const noexcept { return p_.paired && p_.repl_thread; }
  void exit_process(int code);
  [[nodiscard]] lle::exch::ReplStageConfig repl_config(std::uint64_t incarnation, std::uint64_t digest) const;

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
  bool l2_reopened_ = false;  // the L2 file outlived the previous image
  std::unique_ptr<worlds::SimSegmentDir> dir_;
  std::unique_ptr<SimPreparer> prep_;
  std::unique_ptr<SimWriter> writer_;
  std::unique_ptr<SimOutDay> outlog_;
  std::unique_ptr<engine::Engine> engine_;
  std::unique_ptr<SimRecordLog> rlog_;
  std::unique_ptr<SimSeqRing> seq_ring_;
  std::unique_ptr<SimSequencer> sequencer_;
  std::unique_ptr<SimSeqDriver> driver_;
  std::unique_ptr<SimSeqStage> seq_stage_;
  std::unique_ptr<SimReplStage> repl_;
  SimMetrics metrics_;
  RejoinIo rejoin_io_;
  std::unique_ptr<SimRejoinParts> rejoin_parts_;
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
  ReplHost repl_host_{this};
  SeqSideHost seq_side_host_{this};
  std::unique_ptr<SimSeqSide> seq_side_;
  lle::exch::RecoveredDay recovered_;
  std::uint64_t recovered_index_ = 0;
  std::uint64_t rejoin_from_ = 0;  // the journal's end when the rejoin began
  std::vector<std::pair<std::uint32_t, SeqNo>> soup_next_;
  SeqNo itch_next_ = 1;
  Nanos next_follow_ = 0;
  bool follower_failed_ = false;
  bool started_ = false;
  bool stopping_ = false;
  bool rejoin_ = false;    // a paired node restarting mid-day (10 §5)
  bool rejoined_ = false;  // its handshake finished and the stages are built
  bool exited_ = false;    // Env::exit ended the image
  std::uint64_t alarms_seen_ = 0;  // repl_->alarms() already reported
  std::string boot_error_;
};

// snapshotd in a process of its own beside a data node, as production runs it
// (exchange-node.md: `snapshotd --follow`): it follows the node's journal and writes
// snapshots on the node's disk, and lives on while exchanged crashes, restarts and
// rejoins (a rejoin truncates the journal under it, 10 §5). It runs on a node of its own
// (its scheduling, its process crashes) that is a cohost of the data node: a host crash
// takes both down. The world then runs exchanged without its in-process follower.
class SnapshotdProc final : public Process {
 public:
  SnapshotdProc(Node& self, Node& host, const ExchangeDay& day, const NodeParams& p, NodeHooks hooks);
  ~SnapshotdProc() override;
  SnapshotdProc(const SnapshotdProc&) = delete;
  SnapshotdProc& operator=(const SnapshotdProc&) = delete;

  [[nodiscard]] const SimSnapshotter* snapshotter() const noexcept { return snap_.get(); }

 private:
  struct Stage {
    SnapshotdProc* p;
    bool poll() { return p->poll(); }
  };
  bool poll();
  void start();

  Node& self_;
  Node& host_;
  std::uint32_t date_;
  NodeParams p_;
  NodeHooks hooks_;
  std::unique_ptr<SimSnapStorage> st_;
  std::unique_ptr<SimSnapshotter> snap_;
  Nanos next_ = 0;
  bool failed_ = false;
  Stage stage_{this};
};

}  // namespace lle::sim::exch
