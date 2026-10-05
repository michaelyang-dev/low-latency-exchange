#pragma once
// One data node process of the ha world (A or B): the repl core with its links, a
// sequencer, the L2 ring feeding the real JournalWriter on gated MemJournalDevice
// media, the toy engine as the applier, and a SoupBinTCP-like gateway with mirror
// sessions for the scripted clients. Everything here is process memory: a crash
// destroys it, and the constructor runs the production recovery path (journal
// recover(), L2Ring::restore, resume_writer) against the node's surviving media.
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "journal/journal_writer.h"
#include "journal/l2_ring.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "repl/replica.h"
#include "repl/types.h"
#include "sim/ha/harness.h"
#include "sim/ha/journal_dev.h"
#include "sim/ha/toy_engine.h"
#include "sim/network.h"
#include "sim/node.h"

namespace lle::sim::ha {

struct NodeParams {
  repl::Config repl;
  NodeId primary0 = kA;  // the day's initial primary
  std::size_t inbound_cap = 512;
};

class HaNode : public Process {
 public:
  HaNode(Node& n, Truth& t, const NodeParams& p, BootReason why);
  ~HaNode() override;
  HaNode(const HaNode&) = delete;
  HaNode& operator=(const HaNode&) = delete;

  struct Host {
    HaNode* n;
    [[nodiscard]] journal::ChainState log_tail() const { return n->tail_; }
    [[nodiscard]] std::uint64_t durable_index() const { return n->writer_->durable_index(); }
    [[nodiscard]] std::uint64_t applied_index() const { return n->engine_.applied(); }
    bool log_append(std::span<const std::byte> rec) { return n->append_canonical(rec, Origin::kReplica); }
    std::uint32_t log_read(std::uint64_t idx, std::span<std::byte> out) const { return n->read(idx, out); }
    repl::EpochEndInfo log_epoch_end(std::uint64_t e) const { return n->epoch_end(e); }
    repl::EpochEndInfo log_epoch_start(std::uint64_t e) const { return n->epoch_start(e); }
    bool log_truncate(std::uint64_t t) { return n->truncate(t); }
    void request_flush() { (void)n->writer_->flush(); }
    void reload_state(std::uint64_t t) { n->reload(t); }
    bool inject_inbound(const repl::wire::Forward& f) { return n->inject(f); }
    void on_role(repl::Role r, std::uint64_t e) { n->on_role(r, e); }
    void instance_down(repl::NodeId peer) { n->pending_instance_down_ = static_cast<int>(peer); }
    void deposed() { n->on_deposed(); }
    void alarm(repl::Alarm a, std::uint64_t d) { n->on_alarm(a, d); }
    void send_peer(std::span<const std::byte> b) { n->data_port_.send(env::Endpoint{node_ip(n->peer_), kDataPort}, b); }
    void send_witness(std::span<const std::byte> b) {
      n->ctl_port_.send(env::Endpoint{node_ip(kW), kWitnessPort}, b);
    }
    [[nodiscard]] Nanos now_real() const { return n->node_.clock().now_real(); }
    void trace(const repl::TraceEvent& e) { n->on_trace(e); }
    repl::SnapshotOffer snapshot_offer() { return n->snapshot_offer(); }
    std::uint32_t snapshot_read(std::uint64_t off, std::span<std::byte> out) { return n->snapshot_read(off, out); }
    void snapshot_release() { n->snap_tx_.clear(); }
    bool snapshot_receive(std::uint64_t idx, std::uint64_t total, std::uint64_t off, std::span<const std::byte> b) {
      return n->snapshot_receive(idx, total, off, b);
    }
    bool snapshot_install() { return n->snapshot_install(); }
  };

  [[nodiscard]] const repl::Replica<Host>& repl() const { return *repl_; }
  [[nodiscard]] const ToyEngine& engine() const { return engine_; }
  [[nodiscard]] NodeId id() const noexcept { return self_; }
  [[nodiscard]] std::uint64_t incarnation() const noexcept { return inc_; }
  [[nodiscard]] std::uint64_t durable() const { return writer_->durable_index(); }
  [[nodiscard]] std::uint64_t tail() const noexcept { return tail_.last_index; }

 private:
  enum class Origin : std::uint8_t { kSequencer, kReplica };

  struct Inbound {
    bool event = false;
    std::uint32_t session = 0;
    std::uint16_t instance = 0;
    std::uint32_t account = 0;
    journal::SessionEventKind kind = journal::SessionEventKind::Login;
    std::uint64_t requested_seq = 0;
    std::array<std::byte, kToyOrderBytes> msg{};
    std::uint16_t len = 0;
    std::uint16_t flags = 0;  // journal record flags (a backup's FORWARD carries them)
  };

  struct Conn {
    Bytes rx;
    Bytes tx;
    bool logged_in = false;
    std::uint32_t session = 0;
    std::uint16_t instance = 0;
    std::uint64_t next_seq = 1;
  };

  // Stages (01 §5): the scheduler polls each independently.
  struct ReplStage {
    HaNode* n;
    bool poll() { return n->poll_repl(); }
  };
  struct SeqStage {
    HaNode* n;
    bool poll() { return n->poll_seq(); }
  };
  struct IoStage {
    HaNode* n;
    bool poll() { return n->poll_io(); }
  };
  struct AppStage {
    HaNode* n;
    bool poll() { return n->poll_app(); }
  };

  bool poll_repl();
  bool poll_seq();
  bool poll_io();
  bool poll_app();

  void boot(BootReason why);
  bool append_canonical(std::span<const std::byte> rec, Origin origin);
  bool sequence_one(const Inbound& in);
  std::uint32_t read(std::uint64_t idx, std::span<std::byte> out) const;
  repl::EpochEndInfo epoch_end(std::uint64_t e) const;
  repl::EpochEndInfo epoch_start(std::uint64_t e) const;
  bool truncate(std::uint64_t t);
  void reload(std::uint64_t t);
  bool inject(const repl::wire::Forward& f);
  void on_role(repl::Role r, std::uint64_t e);
  void on_deposed();
  void on_alarm(repl::Alarm a, std::uint64_t d);
  void on_trace(const repl::TraceEvent& e);
  repl::SnapshotOffer snapshot_offer();
  std::uint32_t snapshot_read(std::uint64_t off, std::span<std::byte> out);
  bool snapshot_receive(std::uint64_t idx, std::uint64_t total, std::uint64_t off, std::span<const std::byte> b);
  bool snapshot_install();
  void ensure_spares();
  void drain_journal();
  void reset_l2(bool fresh_nonce);
  void note_durable();

  // Gateway.
  bool poll_gateway();
  void on_frame(env::ConnId c, Conn& conn, std::span<const std::byte> f, bool& stop);
  void send_outputs(env::ConnId c, Conn& conn);
  void close_conn(env::ConnId c, Conn& conn);
  std::uint16_t new_instance() noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(self_) << 15) | (++instance_counter_ & 0x7FFF));
  }

  Node& node_;
  Truth& t_;
  NodeStore& store_;
  NodeParams p_;
  NodeId self_;
  NodeId peer_;
  std::uint64_t inc_;
  DiskGate gate_;
  HaDir dir_;
  std::unique_ptr<journal::SegmentPreparer<HaDir, Prng>> prep_;
  std::unique_ptr<journal::JournalWriter<HaDevice>> writer_;
  journal::L2Ring<1> ring_;
  journal::Sealer canonical_;
  journal::ChainState tail_{};
  std::uint64_t durable_seen_ = 0;
  ToyEngine engine_;
  std::uint64_t hash_interval_ = 16;
  std::map<std::uint32_t, std::uint32_t> max_urn_;  // classification shadow for the TLA trace
  std::deque<Inbound> inbound_;
  int pending_instance_down_ = -1;
  std::uint64_t release_seen_ = 0;
  std::string pending_value_ = "rec";  // TLA+ value of the record last appended by the replica
  repl::Role role_seen_ = repl::Role::kNone;
  bool dead_ = false;
  // Outputs before a snapshot-installed engine's base, regenerated from the journal on
  // demand (the output log is derived data, 06 §8).
  std::unique_ptr<ToyEngine> regen_;
  std::uint64_t snap_base_index_ = 0;
  // Snapshot transfer.
  Bytes snap_tx_;
  Bytes snap_rx_;
  std::uint64_t snap_rx_index_ = 0;
  // Ports.
  DatagramPort data_port_;
  DatagramPort ctl_port_;
  StreamPort client_port_;
  std::map<env::ConnId, Conn> conns_;
  std::uint16_t instance_counter_ = 0;
  Host host_;
  std::unique_ptr<repl::Replica<Host>> repl_;
  ReplStage s_repl_{this};
  SeqStage s_seq_{this};
  IoStage s_io_{this};
  AppStage s_app_{this};
};

}  // namespace lle::sim::ha
