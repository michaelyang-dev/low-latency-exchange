#pragma once
// One exchanged process (07 §3, WP N-03): the stages gw0, gw1, seq, engine, md, repl,
// io of 01 §7 wired over the shared queues and rings (shared.h), started on a fresh
// day or recovered from the journal, run either one thread per stage (rt::Launcher with
// the configured core map) or all on one thread (InlineRunner style, dev).
//
// Housekeeping threads, off the core map: the admin port (authenticated lle-admin
// commands into the sequencer, 05 §10), the control port (dev/test: manual clock,
// barrier, day end, status), the GLIMPSE snapshot server (07 §3: never on the 8-core
// set) and the nlog backend.
#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "engine/engine.h"
#include "env/entropy.h"
#include "exchanged/clock.h"
#include "exchanged/config.h"
#include "exchanged/engine_stage.h"
#include "exchanged/io_stage.h"
#include "exchanged/metrics.h"
#include "exchanged/record_log.h"
#include "exchanged/recovery.h"
#include "exchanged/seq_stage.h"
#include "exchanged/shared.h"
#include "gateway/session_table.h"
#include "journal/l2_storage.h"
#include "log/backend.h"
#include "outlog/day.h"
#include "runtime/launcher.h"
#include "sequencer/engine_day.h"

namespace lle::exch {

class NetStagesBase;
struct ReplEnv;
template <class Env>
class BasicReplStage;
using ReplStage = BasicReplStage<ReplEnv>;
template <class Env>
class BasicSeqSide;
using SeqSide = BasicSeqSide<ReplEnv>;
struct HostedBase;
struct ReloadResult;

// Build identity stamped into DayStart and compared by the replication handshake.
inline constexpr std::uint64_t kBuildId = 0x4C4C45'00000001ull;  // "LLE" v1

class Node {
 public:
  explicit Node(ExchangeConfig cfg);
  ~Node();
  Node(const Node&) = delete;
  Node& operator=(const Node&) = delete;

  // Recovery or day start, stages, threads. On failure nothing is left running.
  std::expected<void, std::string> start();
  // Runs until stop is requested (signal, control `shutdown`, fatal error, deposed);
  // returns the exit code.
  int run(const std::atomic<bool>& external_stop);
  void request_stop(int code = 0) noexcept;
  // Checked while start() waits (the rejoin handshake): a signal stops the wait.
  void set_stop_flag(const std::atomic<bool>* f) noexcept { external_stop_ = f; }

  // One status line (control port, logs).
  [[nodiscard]] std::string status() const;

 private:
  std::expected<void, std::string> open_journal();
  std::expected<void, std::string> recover_or_start();
  std::expected<void, std::string> open_writer(const journal::RecoveryResult& rr);
  std::expected<journal::RecoveryResult, std::string> restore_l2(journal::RecoveryResult rr);
  std::expected<void, std::string> rejoin();
  bool truncate_journal_to(std::uint64_t t);
  ReloadResult reload_to(std::uint64_t t);
  std::expected<void, std::string> start_net();
  bool wait_net(const std::atomic<bool>& external_stop);
  void build_stages();
  void start_admin();
  void start_control();
  void shutdown();
  std::string control(const std::string& line);
  void publish_seq();
  void publish_repl();
  void publish_engine();
  void publish_io();

  ExchangeConfig cfg_;
  std::unique_ptr<NodeMetrics> metrics_;
  std::unique_ptr<nlog::Backend> nlog_;
  std::vector<engine::ScheduleEntry> schedule_;
  std::unique_ptr<seq::EngineDay> day_;
  gw::SessionTable sessions_;
  std::unique_ptr<NodeClock> clock_;
  std::unique_ptr<Shared> sh_;
  std::unique_ptr<std::uint64_t[]> l2_mem_;
  std::unique_ptr<journal::L2Storage> l2_storage_;  // [journal] l2_path: survives a process crash
  env::ProdRng rng_;
  std::unique_ptr<SegDir> dir_;
  std::unique_ptr<Preparer> prep_;
  std::unique_ptr<Writer> writer_;
  std::unique_ptr<outlog::OutlogDay> outlog_;
  std::unique_ptr<engine::Engine> engine_;
  std::unique_ptr<RecordLog> rlog_;
  std::unique_ptr<SeqRing> seq_ring_;
  std::unique_ptr<Sequencer> sequencer_;
  std::unique_ptr<SeqDriver> driver_;
  std::unique_ptr<SeqStage> seq_stage_;
  std::unique_ptr<SeqSide> seq_side_;  // split mode: the sequencer's stage, the replica on its own thread
  bool split_ = false;
  std::unique_ptr<ReplStage> repl_;
  std::unique_ptr<EngineStage> engine_stage_;
  std::unique_ptr<IoStage> io_stage_;
  std::unique_ptr<NetStagesBase> net_;
  std::vector<std::unique_ptr<HostedBase>> hosted_;
  std::unique_ptr<rt::Launcher> launcher_;
  std::thread admin_thread_;
  std::thread control_thread_;
  std::atomic<bool> aux_stop_{false};
  bool started_ = false;
  bool fresh_day_ = false;
  bool rejoin_ = false;  // a paired node restarting mid-day (10 §5)
  const std::atomic<bool>* external_stop_ = nullptr;
  std::uint64_t recovered_index_ = 0;
  RecoveredDay recovered_;
  std::vector<std::pair<std::uint32_t, SeqNo>> soup_next_;
  SeqNo itch_next_ = 1;
  // Ring occupancy (ring_gauge.h): sampled by the seq thread (l2, ouch, events, tee) and
  // the engine thread (egress) when they publish.
  RingGauge ring_l2_, ring_ouch_, ring_events_, ring_tee_, ring_egress_;
};

}  // namespace lle::exch
