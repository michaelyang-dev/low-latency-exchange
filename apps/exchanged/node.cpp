#include "exchanged/node.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

#include "admin/admin_port.h"
#include "common/assert.h"
#include "admin/net.h"
#include "admin/protocol.h"
#include "exchanged/hosted.h"
#include "exchanged/net_stages.h"
#include "exchanged/node_log.h"
#include "exchanged/recovery.h"
#include "exchanged/repl_stage.h"
#include "exchanged/restart_guard.h"
#include "exchanged/start_impl.h"
#include "journal/recovery.h"
#include "log/nlog.h"
#include "log/tsc.h"
#include "net/common/endpoint.h"
#if defined(__linux__)
#include <net/if.h>

#include "net/busypoll/busypoll.h"
#endif
#include "repl/journal_truncate.h"
#include "snapshot/format.h"

namespace lle::exch {

namespace {

std::string ep_str(env::Endpoint e) { return net::to_string(e); }

// Polls `pred` until true or `timeout`; cold (control thread).
template <class P>
bool wait_for(P&& pred, std::chrono::milliseconds timeout) {
  const auto end = std::chrono::steady_clock::now() + timeout;
  while (!pred()) {
    if (std::chrono::steady_clock::now() > end) return false;
    std::this_thread::sleep_for(std::chrono::microseconds(200));
  }
  return true;
}

// The incarnation number of a data node (10 §2): unique per process start, monotonic
// and durable before the node talks to the witness (written, fsync'd, renamed, and the
// directory fsync'd).
bool write_incarnation(const std::string& path, std::uint64_t v) {
  const std::string tmp = path + ".tmp";
  const std::string text = std::to_string(v) + "\n";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return false;
  const bool ok = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size()) && ::fsync(fd) == 0;
  ::close(fd);
  if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) return false;
  const std::string dir = std::filesystem::path(path).parent_path().string();
  const int dfd = ::open(dir.c_str(), O_RDONLY);
  if (dfd < 0) return false;
  const bool synced = ::fsync(dfd) == 0;
  ::close(dfd);
  return synced;
}
std::uint64_t read_incarnation(const std::string& path) {
  std::ifstream f(path);
  std::uint64_t v = 0;
  if (!(f >> v) || v == 0) return 1;  // a day started before incarnations were recorded
  return v;
}

// The rejoin steps' storage (start_impl.h): POSIX files, as recovery's.
struct PosixRejoinIo : PosixRecoveryIo {
  void note(const std::string& line) {
    std::printf("%s\n", line.c_str());
    std::fflush(stdout);
  }
  void warn(const std::string& line) { std::fprintf(stderr, "%s\n", line.c_str()); }
  std::uint64_t read_incarnation(const std::string& path) { return exch::read_incarnation(path); }
  bool write_incarnation(const std::string& path, std::uint64_t v) { return exch::write_incarnation(path, v); }
  std::vector<std::uint64_t> remove_snapshots_above(const std::string& dir, std::uint64_t t) {
    std::vector<std::uint64_t> removed;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
      if (const auto i = snap::parse_snapshot_file_name(e.path().filename().string()); i && *i > t) {
        std::filesystem::remove(e.path(), ec);
        removed.push_back(*i);
      }
    }
    return removed;
  }
};
using NodeRejoinParts = RejoinParts<SegDir, Preparer, RecordLog, outlog::OutlogDay>;
NodeRejoinParts rejoin_parts(SegDir& dir, Preparer& prep, RecordLog& rlog, Shared& sh, engine::Engine& eng,
                             outlog::OutlogDay& out, RecoveredDay& recovered, std::uint64_t& recovered_index,
                             const ExchangeConfig& cfg, std::span<const seq::ConfigBlob> config) {
  return NodeRejoinParts{.dir = dir,
                         .prep = prep,
                         .rlog = rlog,
                         .sh = sh,
                         .engine = eng,
                         .out = out,
                         .recovered = recovered,
                         .recovered_index = recovered_index,
                         .date = cfg.date,
                         .layout = recovery_layout(cfg),
                         .config = config,
                         .snapshots_dir = cfg.snapshots_dir(),
                         .replay_snapshots = cfg.use_snapshots ? cfg.snapshots_dir() : std::string(),
                         .incarnation_path = cfg.journal_dir() + "/incarnation"};
}

// The variant's device settings (07 §1; METHODOLOGY §14): busy polling's per-device knobs
// and, for the IRQ-suspend sub-variant, the per-NAPI irq-suspend-timeout. Applied with
// [net] device_setup (root), else read back; either way reported, and a mismatch is
// flagged (the run is then not the variant it claims), not fatal.
std::string device_report(const ExchangeConfig& cfg) {
#if defined(__linux__)
  if (cfg.backend != net::BackendKind::BusyPoll || cfg.net_ifname.empty()) return {};
  namespace bp = net::busypoll;
  bp::Config want;
  want.mode = cfg.busypoll_irq_suspend ? bp::Mode::IrqSuspend : bp::Mode::Plain;
  std::string out = "exchanged: variant " + cfg.variant() + " on " + cfg.net_ifname + ":";
  if (cfg.device_setup) {
    const auto r = bp::configure_device(cfg.net_ifname, want);
    out += r ? " device settings applied;" : " device settings not applied (" + net::to_string(r.error()) + ");";
  }
  bool ok = true;
  const auto defer = bp::napi_defer_hard_irqs(cfg.net_ifname);
  const auto gro = bp::gro_flush_timeout(cfg.net_ifname);
  ok = ok && defer && *defer == want.napi_defer_hard_irqs && gro && *gro == want.gro_flush_timeout_ns;
  out += " napi_defer_hard_irqs " + (defer ? std::to_string(*defer) : std::string("?")) + ", gro_flush_timeout " +
         (gro ? std::to_string(*gro) : std::string("?")) + " ns";
  if (cfg.busypoll_irq_suspend) {
    bp::NapiInfo napis[64];
    const unsigned ifindex = ::if_nametoindex(cfg.net_ifname.c_str());
    const auto n = ifindex == 0 ? net::Result<std::size_t>(std::unexpected(net::Error{ENODEV, "if_nametoindex"}))
                                : bp::list_napi(ifindex, napis);
    std::size_t set = 0, total = 0;
    if (n) {
      total = std::min<std::size_t>(*n, 64);
      for (std::size_t i = 0; i < total; ++i) set += napis[i].irq_suspend_timeout_ns == want.irq_suspend_timeout_ns ? 1 : 0;
    }
    ok = ok && n && total != 0 && set == total;
    out += ", irq-suspend-timeout " + std::to_string(want.irq_suspend_timeout_ns) + " ns on " + std::to_string(set) + " of " +
           std::to_string(total) + " NAPIs";
  }
  out += ok ? " (as the variant requires)" : " (NOT the variant's settings: the run does not measure this variant)";
  return out;
#else
  (void)cfg;
  return {};
#endif
}

ReplStageConfig repl_config(const ExchangeConfig& cfg, std::uint64_t incarnation, std::uint64_t digest) {
  ReplStageConfig rc;
  rc.repl.self = cfg.node_id;
  rc.repl.incarnation = incarnation;
  rc.repl.build_id = cfg.build_id != 0 ? cfg.build_id : kBuildId;
  rc.repl.config_digest = digest;
  rc.repl.heartbeat_ns = cfg.ha_heartbeat;
  rc.repl.t_d = cfg.t_d;
  rc.repl.t_ack = cfg.t_ack;
  rc.repl.rejoin_retry_ns = cfg.rejoin_retry;
  rc.repl.rto_ns = cfg.ha_rto;
  rc.bind = cfg.ha_bind;
  rc.peer = cfg.ha_peer;
  rc.witness = cfg.witness;
  rc.witness_bind = cfg.witness_bind;
  rc.initial_primary = cfg.initial_primary;
  rc.peer_incarnation = 1;
  for (const auto& s : cfg.sessions) rc.sessions.push_back(s.session_id);
  return rc;
}

}  // namespace

// Admin and control listeners live on their own threads (cold paths).
struct AdminState {
  admin::Verifier verifier;
  std::unique_ptr<admin::AdminPort<AdminQueue>> port;
  std::map<std::size_t, admin::FrameAssembler> conns;
  std::optional<admin::TcpListener> listener;
};
struct ControlState {
  std::map<std::size_t, std::string> lines;
  std::optional<admin::TcpListener> listener;
};

Node::Node(ExchangeConfig cfg) : cfg_(std::move(cfg)) {}

Node::~Node() { shutdown(); }

void Node::request_stop(int code) noexcept {
  if (sh_) {
    if (code != 0) sh_->exit_code.store(code);
    sh_->stop.store(true);
  }
}

std::expected<void, std::string> Node::start() {
  std::error_code ec;
  std::filesystem::create_directories(cfg_.journal_dir(), ec);
  if (ec) return std::unexpected("cannot create " + cfg_.journal_dir() + ": " + ec.message());
  std::filesystem::create_directories(cfg_.outlog_root(), ec);
  std::filesystem::create_directories(cfg_.data_dir + "/logs", ec);

  if (cfg_.nlog) {
    nlog_ = std::make_unique<nlog::Backend>();
    nlog::BackendOptions o;
    o.path = cfg_.log_path();
    o.node = cfg_.name;
    if (auto r = nlog_->start(o); !r) return std::unexpected("nlog: " + r.error());
    nlog::ThreadOptions to;
    to.name = "main";
    (void)nlog::register_thread(to);
  }
  auto m = NodeMetrics::create(cfg_.name, cfg_.metrics);
  if (!m) return std::unexpected(m.error());
  metrics_ = std::move(*m);
  metrics_->set(Ctr::node_start_ns, static_cast<std::uint64_t>(env::ProdClock{}.now_real()));

  schedule_ = cfg_.schedule_table();
  day_ = std::make_unique<seq::EngineDay>(
      seq::EngineTables{cfg_.symbols, cfg_.accounts, cfg_.sessions, cfg_.risk, schedule_}, cfg_.local_midnight());
  auto table = gw::SessionTable::build(cfg_.session_specs, md::kGateways);
  if (!table) return std::unexpected("sessions: " + table.error());
  sessions_ = std::move(*table);

  clock_ = std::make_unique<NodeClock>(cfg_.clock, cfg_.local_midnight() + cfg_.start);
  sh_ = std::make_unique<Shared>();
  sh_->egress.init(std::size_t{16} << 20);
  sh_->apply_limit.store(~std::uint64_t{0});
  if (cfg_.l2_path.empty()) {
    l2_mem_.reset(new std::uint64_t[cfg_.l2_bytes / 8]());
    std::uint64_t l2_nonce = 0;
    do {
      l2_nonce = rng_.next_u64();
    } while (!journal::usable_nonce(l2_nonce));
    sh_->l2.init(reinterpret_cast<std::byte*>(l2_mem_.get()), cfg_.l2_bytes, l2_nonce);
  } else {
    // 06 §5: L2 in a file (hugetlbfs in production) survives a process crash; what it
    // holds beyond L3 is journaled at restart (restore_l2).
    std::filesystem::create_directories(cfg_.l2_path, ec);
    journal::L2StorageOptions lo;
    lo.path = cfg_.l2_path + "/" + cfg_.name + "-" + std::to_string(cfg_.date) + ".l2";
    lo.capacity = cfg_.l2_bytes;
    lo.control_bytes = cfg_.l2_page_bytes;
    lo.node = cfg_.node_id;
    lo.day = cfg_.date;
    auto st = journal::L2Storage::open(lo, rng_);
    if (!st) return std::unexpected("L2 storage " + lo.path + ": " + st.error());
    l2_storage_ = std::make_unique<journal::L2Storage>(std::move(*st));
    sh_->l2.init(l2_storage_->data(), l2_storage_->capacity(), l2_storage_->nonce());
  }
  if (cfg_.mode == NodeMode::Paired) {
    sh_->mirror.store(cfg_.node_id != cfg_.initial_primary);
    sh_->lines.store(cfg_.node_id == cfg_.initial_primary ? md::kLineA : md::kLineB);
  }

  if (auto r = open_journal(); !r) return r;
  if (auto r = recover_or_start(); !r) return r;
  build_stages();
  if (auto r = start_net(); !r) return r;
  if (cfg_.admin_port >= 0) start_admin();
  if (cfg_.control_port >= 0) start_control();
  started_ = true;
  return {};
}

std::expected<void, std::string> Node::open_journal() {
  journal::UringDirOptions dio;
  dio.use_io_uring = cfg_.journal_io_uring;
  dio.uring.iopoll = cfg_.journal_iopoll;
  auto dir = SegDir::open(cfg_.journal_dir(), true, dio);
  if (!dir) return std::unexpected("journal: " + dir.error());
  dir_ = std::make_unique<SegDir>(std::move(*dir));
  prep_ = std::make_unique<Preparer>(*dir_, rng_, cfg_.date, cfg_.segment_bytes);
  journal::RecoveryOptions ro;
  ro.day = cfg_.date;
  journal::RecoveryResult rr = journal::recover(*dir_, ro);
  if (!rr.usable() || (rr.torn_tail && !rr.repaired))
    return std::unexpected("journal recovery refused (06 §7): " + rr.detail);
  recovered_index_ = rr.chain.last_index;
  std::vector<std::uint32_t> ids;
  for (const auto& s : cfg_.sessions) ids.push_back(s.session_id);
  std::sort(ids.begin(), ids.end());
  outlog_ = std::make_unique<outlog::OutlogDay>();
  if (auto r = outlog_->open(cfg_.outlog_root(), cfg_.date, ids); !r) return std::unexpected("output log: " + r.error());
  engine_ = std::make_unique<engine::Engine>();
  if (l2_storage_ && l2_storage_->reopened()) {
    auto r = restore_l2(rr);
    if (!r) return std::unexpected(r.error());
    rr = std::move(*r);
    recovered_index_ = rr.chain.last_index;
  }
  // A paired node restarting mid-day rejoins (10 §5), even on an empty journal once the day
  // started here (start_impl.h restart_must_rejoin): the writer opens after the handshake,
  // which may truncate the journal first (rejoin()).
  std::error_code inc_ec;
  rejoin_ = restart_must_rejoin(cfg_.mode == NodeMode::Paired, recovered_index_,
                                std::filesystem::exists(cfg_.journal_dir() + "/incarnation", inc_ec));
  if (!rejoin_) {
    if (auto r = open_writer(rr); !r) return r;
  }
  nodelog::journal_recovered(rr.records, rr.chain.last_index, rr.torn_tail);
  std::printf("exchanged: journal %s: %" PRIu64 " records recovered%s\n", cfg_.journal_dir().c_str(),
              rr.chain.last_index, rr.torn_tail ? " (torn tail repaired)" : "");
  std::fflush(stdout);  // progress is visible even if a later step stalls
  // The restart-loop guard (restart_guard.h): after [ha] restart_loop_limit starts from this
  // same journal that each exited 5 at the same point, refuse, naming the remedy.
  start_recovered_index_ = recovered_index_;
  if (rejoin_) {
    const auto rec = read_restart_record(restart_guard_path());
    if (restart_refused(rec, recovered_index_, cfg_.restart_loop_limit)) {
      restart_loop_refused_ = true;
      NLOG_ERROR("restart loop: {}", std::string_view(restart_refusal(*rec)));
      return std::unexpected(restart_refusal(*rec));
    }
  }

  if (recovered_index_ != 0 && !rejoin_) {
    journal::RecoveryOptions again;
    again.day = cfg_.date;
    again.repair = false;
    const journal::RecoveryResult rr2 = journal::recover(*dir_, again);
    auto day = replay_day(*dir_, rr2, *engine_, *outlog_, cfg_, day_->config(),
                          cfg_.use_snapshots ? cfg_.snapshots_dir() : std::string());
    if (!day) return std::unexpected("recovery: " + day.error());
    if (day->snapshot_index != 0)
      std::printf("exchanged: recovery from the snapshot at %" PRIu64 " (%s)\n", day->snapshot_index,
                  cfg_.snapshots_dir().c_str());
    std::printf("exchanged: recovery replayed %" PRIu64 " records; output log: %" PRIu64 " verified, %" PRIu64
                " regenerated, %" PRIu64 " files rewritten; engine state hash %016" PRIx64 "\n",
                day->chain.last_index, day->outlog_verified, day->outlog_appended, day->outlog_rewritten,
                day->state_hash);
    nodelog::replayed(day->chain.last_index, day->outlog_verified, day->outlog_appended);
    recovered_ = std::move(*day);
  }
  return {};
}

std::expected<void, std::string> Node::open_writer(const journal::RecoveryResult& rr) {
  journal::JournalWriterOptions wo;
  wo.day = cfg_.date;
  writer_ = std::make_unique<Writer>(wo);
  dir_->set_fixed_buffers(writer_->batch_buffers());  // io_uring: WRITE_FIXED
  if (auto r = resume_journal_writer(*writer_, *dir_, *prep_, rr, cfg_.spares); !r) return r;
  if (dir_->count() != 0) {
    const std::string dev = dir_->device(dir_->count() - 1).describe();
    std::printf("exchanged: journal device: %s%s%s\n", dev.c_str(), dir_->fallback_reason().empty() ? "" : "; ",
                dir_->fallback_reason().c_str());
  }
  if (dir_->fixed_buffer_failures() != 0) {
    std::fprintf(stderr, "exchanged: journal: %zu segment(s): %s\n", dir_->fixed_buffer_failures(),
                 dir_->fixed_buffer_note().c_str());
    NLOG_WARN("journal: {} segment(s): {}", dir_->fixed_buffer_failures(), std::string_view(dir_->fixed_buffer_note()));
  }
  return {};
}

// 06 §5: the previous process's L2 (a file that outlived it) may hold records beyond
// L3, e.g. ones a backup acknowledged. They are journaled now, before anything else
// reads the journal; then the ring starts empty.
std::expected<journal::RecoveryResult, std::string> Node::restore_l2(journal::RecoveryResult rr) {
  const std::optional<std::uint32_t> prev =
      rr.chain.last_index == 0 ? std::nullopt : std::optional<std::uint32_t>(rr.chain.last_crc);
  const journal::L2RestoreResult res = sh_->l2.restore(rr.chain.last_index + 1, prev);
  if (res.found && res.records != 0) {
    if (auto r = open_writer(rr); !r) return std::unexpected(r.error());
    IoStage io(*sh_, *dir_, *prep_, *writer_, *outlog_, cfg_.spares, false, *clock_);
    io.drain();
    if (io.failed() || writer_->durable_index() != res.chain.last_index)
      return std::unexpected("L2: journaling the restored records failed at " +
                             std::to_string(writer_->durable_index()) + " of " +
                             std::to_string(res.chain.last_index));
    writer_.reset();
    journal::RecoveryOptions ro;
    ro.day = cfg_.date;
    rr = journal::recover(*dir_, ro);
    if (!rr.usable() || rr.chain.last_index != res.chain.last_index)
      return std::unexpected("L2: recovery after journaling the restored records: " + rr.detail);
    std::printf("exchanged: L2: restored %" PRIu64 " records (%" PRIu64 "..%" PRIu64 ") into the journal\n",
                res.records, res.chain.last_index - res.records + 1, res.chain.last_index);
    nodelog::l2_restored(res.records, res.chain.last_index);
  }
  // What the ring held beyond L3 is journaled now, and a fresh nonce retires it: else a
  // later start journals the same records again into a journal moved aside since (the
  // runbook for an incomplete day start moves it), and refuses at every start (DST-023).
  // Positions start over.
  l2_storage_->renew(rng_);
  sh_->l2.init(l2_storage_->data(), l2_storage_->capacity(), l2_storage_->nonce());
  sh_->durable.store(rr.chain.last_index);
  return rr;
}

std::expected<void, std::string> Node::recover_or_start() {
  rlog_ = cfg_.mode == NodeMode::Paired
              ? std::make_unique<RecordLog>(cfg_.repl_log_bytes, cfg_.repl_log_bytes / 64, cfg_.journal_dir(), cfg_.date)
              : nullptr;
  // The replica on its own thread (10 §3; 01 §7 CPU 13): [ha] repl_thread or a `repl`
  // core-map entry. The sequencer's records then reach its record log through a tee.
  split_ = cfg_.mode == NodeMode::Paired && (cfg_.repl_thread || cfg_.cores.cpu_for("repl").has_value());
  if (split_) {
    constexpr std::size_t kTeeBytes = std::size_t{16} << 20;
    sh_->split.tee_mem.reset(new std::uint64_t[kTeeBytes / 8]());
    sh_->split.tee.init(reinterpret_cast<std::byte*>(sh_->split.tee_mem.get()), kTeeBytes);
  }
  seq_ring_ = std::make_unique<SeqRing>(sh_->l2, rlog_.get(), split_ ? &sh_->split.tee : nullptr);
  seq::SequencerConfig sc;
  sc.snapshot_every = cfg_.snapshot_every;
  // A node started late finds every overdue 1 Hz timer due at once; bounded per poll so
  // the seq thread (shared with replication in paired mode) keeps polling its links.
  sc.timer_batch = 64;
  sequencer_ = std::make_unique<Sequencer>(*clock_, sh_->ouch, sh_->events, sh_->admin, *seq_ring_, day_->timers(), sc);
  driver_ = std::make_unique<SeqDriver>(*sh_, *clock_, *sequencer_, day_->timers(), cfg_.auto_end);

  if (rejoin_) return rejoin();

  // A fresh day start (the journal recovered empty): the day's output log starts empty
  // (outlog_messages, DST-019), and a paired node writes its incarnation file before it
  // sequences or serves anything, or does not start: a restart that finds the file
  // rejoins instead of starting the day again (DST-006).
  if (recovered_index_ == 0) {
    if (const std::uint64_t stale = outlog_messages(outlog_positions(*outlog_)); stale != 0) {
      std::printf("exchanged: day start: the output log holds %" PRIu64
                  " messages of an earlier start of the day (its journal is gone): reset\n",
                  stale);
      NLOG_WARN("day start: output log reset ({} messages of an earlier start of the day)", stale);
    }
    if (auto r = reset_outlog(*outlog_, cfg_); !r) return std::unexpected("day start: " + r.error());
    if (cfg_.mode == NodeMode::Paired && !write_incarnation(cfg_.journal_dir() + "/incarnation", 1))
      return std::unexpected("day start: cannot write " + cfg_.journal_dir() + "/incarnation");
  }

  // Per-session SoupBinTCP and MoldUDP64 positions from the output log (regenerated).
  {
    OutlogPositions pos = outlog_positions(*outlog_);
    soup_next_ = std::move(pos.soup_next);
    itch_next_ = pos.itch_next;
  }

  if (recovered_index_ == 0) {
    fresh_day_ = true;
    if (rlog_) rlog_->reset(journal::ChainState{});
    DayStartParams dp;
    dp.date = cfg_.date;
    dp.local_midnight = cfg_.local_midnight();
    dp.build_id = cfg_.build_id != 0 ? cfg_.build_id : kBuildId;
    dp.mold_session = cfg_.mold_session;
    dp.soup_session = cfg_.soup_session;
    dp.primary = cfg_.mode == NodeMode::Paired ? cfg_.initial_primary : cfg_.node_id;
    // Identical on both data nodes and on a re-run of the day (clock.h).
    if (!start_fresh_day(*sequencer_, *clock_, dp, day_->config()))
      return std::unexpected(std::string("day start: the L2 ring cannot hold the day's configuration"));
    sh_->sequenced.store(sequencer_->chain().last_index);
    std::printf("exchanged: day %u started (%" PRIu64 " records)\n", cfg_.date, sequencer_->chain().last_index);
    nodelog::day_started(cfg_.date, sequencer_->chain().last_index);
    return {};
  }
  // Solo restart (06 §7): continue the journaled day.
  const RecoveredDay& d = recovered_;
  if (d.ended) std::printf("exchanged: day %u already ended at index %" PRIu64 "\n", cfg_.date, d.day_end_index);
  // Egress learns about an ended day through the ring, in order; otherwise the sequencer
  // resumes and the instances that were logged in when the process died are gone.
  continue_day(*sequencer_, *clock_, *sh_, d);
  return {};
}

// 10 §5: RECOVERING with a new incarnation; the witness grants RESUME (this node is
// the solo primary of record) or names the primary, and the node truncates its journal
// by epoch, reloads its engine and catches up. Truncation and reload run here, before
// any stage, so they touch the journal, the engine and the output log alone.
std::expected<void, std::string> Node::rejoin() {
  PosixRejoinIo io;
  NodeRejoinParts parts = rejoin_parts(*dir_, *prep_, *rlog_, *sh_, *engine_, *outlog_, recovered_, recovered_index_,
                                       cfg_, day_->config());
  const auto begun = begin_rejoin(io, parts);
  if (!begun) return std::unexpected(begun.error());
  const std::uint64_t inc = begun->incarnation;
  repl_ = std::make_unique<ReplStage>(*sh_, *clock_, *sequencer_, *driver_, *rlog_,
                                      repl_config(cfg_, inc, begun->config_digest), *metrics_, split_);
  RejoinHooks hooks;
  hooks.truncate = [this](std::uint64_t t) { return truncate_journal_to(t); };
  hooks.reload = [this](std::uint64_t t, bool resume) { return reload_to(t, resume); };
  hooks.before_restart = [this](const char* what, std::uint64_t t) {
    const RestartRecord rec =
        next_restart_record(read_restart_record(restart_guard_path()), what, t, start_recovered_index_);
    (void)write_restart_record(restart_guard_path(), rec);
    std::fprintf(stderr, "exchanged: restart loop guard: %u consecutive exit(s) at this point (limit %u)\n", rec.count,
                 cfg_.restart_loop_limit);
  };
  if (auto r = repl_->start_recovering(begun->config_digest, std::move(hooks)); !r) return r;
  std::printf("exchanged: rejoin: incarnation %" PRIu64 ", journal at %" PRIu64 "\n", inc, recovered_index_);
  std::fflush(stdout);
  const auto start = std::chrono::steady_clock::now();
  auto last_note = start;
  while (!repl_->handshake_done()) {
    if (external_stop_ != nullptr && external_stop_->load()) return std::unexpected(std::string("rejoin: stopped"));
    if (!repl_->poll_prestart()) std::this_thread::sleep_for(std::chrono::microseconds(100));
    const auto now = std::chrono::steady_clock::now();
    if (now - last_note > std::chrono::seconds(5)) {
      last_note = now;
      std::printf("exchanged: rejoin: waiting (%s)\n", status().c_str());
      std::fflush(stdout);
    }
  }
  const auto role = finish_rejoin(parts, *repl_, *clock_,
                                  [this](const journal::RecoveryResult& rr) { return open_writer(rr); });
  if (!role) return std::unexpected(role.error());
  {
    OutlogPositions pos = outlog_positions(*outlog_);
    soup_next_ = std::move(pos.soup_next);
    itch_next_ = pos.itch_next;
  }
  std::printf("exchanged: rejoin: %s %" PRIu64 " (%s)\n",
              *role == repl::Role::kSoloPrimary ? "resumed as the solo primary at" : "catching up from",
              recovered_index_, status().c_str());
  std::fflush(stdout);
  return {};
}

bool Node::truncate_journal_to(std::uint64_t t) {
  PosixRejoinIo io;
  NodeRejoinParts parts = rejoin_parts(*dir_, *prep_, *rlog_, *sh_, *engine_, *outlog_, recovered_, recovered_index_,
                                       cfg_, day_->config());
  return exch::truncate_journal_to(io, parts, t);
}

ReloadResult Node::reload_to(std::uint64_t t, bool resume) {
  PosixRejoinIo io;
  NodeRejoinParts parts = rejoin_parts(*dir_, *prep_, *rlog_, *sh_, *engine_, *outlog_, recovered_, recovered_index_,
                                       cfg_, day_->config());
  return exch::reload_to(io, parts, t, resume);
}

void Node::build_stages() {
  const bool paired = cfg_.mode == NodeMode::Paired;
  EngineStageConfig ec;
  ec.hash_interval = paired ? 65'536 : 0;
  engine_stage_ = std::make_unique<EngineStage>(*sh_, *engine_, ec, recovered_index_, *clock_);
  if (recovered_index_ != 0) engine_stage_->set_totals(recovered_.itch_total, recovered_.soup_total);
  // A rejoin's reloaded outputs still to release, and a recovered DayEnd (DST-013).
  engine_stage_->stage_deferred(recovered_.deferred);
  recovered_.deferred = {};
  io_stage_ = std::make_unique<IoStage>(*sh_, *dir_, *prep_, *writer_, *outlog_, cfg_.spares, !paired, *clock_);
  // Work time (T32): records the sequencer reserves from here on start the driver's
  // meter (the day-start records are behind us); lle_top converts ticks with tsc_hz.
  seq_ring_->set_meter(&driver_->meter());
  metrics_->set(Ctr::tsc_hz, nlog::tsc_hz());
  ring_l2_.cap = sh_->l2.capacity();
  ring_ouch_.cap = OuchQueue::capacity();
  ring_events_.cap = SessionQueue::capacity();
  ring_tee_.cap = split_ ? sh_->split.tee.capacity() : 0;
  ring_egress_.cap = sh_->egress.capacity();
  if (paired) {
    if (!repl_) {
      repl_ = std::make_unique<ReplStage>(*sh_, *clock_, *sequencer_, *driver_, *rlog_,
                                          repl_config(cfg_, 1, sequencer_->config_digest()), *metrics_, split_);
    }
  } else {
    seq_stage_ = std::make_unique<SeqStage>(*driver_);
  }
}

std::expected<void, std::string> Node::start_net() {
  gw::GatewayConfig gc[md::kGateways];
  for (std::uint8_t i = 0; i < md::kGateways; ++i) {
    gc[i].index = i;
    gc[i].instance = cfg_.node_id;
    gc[i].soup.session = soup::SessionId::from(cfg_.soup_session);
    gc[i].soup.heartbeat_interval = cfg_.soup_heartbeat;
    gc[i].soup.idle_timeout = cfg_.soup_idle_timeout;
    gc[i].soup.login_timeout = cfg_.soup_login_timeout;
    gc[i].close_linger = cfg_.close_linger;
    gc[i].tcp.max_conns = cfg_.max_conns;
    gc[i].tcp.max_reads_per_poll = 4;
    gc[i].listen = cfg_.gw[i];
    gc[i].replay_ring_messages = cfg_.replay_ring_msgs;
    gc[i].replay_ring_bytes = cfg_.replay_ring_bytes;
    gc[i].outlog_root = cfg_.outlog_root();
    gc[i].day = cfg_.date;
  }
  md::MdConfig mc;
  mc.session = mold::Session(cfg_.mold_session);
  mc.line_a = cfg_.line_a;
  mc.line_b = cfg_.line_b;
  mc.max_packet_a = cfg_.max_packet_a;
  mc.max_packet_b = cfg_.max_packet_b;
  mc.heartbeat_interval = cfg_.md_heartbeat;
  mc.end_of_session_linger = cfg_.md_eos_linger;
  mc.line_udp.ifname = cfg_.multicast_if;
  mc.line_udp.mcast_ttl = cfg_.ttl;
  mc.line_udp.mcast_loop = cfg_.multicast_loop;
  mc.line_udp.dst_addr = false;
  mc.rerequest_udp.bind = cfg_.rerequest;
  mc.rerequest_udp.dst_addr = false;
  mc.itch_log_path = outlog::OutlogDay::itch_path(cfg_.outlog_root(), cfg_.date);
  mc.first_seq = itch_next_;
  // Messages recovery regenerated into itch.bin may never have been multicast: md sends
  // them first (a solo restart, a RESUME; on a rejoining backup the lines are still off).
  mc.republish_from = republish_from(recovered_index_, recovered_, itch_next_);
  md::GlimpseConfig glc;
  if (cfg_.glimpse) {
    glc.soup.session = soup::SessionId::from(cfg_.soup_session);
    glc.soup.heartbeat_interval = cfg_.soup_heartbeat;
    glc.soup.idle_timeout = cfg_.soup_idle_timeout;
    glc.close_linger = cfg_.close_linger;
    glc.tcp.max_conns = 16;
    glc.listen = *cfg_.glimpse;
    glc.itch_log_path = mc.itch_log_path;
    glc.user = cfg_.glimpse_user;
    glc.credential = cfg_.glimpse_credential;
    glc.locates = cfg_.symbols.size();
  }
  if (const std::string dev = device_report(cfg_); !dev.empty()) {
    std::printf("%s\n", dev.c_str());
    nodelog::note(dev);
  }
  auto net = make_net_stages(cfg_, gc, sessions_, soup_next_, mc, cfg_.glimpse ? &glc : nullptr, *sh_, *clock_);
  if (!net) return std::unexpected(net.error());
  net_ = std::move(*net);
  net_->defer_start();  // sockets open on the stage threads (run())
  return {};
}

bool Node::wait_net(const std::atomic<bool>& external_stop) {
  std::string err;
  const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(20);
  int st = 0;
  while ((st = net_->start_state(&err)) == 0 && !external_stop.load() && std::chrono::steady_clock::now() < end)
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  if (st != 1) {
    std::fprintf(stderr, "exchanged: %s\n", st < 0 ? err.c_str() : "network stages did not start");
    return false;
  }
  const NetPorts p = net_->ports();
  std::printf("exchanged: gw0=%s gw1=%s rerequest=%s line_a=%s line_b=%s\n", ep_str(p.gw[0]).c_str(),
              ep_str(p.gw[1]).c_str(), ep_str(p.rerequest).c_str(), ep_str(cfg_.line_a).c_str(),
              ep_str(cfg_.line_b).c_str());
  if (cfg_.glimpse) std::printf("exchanged: glimpse=%s\n", ep_str(p.glimpse).c_str());
  return true;
}

void Node::start_admin() {
  auto st = std::make_shared<AdminState>();
  for (const Operator& op : cfg_.operators) st->verifier.add_operator(op.id, op.key);
  st->port = std::make_unique<admin::AdminPort<AdminQueue>>(st->verifier, sh_->admin);
  // The listener belongs to the state and calls back only from step() on the admin
  // thread, which holds the state: a plain pointer, not a cycle that is never freed.
  AdminState* s = st.get();
  auto l = admin::TcpListener::open(
      cfg_.admin_bind, static_cast<std::uint16_t>(cfg_.admin_port),
      [s](std::size_t c, std::span<const std::byte> in, std::vector<std::byte>& out) {
        return s->port->on_bytes(s->conns[c], in, out);
      },
      [s](std::size_t c) { s->conns.erase(c); });
  if (!l) {
    std::fprintf(stderr, "exchanged: admin port: %s\n", l.error().c_str());
    return;
  }
  st->listener.emplace(std::move(*l));
  std::printf("exchanged: admin=%s\n",
              net::to_string(env::Endpoint{cfg_.admin_bind, st->listener->port()}).c_str());
  admin_thread_ = std::thread([this, st] {
    nlog::ThreadOptions o;
    o.name = "admin";
    (void)nlog::register_thread(o);
    while (!aux_stop_.load(std::memory_order_acquire)) (void)st->listener->step(50);
  });
}

void Node::start_control() {
  auto st = std::make_shared<ControlState>();
  ControlState* s = st.get();  // as in start_admin: the listener's callbacks must not own it
  auto l = admin::TcpListener::open(
      cfg_.control_bind, static_cast<std::uint16_t>(cfg_.control_port),
      [this, s](std::size_t c, std::span<const std::byte> in, std::vector<std::byte>& out) {
        std::string& buf = s->lines[c];
        buf.append(reinterpret_cast<const char*>(in.data()), in.size());
        for (std::size_t nl = buf.find('\n'); nl != std::string::npos; nl = buf.find('\n')) {
          const std::string reply = control(buf.substr(0, nl)) + "\n";
          buf.erase(0, nl + 1);
          const auto* b = reinterpret_cast<const std::byte*>(reply.data());
          out.insert(out.end(), b, b + reply.size());
        }
        return true;
      },
      [s](std::size_t c) { s->lines.erase(c); });
  if (!l) {
    std::fprintf(stderr, "exchanged: control port: %s\n", l.error().c_str());
    return;
  }
  st->listener.emplace(std::move(*l));
  std::printf("exchanged: control=%s\n",
              net::to_string(env::Endpoint{cfg_.control_bind, st->listener->port()}).c_str());
  control_thread_ = std::thread([this, st] {
    while (!aux_stop_.load(std::memory_order_acquire)) (void)st->listener->step(50);
  });
}

std::string Node::control(const std::string& line) {
  std::istringstream in(line);
  std::string cmd, arg;
  in >> cmd >> arg;
  using namespace std::chrono_literals;
  if (cmd == "status") return "ok " + status();
  if (cmd == "clock") {
    if (clock_->mode() != ClockMode::Manual) return "err clock is not manual";
    const auto t = parse_time_of_day(arg);
    if (!t) return "err " + t.error();
    const Nanos target = cfg_.local_midnight() + *t;
    if (target < clock_->manual()) return "err the clock only moves forward";
    sh_->clock_target.store(target, std::memory_order_release);
    if (!wait_for([&] { return sh_->clock_reached.load() >= static_cast<std::uint64_t>(target); }, 60s))
      return "err timeout";
    return "ok " + std::to_string(target - cfg_.local_midnight());
  }
  if (cmd == "sync") {
    const std::uint64_t g = sh_->sync_req.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (!wait_for([&] { return sh_->sync_ack.load() >= g; }, 30s)) return "err timeout";
    const std::uint64_t idx = sh_->sync_index.load();
    auto settled = [&] {
      if (sh_->egress_state.applied.load() < idx || sh_->egress_state.release.load() < idx) return false;
      for (std::size_t c = 0; c < md::kConsumers; ++c)
        if (sh_->egress_state.done[c].load() < idx) return false;
      return true;
    };
    if (!wait_for(settled, 30s)) return "err timeout " + status();
    return "ok " + std::to_string(idx);
  }
  if (cmd == "end-day") {
    sh_->end_day_req.store(true);
    if (!wait_for([&] { return sh_->day_end_index.load() != 0; }, 60s)) return "err timeout";
    const std::uint64_t idx = sh_->day_end_index.load();
    auto settled = [&] {
      if (sh_->egress_state.release.load() < idx) return false;
      for (std::size_t c = 0; c < md::kConsumers; ++c)
        if (sh_->egress_state.done[c].load() < idx) return false;
      return true;
    };
    if (!wait_for(settled, 30s)) return "err timeout";
    return "ok " + std::to_string(idx);
  }
  if (cmd == "io-hold") {  // tests: records stay in L2 (not journaled) while on
    sh_->io_hold.store(arg == "on");
    return std::string("ok ") + (arg == "on" ? "on" : "off");
  }
  if (cmd == "shutdown") {
    request_stop(0);
    return "ok";
  }
  return "err unknown command";
}

std::string Node::status() const {
  if (!sh_ || !metrics_) return "starting";
  const char* role = "solo";
  if (cfg_.mode == NodeMode::Paired) role = repl::to_string(static_cast<repl::Role>(sh_->role.load()));
  std::string s = "role=" + std::string(role) + " epoch=" + std::to_string(sh_->epoch.load()) +
                  " seq=" + std::to_string(sh_->sequenced.load()) +
                  " applied=" + std::to_string(sh_->egress_state.applied.load()) +
                  " durable=" + std::to_string(sh_->durable.load()) +
                  " release=" + std::to_string(sh_->egress_state.release.load()) +
                  " itch=" + std::to_string(sh_->itch_total.load()) + " ouch=" + std::to_string(sh_->soup_total.load()) +
                  " day_end=" + std::to_string(sh_->day_end_index.load());
  // Stage counters as last published into the metrics segment (atomics; each stage
  // publishes from its own thread every 1,024 polls).
  auto m = [&](Ctr c) { return std::to_string(metrics_->c(c).value()); };
  auto sum = [&](Ctr x, Ctr y) { return std::to_string(metrics_->c(x).value() + metrics_->c(y).value()); };
  s += " sessions=" + sum(Ctr::gw0_sessions, Ctr::gw1_sessions) + " gw_in=" + sum(Ctr::gw0_msgs_in, Ctr::gw1_msgs_in) +
       " gw_out=" + sum(Ctr::gw0_msgs_out, Ctr::gw1_msgs_out) + " mpsc_full=" + sum(Ctr::gw0_mpsc_full, Ctr::gw1_mpsc_full) +
       " md_seq=" + m(Ctr::md_next_seq) + " md_pkts_a=" + m(Ctr::md_packets_a) + " md_pkts_b=" + m(Ctr::md_packets_b) +
       " md_rerequests=" + m(Ctr::md_rerequests_served) + "/" + m(Ctr::md_rerequests);
  return s;
}

void Node::publish_seq() {
  const seq::SequencerStats& s = sequencer_->stats();
  metrics_->set(Ctr::seq_records, s.records);
  metrics_->set(Ctr::seq_ouch, s.ouch);
  metrics_->set(Ctr::seq_session_events, s.session_events);
  metrics_->set(Ctr::seq_admin, s.admin);
  metrics_->set(Ctr::seq_timers, s.timers);
  metrics_->set(Ctr::seq_backpressure, s.backpressure);
  metrics_->set(Ctr::seq_last_index, sequencer_->chain().last_index);
  metrics_->set_work(Ctr::seq_work_tsc, driver_->work());
  const Nanos now = clock_->now_mono();
  ring_l2_.sample(std::max(sh_->l2.backlog(kL2Io), sh_->l2.backlog(kL2Engine)), now);
  ring_ouch_.sample(sh_->ouch.size_approx(), now);
  ring_events_.sample(sh_->events.size_approx(), now);
  metrics_->set_ring(Ctr::ring_l2_cap, ring_l2_);
  metrics_->set_ring(Ctr::ring_ouch_cap, ring_ouch_);
  metrics_->set_ring(Ctr::ring_events_cap, ring_events_);
  if (split_) {
    ring_tee_.sample(sh_->split.tee.used_bytes_approx(), now);
    metrics_->set_ring(Ctr::ring_tee_cap, ring_tee_);
  }
}
void Node::publish_repl() { repl_->publish_metrics(); }

void Node::publish_engine() {
  const EngineStats& s = engine_stage_->stats();
  metrics_->set(Ctr::engine_records, s.records);
  metrics_->set(Ctr::engine_orders, s.accepted);
  metrics_->set(Ctr::engine_fills, s.executed);
  metrics_->set(Ctr::engine_rejects, s.rejected);
  metrics_->set(Ctr::engine_cancels, s.canceled);
  metrics_->set(Ctr::engine_audits, s.audits);
  metrics_->set(Ctr::engine_itch, s.itch);
  metrics_->set(Ctr::engine_ouch, s.ouch);
  metrics_->set(Ctr::engine_halts, s.halts);
  metrics_->set(Ctr::engine_crosses, s.crosses);
  metrics_->set(Ctr::engine_applied, engine_stage_->applied());
  metrics_->set(Ctr::engine_live_orders, engine_->live_orders());
  metrics_->set(Ctr::engine_state_hash, s.state_hash);
  metrics_->set(Ctr::engine_replaced, s.replaced);
  metrics_->set(Ctr::engine_supervisory_cancels, s.supervisory_cancels);
  const std::uint64_t seqd = sh_->sequenced.load();
  metrics_->set(Ctr::engine_lag, seqd > engine_stage_->applied() ? seqd - engine_stage_->applied() : 0);
  // Book counts: books holding orders and their price levels (both sides).
  std::uint64_t books = 0, levels = 0;
  for (Locate l = 1; l <= engine_->symbols(); ++l) {
    const std::size_t n = engine_->book().level_count(l, Side::Buy) + engine_->book().level_count(l, Side::Sell);
    books += n != 0 ? 1 : 0;
    levels += n;
  }
  metrics_->set(Ctr::engine_books_active, books);
  metrics_->set(Ctr::engine_book_levels, levels);
  // Rejects by code since the last publication, one histogram count each.
  metrics::Histogram codes = metrics_->engine_reject_codes();
  for (std::size_t c = 0; c < std::size(s.reject_codes); ++c) {
    for (std::uint64_t k = published_rejects_[c]; k < s.reject_codes[c]; ++k) codes.record(static_cast<std::int64_t>(c));
    published_rejects_[c] = s.reject_codes[c];
  }
  metrics_->set_work(Ctr::engine_work_tsc, engine_stage_->work());
  std::uint64_t egress = 0;
  for (std::size_t c = 0; c < md::kConsumers; ++c) egress = std::max(egress, sh_->egress.backlog(c));
  ring_egress_.sample(egress, clock_->now_mono());
  metrics_->set_ring(Ctr::ring_egress_cap, ring_egress_);
}

void Node::publish_io() {
  const IoStats& s = io_stage_->stats();
  metrics_->set(Ctr::io_durable_index, io_stage_->durable());
  metrics_->set(Ctr::io_records, s.appended);
  metrics_->set(Ctr::io_segments, s.segments_prepared);
  const std::uint64_t seqd = sh_->sequenced.load();
  metrics_->set(Ctr::io_l2_lag, seqd > io_stage_->durable() ? seqd - io_stage_->durable() : 0);
  metrics_->set(Ctr::outlog_itch, s.outlog_itch);
  metrics_->set(Ctr::outlog_soup, s.outlog_soup);
  metrics_->set(Ctr::outlog_errors, s.outlog_errors);
  metrics_->set(Ctr::io_batches, s.batches);
  // Batch commit times since the last publication (the newest kCommitSamples at most).
  metrics::Histogram commit = metrics_->journal_commit();
  const std::uint64_t n = io_stage_->commit_count();
  const std::uint64_t held = IoStage::kCommitSamples;
  for (std::uint64_t k = std::max(published_commits_, n > held ? n - held : 0); k < n; ++k)
    commit.record(io_stage_->commit_sample(k));
  published_commits_ = n;
  if (cfg_.mode == NodeMode::Solo) metrics_->set(Ctr::release_index, sh_->egress_state.release.load());
  metrics_->set_work(Ctr::io_work_tsc, io_stage_->work());
  metrics_->heartbeat();
}

int Node::run(const std::atomic<bool>& external_stop) {
  if (!started_) return 2;
  if (repl_ && !repl_->started()) {
    if (auto r = repl_->start(sequencer_->config_digest()); !r) {
      std::fprintf(stderr, "exchanged: %s\n", r.error().c_str());
      return 2;
    }
  }
  hosted_.clear();
  if (repl_ && split_) {
    seq_side_ = std::make_unique<SeqSide>(*sh_, *sequencer_, *driver_);
    hosted_.push_back(host("seq", *seq_side_, [this] { publish_seq(); }));
    hosted_.push_back(host("repl", *repl_, [this] { publish_repl(); }));
  } else if (repl_) {
    hosted_.push_back(host("seq", *repl_, [this] { publish_seq(); publish_repl(); }));
  } else {
    hosted_.push_back(host("seq", *seq_stage_, [this] { publish_seq(); }));
  }
  hosted_.push_back(host("engine", *engine_stage_, [this] { publish_engine(); }));
  hosted_.push_back(host("io", *io_stage_, [this] { publish_io(); }));
  net_->host_stages(hosted_, *metrics_);
  auto stopping = [&] { return external_stop.load(std::memory_order_acquire) || sh_->stop.load(); };
  auto ready = [&] {
    std::printf("exchanged: ready (%s%s, %s runner, variant %s) %s\n", cfg_.mode == NodeMode::Paired ? "paired" : "solo",
                split_ ? ", replica on its own thread" : "", cfg_.runner == RunnerMode::Threads ? "threads" : "inline",
                cfg_.variant().c_str(), status().c_str());
    std::fflush(stdout);
  };
  if (cfg_.runner == RunnerMode::Threads) {
    rt::LaunchOptions lo;
    lo.idle = rt::IdlePolicy::Backoff;
    launcher_ = std::make_unique<rt::Launcher>(cfg_.cores, lo);
    for (auto& h : hosted_) launcher_->add(h->name, h->ref());
    if (auto r = launcher_->start(); !r) {
      std::fprintf(stderr, "exchanged: %s\n", r.error().c_str());
      return 2;
    }
    if (!wait_net(external_stop)) {
      request_stop(2);
    } else {
      ready();
    }
    while (!stopping()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    launcher_->request_stop();
    launcher_->join();
  } else {
    // Dev mode (01 §7): rt::InlineRunner polls every stage round-robin on this thread,
    // the code path the simulator uses; after a run of idle passes it sleeps briefly.
    struct NoStage {
      bool poll() { return false; }
    } none;
    std::vector<rt::StageRef> r;
    for (auto& h : hosted_) r.push_back(h->ref());
    LLE_ASSERT(r.size() <= 8, "inline runner: more stages than slots");
    while (r.size() < 8) r.push_back(rt::StageRef(none));
    rt::InlineRunner<rt::StageRef, rt::StageRef, rt::StageRef, rt::StageRef, rt::StageRef, rt::StageRef, rt::StageRef,
                     rt::StageRef>
        runner(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    (void)runner.poll_once();  // the network stages open their sockets on this thread
    if (!wait_net(external_stop)) {
      request_stop(2);
    } else {
      ready();
    }
    while (!stopping()) {
      (void)runner.run_until(stopping, 64);
      if (!stopping() && cfg_.idle_sleep_us != 0) std::this_thread::sleep_for(std::chrono::microseconds(cfg_.idle_sleep_us));
    }
  }
  shutdown();
  const int code = sh_->exit_code.load();
  if (code == 0 && cfg_.mode == NodeMode::Paired) clear_restart_record(restart_guard_path());  // a clean stop
  return code;
}

void Node::shutdown() {
  aux_stop_.store(true, std::memory_order_release);
  if (admin_thread_.joinable()) admin_thread_.join();
  if (control_thread_.joinable()) control_thread_.join();
  if (launcher_) {
    launcher_->request_stop();
    launcher_->join();
    launcher_.reset();
  }
  if (io_stage_ && !io_stage_->failed() && started_) {
    io_stage_->drain();  // everything sequenced is made durable; the output log flushed
    started_ = false;
  }
  if (net_) {
    for (const std::string& line : net_->report()) std::printf("%s\n", line.c_str());
    std::fflush(stdout);
  }
  if (nlog_) {
    nlog::unregister_thread();
    nlog_->stop();
    nlog_.reset();
  }
}

}  // namespace lle::exch
