#include "sim/exchange/exchange_node.h"

#include <algorithm>
#include <format>

#include "exchanged/node.h"
#include "exchanged/recovery_impl.h"
#include "exchanged/start_impl.h"
#include "journal/recovery.h"
#include "outlog/reader_impl.h"
#include "outlog/writer_impl.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/soupbin/soupbin.h"

// The output log's writers and readers on the simulated disk.
template class lle::outlog::BasicOutlogWriter<lle::sim::exch::SimNodeOutlogFs>;
template class lle::outlog::BasicOutlogReader<lle::sim::exch::SimNodeOutlogFs>;
template class lle::outlog::BasicOutlogReader<lle::sim::exch::SimBoundOutlogFs>;

namespace lle::sim::exch {

namespace ex = lle::exch;

std::expected<void, std::string> ExchangeDay::build() {
  day =
      std::make_unique<seq::EngineDay>(seq::EngineTables{symbols, accounts, sessions, risk, schedule}, local_midnight);
  auto t = gw::SessionTable::build(specs, md::kGateways);
  if (!t) return std::unexpected("sessions: " + t.error());
  table = std::move(*t);
  return {};
}

std::vector<std::uint32_t> ExchangeDay::session_ids() const {
  std::vector<std::uint32_t> ids;
  for (const auto& s : sessions) ids.push_back(s.session_id);
  std::sort(ids.begin(), ids.end());
  return ids;
}

std::string NodeParams::journal_prefix(std::uint32_t date) const { return std::format("{}journal/{:08}/", root, date); }
std::string NodeParams::outlog_root() const { return root + "outlog"; }
std::string NodeParams::snapshots_dir(std::uint32_t date) const { return std::format("{}snapshots/{:08}", root, date); }

ExchangeProc::ExchangeProc(Node& n, const ExchangeDay& day, const NodeParams& p, NodeHooks hooks)
    : node_(n), d_(day), p_(p), hooks_(std::move(hooks)), rng_(n.rng(0xE7C4)), clock_(n.clock()) {
  NodeBinding bind(n, eph_);  // the stages' sockets and output-log readers bind to this node
  snaps_ = std::make_unique<SimSnapStorage>(n);
  sh_ = std::make_unique<ex::Shared>();
  sh_->egress.init(p_.egress_bytes);
  sh_->apply_limit.store(~std::uint64_t{0});
  // Node::open_journal's L2: in a file that may outlive the previous image (06 §5), or
  // anonymous memory.
  std::uint64_t nonce = 0;
  auto draw_nonce = [&] {
    do {
      nonce = rng_.next_u64();
    } while (!journal::usable_nonce(nonce));
  };
  std::byte* l2 = nullptr;
  if (p_.l2_file) {
    L2File& f = *p_.l2_file;
    l2_reopened_ = f.mem && f.bytes == p_.l2_bytes && f.host_crashes == n.host_crashes();
    if (!l2_reopened_) {
      f.mem.reset(new std::uint64_t[p_.l2_bytes / 8]());
      f.bytes = p_.l2_bytes;
      draw_nonce();
      f.nonce = nonce;
      f.host_crashes = n.host_crashes();
    }
    nonce = f.nonce;
    l2 = reinterpret_cast<std::byte*>(f.mem.get());
  } else {
    l2_mem_.reset(new std::uint64_t[p_.l2_bytes / 8]());
    draw_nonce();
    l2 = reinterpret_cast<std::byte*>(l2_mem_.get());
  }
  sh_->l2.init(l2, p_.l2_bytes, nonce);
  if (p_.paired) {
    sh_->mirror.store(p_.node_id != p_.initial_primary);
    sh_->lines.store(p_.node_id == p_.initial_primary ? md::kLineA : md::kLineB);
  }
  supervisor_ = Supervisor{this};
  n.add_stage(supervisor_, "x-supervisor");
  rejoin_io_.st = snaps_.get();
  rejoin_io_.node = &n;
  rejoin_io_.note_fn = hooks_.log;

  open_journal();
  if (!boot_error_.empty()) return;
  recover_or_start();
  if (!boot_error_.empty() || rejoin_) return;  // a rejoin builds its stages after the handshake
  finish_boot();
}

// ---- Node::open_journal ---------------------------------------------------------------
void ExchangeProc::open_journal() {
  Node& n = node_;
  const std::vector<std::uint32_t> ids = d_.session_ids();
  dir_ = std::make_unique<worlds::SimSegmentDir>(n, p_.journal_prefix(d_.date), hooks_.durable);
  prep_ = std::make_unique<SimPreparer>(*dir_, rng_, d_.date, p_.segment_bytes);
  journal::RecoveryOptions ro;
  ro.day = d_.date;
  journal::RecoveryResult rr = journal::recover(*dir_, ro);
  if (!rr.usable() || (rr.torn_tail && !rr.repaired)) {
    fail("journal recovery refused (06 §7): " + rr.detail);
    return;
  }
  recovered_index_ = rr.chain.last_index;
  outlog_ = std::make_unique<SimOutDay>(SimNodeOutlogFs(n));
  if (auto r = outlog_->open(p_.outlog_root(), d_.date, ids); !r) {
    fail("output log: " + r.error());
    return;
  }
  engine_ = std::make_unique<engine::Engine>();
  if (l2_reopened_) {
    if (!restore_l2(rr)) return;
    recovered_index_ = rr.chain.last_index;
  }
  // A paired node restarting mid-day rejoins (10 §5): the writer opens after the
  // handshake, which may truncate the journal first. Node::open_journal's decision,
  // including a restart on an empty journal of a day this node already started.
  rejoin_ = ex::restart_must_rejoin(p_.paired, recovered_index_,
                                    n.disk().exists(p_.journal_prefix(d_.date) + "incarnation"));
  if (!rejoin_) {
    if (auto r = open_writer(rr); !r) {
      fail(r.error());
      return;
    }
  }
  if (recovered_index_ != 0 && !rejoin_) {
    journal::RecoveryOptions again;
    again.day = d_.date;
    again.repair = false;
    const journal::RecoveryResult rr2 = journal::recover(*dir_, again);
    SimRecoveryIo io;
    io.st = snaps_.get();
    io.node = &n;
    io.note_fn = hooks_.log;
    const ex::RecoveryLayout layout{p_.outlog_root(), d_.date, ids};
    auto rd = ex::basic_replay_day(io, *dir_, rr2, *engine_, *outlog_, layout, d_.day->config(),
                                   p_.use_snapshots ? p_.snapshots_dir(d_.date) : std::string());
    if (!rd) {
      fail("recovery: " + rd.error());
      return;
    }
    recovered_ = std::move(*rd);
    if (hooks_.recovered) hooks_.recovered(recovered_);
  }
}

// Node::restore_l2 (06 §5): the previous image's L2 may hold records beyond L3, e.g. ones
// a backup acknowledged. They are journaled now, before anything else reads the journal;
// then the ring starts over (its bytes stay: only a chain from durable + 1 validates).
// The writer's drain runs inside this event, its I/O applied at once (the directory's
// at-once mode), as it spins inside start-up in production.
bool ExchangeProc::restore_l2(journal::RecoveryResult& rr) {
  const std::optional<std::uint32_t> prev =
      rr.chain.last_index == 0 ? std::nullopt : std::optional<std::uint32_t>(rr.chain.last_crc);
  const journal::L2RestoreResult res = sh_->l2.restore(rr.chain.last_index + 1, prev);
  if (res.found && res.records != 0) {
    if (auto r = open_writer(rr); !r) {
      fail(r.error());
      return false;
    }
    dir_->set_at_once(true);
    bool ok = false;
    {
      SimIoStage io(*sh_, *dir_, *prep_, *writer_, *outlog_, p_.spares, false, clock_);
      io.drain();
      ok = !io.failed() && writer_->durable_index() == res.chain.last_index;
    }
    dir_->set_at_once(false);
    if (!ok) {
      fail("L2: journaling the restored records failed at " + std::to_string(writer_->durable_index()) + " of " +
           std::to_string(res.chain.last_index));
      return false;
    }
    writer_.reset();
    journal::RecoveryOptions ro;
    ro.day = d_.date;
    rr = journal::recover(*dir_, ro);
    if (!rr.usable() || rr.chain.last_index != res.chain.last_index) {
      fail("L2: recovery after journaling the restored records: " + rr.detail);
      return false;
    }
    if (hooks_.log)
      hooks_.log(std::format("exchanged: L2: restored {} records ({}..{}) into the journal", res.records,
                             res.chain.last_index - res.records + 1, res.chain.last_index));
    if (hooks_.l2_restored) hooks_.l2_restored(res.records, res.chain.last_index);
  }
  sh_->l2.init(reinterpret_cast<std::byte*>(p_.l2_file->mem.get()), p_.l2_bytes, p_.l2_file->nonce);
  sh_->durable.store(rr.chain.last_index);
  return true;
}

// Node::open_writer: the writer continues after the recovered prefix.
std::expected<void, std::string> ExchangeProc::open_writer(const journal::RecoveryResult& rr) {
  journal::JournalWriterOptions wo;
  wo.day = d_.date;
  writer_ = std::make_unique<SimWriter>(wo);
  return ex::resume_journal_writer(*writer_, *dir_, *prep_, rr, p_.spares);
}

// ---- Node::recover_or_start -----------------------------------------------------------
void ExchangeProc::recover_or_start() {
  if (p_.paired) {
    rlog_ = std::make_unique<SimRecordLog>(p_.repl_log_bytes, p_.repl_log_bytes / 64, p_.journal_prefix(d_.date),
                                           d_.date, SimL3Opener{&node_}, &hooks_.held);
  }
  // Node::open: in split mode the sequencer's records reach the record log through a tee.
  if (split()) {
    sh_->split.tee_mem.reset(new std::uint64_t[p_.tee_bytes / 8]());
    sh_->split.tee.init(reinterpret_cast<std::byte*>(sh_->split.tee_mem.get()), p_.tee_bytes);
  }
  seq_ring_ = std::make_unique<SimSeqRing>(sh_->l2, rlog_.get(), split() ? &sh_->split.tee : nullptr);
  seq::SequencerConfig sc;
  sc.snapshot_every = p_.snapshot_every;
  sc.timer_batch = 64;
  sequencer_ =
      std::make_unique<SimSequencer>(clock_, sh_->ouch, sh_->events, sh_->admin, *seq_ring_, d_.day->timers(), sc);
  driver_ = std::make_unique<SimSeqDriver>(*sh_, clock_, *sequencer_, d_.day->timers(), p_.auto_end);
  if (rejoin_) {
    begin_rejoin();
    return;
  }
  {
    ex::OutlogPositions pos = ex::outlog_positions(*outlog_);
    soup_next_ = std::move(pos.soup_next);
    itch_next_ = pos.itch_next;
  }
  if (recovered_index_ == 0) {
    if (rlog_) rlog_->reset(journal::ChainState{});
    ex::DayStartParams dp;
    dp.date = d_.date;
    dp.local_midnight = d_.local_midnight;
    dp.build_id = ex::kBuildId;
    dp.mold_session = d_.mold_session;
    dp.soup_session = d_.soup_session;
    dp.primary = p_.paired ? p_.initial_primary : p_.node_id;
    if (!ex::start_fresh_day(*sequencer_, clock_, dp, d_.day->config())) {
      fail("day start: the L2 ring cannot hold the day's configuration");
      return;
    }
    sh_->sequenced.store(sequencer_->chain().last_index);
    if (p_.paired) (void)rejoin_io_.write_incarnation(p_.journal_prefix(d_.date) + "incarnation", 1);
  } else {
    ex::continue_day(*sequencer_, clock_, *sh_, recovered_);
    if (hooks_.log) {
      std::string live;
      for (const auto& [session, instance] : recovered_.live)
        live += " " + std::to_string(session) + "/" + std::to_string(instance);
      hooks_.log("exchanged: live instances at the restart:" + live);
    }
  }
}

ex::ReplStageConfig ExchangeProc::repl_config(std::uint64_t incarnation, std::uint64_t digest) const {
  ex::ReplStageConfig rc;
  rc.repl.self = static_cast<repl::NodeId>(p_.node_id);
  rc.repl.incarnation = incarnation;
  rc.repl.build_id = ex::kBuildId;
  rc.repl.config_digest = digest;
  rc.repl.heartbeat_ns = p_.ha_heartbeat;
  rc.repl.t_d = p_.t_d;
  rc.repl.t_ack = p_.t_ack;
  rc.repl.rejoin_retry_ns = p_.rejoin_retry;
  rc.repl.rto_ns = p_.ha_rto;
  rc.bind = p_.ha_bind;
  rc.peer = p_.ha_peer;
  rc.witness = p_.witness;
  rc.initial_primary = static_cast<repl::NodeId>(p_.initial_primary);
  rc.peer_incarnation = 1;
  for (const auto& s : d_.sessions) rc.sessions.push_back(s.session_id);
  return rc;
}

// ---- Node::rejoin (10 §5) ------------------------------------------------------------
// RECOVERING with a new incarnation; the handshake runs as the image's only stage (with
// the supervisor) until the engine is reloaded, then the stages are built.
void ExchangeProc::begin_rejoin() {
  rejoin_parts_ = std::make_unique<SimRejoinParts>(SimRejoinParts{
      .dir = *dir_,
      .prep = *prep_,
      .rlog = *rlog_,
      .sh = *sh_,
      .engine = *engine_,
      .out = *outlog_,
      .recovered = recovered_,
      .recovered_index = recovered_index_,
      .date = d_.date,
      .layout = ex::RecoveryLayout{p_.outlog_root(), d_.date, d_.session_ids()},
      .config = d_.day->config(),
      .snapshots_dir = p_.snapshots_dir(d_.date),
      .replay_snapshots = p_.use_snapshots ? p_.snapshots_dir(d_.date) : std::string(),
      .incarnation_path = p_.journal_prefix(d_.date) + "incarnation"});
  const auto begun = ex::begin_rejoin(rejoin_io_, *rejoin_parts_);
  if (!begun) {
    fail(begun.error());
    return;
  }
  repl_ = std::make_unique<SimReplStage>(*sh_, clock_, *sequencer_, *driver_, *rlog_,
                                         repl_config(begun->incarnation, begun->config_digest), metrics_, split());
  if (auto r = repl_->start_recovering(begun->config_digest, ex::rejoin_hooks(rejoin_io_, *rejoin_parts_)); !r) {
    fail(r.error());
    return;
  }
  if (hooks_.log)
    hooks_.log(std::format("exchanged: rejoin: incarnation {}, journal at {}", begun->incarnation, recovered_index_));
  if (hooks_.rejoining) hooks_.rejoining(begun->incarnation);
  rejoin_from_ = recovered_index_;
  node_.add_stage(repl_host_, "x-seq");
}

void ExchangeProc::complete_rejoin() {
  NodeBinding bind(node_, eph_);
  rejoined_ = true;
  const auto role = ex::finish_rejoin(*rejoin_parts_, *repl_, clock_,
                                      [this](const journal::RecoveryResult& rr) { return open_writer(rr); });
  if (!role) {
    fail(role.error());
    return;
  }
  {
    ex::OutlogPositions pos = ex::outlog_positions(*outlog_);
    soup_next_ = std::move(pos.soup_next);
    itch_next_ = pos.itch_next;
  }
  if (hooks_.log) {
    hooks_.log(std::format("exchanged: rejoin: {} {}",
                           *role == repl::Role::kSoloPrimary ? "resumed as the solo primary at" : "catching up from",
                           recovered_index_));
  }
  if (hooks_.rejoined) hooks_.rejoined(*role, recovered_index_, rejoin_from_);
  finish_boot();
}

bool ExchangeProc::seq_side_poll() {
  if (exited_ || stopping_) return false;
  try {
    return seq_side_->poll();
  } catch (const ProcessExit& e) {
    exit_process(e.code);
    return true;
  }
}

bool ExchangeProc::repl_poll() {
  if (exited_ || stopping_) return false;
  try {
    if (rejoin_ && !rejoined_) {
      const bool did = repl_->poll_prestart();
      note_alarms();
      if (!repl_->handshake_done()) return did;
      complete_rejoin();
      return true;
    }
    const bool did = repl_->poll();
    note_alarms();
    return did;
  } catch (const ProcessExit& e) {
    note_alarms();
    exit_process(e.code);
    return true;
  }
}

// The replica's ALARMs (10 §3: an nlog ERROR and the repl_alarms metric in production).
void ExchangeProc::note_alarms() {
  if (!repl_ || repl_->alarms() == alarms_seen_) return;
  const auto [a, detail] = repl_->last_alarm();
  const std::uint64_t n = repl_->alarms() - alarms_seen_;
  alarms_seen_ = repl_->alarms();
  if (hooks_.alarm) hooks_.alarm(a, detail, n);
}

void ExchangeProc::exit_process(int code) {
  exited_ = true;
  if (hooks_.exited) hooks_.exited(code);
  node_.request_crash();
}

std::uint64_t ExchangeProc::RejoinIo::read_incarnation(const std::string& path) {
  const auto b = st->read_all(path);
  if (!b) return 1;
  std::uint64_t v = 0;
  bool digits = false;
  for (const std::byte c : *b) {
    const char ch = static_cast<char>(c);
    if (ch < '0' || ch > '9') break;
    v = v * 10 + static_cast<std::uint64_t>(ch - '0');
    digits = true;
  }
  return !digits || v == 0 ? 1 : v;  // a day started before incarnations were recorded
}

// As node.cpp's write_incarnation: temp file, sync, rename, directory sync.
bool ExchangeProc::RejoinIo::write_incarnation(const std::string& path, std::uint64_t v) {
  const std::string text = std::to_string(v) + "\n";
  const std::string tmp = path + ".tmp";
  const int h = st->create(tmp);
  if (h < 0) return false;
  const bool ok = st->write_at(h, 0, std::as_bytes(std::span<const char>(text.data(), text.size()))) == 0 &&
                  st->sync(h, false) == 0;
  (void)st->close(h);
  if (!ok || st->rename(tmp, path) != 0) return false;
  const std::size_t slash = path.rfind('/');
  return st->sync_dir(slash == std::string::npos ? std::string(".") : path.substr(0, slash)) == 0;
}

std::vector<std::uint64_t> ExchangeProc::RejoinIo::remove_snapshots_above(const std::string& dir, std::uint64_t t) {
  std::vector<std::uint64_t> removed;
  for (const std::string& name : st->list(dir)) {
    if (const auto i = snap::parse_snapshot_file_name(name); i && *i > t) {
      (void)st->remove(dir + "/" + name);
      removed.push_back(*i);
    }
  }
  return removed;
}

// ---- Node::build_stages, Node::start_net, Node::run's hosting ---------------------------
void ExchangeProc::finish_boot() {
  Node& n = node_;
  NodeBinding bind(n, eph_);
  const bool paired = p_.paired;
  ex::EngineStageConfig ec;
  ec.hash_interval = paired ? p_.hash_interval : 0;
  engine_stage_ = std::make_unique<SimEngineStage>(*sh_, *engine_, ec, recovered_index_, clock_);
  if (recovered_index_ != 0) engine_stage_->set_totals(recovered_.itch_total, recovered_.soup_total);
  // Node::build_stages: a rejoin's reloaded outputs still to release (DST-013).
  engine_stage_->stage_deferred(recovered_.deferred);
  recovered_.deferred = {};
  io_stage_ = std::make_unique<SimIoStage>(*sh_, *dir_, *prep_, *writer_, *outlog_, p_.spares, !paired, clock_);
  seq_ring_->set_meter(&driver_->meter());
  if (paired) {
    if (!repl_) {
      repl_ = std::make_unique<SimReplStage>(*sh_, clock_, *sequencer_, *driver_, *rlog_,
                                             repl_config(1, sequencer_->config_digest()), metrics_, split());
    }
  } else {
    seq_stage_ = std::make_unique<SimSeqStage>(*driver_);
  }

  // ---- Node::start_net ------------------------------------------------------------------
  tap_ouch_ = TapOuchQueue{&sh_->ouch, &hooks_.taps};
  tap_events_ = TapSessionQueue{&sh_->events, &hooks_.taps};
  for (std::uint8_t i = 0; i < md::kGateways; ++i) {
    gw::GatewayConfig gc;
    gc.index = i;
    gc.instance = p_.node_id;
    gc.soup.session = soup::SessionId::from(d_.soup_session);
    gc.soup.heartbeat_interval = p_.soup_heartbeat;
    gc.soup.idle_timeout = p_.soup_idle_timeout;
    gc.soup.login_timeout = p_.soup_login_timeout;
    gc.close_linger = p_.close_linger;
    gc.tcp.max_conns = p_.max_conns;
    gc.tcp.max_reads_per_poll = 4;
    gc.listen = p_.gw[i];
    gc.replay_ring_messages = p_.replay_ring_msgs;
    gc.replay_ring_bytes = p_.replay_ring_bytes;
    gc.outlog_root = p_.outlog_root();
    gc.day = d_.date;
    gw_[i] = std::make_unique<SimGateway>(gc, d_.table, soup_next_, tap_ouch_, tap_events_, clock_,
                                          gw::GatewayShared{&sh_->egress, &sh_->egress_state, &sh_->mirror});
  }
  md::MdConfig mc;
  mc.session = mold::Session(d_.mold_session);
  mc.line_a = p_.line_a;
  mc.line_b = p_.line_b;
  mc.max_packet_a = p_.max_packet_a;
  mc.max_packet_b = p_.max_packet_b;
  mc.heartbeat_interval = p_.md_heartbeat;
  mc.end_of_session_linger = p_.md_eos_linger;
  mc.line_udp.dst_addr = false;
  mc.rerequest_udp.bind = env::Endpoint{n.ip(), p_.rerequest_port};
  mc.rerequest_udp.dst_addr = false;
  mc.ring_messages = p_.md_ring_messages;
  mc.ring_bytes = p_.md_ring_bytes;
  mc.itch_log_path = outlog::OutlogDayPaths::itch_path(p_.outlog_root(), d_.date);
  mc.first_seq = itch_next_;
  mc.republish_from = ex::republish_from(recovered_index_, recovered_, itch_next_);
  md_ = std::make_unique<SimMd>(mc, clock_, md::MdShared{&sh_->egress, &sh_->egress_state, &sh_->lines});
  if (p_.glimpse_port != 0) {
    md::GlimpseConfig glc;
    glc.soup.session = soup::SessionId::from(d_.soup_session);
    glc.soup.heartbeat_interval = p_.soup_heartbeat;
    glc.soup.idle_timeout = p_.soup_idle_timeout;
    glc.close_linger = p_.close_linger;
    glc.tcp.max_conns = 16;
    glc.listen = env::Endpoint{n.ip(), p_.glimpse_port};
    glc.itch_log_path = mc.itch_log_path;
    glc.user = p_.glimpse_user;
    glc.credential = p_.glimpse_credential;
    glc.locates = d_.symbols.size();
    glimpse_ = std::make_unique<SimGlimpse>(glc, clock_);
  }
  for (auto& g : gw_) {
    if (auto r = g->start(); !r) {
      fail(r.error());
      return;
    }
  }
  if (auto r = md_->start(); !r) {
    fail(r.error());
    return;
  }
  if (glimpse_) {
    if (auto r = glimpse_->start(); !r) {
      fail(r.error());
      return;
    }
  }

  // Node::run: a paired day's replica starts paired once the stages exist; the seq
  // stage is the ReplStage (no repl_thread), registered first on a rejoin. In split mode
  // the ReplStage is the repl thread and BasicSeqSide the seq thread.
  if (repl_ && !repl_->started()) {
    if (auto r = repl_->start(sequencer_->config_digest()); !r) {
      fail(r.error());
      return;
    }
  }
  if (paired) {
    if (!rejoin_) n.add_stage(repl_host_, split() ? "x-repl" : "x-seq");
    if (split()) {
      seq_side_ = std::make_unique<SimSeqSide>(*sh_, *sequencer_, *driver_);
      n.add_stage(seq_side_host_, "x-seq");
    }
  } else {
    n.add_stage(*seq_stage_, "x-seq");
  }
  n.add_stage(*engine_stage_, "x-engine");
  n.add_stage(*io_stage_, "x-io");
  n.add_stage(*gw_[0], "x-gw0");
  n.add_stage(*gw_[1], "x-gw1");
  n.add_stage(*md_, "x-md");
  if (glimpse_) n.add_stage(*glimpse_, "x-glimpse");
  if (p_.follower) {
    start_follower();
    n.add_stage(follower_stage_, "x-snapshotd");
  }
  started_ = true;
  if (hooks_.log) {
    hooks_.log(std::format("exchanged: {} at index {} (itch next {}, republish from {})",
                           recovered_index_ == 0 ? "day started" : "recovered", sequencer_->chain().last_index,
                           itch_next_, mc.republish_from));
  }
}

ExchangeProc::~ExchangeProc() = default;

void ExchangeProc::fail(std::string why) {
  boot_error_ = std::move(why);
  if (hooks_.boot_failed) hooks_.boot_failed(boot_error_);
  node_.request_crash();  // exchanged exits non-zero; the supervisor restarts it
}

bool ExchangeProc::supervise() {
  if (stopping_ || !sh_->stop.load()) return false;
  // Node::run: a stage stopped the node (io: a failed journal write is never retried).
  stopping_ = true;
  if (hooks_.stopped) hooks_.stopped(sh_->exit_code.load());
  node_.request_crash();
  return true;
}

void ExchangeProc::start_follower() {
  snapd::SnapshotterOptions so;
  so.journal = p_.journal_prefix(d_.date);
  so.snapshots = p_.snapshots_dir(d_.date);
  so.day = d_.date;
  so.build_id = ex::kBuildId;
  so.follow = true;
  so.keep = p_.follower_keep;
  SimSnapIo io;
  io.st = snaps_.get();
  io.node = &node_;
  io.out_fn = hooks_.log;
  io.written_fn = hooks_.snapshot_written;
  follower_ = std::make_unique<SimSnapshotter>(so, std::move(io));
  follower_failed_ = !follower_->start(~std::uint64_t{0});
}

bool ExchangeProc::follow() {
  const Nanos now = node_.clock().now_mono();
  if (now < next_follow_) return false;
  next_follow_ = now + p_.follower_poll;
  if (follower_failed_) {
    // snapshotd exited (exit 1: a snapshot could not be written or loaded); its own
    // supervisor starts it again.
    start_follower();
    return true;
  }
  if (!follower_->pass()) follower_failed_ = true;
  return true;
}

SnapshotdProc::SnapshotdProc(Node& self, Node& host, const ExchangeDay& day, const NodeParams& p, NodeHooks hooks)
    : self_(self), host_(host), date_(day.date), p_(p), hooks_(std::move(hooks)) {
  st_ = std::make_unique<SimSnapStorage>(host_);
  start();
  self_.add_stage(stage_, "snapshotd");
}

SnapshotdProc::~SnapshotdProc() = default;

void SnapshotdProc::start() {
  snapd::SnapshotterOptions so;
  so.journal = p_.journal_prefix(date_);
  so.snapshots = p_.snapshots_dir(date_);
  so.day = date_;
  so.build_id = ex::kBuildId;
  so.follow = true;
  so.keep = p_.follower_keep;
  SimSnapIo io;
  io.st = st_.get();
  io.node = &host_;
  io.out_fn = hooks_.log;
  io.written_fn = hooks_.snapshot_written;
  snap_ = std::make_unique<SimSnapshotter>(so, std::move(io));
  failed_ = !snap_->start(~std::uint64_t{0});
}

bool SnapshotdProc::poll() {
  const Nanos now = self_.clock().now_mono();
  if (now < next_) return false;
  next_ = now + p_.follower_poll;
  if (failed_) {
    // snapshotd exited (exit 1: a snapshot could not be written or loaded); its
    // supervisor starts it again.
    start();
    return true;
  }
  if (!snap_->pass()) failed_ = true;
  return true;
}

bool ExchangeProc::settled() const noexcept {
  if (!started_) return false;
  const std::uint64_t idx = sh_->sequenced.load();
  if (sh_->egress_state.applied.load() < idx || sh_->egress_state.release.load() < idx) return false;
  for (std::size_t c = 0; c < md::kConsumers; ++c)
    if (sh_->egress_state.done[c].load() < idx) return false;
  return true;
}

}  // namespace lle::sim::exch
