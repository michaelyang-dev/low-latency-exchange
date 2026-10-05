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
  l2_mem_.reset(new std::uint64_t[p_.l2_bytes / 8]());
  std::uint64_t nonce = 0;
  do {
    nonce = rng_.next_u64();
  } while (!journal::usable_nonce(nonce));
  sh_->l2.init(reinterpret_cast<std::byte*>(l2_mem_.get()), p_.l2_bytes, nonce);
  supervisor_ = Supervisor{this};
  n.add_stage(supervisor_, "x-supervisor");

  // ---- Node::open_journal (solo) ------------------------------------------------------
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
  journal::JournalWriterOptions wo;
  wo.day = d_.date;
  writer_ = std::make_unique<SimWriter>(wo);
  if (auto r = ex::resume_journal_writer(*writer_, *dir_, *prep_, rr, p_.spares); !r) {
    fail(r.error());
    return;
  }
  if (recovered_index_ != 0) {
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

  // ---- Node::recover_or_start (solo) --------------------------------------------------
  seq_ring_ = std::make_unique<SimSeqRing>(sh_->l2, nullptr);
  seq::SequencerConfig sc;
  sc.snapshot_every = p_.snapshot_every;
  sc.timer_batch = 64;
  sequencer_ =
      std::make_unique<SimSequencer>(clock_, sh_->ouch, sh_->events, sh_->admin, *seq_ring_, d_.day->timers(), sc);
  driver_ = std::make_unique<SimSeqDriver>(*sh_, clock_, *sequencer_, d_.day->timers(), p_.auto_end);
  {
    ex::OutlogPositions pos = ex::outlog_positions(*outlog_);
    soup_next_ = std::move(pos.soup_next);
    itch_next_ = pos.itch_next;
  }
  if (recovered_index_ == 0) {
    ex::DayStartParams dp;
    dp.date = d_.date;
    dp.local_midnight = d_.local_midnight;
    dp.build_id = ex::kBuildId;
    dp.mold_session = d_.mold_session;
    dp.soup_session = d_.soup_session;
    dp.primary = p_.node_id;
    if (!ex::start_fresh_day(*sequencer_, clock_, dp, d_.day->config())) {
      fail("day start: the L2 ring cannot hold the day's configuration");
      return;
    }
    sh_->sequenced.store(sequencer_->chain().last_index);
  } else {
    ex::continue_day(*sequencer_, clock_, *sh_, recovered_);
    if (hooks_.log) {
      std::string live;
      for (const auto& [session, instance] : recovered_.live)
        live += " " + std::to_string(session) + "/" + std::to_string(instance);
      hooks_.log("exchanged: live instances at the restart:" + live);
    }
  }

  // ---- Node::build_stages (solo) ------------------------------------------------------
  ex::EngineStageConfig ec;
  ec.hash_interval = 0;
  engine_stage_ = std::make_unique<SimEngineStage>(*sh_, *engine_, ec, recovered_index_, clock_);
  if (recovered_index_ != 0) engine_stage_->set_totals(recovered_.itch_total, recovered_.soup_total);
  io_stage_ = std::make_unique<SimIoStage>(*sh_, *dir_, *prep_, *writer_, *outlog_, p_.spares, true, clock_);
  seq_ring_->set_meter(&driver_->meter());
  seq_stage_ = std::make_unique<SimSeqStage>(*driver_);

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

  n.add_stage(*seq_stage_, "x-seq");
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

bool ExchangeProc::settled() const noexcept {
  if (!started_) return false;
  const std::uint64_t idx = sh_->sequenced.load();
  if (sh_->egress_state.applied.load() < idx || sh_->egress_state.release.load() < idx) return false;
  for (std::size_t c = 0; c < md::kConsumers; ++c)
    if (sh_->egress_state.done[c].load() < idx) return false;
  return true;
}

}  // namespace lle::sim::exch
