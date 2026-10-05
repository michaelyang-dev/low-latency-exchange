#pragma once
// Node start-up steps (node.cpp, 06 §7, §10) generic over storage and clock, so the
// simulator boots and restarts its node exactly as exchanged does. node.cpp calls them
// with its POSIX journal, output log and NodeClock.
//   Clock: env::ClockLike plus mode(), manual(), set_manual() and freeze() (clock.h).
// A paired node restarting mid-day (10 §5) goes through begin_rejoin, the handshake
// (BasicReplStage::poll_prestart, driven by the caller), whose RejoinHooks call
// truncate_journal_to and reload_to, then finish_rejoin. Their storage policy (Io)
// extends recovery_impl.h's:
//   std::uint64_t read_incarnation(path);          1 if absent (write_incarnation's file)
//   bool write_incarnation(path, v);               durable before the witness is asked
//   std::vector<std::uint64_t> remove_snapshots_above(dir, t);  removed snapshot indices
//   void warn(const std::string& line);            operator-visible failure (stderr)
// Cold path.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "common/types.h"
#include "engine/engine.h"
#include "exchanged/config.h"
#include "exchanged/node_log.h"
#include "exchanged/recovery.h"
#include "exchanged/recovery_impl.h"
#include "exchanged/repl_stage.h"
#include "exchanged/shared.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "md/egress.h"
#include "repl/journal_truncate.h"
#include "repl/types.h"
#include "sequencer/sequencer.h"

namespace lle::exch {

// Node::open_writer: the writer continues after the recovered prefix; dirty spare
// segments are recycled and spares prepared so appends never wait for a zero-fill.
template <class WriterT, class DirT, class PreparerT>
std::expected<void, std::string> resume_journal_writer(WriterT& w, DirT& dir, PreparerT& prep,
                                                      const journal::RecoveryResult& rr, std::size_t spares) {
  if (!journal::resume_writer(w, dir, rr)) return std::unexpected(std::string("journal: cannot resume the writer"));
  for (std::size_t h : rr.dirty_spares) {
    auto p = prep.recycle(h);
    if (!p) return std::unexpected(std::string("journal: cannot recycle a dirty spare segment"));
    (void)w.add_prepared(dir.device(p->handle), p->handle, p->header);
  }
  while (w.prepared_count() < spares) {
    auto p = prep.create();
    if (!p) return std::unexpected(std::string("journal: cannot prepare a segment"));
    if (!w.add_prepared(dir.device(p->handle), p->handle, p->header)) break;
  }
  return {};
}

// Per-session SoupBinTCP and MoldUDP64 positions: the output log's counts (recovery
// regenerated it from the journal first).
struct OutlogPositions {
  std::vector<std::pair<std::uint32_t, SeqNo>> soup_next;  // sorted by session id
  SeqNo itch_next = 1;
};
template <class OutDayT>
[[nodiscard]] OutlogPositions outlog_positions(OutDayT& out) {
  OutlogPositions p;
  // Every id in sessions() has a writer (soup() returns null only for an unknown id).
  for (std::uint32_t id : out.sessions())
    if (const auto* w = out.soup(id)) p.soup_next.emplace_back(id, w->count() + 1);
  p.itch_next = out.itch().count() + 1;
  return p;
}

// MdConfig::republish_from: messages recovery regenerated into itch.bin may never have
// been multicast (a solo restart, a RESUME): md sends them first. 0: nothing.
[[nodiscard]] inline SeqNo republish_from(std::uint64_t recovered_index, const RecoveredDay& d,
                                          SeqNo itch_next) noexcept {
  return recovered_index != 0 && d.itch_kept + 1 < itch_next ? d.itch_kept + 1 : 0;
}

struct DayStartParams {
  std::uint32_t date = 0;
  Nanos local_midnight = 0;
  std::uint64_t build_id = 0;
  std::string mold_session;
  std::string soup_session;
  std::uint32_t primary = 0;  // the node of record for the day's first epoch
};

// A fresh day on an empty journal: the day-start records, stamped at local midnight so
// both data nodes of a pair, and a re-run of the day, write identical records (clock.h).
// False if the L2 ring cannot hold the day's configuration.
template <class SequencerT, class ClockT>
bool start_fresh_day(SequencerT& seq, ClockT& clock, const DayStartParams& p,
                     std::span<const seq::ConfigBlob> config) {
  journal::DayStart ds;
  ds.trading_date = p.date;
  ds.local_midnight_ns = p.local_midnight;
  ds.build_id = p.build_id;
  std::fill(ds.mold_session.begin(), ds.mold_session.end(), ' ');
  std::fill(ds.soup_session.begin(), ds.soup_session.end(), ' ');
  std::copy(p.mold_session.begin(), p.mold_session.end(), ds.mold_session.begin());
  std::copy(p.soup_session.begin(), p.soup_session.end(), ds.soup_session.begin());
  clock.freeze(p.local_midnight);
  auto r = seq.start_day(ds, config, 1, p.primary);
  clock.freeze(0);
  return r.has_value();
}

// Solo restart (06 §7): continue the journaled day. The process died with `d.live`
// instances logged in: they are gone (05 §4 step 8), so cancel-on-disconnect sees the
// disconnect through InstanceDown. Those records go first (ADR-032): the connections
// died at the crash, before any Timer that came due while the node was down, so a cross
// that came due meanwhile never executes their cancel-on-disconnect orders. A day that
// already ended only tells egress, in order.
template <class SequencerT, class ClockT>
void continue_day(SequencerT& seq, ClockT& clock, Shared& sh, const RecoveredDay& d) {
  if (d.ended) {
    sh.day_end_index.store(d.day_end_index);
    (void)sh.egress.try_push(d.day_end_index, md::OutKind::DayEnd, 0, {});
  } else {
    seq.resume(d.chain, d.timers, d.next_snapshot_id, d.config_digest);
    if (seq.first_capacity() < seq.first_pending() + d.live.size()) seq.reserve_first(d.live.size());
    for (const auto& [session, instance] : d.live) {
      const bool ok = seq.inject_first(seq::SessionEventMsg{session, instance, journal::SessionEventKind::InstanceDown, 0});
      LLE_ASSERT(ok, "the sequencer's first list was sized for the live instances");
    }
  }
  if (clock.mode() == ClockMode::Manual && d.chain.last_ts > clock.manual()) clock.set_manual(d.chain.last_ts);
  sh.sequenced.store(d.chain.last_index);
}

// ---- Paired restart (10 §5) -------------------------------------------------------------
// What the rejoin steps touch, by reference: Node's members (POSIX), or the simulator's.
template <class DirT, class PreparerT, class LogT, class OutDayT>
struct RejoinParts {
  DirT& dir;                      // the L3 journal
  PreparerT& prep;                // its segment preparer (truncation recycles segments)
  LogT& rlog;                     // the RecordLog (record_log.h)
  Shared& sh;
  engine::Engine& engine;
  OutDayT& out;                   // the output log
  RecoveredDay& recovered;        // the replayed day (reload_to)
  std::uint64_t& recovered_index; // the journal's last index
  std::uint32_t date = 0;
  RecoveryLayout layout;
  std::span<const seq::ConfigBlob> config;  // the configuration file's (ADR-028)
  std::string snapshots_dir;      // snapshots above a truncation point are removed here
  std::string replay_snapshots;   // recovery may start from a snapshot here; empty: never
  std::string incarnation_path;   // <journal dir>/incarnation
};

// A paired node restarting mid-day rejoins (10 §5), also when its journal recovered empty:
// the incarnation file (written at the day start, before the node serves anything) says
// this day already started here, and records it released (held by both L2s, 10 §4) may
// never have reached its journal. Starting the day again would re-sequence it from the day
// start under incarnation 1 while its partner runs the day (DST-006).
[[nodiscard]] inline bool restart_must_rejoin(bool paired, std::uint64_t recovered_index, bool incarnation_exists) noexcept {
  return paired && (recovered_index != 0 || incarnation_exists);
}

struct RejoinStart {
  std::uint64_t incarnation = 0;
  std::uint64_t config_digest = 0;  // the day's, from its EpochStart
};

// Node::rejoin up to the handshake: the record log holds the recovered journal, the
// day's configuration digest is read from its EpochStart, and this process start takes
// the next incarnation (durable before the witness hears of it). The node is then a
// mirror with its lines off until the witness decides (RESUME or rejoin).
template <class Io, class Parts>
std::expected<RejoinStart, std::string> begin_rejoin(Io& io, Parts& p) {
  if (!p.rlog.load(p.recovered_index))
    return std::unexpected(std::string("rejoin: cannot read the recovered journal back"));
  std::uint64_t digest = 0;
  p.rlog.scan(1, [&](const journal::RecordView& v) {
    if (v.type() != journal::RecordType::EpochStart) return true;
    if (const auto e = journal::decode_epoch_start(v)) digest = e->config_digest;
    return false;
  });
  // An empty journal (restart_must_rejoin: the day started here, nothing became durable):
  // the node joins from nothing under its configuration file's digest; the handshake
  // reloads it to 0, output log included.
  if (digest == 0 && p.recovered_index == 0) digest = seq::config_digest(p.config);
  if (digest == 0)
    return std::unexpected(std::string("rejoin: the journal holds an incomplete day start (no EpochStart); move "
                                       "its segment files (*.seg) aside, keeping the incarnation file, to join "
                                       "from an empty journal"));
  const std::uint64_t inc = io.read_incarnation(p.incarnation_path) + 1;
  if (!io.write_incarnation(p.incarnation_path, inc))
    return std::unexpected("rejoin: cannot record incarnation in " + p.incarnation_path);
  p.sh.sequenced.store(p.recovered_index);
  p.sh.durable.store(p.recovered_index);
  p.sh.mirror.store(true);
  p.sh.lines.store(0);
  return RejoinStart{inc, digest};
}

// RejoinHooks::truncate: the journal (L3) and the record log end at index t (10 §5
// step 2). Runs before any stage, so nothing else touches the journal.
template <class Io, class Parts>
bool truncate_journal_to(Io& io, Parts& p, std::uint64_t t) {
  const repl::TruncateResult r = repl::truncate_journal(p.dir, p.prep, p.date, t);
  if (!r.ok) {
    io.warn("exchanged: rejoin: journal truncation to " + std::to_string(t) + " failed: " + r.detail);
    return false;
  }
  if (!p.rlog.load(t)) return false;
  p.recovered_index = t;
  p.sh.durable.store(t);
  p.sh.sequenced.store(t);
  io.note("exchanged: rejoin: journal truncated to " + std::to_string(t) + " (" + std::to_string(r.recycled) +
          " segments recycled)");
  nodelog::rejoin_truncated(t, r.recycled);
  return true;
}

// RejoinHooks::reload: the engine and the output log from records 1..t (10 §5 step 3);
// snapshots above t describe records that are gone.
template <class Io, class Parts>
ReloadResult reload_to(Io& io, Parts& p, std::uint64_t t) {
  ReloadResult out;
  journal::RecoveryOptions again;
  again.day = p.date;
  again.repair = false;
  const journal::RecoveryResult rr = journal::recover(p.dir, again);
  if (rr.chain.last_index != t) {
    io.warn("exchanged: rejoin: reload to " + std::to_string(t) + " but the journal ends at " +
            std::to_string(rr.chain.last_index));
    return out;
  }
  if (t == 0) {
    (void)p.engine.restore({});
    if (auto r = basic_reset_outlog(io, p.out, p.layout); !r) {
      io.warn("exchanged: rejoin: " + r.error());
      return out;
    }
    p.recovered = RecoveredDay{};
  } else {
    for (const std::uint64_t i : io.remove_snapshots_above(p.snapshots_dir, t))
      io.note("exchanged: rejoin: snapshot at " + std::to_string(i) + " above the truncation point removed");
    auto day = basic_replay_day(io, p.dir, rr, p.engine, p.out, p.layout, p.config, p.replay_snapshots);
    if (!day) {
      io.warn("exchanged: rejoin: " + day.error());
      return out;
    }
    p.recovered = std::move(*day);
  }
  io.note("exchanged: rejoin: engine reloaded to " + std::to_string(t) + "; output log: " +
          std::to_string(p.recovered.outlog_verified) + " verified, " + std::to_string(p.recovered.outlog_appended) +
          " regenerated, " + std::to_string(p.recovered.outlog_rewritten) + " files rewritten");
  nodelog::replayed(t, p.recovered.outlog_verified, p.recovered.outlog_appended);
  out.ok = true;
  out.timers = p.recovered.timers;
  out.next_snapshot_id = p.recovered.next_snapshot_id;
  out.config_digest = p.recovered.config_digest;
  return out;
}

// The hooks a rejoining node hands to BasicReplStage::start_recovering. `io` and `p`
// must outlive the handshake.
template <class Io, class Parts>
RejoinHooks rejoin_hooks(Io& io, Parts& p) {
  RejoinHooks h;
  h.truncate = [&io, &p](std::uint64_t t) { return truncate_journal_to(io, p, t); };
  h.reload = [&io, &p](std::uint64_t t) { return reload_to(io, p, t); };
  return h;
}

// Node::rejoin after the handshake: the replica goes live and the writer continues where
// the journal now ends (the truncation point, plus after RESUME the new epoch's
// EpochStart in L2). The solo primary of record (RESUME) lost its own instances: the
// replication stage hands their InstanceDowns to the sequencer's first list (ADR-032).
// A day that already ended only tells egress, in order. `open_writer(rr)` is Node::open_writer
// (-> std::expected<void, std::string>). Returns the role the handshake ended in.
template <class Parts, class ReplT, class ClockT, class OpenWriter>
std::expected<repl::Role, std::string> finish_rejoin(Parts& p, ReplT& repl, ClockT& clock, OpenWriter&& open_writer) {
  repl.go_live();
  journal::RecoveryOptions ro;
  ro.day = p.date;
  const journal::RecoveryResult rr = journal::recover(p.dir, ro);
  if (!rr.usable()) return std::unexpected("rejoin: journal recovery after truncation refused: " + rr.detail);
  if (auto r = open_writer(rr); !r) return std::unexpected(r.error());
  p.recovered_index = rr.chain.last_index;
  p.sh.durable.store(p.recovered_index);
  p.sh.sequenced.store(p.rlog.tail().last_index);
  if (clock.mode() == ClockMode::Manual && p.recovered.chain.last_ts > clock.manual())
    clock.set_manual(p.recovered.chain.last_ts);
  const auto role = static_cast<repl::Role>(p.sh.role.load());
  if (role == repl::Role::kSoloPrimary) {
    // RESUME: the solo primary of record restarted; its own instances are gone. They go
    // down first after the new epoch's EpochStart, before any overdue Timer (ADR-032).
    for (const auto& [session, instance] : p.recovered.live) repl.queue_instance_down(session, instance);
  }
  if (p.recovered.ended) {
    p.sh.day_end_index.store(p.recovered.day_end_index);
    (void)p.sh.egress.try_push(p.recovered.day_end_index, md::OutKind::DayEnd, 0, {});
  }
  return role;
}

}  // namespace lle::exch
