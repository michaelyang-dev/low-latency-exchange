#pragma once
// Node startup, recovery steps 4-5 (06 §7, 10 §5), after journal::recover()
// has established the valid journal prefix (steps 1-3, recovery.h):
//
//  4. Load the newest snapshot whose index is <= the last valid journal index
//     and that fully validates (snap::find_latest), restoring the engine from
//     its engine section and checking it against the header (state hash, S(P),
//     session table: snapshot/engine_section.h). A snapshot of another day, or
//     one the engine rejects, is skipped and recovery starts from index 1 on a
//     fresh engine.
//  5. Replay journal records snapshot.index + 1 .. last valid index into the
//     engine with output suppressed: the engine's outputs were derived before
//     the crash and are regenerated on demand (re-requests, ADR-005).
//
// The result carries what the node needs to rejoin: the index reached, S(P)
// (ITCH messages derived so far), the OUCH messages sent per session and the
// engine state hash (compared with the primary when a backup rejoins).
// Rejoin truncation (a backup discarding records past the primary's
// commit point, 10 §5) is the replication layer's step and is not done here.
//
// This header ties the journal, the snapshot container and the engine
// together; it is header-only so lle_journal keeps no link dependency on the
// engine. Users link lle_journal, lle_snapshot_engine (and so lle_engine).
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "journal/recovery.h"
#include "journal/replay.h"
#include "snapshot/engine_section.h"
#include "snapshot/reader.h"

namespace lle::journal {

enum class EngineRecoveryStatus : std::uint8_t {
  Ok,              // the engine holds the state after the last valid record (none: an empty day)
  JournalUnusable, // journal::recover refused (corruption) or failed (I/O); see `journal`
  ReplayGap,       // the replay did not reach the last valid index
};

struct EngineRecovery {
  EngineRecoveryStatus status = EngineRecoveryStatus::Ok;
  RecoveryResult journal;               // steps 1-3
  std::string snapshot_path;            // empty: replayed from index 1
  std::uint64_t snapshot_index = 0;
  bool snapshot_rejected = false;       // a snapshot existed but did not load
  std::string snapshot_detail;          // why it was rejected
  std::uint64_t replayed = 0;           // records applied after the snapshot
  std::uint64_t last_index = 0;         // the state is after this record
  std::uint64_t mold_seq = 0;           // S(P)
  std::uint64_t state_hash = 0;
  std::vector<std::pair<std::uint32_t, std::uint64_t>> session_outputs;  // (session id, OUCH sent)
};

namespace detail {
struct NullEngineSink {
  void itch(std::uint64_t, std::span<const std::byte>) noexcept {}
  void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte>) noexcept {}
  void audit(std::uint64_t, const engine::AuditEvent&) noexcept {}
};
}  // namespace detail

// Recovers `e` from the journal in `dir` and the snapshots in `snap_day_dir`
// (empty: none). `e` is reset first.
template <SegmentDirLike Dir>
EngineRecovery recover_engine(Dir& dir, const std::string& snap_day_dir, engine::Engine& e,
                              const RecoveryOptions& opts = {}) {
  EngineRecovery out;
  (void)e.restore({});  // an empty, reset engine
  out.journal = recover(dir, opts);
  if (!out.journal.usable()) {
    out.status = EngineRecoveryStatus::JournalUnusable;
    return out;
  }
  const std::uint64_t last = out.journal.chain.last_index;
  std::uint64_t from = 1;
  if (!snap_day_dir.empty() && last > 0) {
    if (auto s = snap::find_latest(snap_day_dir, last); s.has_value()) {
      if (out.journal.day != 0 && s->meta.day != out.journal.day) {
        out.snapshot_rejected = true;
        out.snapshot_detail = "snapshot of another day";
      } else if (auto m = snap::MappedSnapshot::open(s->path); !m.has_value()) {
        out.snapshot_rejected = true;
        out.snapshot_detail = std::string(snap::to_string(m.error()));
      } else if (auto ok = snap::load_engine(m->reader(), e); !ok.has_value()) {
        out.snapshot_rejected = true;
        out.snapshot_detail = std::string(snap::to_string(ok.error()));
      } else {
        out.snapshot_path = s->path;
        out.snapshot_index = s->meta.index;
        from = s->meta.index + 1;
      }
    }
  }
  out.last_index = from - 1;
  if (from <= last) {
    struct Sink {
      engine::Engine& e;
      detail::NullEngineSink null;
      std::uint64_t expect;
      bool gap = false;
      bool on_record(const RecordView& r) {
        if (r.index() != expect) {
          gap = true;
          return false;
        }
        ++expect;
        e.apply(engine::to_input(r), null);
        return true;
      }
    } sink{e, {}, from};
    const ReplayStats st = replay(dir, ReplayRange{from, last}, sink, out.journal.day);
    out.replayed = st.records;
    if (st.records > 0) out.last_index = st.last_index;
    if (sink.gap || out.last_index != last) out.status = EngineRecoveryStatus::ReplayGap;
  }
  out.mold_seq = e.itch_count();
  out.state_hash = e.state_hash();
  out.session_outputs = e.session_outputs();
  return out;
}

}  // namespace lle::journal
