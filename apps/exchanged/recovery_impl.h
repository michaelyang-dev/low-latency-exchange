#pragma once
// Recovery (recovery.h) generic over its storage, so the simulator runs the production
// recovery on its disk (09 S-03). recovery.cpp instantiates it for POSIX files
// (PosixRecoveryIo, below; node.cpp's rejoin extends it); behaviour and messages are
// those of the node.
//
//   Dir     journal segment directory (journal::SegmentDirLike: journal::replay)
//   OutDay  output-log day (outlog::BasicOutlogDay<Fs>)
//   Io      the rest of the storage recovery touches:
//             using Reader = ...;                      outlog::BasicOutlogReader<Fs>
//             std::unique_ptr<Reader> make_reader();   a closed reader
//             bool truncate_outlog(path, SeqNo keep);  outlog::truncate_to
//             std::optional<snap::SnapshotInfo> find_snapshot(dir, max_index);
//             open_snapshot(path) -> std::expected<S, snap::LoadError>, S::reader()
//             std::optional<snapd::OutDigests> read_sidecar(path);
//             void note(const std::string& line);      operator-visible progress (stdout)
// Cold path.
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/types.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "exchanged/node_log.h"
#include "exchanged/recovery.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/replay.h"
#include "log/nlog.h"
#include "outlog/day.h"
#include "outlog/format.h"
#include "outlog/reader.h"
#include "outlog/repair.h"
#include "sequencer/sequencer.h"
#include "snapshot/engine_section.h"
#include "snapshot/reader.h"
#include "snapshotd/out_digest.h"

namespace lle::exch {

namespace recovery_detail {

template <class OutDay, class Reader>
struct Stream {
  typename OutDay::Writer* w = nullptr;
  std::string path;
  SeqNo existing = 0;  // messages the file held before this pass
  SeqNo pos = 0;       // messages regenerated so far
  SeqNo diverged = 0;  // first sequence that differs (0: none)
  std::unique_ptr<Reader> rd;
};

template <class OutDay, class Reader>
struct Streams {
  Stream<OutDay, Reader> itch;
  std::vector<std::uint32_t> ids;  // sorted, parallel to soup
  std::vector<Stream<OutDay, Reader>> soup;
};

template <class Io, class OutDay>
std::expected<Streams<OutDay, typename Io::Reader>, std::string> open_streams(Io& io, OutDay& out,
                                                                             const RecoveryLayout& L) {
  using St = Stream<OutDay, typename Io::Reader>;
  Streams<OutDay, typename Io::Reader> s;
  s.itch.w = &out.itch();
  s.itch.path = outlog::OutlogDayPaths::itch_path(L.outlog_root, L.date);
  for (std::uint32_t id : out.sessions()) {
    St st;
    st.w = out.soup(id);
    st.path = outlog::OutlogDayPaths::soup_path(L.outlog_root, L.date, id);
    s.ids.push_back(id);
    s.soup.push_back(std::move(st));
  }
  auto init = [&io](St& st) -> std::expected<void, std::string> {
    st.existing = st.w->count();
    if (st.existing != 0) {
      st.rd = io.make_reader();
      if (auto r = st.rd->open(st.path); !r) return std::unexpected("output log " + st.path + ": " + r.error());
    }
    return {};
  };
  if (auto r = init(s.itch); !r) return std::unexpected(r.error());
  for (St& st : s.soup)
    if (auto r = init(st); !r) return std::unexpected(r.error());
  return s;
}

// Verifies the regenerated output against the output log as found and appends what
// follows its end, or, with `defer` (a rejoin's reload), keeps what follows its end in
// RecoveredDay::deferred for egress to release (DST-013).
template <class OutDay, class Reader>
class RegenSink {
 public:
  RegenSink(Streams<OutDay, Reader>& s, RecoveredDay& d, bool defer = false)
      : s_(&s), d_(&d), defer_(defer), scratch_(std::make_unique<std::byte[]>(outlog::kMaxMessageBytes)) {}
  void itch(std::uint64_t idx, std::span<const std::byte> b) {
    ++d_->itch_total;
    put(s_->itch, b, idx, md::OutKind::Itch, 0);
  }
  void ouch(std::uint64_t idx, std::uint32_t session, std::span<const std::byte> b) {
    ++d_->soup_total;
    const auto it = std::lower_bound(s_->ids.begin(), s_->ids.end(), session);
    if (it == s_->ids.end() || *it != session) return;
    put(s_->soup[static_cast<std::size_t>(it - s_->ids.begin())], b, idx, md::OutKind::Ouch, session);
  }
  void audit(std::uint64_t, const engine::AuditEvent&) {}
  [[nodiscard]] bool failed() const noexcept { return failed_; }

 private:
  void put(Stream<OutDay, Reader>& st, std::span<const std::byte> b, std::uint64_t idx, md::OutKind kind,
           std::uint32_t session) {
    ++st.pos;
    if (st.diverged != 0) return;
    if (st.pos <= st.existing) {
      const auto r = st.rd->read(st.pos, std::span<std::byte>(scratch_.get(), outlog::kMaxMessageBytes));
      if (r && r->size() == b.size() && std::equal(r->begin(), r->end(), b.begin())) {
        ++d_->outlog_verified;
      } else {
        st.diverged = st.pos;
      }
      return;
    }
    if (defer_) {
      d_->deferred.push_back(RecoveredDay::DeferredOutput{idx, kind, session, std::vector<std::byte>(b.begin(), b.end())});
      ++d_->outlog_deferred;
      return;
    }
    if (!st.w->append(b)) failed_ = true;
    ++d_->outlog_appended;
  }

  Streams<OutDay, Reader>* s_;
  RecoveredDay* d_;
  bool defer_;
  std::unique_ptr<std::byte[]> scratch_;
  bool failed_ = false;
};

template <class Regen>
struct ReplaySink {
  engine::Engine* eng;
  Regen* regen;
  RecoveredDay* day;
  std::uint64_t expect = 1;
  bool gap = false;
  bool observe = true;
  std::uint64_t apply_from = 1;  // records below it are in the snapshot: observed, not applied
  std::map<std::pair<std::uint32_t, std::uint16_t>, bool>* live;
  std::vector<std::pair<journal::ConfigTable, std::vector<std::byte>>>* tables;
  std::vector<std::byte> pending;

  bool on_record(const journal::RecordView& r) {
    if (r.index() != expect) {
      gap = true;
      return false;
    }
    ++expect;
    if (observe) note(r);
    if (r.index() >= apply_from) eng->apply(engine::to_input(r), *regen);
    day->chain = journal::ChainState{r.index(), r.content(), r.ts_ns(), r.epoch()};
    return true;
  }

  void note(const journal::RecordView& r) {
    switch (r.type()) {
      case journal::RecordType::Config:
        if (const auto c = journal::decode_config(r)) {
          if (c->chunk_index == 0) pending.clear();
          pending.insert(pending.end(), c->bytes.begin(), c->bytes.end());
          if (c->chunk_index + 1 == c->chunk_count) tables->emplace_back(c->table, pending);
        }
        break;
      case journal::RecordType::EpochStart:
        if (const auto e = journal::decode_epoch_start(r)) {
          day->started = true;
          day->config_digest = e->config_digest;
          day->epoch = e->epoch;
        }
        break;
      case journal::RecordType::Timer: ++day->timers; break;
      case journal::RecordType::SnapshotMark:
        if (const auto m = journal::decode_snapshot_mark(r)) day->next_snapshot_id = m->snapshot_id + 1;
        break;
      case journal::RecordType::DayEnd:
        day->ended = true;
        day->day_end_index = r.index();
        break;
      case journal::RecordType::SessionEvent:
        if (const auto e = journal::decode_session_event(r)) {
          const bool up = e->event == journal::SessionEventKind::Login || e->event == journal::SessionEventKind::MirrorAttach;
          (*live)[{e->session_id, e->instance}] = up;
        }
        break;
      default: break;
    }
  }
};

// The engine from the newest usable snapshot at or below `last` (nullopt: none).
struct SnapStart {
  std::uint64_t index = 0;
  std::uint64_t mold_seq = 0;                           // S(P)
  std::vector<std::pair<std::uint32_t, SeqNo>> next;    // SoupBinTCP next sequence per session
  std::string path;
  std::uint64_t rejected = 0;                           // newer snapshots not used
};

// The first `count` messages of an output-log file, digested as snapshotd digests the
// stream it regenerates (out_digest.h). nullopt: the file holds fewer.
template <class Io>
std::optional<snapd::StreamDigest> digest_prefix(Io& io, const std::string& path, std::uint64_t count) {
  snapd::StreamDigest d;
  if (count == 0) return d;
  const auto rd = io.make_reader();
  if (!rd->open(path)) return std::nullopt;
  while (d.count < count) {
    const std::size_t n = rd->for_each(d.count + 1, std::min<std::uint64_t>(count - d.count, 65'536),
                                       [&](SeqNo, std::span<const std::byte> m) { d.add(m); });
    if (n == 0) return std::nullopt;
  }
  return d;
}

// Why the snapshot's outputs cannot be trusted, or empty if the output log matches them.
template <class Io, class OutDay>
std::string check_outputs(Io& io, const snap::SnapshotInfo& s, const snap::Reader& r, const snapd::OutDigests* d,
                          OutDay& out, const RecoveryLayout& L) {
  if (d == nullptr || d->index != s.meta.index) return "no output digests";
  if (d->itch.count != s.meta.mold_seq) return "output digests disagree with S(P)";
  const auto itch = digest_prefix(io, outlog::OutlogDayPaths::itch_path(L.outlog_root, L.date), d->itch.count);
  if (!itch || !(*itch == d->itch)) return "itch.bin differs from the snapshot's digest below S(P)";
  for (const snap::SessionSeq& q : r.sessions()) {
    const snapd::StreamDigest* want = d->find(q.session_id);
    const std::uint64_t n = q.next_seq - 1;
    if ((want == nullptr && n != 0) || (want != nullptr && want->count != n))
      return "output digests disagree with session " + std::to_string(q.session_id);
    if (n == 0) continue;
    if (out.soup(q.session_id) == nullptr) return "no output log for session " + std::to_string(q.session_id);
    const auto got = digest_prefix(io, outlog::OutlogDayPaths::soup_path(L.outlog_root, L.date, q.session_id), n);
    if (!got || !(*got == *want))
      return "session " + std::to_string(q.session_id) + " output log differs from the snapshot's digest";
  }
  return {};
}

template <class Io, class OutDay>
std::optional<SnapStart> load_snapshot(Io& io, const std::string& dir, std::uint64_t last, engine::Engine& eng,
                                       OutDay& out, const RecoveryLayout& L) {
  if (dir.empty()) return std::nullopt;
  std::uint64_t rejected = 0;
  for (std::uint64_t max = last; max != 0;) {
    const auto s = io.find_snapshot(dir, max);
    if (!s) break;
    max = s->meta.index - 1;
    auto loaded = io.open_snapshot(s->path);
    if (!loaded) continue;
    // The output log up to the snapshot is not regenerated: it must match what snapshotd
    // regenerated (a torn record keeps its length but not its bytes, ADR-029).
    const auto d = io.read_sidecar(snapd::sidecar_path(s->path));
    const std::string why = check_outputs(io, *s, loaded->reader(), d ? &*d : nullptr, out, L);
    if (!why.empty()) {
      ++rejected;
      NLOG_WARN("recovery: snapshot at {} not used: {}", s->meta.index, std::string_view(why));
      io.note("exchanged: recovery: snapshot at " + std::to_string(s->meta.index) + " not used: " + why);
      continue;
    }
    if (const auto ok = snap::load_engine(loaded->reader(), eng); !ok) {
      ++rejected;
      NLOG_ERROR("recovery: snapshot at {} not loaded: {}", s->meta.index,
                 std::string_view(snap::to_string(ok.error())));
      (void)eng.restore({});
      continue;
    }
    SnapStart st;
    for (const snap::SessionSeq& q : loaded->reader().sessions()) st.next.emplace_back(q.session_id, q.next_seq);
    st.index = s->meta.index;
    st.mold_seq = s->meta.mold_seq;
    st.path = s->path;
    st.rejected = rejected;
    return st;
  }
  if (rejected != 0) io.note("exchanged: recovery: no usable snapshot; replaying the whole day");
  return std::nullopt;
}

}  // namespace recovery_detail

// reset_outlog() (recovery.h) on any storage.
template <class Io, class OutDay>
std::expected<void, std::string> basic_reset_outlog(Io& io, OutDay& out, const RecoveryLayout& L) {
  std::vector<std::string> paths{outlog::OutlogDayPaths::itch_path(L.outlog_root, L.date)};
  for (std::uint32_t id : L.session_ids) paths.push_back(outlog::OutlogDayPaths::soup_path(L.outlog_root, L.date, id));
  (void)out.close();
  for (const std::string& p : paths) {
    if (!io.truncate_outlog(p, 0)) return std::unexpected("output log " + p + ": cannot cut back to 0");
  }
  return out.open(L.outlog_root, L.date, L.session_ids);
}

// replay_day() (recovery.h) on any storage. `snapshot_dir` empty: no snapshot is used.
template <class Io, class Dir, class OutDay>
std::expected<RecoveredDay, std::string> basic_replay_day(Io& io, Dir& dir, const journal::RecoveryResult& rr,
                                                          engine::Engine& eng, OutDay& out, const RecoveryLayout& L,
                                                          std::span<const seq::ConfigBlob> expected_config,
                                                          const std::string& snapshot_dir, bool defer_unlogged = false) {
  using namespace recovery_detail;
  using Reader = typename Io::Reader;
  const std::uint64_t last = rr.chain.last_index;
  std::uint64_t rewritten = 0;
  std::uint64_t first_verified = 0, first_appended = 0;  // pass 0's counts (pass 1 re-verifies them)
  std::uint64_t itch_kept = 0;  // pass 0: the verified prefix of itch.bin as found
  for (int pass = 0; pass < 2; ++pass) {
    RecoveredDay day;
    day.outlog_rewritten = rewritten;
    auto streams = open_streams(io, out, L);
    if (!streams) return std::unexpected(streams.error());
    std::map<std::pair<std::uint32_t, std::uint16_t>, bool> live;
    std::vector<std::pair<journal::ConfigTable, std::vector<std::byte>>> tables;
    RegenSink<OutDay, Reader> regen(*streams, day, defer_unlogged);
    (void)eng.restore({});  // an empty, reset engine
    const std::optional<SnapStart> snap = load_snapshot(io, snapshot_dir, last, eng, out, L);
    std::uint64_t apply_from = 1;
    if (snap) {
      // Outputs up to the snapshot are not regenerated: the streams start after them.
      apply_from = snap->index + 1;
      streams->itch.pos = snap->mold_seq;
      day.itch_total = snap->mold_seq;
      for (const auto& [id, next] : snap->next) {
        day.soup_total += next - 1;
        const auto it = std::lower_bound(streams->ids.begin(), streams->ids.end(), id);
        if (it != streams->ids.end() && *it == id) streams->soup[static_cast<std::size_t>(it - streams->ids.begin())].pos = next - 1;
      }
      day.snapshot_index = snap->index;
    }
    ReplaySink<RegenSink<OutDay, Reader>> sink{&eng, &regen, &day, 1, false, true, apply_from, &live, &tables, {}};
    const journal::ReplayStats st = journal::replay(dir, journal::ReplayRange{1, last}, sink, rr.day);
    if (sink.gap || st.last_index != last)
      return std::unexpected("journal replay stopped at " + std::to_string(st.last_index) + " of " + std::to_string(last));
    if (regen.failed()) return std::unexpected(std::string("output log: append failed during regeneration"));
    // ADR-028: the journal is the day's configuration.
    bool same = tables.size() == expected_config.size();
    for (std::size_t i = 0; same && i < tables.size(); ++i) {
      same = tables[i].first == expected_config[i].table && tables[i].second.size() == expected_config[i].bytes.size() &&
             std::equal(tables[i].second.begin(), tables[i].second.end(), expected_config[i].bytes.begin());
    }
    if (!same) {
      return std::unexpected(
          std::string("the journaled configuration differs from the configuration file (ADR-028): restore the file "
                      "the day was started with"));
    }
    if (!day.started)
      return std::unexpected(std::string("the journal holds an incomplete day start (no EpochStart): nothing was "
                                         "released; move the journal directory aside and start the day again"));
    for (const auto& [k, up] : live)
      if (up) day.live.push_back(k);
    if (pass == 0) {
      const auto& it = streams->itch;
      itch_kept = it.diverged != 0 ? it.diverged - 1 : std::min(it.existing, it.pos);
    }
    day.state_hash = eng.state_hash();
    day.itch_kept = itch_kept;
    // Files that differ from the regeneration are cut back and rewritten (second pass).
    std::vector<std::pair<std::string, SeqNo>> cuts;
    auto check = [&](const Stream<OutDay, Reader>& s) {
      if (s.diverged != 0) cuts.emplace_back(s.path, s.diverged - 1);
      else if (s.pos < s.existing) cuts.emplace_back(s.path, s.pos);  // longer than the regeneration
    };
    check(streams->itch);
    for (const auto& s : streams->soup) check(s);
    if (cuts.empty()) {
      if (auto r = out.flush_all(); !r) return std::unexpected(std::string("output log flush failed"));
      if (pass == 1) {
        // Report what the files held and what was written, over both passes.
        day.outlog_appended += first_appended;
        day.outlog_verified = first_verified;
      }
      return day;
    }
    if (pass == 1) return std::unexpected(std::string("output log still differs after regeneration"));
    first_verified = day.outlog_verified;
    first_appended = day.outlog_appended;
    nodelog::outlog_rewrite(cuts.size());
    streams->itch.rd.reset();
    for (auto& s : streams->soup) s.rd.reset();
    (void)out.close();
    for (const auto& [path, keep] : cuts) {
      if (!io.truncate_outlog(path, keep))
        return std::unexpected("output log " + path + ": cannot cut back to " + std::to_string(keep));
    }
    if (auto r = out.open(L.outlog_root, L.date, L.session_ids); !r) return std::unexpected(r.error());
    rewritten = cuts.size();
  }
  return std::unexpected(std::string("unreachable"));
}

// The node's own storage: POSIX files, snapshots mapped read-only.
struct PosixRecoveryIo {
  using Reader = outlog::OutlogReader;
  std::unique_ptr<Reader> make_reader() { return std::make_unique<Reader>(); }
  bool truncate_outlog(const std::string& path, SeqNo keep) { return outlog::truncate_to(path, keep).has_value(); }
  std::optional<snap::SnapshotInfo> find_snapshot(const std::string& dir, std::uint64_t max_index) {
    return snap::find_latest(dir, max_index);
  }
  std::expected<snap::MappedSnapshot, snap::LoadError> open_snapshot(const std::string& path) {
    return snap::MappedSnapshot::open(path);
  }
  std::optional<snapd::OutDigests> read_sidecar(const std::string& path) { return snapd::read_sidecar(path); }
  void note(const std::string& line) { std::printf("%s\n", line.c_str()); }
};

}  // namespace lle::exch
