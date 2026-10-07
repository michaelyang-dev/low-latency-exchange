#pragma once
// snapshotd's follower (main.cpp, 06 §9, ADR-007) generic over its storage, so the
// simulator runs the production follower on its disk (09 S-03). main.cpp instantiates
// it for POSIX files (PosixSnapIo); behaviour and messages are those of snapshotd.
//
//   Io:
//     open_journal(path) -> std::expected<Dir, std::string>   read-only journal directory
//                                                           (journal::SegmentDirLike)
//     find_snapshot(dir, max_index) -> std::optional<snap::SnapshotInfo>
//     open_snapshot(path) -> std::expected<S, snap::LoadError>, S::reader()
//     read_sidecar(path) -> std::optional<OutDigests>
//     save_engine(engine, ids, dir) -> std::expected<std::string, snap::Error>   published atomically
//     write_sidecar(path, digests) -> bool                 published atomically
//     list(dir) -> std::vector<std::string>                file names in `dir`
//     remove(path)                                         a missing file is not an error
//     out(line), err(line), flush()                        stdout / stderr
//
// The journal is followed with a journal::FollowCursor (journal/follow_cursor.h) over
// io.open_journal: it keeps its place between passes, so a pass reads only what was
// appended since the previous one (and lists the directory only when idle at the tail).
// The cursor holds a pointer to this object: a snapshotter is not moved once it has run
// a pass.
// Cold path (housekeeping cores).
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "journal/follow_cursor.h"
#include "journal/record.h"
#include "journal/replay.h"
#include "snapshot/engine_section.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshotd/out_digest.h"

namespace lle::snapd {

struct SnapshotterOptions {
  std::string journal;
  std::string snapshots;
  std::uint32_t day = 0;
  std::uint64_t build_id = 0;
  bool follow = false;
  std::size_t keep = 0;
  std::uint64_t stop_after = 0;  // tests: stop once this index is applied
};

// The engine's outputs, folded into the digests the snapshots carry.
struct DigestSink {
  OutDigests* d;
  void itch(std::uint64_t, std::span<const std::byte> m) { d->itch.add(m); }
  void ouch(std::uint64_t, std::uint32_t session, std::span<const std::byte> m) { d->session(session).add(m); }
  void audit(std::uint64_t, const engine::AuditEvent&) {}
};

template <class Io>
class BasicSnapshotter {
 public:
  BasicSnapshotter(SnapshotterOptions o, Io io) : o_(std::move(o)), io_(std::move(io)) {}

  // From the newest valid snapshot at or below `max_index` (or the start of the day).
  bool start(std::uint64_t max_index) {
    (void)engine_.restore({});  // an empty engine
    last_ = journal::ChainState{};
    resume_crc_.reset();
    cursor_.reset();  // the next pass follows from the new position
    digests_ = OutDigests{};
    // The newest snapshot whose output digests are there too (they continue from it).
    std::optional<snap::SnapshotInfo> s;
    std::optional<OutDigests> d;
    // ... and whose record P is still the journal's (a rejoin can truncate the history a
    // snapshot describes and write other records at the same indices): a snapshot of a
    // record that is gone is removed.
    for (std::uint64_t max = max_index; max != 0;) {
      s = io_.find_snapshot(o_.snapshots, max);
      if (!s) break;
      d = io_.read_sidecar(sidecar_path(s->path));
      if (d && d->index == s->meta.index) {
        if (!d->record_crc || journal_holds(s->meta.index, *d->record_crc) != Held::kNo) break;
        io_.out(std::format("snapshotd: {}: the journal no longer holds its record {} (a rejoin truncation): removed",
                            s->path, s->meta.index));
        io_.remove(sidecar_path(s->path));
        io_.remove(s->path);
      } else {
        io_.out(std::format("snapshotd: {} has no output digests: not continued from", s->path));
      }
      max = s->meta.index - 1;
      s.reset();
    }
    if (!s) {
      io_.out(std::format("snapshotd: no snapshot at or below {}: replaying from the start of the day", max_index));
      return true;
    }
    auto loaded = io_.open_snapshot(s->path);
    if (!loaded) {
      io_.err(std::format("snapshotd: {}: {}", s->path, snap::to_string(loaded.error())));
      return false;
    }
    if (const auto ok = snap::load_engine(loaded->reader(), engine_); !ok) {
      io_.err(std::format("snapshotd: {}: engine section: {}", s->path, snap::to_string(ok.error())));
      return false;
    }
    last_.last_index = s->meta.index;
    resume_crc_ = d->record_crc;
    digests_ = *d;
    io_.out(std::format("snapshotd: continuing from {} (index {})", s->path, s->meta.index));
    return true;
  }

  // One pass over what the journal holds now beyond the record applied last. False on
  // an error that ends the process. Following, a pass reads what is there now; a
  // one-shot run (not following) reads to the journal's end. If the journal no longer
  // holds the history applied (a rejoin truncated it, 10 §5), snapshots above its end
  // are dropped and the snapshotter starts again from the newest one that remains.
  bool pass() {
    if (!cursor_) {
      journal::FollowOptions fo;
      fo.day = o_.day;
      cursor_.emplace(JournalOpener{this}, fo);
      // From a snapshot: the cursor checks that record P is still the one it describes
      // (a truncation after start() shows as a divergence).
      cursor_->seek(last_.last_index + 1, resume_crc_);
    }
    ok_ = true;
    for (int spins = 0;; ++spins) {
      const journal::FollowStatus st = cursor_->poll([this](const journal::RecordView& r) { return apply(r); });
      switch (st) {
        case journal::FollowStatus::Records: continue;
        case journal::FollowStatus::Idle:
          // A one-shot run goes on until the cursor has seen the whole journal.
          if (!o_.follow && !cursor_->settled() && spins < 100'000) continue;
          return ok_;
        case journal::FollowStatus::Stopped: return ok_;
        case journal::FollowStatus::Diverged: return start_over();
        case journal::FollowStatus::NoJournal:
          if (!o_.follow) io_.err(std::format("snapshotd: {}", cursor_->detail()));
          return o_.follow;  // following: the directory may not exist yet
        case journal::FollowStatus::IoError:
          io_.err(std::format("snapshotd: journal read error ({}): reading it again", cursor_->detail()));
          return o_.follow;
      }
    }
  }

  [[nodiscard]] std::uint64_t applied() const noexcept { return last_.last_index; }
  [[nodiscard]] std::uint64_t written() const noexcept { return written_; }
  [[nodiscard]] const engine::Engine& engine() const noexcept { return engine_; }
  [[nodiscard]] Io& io() noexcept { return io_; }
  // The follower's reading (null before the first pass).
  [[nodiscard]] const journal::FollowStats* follow_stats() const noexcept {
    return cursor_ ? &cursor_->stats() : nullptr;
  }
  [[nodiscard]] std::string follow_last_suspicion() const { return cursor_ ? cursor_->last_suspicion() : std::string(); }

 private:
  // A fresh read-only listing of the journal directory, for the cursor.
  struct JournalOpener {
    using Listing = decltype(std::declval<Io&>().open_journal(std::declval<const std::string&>()));
    BasicSnapshotter* s;
    Listing operator()() const { return s->io_.open_journal(s->o_.journal); }
  };
  using Cursor = journal::FollowCursor<JournalOpener>;

  // One record, in order (the cursor checked its place in the chain).
  bool apply(const journal::RecordView& r) {
    DigestSink n{&digests_};
    engine_.apply(engine::to_input(r), n);
    last_ = journal::ChainState{r.index(), r.crc(), r.ts_ns(), r.epoch()};
    if (r.type() == journal::RecordType::SnapshotMark) {
      if (const auto m = journal::decode_snapshot_mark(r)) ok_ = write(r, m->snapshot_id);
      if (!ok_) return false;
    }
    return !(o_.stop_after != 0 && r.index() >= o_.stop_after);
  }

  bool write(const journal::RecordView& r, std::uint64_t snapshot_id) {
    const snap::EngineSnapshotIds ids{o_.day, r.epoch(), r.index(), snapshot_id, o_.build_id};
    const auto path = io_.save_engine(engine_, ids, o_.snapshots);
    if (!path) {
      io_.err(std::format("snapshotd: snapshot at {} failed: {}", r.index(), snap::to_string(path.error())));
      return false;
    }
    digests_.index = r.index();
    digests_.record_crc = r.content();  // the content crc (the header's crc field is sealed per medium)
    if (!io_.write_sidecar(sidecar_path(*path), digests_)) {
      io_.err(std::format("snapshotd: output digests for {} failed", *path));
      return false;
    }
    ++written_;
    io_.out(std::format("snapshotd: snapshot {} at index {} (S(P) {}, state hash {:016x}): {}", snapshot_id, r.index(),
                        engine_.itch_count(), engine_.state_hash(), *path));
    io_.flush();
    prune();
    return true;
  }

  [[nodiscard]] std::string in_dir(const std::string& name) const {
    return o_.snapshots.empty() || o_.snapshots.back() == '/' ? o_.snapshots + name : o_.snapshots + "/" + name;
  }

  // The newest `keep` snapshots stay.
  void prune() {
    if (o_.keep == 0) return;
    std::vector<std::uint64_t> idx;
    for (const std::string& name : io_.list(o_.snapshots)) {
      if (const auto i = snap::parse_snapshot_file_name(name)) idx.push_back(*i);
    }
    std::sort(idx.begin(), idx.end());
    for (std::size_t k = 0; k + o_.keep < idx.size(); ++k) {
      const std::string p = in_dir(snap::snapshot_file_name(idx[k]));
      io_.remove(sidecar_path(p));
      io_.remove(p);
    }
  }

  // Whether the journal's record `index` has content crc `crc` (kUnknown: the journal
  // cannot be read now; the cursor checks again when it walks the record).
  enum class Held : std::uint8_t { kYes, kNo, kUnknown };
  Held journal_holds(std::uint64_t index, std::uint32_t crc) {
    auto dir = io_.open_journal(o_.journal);
    if (!dir) return Held::kUnknown;
    struct One {
      std::uint64_t want;
      std::optional<std::uint32_t> crc;
      bool on_record(const journal::RecordView& r) {
        if (r.index() == want) crc = r.content();
        return r.index() < want;
      }
    } one{index, std::nullopt};
    (void)journal::replay(*dir, journal::ReplayRange{index, index}, one, o_.day);
    return one.crc && *one.crc == crc ? Held::kYes : Held::kNo;
  }

  template <class Dir>
  std::uint64_t journal_tail(Dir& dir) {
    struct Tail {
      std::uint64_t last = 0;
      bool on_record(const journal::RecordView& r) {
        last = r.index();
        return true;
      }
    } t;
    (void)journal::replay(dir, journal::ReplayRange{1, ~std::uint64_t{0}}, t, o_.day);
    return t.last;
  }

  // The journal no longer holds the history snapshotd applied: snapshots above its end
  // describe records that are gone; start again from the newest one at or below it.
  bool start_over() {
    auto dir = io_.open_journal(o_.journal);
    if (!dir) {
      cursor_.reset();  // cannot read it now: the next pass looks again
      return true;
    }
    const std::uint64_t tail = journal_tail(*dir);
    io_.out(std::format("snapshotd: the journal (now ending at {}) no longer holds record {} as applied (a rejoin "
                        "truncation): dropping snapshots above {}",
                        tail, last_.last_index, tail));
    for (const std::string& name : io_.list(o_.snapshots)) {
      if (const auto i = snap::parse_snapshot_file_name(name); i && *i > tail) {
        const std::string p = in_dir(name);
        io_.remove(sidecar_path(p));
        io_.remove(p);
      }
    }
    return start(tail);
  }

  SnapshotterOptions o_;
  Io io_;
  engine::Engine engine_;
  journal::ChainState last_{};
  std::optional<std::uint32_t> resume_crc_;  // record P's crc when continuing from a snapshot
  OutDigests digests_;
  std::optional<Cursor> cursor_;
  bool ok_ = true;
  std::uint64_t written_ = 0;
};

}  // namespace lle::snapd
