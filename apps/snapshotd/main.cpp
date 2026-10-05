// snapshotd (06 §9, ADR-007): engine snapshots from the journal, in a process of its own.
//
//   snapshotd --journal DIR --snapshots DIR [--day YYYYMMDD] [--build-id N]
//             [--follow] [--poll-ms N] [--keep N] [--stop-after-index I]
//
// It replays the day's journal (read only) through its own matching engine and, at
// every SnapshotMark record P the sequencer journaled, writes the engine state after
// records 1..P to <snapshots>/<P:020>.snap (snapshot/engine_section.h: S(P), the
// SoupBinTCP next sequence per session, the state hash; published atomically). The
// trading node never pays for a snapshot: it only journals the mark.
//
// Start: from the newest valid snapshot already in the directory (its engine state,
// then the journal after it), so a restarted snapshotd does not replay the whole day.
// --follow keeps tailing the journal as the node writes it. If the journal it follows
// no longer holds the record it last applied (a rejoining node truncated it, 10 §5),
// snapshotd deletes its snapshots above the journal's end and starts again from the
// newest one that remains.
// --keep N: only the newest N snapshots are kept (0: all).
// Next to every snapshot it writes `<P>.snap.out` (out_digest.h): digests of the ITCH
// stream and of each session's OUCH stream up to P, which it regenerates while it
// replays; recovery uses a snapshot only if the node's output log matches them.
// At exit it reports how much of the journal it read (bytes, records, segments,
// directory listings): following never re-reads what it has read.
// Exit status: 0 done (or stopped by a signal), 1 a snapshot could not be written or
// loaded, 2 usage or an unreadable journal.
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "journal/posix_segment_dir.h"
#include "snapshot/engine_section.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshotd/out_digest.h"
#include "snapshotd/snapshotter.h"

namespace {

using namespace lle;

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

// snapshotd's storage: POSIX files, snapshots mapped read-only (snapshotter.h).
struct PosixSnapIo {
  std::expected<journal::PosixSegmentDir, std::string> open_journal(const std::string& path) {
    return journal::PosixSegmentDir::open(path, false, journal::PosixDeviceOptions{.read_only = true});
  }
  std::optional<snap::SnapshotInfo> find_snapshot(const std::string& dir, std::uint64_t max_index) {
    return snap::find_latest(dir, max_index);
  }
  std::expected<snap::MappedSnapshot, snap::LoadError> open_snapshot(const std::string& path) {
    return snap::MappedSnapshot::open(path);
  }
  std::optional<snapd::OutDigests> read_sidecar(const std::string& path) { return snapd::read_sidecar(path); }
  std::expected<std::string, snap::Error> save_engine(const engine::Engine& e, const snap::EngineSnapshotIds& ids,
                                                      const std::string& dir) {
    return snap::save_engine(e, ids, dir);
  }
  bool write_sidecar(const std::string& path, const snapd::OutDigests& d) { return snapd::write_sidecar(path, d); }
  std::vector<std::string> list(const std::string& dir) {
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(dir, ec)) names.push_back(e.path().filename().string());
    return names;
  }
  void remove(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
  }
  void out(const std::string& line) { std::printf("%s\n", line.c_str()); }
  void err(const std::string& line) { std::fprintf(stderr, "%s\n", line.c_str()); }
  void flush() { std::fflush(stdout); }
};

using Snapshotter = snapd::BasicSnapshotter<PosixSnapIo>;

struct Options {
  snapd::SnapshotterOptions s;
  int poll_ms = 20;
};

int usage() {
  std::fprintf(stderr,
               "usage: snapshotd --journal DIR --snapshots DIR [--day YYYYMMDD] [--build-id N] [--follow]\n"
               "                 [--poll-ms N] [--keep N] [--stop-after-index I]\n");
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;
  snapd::SnapshotterOptions& o = opt.s;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    if (a == "--follow") {
      o.follow = true;
      continue;
    }
    const char* v = next();
    if (v == nullptr) return usage();
    if (a == "--journal") o.journal = v;
    else if (a == "--snapshots") o.snapshots = v;
    else if (a == "--day") o.day = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10));
    else if (a == "--build-id") o.build_id = std::strtoull(v, nullptr, 0);
    else if (a == "--poll-ms") opt.poll_ms = std::atoi(v);
    else if (a == "--keep") o.keep = std::strtoull(v, nullptr, 10);
    else if (a == "--stop-after-index") o.stop_after = std::strtoull(v, nullptr, 10);
    else return usage();
  }
  if (o.journal.empty() || o.snapshots.empty() || opt.poll_ms < 1) return usage();
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::error_code ec;
  std::filesystem::create_directories(o.snapshots, ec);
  Snapshotter s(o, PosixSnapIo{});
  if (!s.start(~std::uint64_t{0})) return 1;
  std::printf("snapshotd: following %s\n", o.journal.c_str());
  std::fflush(stdout);
  for (;;) {
    if (!s.pass()) return 1;
    if (o.stop_after != 0 && s.applied() >= o.stop_after) break;
    if (!o.follow || g_stop != 0) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(opt.poll_ms));
  }
  std::printf("snapshotd: applied %" PRIu64 " records, wrote %" PRIu64 " snapshots\n", s.applied(), s.written());
  if (const lle::journal::FollowStats* f = s.follow_stats()) {
    // How the journal was followed (journal/follow_cursor.h): bytes read and listings.
    std::printf("snapshotd: read %" PRIu64 " journal bytes in %" PRIu64 " polls: %" PRIu64 " records, %" PRIu64
                " segments, %" PRIu64 " directory listings, %" PRIu64 " positionings, %" PRIu64 " suspicions%s%s\n",
                f->bytes_read, f->polls, f->records, f->segments, f->listings, f->positions, f->suspicions,
                f->suspicions != 0 ? "; last: " : "", s.follow_last_suspicion().c_str());
  }
  return 0;
}
