// snapshot world (06 §9; 09 §2): the production snapshot writer and loader
// (src/snapshot: Writer in storage mode, LoadedSnapshot, find_latest) on the
// simulated disk through SimSnapStorage, under EIO, stalls, process and host
// crashes (lost, torn and out-of-order persisted unsynced writes) and, on half
// the seeds, the fault atlas's corruption classes: a snapshot is derived data
// (the state replays from an older snapshot and the journal), so the loader
// must reject a corrupted one and fall back.
//
// A snapshotd process writes snapshots one after another, each over several
// polls (so crashes land mid-write), and commits it: write temp -> fdatasync ->
// rename -> fsync(dir). The harness records every commit that returned success.
// Every start, and a final power cut, loads the latest snapshot.
//
// Oracles:
//   O-SNAP-VISIBLE  a snapshot the loader finds is complete and validated and
//                   carries exactly the payload written for its index (no
//                   partially written or torn snapshot is ever visible)
//   O-SNAP-DURABLE  a snapshot whose commit succeeded is never lost: the
//                   loader finds it or a newer one (without the corruption atlas)
//   O-LIVE          after healing, the target number of snapshots is committed
//
// Directory operations are durable at once in the simulator (dst.md), so this
// world checks the data side of atomic publication: data durable before the
// name appears.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/hash.h"
#include "env/buggify.h"
#include "sim/dist.h"
#include "sim/node.h"
#include "sim/worlds/worlds.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshot/storage.h"
#include "snapshot/writer.h"

namespace lle::sim::worlds::detail {

namespace {

constexpr char kDir[] = "snap/20261002";

// snap::Storage over the simulated disk: synchronous I/O applied at once
// (write_now / sync_now, with the disk's EIO draws), names in a flat namespace.
class SimSnapStorage final : public snap::Storage {
 public:
  explicit SimSnapStorage(Node& node) : disk_(&node.disk()) {}

  int create(const std::string& path) override {
    const std::uint32_t f = disk_->open(path);
    disk_->resize(f, 0);
    handles_.push_back(f);
    return static_cast<int>(handles_.size() - 1);
  }
  int write_at(int h, std::uint64_t off, std::span<const std::byte> data) override {
    return disk_->write_now(file(h), off, data, false) < 0 ? EIO : 0;
  }
  int sync(int h, bool) override { return disk_->sync_now(file(h)) < 0 ? EIO : 0; }
  int close(int) override { return 0; }
  int rename(const std::string& from, const std::string& to) override { return disk_->rename(from, to) ? 0 : ENOENT; }
  int sync_dir(const std::string&) override { return 0; }  // directory operations are durable at once
  int remove(const std::string& path) override { return disk_->remove(path) ? 0 : ENOENT; }
  std::vector<std::string> list(const std::string& dir) override {
    std::vector<std::string> out;
    const std::string prefix = dir + "/";
    for (const std::string& n : disk_->list()) {
      if (n.starts_with(prefix)) out.push_back(n.substr(prefix.size()));
    }
    return out;
  }
  std::expected<std::vector<std::byte>, int> read_all(const std::string& path) override {
    if (!disk_->exists(path)) return std::unexpected(ENOENT);
    const std::uint32_t f = disk_->open(path);
    std::vector<std::byte> out(static_cast<std::size_t>(disk_->size(f)));
    if (disk_->read(f, 0, out) != out.size()) return std::unexpected(EIO);
    return out;
  }

 private:
  std::uint32_t file(int h) const { return handles_[static_cast<std::size_t>(h)]; }
  Disk* disk_;
  std::vector<std::uint32_t> handles_;
};

std::uint64_t payload_len(std::uint64_t seed, std::uint64_t index) noexcept {
  const std::uint64_t h = mix64(seed ^ (index * 0x9E3779B97F4A7C15ull));
  return (h & 7) == 0 ? (h >> 8) % 400'000 : (h >> 8) % 40'000;
}
std::byte payload_byte(std::uint64_t seed, std::uint64_t index, std::uint64_t i) noexcept {
  return static_cast<std::byte>(mix64(seed ^ (index << 40) ^ (i >> 3)) >> (8 * (i & 7)));
}

struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_visible = 0, o_durable = 0;
  std::uint64_t seed = 0;
  bool verbose = false;
  bool corruption = false;
  std::uint64_t target = 0;
  std::uint64_t next_index = 1;      // durable counter of snapshot indices
  std::uint64_t last_committed = 0;  // newest index whose commit() succeeded
  std::uint64_t committed = 0, failed_commits = 0, loads = 0, fallbacks = 0;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  // Loads the latest snapshot as recovery would and checks it.
  void check_load(SimSnapStorage& st, const char* when) {
    ++loads;
    const std::optional<snap::SnapshotInfo> info = snap::find_latest(st, kDir, ~std::uint64_t{0});
    const std::uint64_t found = info ? info->meta.index : 0;
    log("%s: latest snapshot %llu (committed %llu)", when, static_cast<unsigned long long>(found),
        static_cast<unsigned long long>(last_committed));
    if (info) {
      auto s = snap::LoadedSnapshot::open(st, info->path);
      if (!s) {
        o->fail(o_visible, std::string(when) + ": find_latest returned snapshot " + std::to_string(found) +
                               " that does not load");
        return;
      }
      snap::Reader& r = s->reader();
      const std::uint64_t n = payload_len(seed, found);
      bool same = r.remaining() == n;
      std::vector<std::byte> buf(4096);
      for (std::uint64_t i = 0; same && i < n;) {
        const std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), n - i));
        if (!r.read(std::span<std::byte>(buf.data(), take))) {
          same = false;
          break;
        }
        for (std::size_t k = 0; k < take; ++k) {
          if (buf[k] != payload_byte(seed, found, i + k)) {
            same = false;
            break;
          }
        }
        i += take;
      }
      if (!same || s->meta().index != found) {
        o->fail(o_visible, std::string(when) + ": snapshot " + std::to_string(found) +
                               " is visible but its payload is not what was written");
        return;
      }
      o->pass(o_visible);
    }
    if (found < last_committed) {
      if (corruption) {
        ++fallbacks;
        SIM_PROBE("snapshot_world.corrupt_snapshot_rejected");
      } else {
        o->fail(o_durable, std::string(when) + ": committed snapshot " + std::to_string(last_committed) +
                               " was lost (latest loadable is " + std::to_string(found) + ")");
        return;
      }
    }
    o->pass(o_durable);
  }
};

class SnapProc : public Process {
 public:
  SnapProc(Node& n, Harness& h) : node_(n), h_(h), st_(n), rng_(n.rng(0x5A)) {
    h_.check_load(st_, "start");
    n.add_stage(stage_, "snapshotd");
  }

  bool poll() {
    const Nanos now = node_.clock().now_mono();
    if (!writer_) {
      if (h_.committed >= h_.target || now < next_start_) return false;
      start(now);
      return true;
    }
    // A slice of the payload per poll, in random pieces.
    for (int k = 0; k < 4 && written_ < total_; ++k) {
      const std::uint64_t take = std::min<std::uint64_t>(total_ - written_, 1 + rng_.below(20'000));
      piece_.resize(static_cast<std::size_t>(take));
      for (std::uint64_t i = 0; i < take; ++i) piece_[static_cast<std::size_t>(i)] = payload_byte(h_.seed, index_, written_ + i);
      writer_->put_bytes(piece_);
      written_ += take;
    }
    if (written_ == total_) {
      const auto r = writer_->commit();
      if (r) {
        ++h_.committed;
        h_.last_committed = std::max(h_.last_committed, index_);
        h_.log("committed snapshot %llu (%llu bytes)", static_cast<unsigned long long>(index_),
               static_cast<unsigned long long>(total_));
      } else {
        ++h_.failed_commits;
        SIM_PROBE("snapshot_world.commit_failed");
      }
      writer_.reset();
      next_start_ = now + static_cast<Nanos>(rng_.below(5 * kMs));
    }
    return true;
  }

 private:
  struct Stage {
    SnapProc* p;
    bool poll() { return p->poll(); }
  };

  void start(Nanos) {
    index_ = h_.next_index++;
    total_ = payload_len(h_.seed, index_);
    written_ = 0;
    snap::SnapshotMeta meta{};
    meta.index = index_;
    snap::WriterOptions opts;
    opts.chunk_bytes = std::uint32_t{4096} << rng_.below(5);
    std::vector<snap::SessionSeq> sessions;
    for (std::uint32_t s = 1; s <= rng_.below(4); ++s) sessions.push_back(snap::SessionSeq{s, index_ * 10 + s});
    auto w = snap::Writer::create(st_, kDir, meta, sessions, opts);
    if (!w) {
      ++h_.failed_commits;
      return;
    }
    writer_.emplace(std::move(*w));
  }

  Node& node_;
  Harness& h_;
  SimSnapStorage st_;
  Rng rng_;
  std::optional<snap::Writer> writer_;
  std::uint64_t index_ = 0;
  std::uint64_t total_ = 0;
  std::uint64_t written_ = 0;
  std::vector<std::byte> piece_;
  Nanos next_start_ = 0;
  Stage stage_{this};
};

}  // namespace

Report run_snapshot(const Options& o) {
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x5A9);
  h->w = &w;
  h->o = &w.oracles();
  h->seed = o.seed;
  h->verbose = o.verbose;
  h->o_visible = w.oracles().activate("O-SNAP-VISIBLE", "a visible snapshot is complete, valid and as written");
  h->o_durable = w.oracles().activate("O-SNAP-DURABLE", "a snapshot whose commit succeeded is never lost");
  h->target = 5 + wl.below(30);
  h->corruption = wl.below(2) == 0;

  Node& n = w.add_node("snapd", NodeOptions{true, true});
  if (h->corruption) n.disk().set_atlas_replica(0, 2);  // older snapshot + journal replay: the clean copy
  Harness* hp = h.get();
  n.set_boot([hp](Node& nd, BootReason) { nd.emplace_process<SnapProc>(nd, *hp); });
  n.boot();

  w.oracles().add_final_check(hp->o_durable, [&w, hp] {
    Node& nd = w.node(0);
    if (nd.alive()) {
      nd.crash(CrashKind::Host, /*injected=*/false);
    } else {
      nd.disk().crash_host();
    }
    SimSnapStorage st(nd);
    hp->check_load(st, "after final power cut");
  });

  return finish(
      w, WorldKind::Snapshot, o, [hp] { return hp->committed >= hp->target; },
      [hp] {
        return "committed=" + std::to_string(hp->committed) + " failed=" + std::to_string(hp->failed_commits) +
               " corruption=" + std::to_string(hp->corruption ? 1 : 0) + " loads=" + std::to_string(hp->loads) +
               " fallbacks=" + std::to_string(hp->fallbacks);
      });
}

}  // namespace lle::sim::worlds::detail
