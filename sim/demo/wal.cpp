// wal world: a write-ahead log under disk latency, stalls, EIO, torn and
// unsynced writes, out-of-order persistence, process and host crashes.
//
// The writer appends checksummed records and acknowledges a record only after
// a sync that covers it completes (the output rule in miniature). It aborts on
// any EIO (fsyncgate-safe: a failed fsync means the page cache can no longer be
// trusted) and a supervisor restarts it. Recovery scans the log, stops at the
// first invalid record, then rewrites and syncs the recovered prefix before
// acknowledging anything else, because pages a failed fsync doomed may still
// be readable from the cache. O-WAL-DURABLE checks after every recovery, and
// once more after a final power cut, that every acknowledged record survived.
#include <cstring>
#include <memory>
#include <vector>

#include "common/endian.h"
#include "common/hash.h"
#include "env/concepts.h"
#include "sim/worlds/worlds.h"
#include "sim/dist.h"
#include "sim/fault/buggify.h"
#include "sim/node.h"

namespace lle::sim::worlds::detail {

namespace {

constexpr std::uint32_t kMagic = 0x57414C31u;  // "WAL1"
constexpr std::size_t kHeader = 16;            // magic, len, seq
constexpr std::size_t kTrailer = 8;            // FNV-1a over header + payload
constexpr std::uint32_t kMaxPayload = 4096;
constexpr std::uint64_t kSyncTag = std::uint64_t{1} << 62;
constexpr std::uint64_t kRewriteTag = std::uint64_t{1} << 61;
constexpr std::uint64_t kRewriteSyncTag = kRewriteTag | 1;

std::uint32_t payload_len(std::uint64_t seed, std::uint64_t seq) noexcept {
  return 16 + static_cast<std::uint32_t>(mix64(seed ^ (seq * 0x51ED27ull)) % 600);
}

void fill_payload(std::uint64_t seed, std::uint64_t seq, std::byte* out, std::uint32_t len) noexcept {
  SplitMix64 sm(seed ^ (seq << 20));
  for (std::uint32_t i = 0; i < len; i += 8) {
    const std::uint64_t v = sm.next();
    for (std::uint32_t k = 0; k < 8 && i + k < len; ++k) out[i + k] = static_cast<std::byte>(v >> (8 * k));
  }
}

std::size_t encode(std::uint64_t seed, std::uint64_t seq, std::vector<std::byte>& buf) {
  const std::uint32_t len = payload_len(seed, seq);
  buf.resize(kHeader + len + kTrailer);
  store_le32(buf.data(), kMagic);
  store_le32(buf.data() + 4, len);
  store_le64(buf.data() + 8, seq);
  fill_payload(seed, seq, buf.data() + kHeader, len);
  Fnv1a64 h;
  h.bytes(buf.data(), kHeader + len);
  store_le64(buf.data() + kHeader + len, h.value());
  return buf.size();
}

struct ScanResult {
  std::uint64_t last_seq = 0;   // records 1..last_seq are valid and contiguous
  std::uint64_t end = 0;        // byte offset after the last valid record
  bool torn_tail = false;       // bytes follow the last valid record
};

// Validates the log from offset 0 (paired with encode: TigerStyle paired
// assertions, validated before writing and after reading).
template <class ReadFn>
ScanResult scan(std::uint64_t seed, std::uint64_t size, ReadFn&& read) {
  ScanResult r;
  std::vector<std::byte> rec;
  std::vector<std::byte> want;
  std::uint64_t off = 0;
  while (true) {
    std::byte hdr[kHeader];
    if (read(off, std::span<std::byte>(hdr, kHeader)) != kHeader) break;
    const std::uint32_t len = load_le32(hdr + 4);
    if (load_le32(hdr) != kMagic || len > kMaxPayload) break;
    rec.resize(kHeader + len + kTrailer);
    if (read(off, std::span<std::byte>(rec)) != rec.size()) break;
    Fnv1a64 h;
    h.bytes(rec.data(), kHeader + len);
    if (load_le64(rec.data() + kHeader + len) != h.value()) break;
    const std::uint64_t seq = load_le64(hdr + 8);
    if (seq != r.last_seq + 1) break;
    encode(seed, seq, want);
    if (want != rec) break;  // valid checksum but wrong content: not ours
    r.last_seq = seq;
    off += rec.size();
  }
  r.end = off;
  r.torn_tail = off < size;
  return r;
}

// Harness-side truth: what was acknowledged. Survives every crash.
struct Ledger {
  std::uint64_t target = 0;
  std::uint64_t max_acked = 0;
  std::uint64_t boots = 0;
  std::uint64_t aborts = 0;
  OracleRegistry* oracles = nullptr;
  OracleId o_durable = 0;

  void ack(std::uint64_t seq) {
    if (seq <= max_acked) return;  // re-acknowledged after recovery: idempotent
    if (seq != max_acked + 1) {
      oracles->fail(o_durable, "ack gap: acked " + std::to_string(seq) + " after " + std::to_string(max_acked));
      return;
    }
    max_acked = seq;
  }
  void check_recovered(std::uint64_t last, const char* when) {
    ++boots;
    oracles->check(o_durable, last >= max_acked,
                   std::string("acknowledged record ") + std::to_string(max_acked) + " lost " + when +
                       " (recovered through " + std::to_string(last) + ")");
  }
};

template <env::DiskFileLike File>
class WalWriter {
 public:
  using AbortFn = void (*)(void*);

  WalWriter(File& file, Ledger& ledger, std::uint64_t seed, std::uint32_t max_inflight, bool canary, AbortFn abort_fn,
            void* abort_ctx)
      : file_(file),
        ledger_(ledger),
        seed_(seed),
        max_inflight_(max_inflight),
        canary_(canary),
        abort_fn_(abort_fn),
        abort_ctx_(abort_ctx),
        completed_(ledger.target + 2, 0) {}

  // Runs the recovery scan on the visible image and arms the rewrite.
  void recover(std::uint64_t size) {
    const ScanResult r = scan(seed_, size, [&](std::uint64_t off, std::span<std::byte> out) {
      return file_.read(off, out);
    });
    if (r.torn_tail) SIM_PROBE("demo.wal.recovered_torn_tail");
    ledger_.check_recovered(r.last_seq, "at restart");
    recovered_ = r.last_seq;
    end_ = r.end;
    next_seq_ = r.last_seq + 1;
    completed_prefix_ = r.last_seq;
    synced_ = r.last_seq;
    rewriting_ = r.end > 0;
  }

  bool poll() {
    bool did = false;
    file_.poll([&](const env::DiskCompletion& c) {
      did = true;
      on_completion(c);
    });
    if (aborted_) return did;
    if (rewriting_) {
      if (!rewrite_submitted_) {
        // Re-persist the recovered prefix: it may only exist in the cache.
        rewrite_buf_.resize(static_cast<std::size_t>(end_));
        if (file_.read(0, std::span<std::byte>(rewrite_buf_)) != rewrite_buf_.size()) return abort();
        if (file_.submit_write(0, std::span<const std::byte>(rewrite_buf_), false, kRewriteTag)) {
          rewrite_submitted_ = true;
          did = true;
        }
      }
      return did;
    }
    while (inflight_ < max_inflight_ && next_seq_ <= ledger_.target) {
      encode(seed_, next_seq_, buf_);
      const bool dsync = SIM_BUGGIFY("demo.wal.dsync_write");
      if (!file_.submit_write(end_, std::span<const std::byte>(buf_), dsync, next_seq_)) break;
      end_ += buf_.size();
      ++next_seq_;
      ++inflight_;
      did = true;
    }
    if (!sync_inflight_ && completed_prefix_ > synced_ && !SIM_BUGGIFY("demo.wal.delay_sync")) {
      if (file_.submit_sync(kSyncTag | completed_prefix_)) {
        sync_inflight_ = true;
        did = true;
      }
    }
    return did;
  }

  [[nodiscard]] std::uint64_t recovered() const noexcept { return recovered_; }

 private:
  bool abort() {
    if (!aborted_) {
      aborted_ = true;
      ++ledger_.aborts;
      SIM_PROBE("demo.wal.abort_on_eio");
      abort_fn_(abort_ctx_);
    }
    return true;
  }

  void on_completion(const env::DiskCompletion& c) {
    if (aborted_) return;
    if (c.result < 0) {
      abort();
      return;
    }
    if (c.tag == kRewriteTag) {
      // The sync must be submitted after the write completed to cover it.
      if (!file_.submit_sync(kRewriteSyncTag)) abort();
      return;
    }
    if (c.tag == kRewriteSyncTag) {
      for (std::uint64_t s = 1; s <= recovered_; ++s) ledger_.ack(s);
      rewriting_ = false;
      return;
    }
    if ((c.tag & kSyncTag) != 0) {
      sync_inflight_ = false;
      const std::uint64_t covers = c.tag & ~kSyncTag;
      for (std::uint64_t s = synced_ + 1; s <= covers; ++s) ledger_.ack(s);
      if (covers > synced_) synced_ = covers;
      return;
    }
    const std::uint64_t seq = c.tag;
    --inflight_;
    completed_[seq] = 1;
    while (completed_prefix_ + 1 < completed_.size() && completed_[completed_prefix_ + 1] != 0) ++completed_prefix_;
    // Planted canary bug: acknowledge on write completion, before any sync.
    if (canary_) {
      for (std::uint64_t s = ledger_.max_acked + 1; s <= completed_prefix_; ++s) ledger_.ack(s);
    }
  }

  File& file_;
  Ledger& ledger_;
  std::uint64_t seed_;
  std::uint32_t max_inflight_;
  bool canary_;
  AbortFn abort_fn_;
  void* abort_ctx_;
  std::vector<std::uint8_t> completed_;
  std::vector<std::byte> buf_;
  std::vector<std::byte> rewrite_buf_;
  std::uint64_t recovered_ = 0;
  std::uint64_t end_ = 0;
  std::uint64_t next_seq_ = 1;
  std::uint64_t completed_prefix_ = 0;
  std::uint64_t synced_ = 0;
  std::uint32_t inflight_ = 0;
  bool sync_inflight_ = false;
  bool rewriting_ = false;
  bool rewrite_submitted_ = false;
  bool aborted_ = false;
};

struct WalProcess : Process {
  WalProcess(Node& n, Ledger& l, std::uint64_t seed, std::uint32_t max_inflight, bool canary)
      : file(n, "wal"),
        writer(file, l, seed, max_inflight, canary, [](void* node) { static_cast<Node*>(node)->request_crash(); }, &n) {
    writer.recover(file.size());
    n.add_stage(writer, "wal");
  }
  DiskFile file;
  WalWriter<DiskFile> writer;
};

}  // namespace

Report run_wal(const Options& o) {
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x3A1);
  auto ledger = std::make_unique<Ledger>();
  ledger->target = 100 + wl.below(301);
  ledger->oracles = &w.oracles();
  ledger->o_durable = w.oracles().activate("O-WAL-DURABLE", "demo: no acknowledged WAL record lost across crashes");
  const auto max_inflight = static_cast<std::uint32_t>(1 + wl.below(8));
  declare_demo_probe(w, "demo.wal.recovered_torn_tail");
  declare_demo_probe(w, "demo.wal.abort_on_eio");

  Node& db = w.add_node("db", NodeOptions{true, true});
  Ledger* lp = ledger.get();
  const std::uint64_t seed = o.seed;
  const bool canary = o.canary;
  db.set_boot([=](Node& n, BootReason) { n.emplace_process<WalProcess>(n, *lp, seed, max_inflight, canary); });
  db.boot();

  // Final check: cut power after convergence and re-scan the durable image.
  w.oracles().add_final_check(lp->o_durable, [&w, lp, seed] {
    Node& n = w.node(0);
    if (n.alive()) {
      n.crash(CrashKind::Host, /*injected=*/false);
    } else {
      n.disk().crash_host();  // power loss while the process is down
    }
    Disk& d = n.disk();
    const std::uint32_t f = d.open("wal");
    const ScanResult r = scan(seed, d.size(f), [&](std::uint64_t off, std::span<std::byte> out) {
      return d.read(f, off, out);
    });
    lp->check_recovered(r.last_seq, "after final power cut");
  });

  return finish(
      w, WorldKind::Wal, o, [lp] { return lp->max_acked >= lp->target; },
      [lp] {
        return "acked=" + std::to_string(lp->max_acked) + "/" + std::to_string(lp->target) +
               " boots=" + std::to_string(lp->boots) + " aborts=" + std::to_string(lp->aborts);
      });
}

}  // namespace lle::sim::worlds::detail
