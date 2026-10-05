// journal world (09 S-03, S-04; 06 §4–§7): the production journal (src/journal)
// on the simulated disk. One node runs the L3 writer exactly as the sequencer's
// io stage would: recovery, recycling of dirty spares, resume_writer, segment
// preparation, append / flush / poll, renaming assigned segments, and retiring
// the oldest segments (snapshot retention) back into the spare pool. The device
// (SimJournalDevice) mirrors PosixJournalDevice: pwrite then fdatasync, so
// process crashes, host crashes, torn and lost unsynced writes, out-of-order
// persistence, EIO on write or fsync (fsyncgate) and stalls all reach the
// journal as they would on Linux.
//
// Oracles (the canonical record stream lives in the harness, outside the
// process):
//   O-WAL-DURABLE      every index the writer ever reported durable (including
//                      the durable_index a resumed writer starts from) survives
//                      every later recovery, also after a final power cut
//   O-JOURNAL-CHAIN    recovery and the reader agree on a contiguous chain that
//                      starts at the oldest retained index, and every record is
//                      byte-identical in content to the canonical record
//   O-JOURNAL-RECYCLE  every recovered record sits exactly where the current
//                      history wrote it (segment nonce and offset): nothing is
//                      accepted from a recycled segment's old contents
//   O-JOURNAL-IDEMPOTENT  recovering twice gives the same chain and position,
//                      with no torn tail the second time
//   O-JOURNAL-RECOVERABLE recovery never refuses (Corruption) inside the
//                      failure model; I/O errors are retried by a restart
//   O-LIVE             after healing the writer makes every record durable
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/hash.h"
#include "env/buggify.h"
#include "journal/journal_writer.h"
#include "journal/reader.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment.h"
#include "journal/segment_preparer.h"
#include "sim/dist.h"
#include "sim/node.h"
#include "sim/worlds/journal_device.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

namespace {

namespace jr = lle::journal;
using Writer = jr::JournalWriter<SimJournalDevice>;
using Preparer = jr::SegmentPreparer<SimSegmentDir, Rng>;

constexpr char kPrefix[] = "journal/";
constexpr std::uint32_t kDay = 20261001;

struct JournalConfig {
  jr::JournalWriterOptions writer;
  std::uint64_t segment_bytes = jr::kMinSegmentBytes;
  std::size_t spares = 2;
  std::size_t keep_segments = 3;
  std::uint64_t records = 1000;
  std::uint32_t per_poll = 8;
  Nanos interval_ns = 0;  // record i arrives at i * interval (input spread over the fault phase)
  [[nodiscard]] jr::RecoveryOptions recovery() const {
    return jr::RecoveryOptions{kDay, std::uint64_t{writer.queue_depth} * writer.batch_bytes, true};
  }
};

std::string chain_str(const jr::ChainState& c) {
  return "last " + std::to_string(c.last_index) + " crc " + std::to_string(c.last_crc);
}

// ---- harness ---------------------------------------------------------------
struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_durable = 0;
  OracleId o_chain = 0;
  OracleId o_recycle = 0;
  OracleId o_idem = 0;
  OracleId o_recoverable = 0;
  bool verbose = false;

  // Canonical stream: record i (1-based) at bytes [off[i], off[i+1]).
  std::vector<std::byte> canon;
  std::vector<std::size_t> off;
  jr::Sealer canonical_sealer;  // nonce 0

  std::uint64_t claimed_durable = 0;  // max durable_index any writer incarnation reported
  std::uint64_t expected_first = 1;   // oldest index not retired
  struct Loc {
    std::uint64_t nonce = 0;
    std::uint64_t offset = 0;
  };
  std::vector<Loc> placed;  // where the current history wrote record i
  std::uint64_t durable_now = 0;
  std::uint64_t appended_now = 0;
  std::uint64_t recoveries = 0;
  std::uint64_t torn_tails = 0;
  std::uint64_t recycled = 0;
  std::uint64_t writer_failures = 0;
  std::uint64_t ooo_seen = 0;  // disk_ooo_persist at the previous boot

  // A host crash that persisted a later in-flight journal write while losing
  // an earlier one (the journal node owns the only disk in this world).
  void note_restart() {
    const std::uint64_t ooo = w->stats().disk_ooo_persist;
    if (ooo > ooo_seen) w->probes().hit("journal.ooo_persist_inflight_at_crash", /*rare=*/true);
    ooo_seen = ooo;
  }

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  void build_canonical(std::uint64_t seed, std::uint64_t n, std::uint32_t max_args) {
    jr::RecordBuilder b(canonical_sealer);
    std::vector<std::byte> args;
    std::vector<std::byte> rec(jr::kMaxRecordBytes);
    off.assign(1, 0);
    off.push_back(0);  // off[1] = 0
    for (std::uint64_t i = 1; i <= n; ++i) {
      const std::uint64_t h = mix64(seed ^ (i * 0x9E3779B97F4A7C15ull));
      args.resize(static_cast<std::size_t>(h % (max_args + 1)));
      SplitMix64 sm(h);
      for (std::size_t k = 0; k < args.size(); ++k) args[k] = static_cast<std::byte>(sm.next());
      const jr::Admin a{static_cast<std::uint16_t>(1 + i % 5), 1, static_cast<std::uint32_t>(h >> 32), args};
      const auto r = b.append(rec, static_cast<Nanos>(i) * 1000, a);
      LLE_ASSERT(!r.empty(), "canonical record does not fit");
      canon.insert(canon.end(), r.begin(), r.end());
      off.push_back(canon.size());
    }
    placed.assign(n + 1, Loc{});
  }
  [[nodiscard]] std::span<const std::byte> record(std::uint64_t i) const {
    return std::span<const std::byte>(canon).subspan(off[i], off[i + 1] - off[i]);
  }
  [[nodiscard]] std::uint64_t total() const { return off.size() - 2; }

  void on_durable(std::uint64_t d) {
    durable_now = d;
    if (d > claimed_durable) claimed_durable = d;
  }

  // Checks a successful recovery against the canonical stream.
  void check_recovered(const jr::RecoveryResult& r, SimSegmentDir& dir, const char* when) {
    ++recoveries;
    if (r.torn_tail) ++torn_tails;
    log("recovery (%s): %s, first %llu, %s, durable claimed %llu", when, r.detail.c_str(),
        static_cast<unsigned long long>(r.first_index), chain_str(r.chain).c_str(),
        static_cast<unsigned long long>(claimed_durable));
    if (!r.usable()) {
      if (r.status == jr::RecoveryStatus::Corruption) {
        o->fail(o_recoverable, std::string("recovery refused (") + when + "): " + r.detail);
      }
      return;
    }
    o->pass(o_recoverable);
    const std::uint64_t last = r.chain.last_index;
    if (last < claimed_durable) {
      o->fail(o_durable, std::string("index ") + std::to_string(claimed_durable) +
                             " was reported durable but recovery (" + when + ") ends at " + std::to_string(last));
      return;
    }
    o->pass(o_durable);
    if (last == 0) return;
    if (r.first_index > expected_first) {
      o->fail(o_chain, "recovered chain starts at " + std::to_string(r.first_index) +
                           " but indices from " + std::to_string(expected_first) + " were never retired");
      return;
    }
    std::uint64_t next = r.first_index;
    bool ok = true;
    const jr::ReadSummary s = jr::read_journal(
        dir, jr::ReadOptions{kDay, 0, last, false}, [&](const jr::RecordView& rv, const jr::RecordLocation& loc) {
          const std::uint64_t i = rv.index();
          if (i != next || i > total()) {
            o->fail(o_chain, "reader delivered index " + std::to_string(i) + ", expected " + std::to_string(next));
            ok = false;
            return false;
          }
          ++next;
          if (!jr::same_content(rv, jr::RecordView(record(i)))) {
            o->fail(o_chain, "record " + std::to_string(i) + " differs from the canonical record");
            ok = false;
            return false;
          }
          if (i >= expected_first && (placed[i].nonce != loc.header->nonce || placed[i].offset != loc.offset)) {
            o->fail(o_recycle, "record " + std::to_string(i) + " read at segment nonce " +
                                   std::to_string(loc.header->nonce) + " offset " + std::to_string(loc.offset) +
                                   ", but the current history wrote it at nonce " +
                                   std::to_string(placed[i].nonce) + " offset " + std::to_string(placed[i].offset));
            ok = false;
            return false;
          }
          return true;
        });
    if (!ok) return;
    if (next != last + 1 || s.chain.last_index != last) {
      o->fail(o_chain, std::string("reader walked to ") + std::to_string(s.chain.last_index) +
                           " but recovery (" + when + ") reported " + std::to_string(last));
      return;
    }
    o->pass(o_chain);
    o->pass(o_recycle);
  }

  void check_idempotent(const jr::RecoveryResult& a, const jr::RecoveryResult& b) {
    const bool same = a.status == b.status && a.chain.last_index == b.chain.last_index &&
                      a.chain.last_crc == b.chain.last_crc && a.resume_offset == b.resume_offset &&
                      a.first_index == b.first_index && !b.torn_tail;
    o->check(o_idem, same,
             "second recovery differs: " + chain_str(a.chain) + " resume " + std::to_string(a.resume_offset) +
                 " vs " + chain_str(b.chain) + " resume " + std::to_string(b.resume_offset) +
                 (b.torn_tail ? " (torn tail again)" : ""));
  }
};

// ---- the journal process ---------------------------------------------------
struct JournalProc : Process {
  struct Stage {
    JournalProc* p;
    bool poll() { return p->poll(); }
  };

  JournalProc(Node& n, Harness& h, const JournalConfig& cfg)
      : node_(n), h_(h), cfg_(cfg), dir_(n, kPrefix), rng_(n.rng(7)), prep_(dir_, rng_, kDay, cfg.segment_bytes),
        writer_(cfg.writer), stage_{this} {
    boot();
    n.add_stage(stage_, "io");
  }

  void boot() {
    jr::RecoveryResult r = jr::recover(dir_, cfg_.recovery());
    if (r.status == jr::RecoveryStatus::IoError) return fatal("recovery I/O error");
    h_.check_recovered(r, dir_, "restart");
    if (!r.usable()) return halt();
    if (!r.dirty_spares.empty()) {
      for (const std::size_t hd : r.dirty_spares) {
        if (!prep_.recycle(hd)) return fatal("recycling a dirty spare failed");
      }
      SIM_PROBE("journal_world.dirty_spare_recycled");
      r = jr::recover(dir_, cfg_.recovery());
      if (r.status == jr::RecoveryStatus::IoError) return fatal("recovery I/O error");
      h_.check_recovered(r, dir_, "after recycling dirty spares");
      if (!r.usable()) return halt();
    }
    const jr::RecoveryResult again = jr::recover(dir_, cfg_.recovery());
    if (again.status == jr::RecoveryStatus::IoError) return fatal("recovery I/O error");
    h_.check_idempotent(r, again);
    if (r.torn_tail) SIM_PROBE("journal_world.recovered_torn_tail");
    if (!jr::resume_writer(writer_, dir_, r)) {
      h_.o->fail(h_.o_recoverable, "resume_writer refused a usable recovery: " + r.detail);
      return halt();
    }
    for (const auto& s : r.segments) assigned_.push_back(Assigned{s.handle, s.header.first_index});
    prepared_ = r.spares.size();
    // Everything up to chain.last_index is now reported durable.
    h_.on_durable(writer_.durable_index());
    if (!top_up_spares()) return;
    ok_ = true;
  }

  bool top_up_spares() {
    while (prepared_ < cfg_.spares) {
      const auto ps = prep_.create();
      if (!ps) {
        fatal("preparing a segment failed");
        return false;
      }
      if (!writer_.add_prepared(dir_.device(ps->handle), ps->handle, ps->header)) break;
      ++prepared_;
    }
    return true;
  }

  bool poll() {
    if (!ok_) return false;
    bool did = writer_.poll() > 0;
    h_.on_durable(writer_.durable_index());
    if (writer_.failed()) {
      ++h_.writer_failures;
      SIM_PROBE("journal_world.writer_failed_exits");
      fatal("writer failed");  // 06 §6: intake halts; the process exits and recovers
      return true;
    }
    Writer::AssignedSegment as;
    while (writer_.take_assigned(as)) {
      (void)dir_.rename(as.handle, jr::segment_file_name(as.header.epoch, as.header.first_index));
      assigned_.push_back(Assigned{as.handle, as.header.first_index});
      if (prepared_ > 0) --prepared_;
      did = true;
    }
    did = retire() || did;
    if (!ok_) return true;
    std::uint32_t budget = cfg_.per_poll;
    bool appended = false;
    const Nanos now = node_.clock().now_mono();
    const std::uint64_t arrived =
        cfg_.interval_ns > 0 ? std::min<std::uint64_t>(h_.total(), static_cast<std::uint64_t>(now / cfg_.interval_ns) + 1)
                             : h_.total();
    while (budget > 0 && writer_.appended_index() < arrived) {
      const std::uint64_t i = writer_.appended_index() + 1;
      const auto rec = h_.record(i);
      const Writer::Status st = writer_.append(rec, h_.canonical_sealer);
      if (st == Writer::Status::Ok) {
        h_.placed[i] = Harness::Loc{writer_.segment_header().nonce,
                                    writer_.write_offset() + writer_.batch_used() - rec.size()};
        h_.appended_now = i;
        --budget;
        appended = true;
        continue;
      }
      if (st == Writer::Status::Busy) break;
      if (st == Writer::Status::NeedSegment) {
        SIM_PROBE("journal_world.need_segment");
        const auto ps = prep_.create();
        if (!ps) {
          fatal("preparing a segment failed");
          return true;
        }
        LLE_ASSERT(writer_.add_prepared(dir_.device(ps->handle), ps->handle, ps->header), "prepared segment refused");
        ++prepared_;
        continue;
      }
      if (st == Writer::Status::Failed) {
        fatal("writer failed on append");
        return true;
      }
      LLE_UNREACHABLE("canonical record rejected by the writer");
    }
    // Group commit: flush when the input is drained for now.
    if (writer_.batch_used() != 0 && (budget > 0 || SIM_BUGGIFY("journal_world.flush_mid_burst"))) {
      did = writer_.flush() || did;
    }
    return appended || did;
  }

  // Snapshot retention: the oldest segment, once everything in it (and in its
  // successor's predecessor range) is durable, is recycled into the spare pool.
  bool retire() {
    if (assigned_.size() <= cfg_.keep_segments || prepared_ >= jr::JournalWriter<SimJournalDevice>::kMaxPrepared) {
      return false;
    }
    const Assigned oldest = assigned_.front();
    const std::uint64_t next_first = assigned_[1].first_index;
    if (next_first == 0 || next_first - 1 > writer_.durable_index()) return false;
    // From here on, indices below next_first are gone by design.
    h_.expected_first = std::max(h_.expected_first, next_first);
    assigned_.erase(assigned_.begin());
    const auto ps = prep_.recycle(oldest.handle);
    if (!ps) {
      fatal("recycling a retired segment failed");
      return true;
    }
    ++h_.recycled;
    SIM_PROBE("journal_world.segment_recycled");
    if (writer_.add_prepared(dir_.device(ps->handle), ps->handle, ps->header)) ++prepared_;
    return true;
  }

  void fatal(const char* why) {
    h_.log("journal process exits: %s", why);
    ok_ = false;
    node_.request_crash();
  }
  void halt() { ok_ = false; }

  struct Assigned {
    std::size_t handle;
    std::uint64_t first_index;
  };

  Node& node_;
  Harness& h_;
  JournalConfig cfg_;
  SimSegmentDir dir_;
  Rng rng_;
  Preparer prep_;
  Writer writer_;
  std::vector<Assigned> assigned_;
  std::size_t prepared_ = 0;
  bool ok_ = false;
  Stage stage_;
};

}  // namespace

Report run_journal(const Options& o) {
  // The harness outlives the world: process destructors still report to it.
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x10A1);
  h->w = &w;
  h->o = &w.oracles();
  h->verbose = o.verbose;
  h->o_durable = w.oracles().activate("O-WAL-DURABLE", "every index reported durable survives recovery");
  h->o_chain = w.oracles().activate("O-JOURNAL-CHAIN", "recovered chain contiguous and identical to the canonical stream");
  h->o_recycle = w.oracles().activate("O-JOURNAL-RECYCLE", "no record accepted from a recycled segment's old contents");
  h->o_idem = w.oracles().activate("O-JOURNAL-IDEMPOTENT", "a second recovery gives the same result, no torn tail");
  h->o_recoverable = w.oracles().activate("O-JOURNAL-RECOVERABLE", "recovery never refuses inside the failure model");

  JournalConfig cfg;
  cfg.writer.day = kDay;
  cfg.writer.queue_depth = static_cast<std::uint32_t>(1 + wl.below(4));
  cfg.writer.batch_bytes = jr::kBatchBytes;
  cfg.writer.buffers = cfg.writer.queue_depth + 1 + static_cast<std::uint32_t>(wl.below(3));
  cfg.segment_bytes = jr::kSegmentHeaderBytes + jr::kBatchBytes * (1 + wl.below(3));
  cfg.spares = static_cast<std::size_t>(1 + wl.below(2));
  cfg.keep_segments = static_cast<std::size_t>(2 + wl.below(3));
  cfg.records = 300 + wl.below(1201);
  cfg.per_poll = static_cast<std::uint32_t>(1 + wl.below(16));
  // Spread arrivals over most of the safety phase so crashes land mid-write.
  cfg.interval_ns = static_cast<Nanos>((o.plan.safety_ns * (60 + static_cast<Nanos>(wl.below(40))) / 100) /
                                       static_cast<Nanos>(cfg.records));
  static constexpr std::uint32_t kMaxArgs[] = {64, 1024, 4000};
  h->build_canonical(o.seed, cfg.records, kMaxArgs[wl.below(3)]);

  Node& n = w.add_node("journal", NodeOptions{true, true});
  Harness* hp = h.get();
  n.set_boot([hp, cfg](Node& nd, BootReason why) {
    if (why == BootReason::Restart) hp->note_restart();
    nd.emplace_process<JournalProc>(nd, *hp, cfg);
  });
  n.boot();

  // Final oracle: cut the power after convergence and recover from what is
  // durable, with a fresh directory listing (as a new process would).
  w.oracles().add_final_check(hp->o_durable, [&w, hp, cfg] {
    Node& nd = w.node(0);
    if (nd.alive()) {
      nd.crash(CrashKind::Host, /*injected=*/false);
    } else {
      nd.disk().crash_host();
    }
    SimSegmentDir dir(nd, kPrefix);
    const jr::RecoveryResult r = jr::recover(dir, cfg.recovery());
    hp->check_recovered(r, dir, "after final power cut");
  });

  return finish(
      w, WorldKind::Journal, o, [hp] { return hp->durable_now >= hp->total(); },
      [hp, cfg] {
        return "records=" + std::to_string(hp->total()) + " durable=" + std::to_string(hp->durable_now) +
               " qd=" + std::to_string(cfg.writer.queue_depth) + " seg_kib=" +
               std::to_string(cfg.segment_bytes / 1024) + " recoveries=" + std::to_string(hp->recoveries) +
               " torn=" + std::to_string(hp->torn_tails) + " recycled=" + std::to_string(hp->recycled) +
               " writer_failures=" + std::to_string(hp->writer_failures);
      });
}

}  // namespace lle::sim::worlds::detail
