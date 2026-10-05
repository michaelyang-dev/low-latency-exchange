// outlog world (06 §8; 09 §2): the production output-log writer, reader and
// repair tools (src/outlog, BasicOutlogWriter / BasicOutlogReader / repair /
// truncate_to / regenerate / first_difference on SimOutlogFs) on the
// simulated disk, under EIO, stalls, process and host crashes (lost, torn and
// out-of-order persisted unsynced writes) and, on half the seeds, the fault
// atlas's corruption classes (misdirected writes, bit flips).
//
// The output log is derived data: the journal (here the canonical message
// stream, a pure function of the seed, standing in for the durable journal)
// grows with time whether or not the io process is up. The io node appends
// it with flushes on a cadence and occasional syncs. Every start recovers the
// way 06 §8 describes ("recovery rebuilds or extends it from the journal"):
// open() repairs the log (torn tail cut, index rebuilt), the kept messages are
// checked against the journal, the log is cut back to the first message that
// differs (truncate_to), and the missing suffix is regenerated (regenerate).
// Because the journal is a clean copy of everything in the log, the disk is
// replica 0 of 2 for the fault atlas: corruption hits only the output log.
//
// repair() alone cannot make the log trustworthy after a power cut: a torn
// record whose length prefix and extent survived (some payload sectors did
// not) is structurally complete, and BinaryFILE records carry no checksum.
// The comparison with the journal is what removes it (probe
// outlog_world.repair_kept_torn_record; docs/testing/dst.md, findings).
//
// Oracles:
//   O-OUTLOG-TORN       repair keeps only complete records and (without the
//                       corruption atlas) never more messages than were appended
//   O-OUTLOG-RECOVERED  after every recovery the whole log equals the journal's
//                       prefix, and recovery never refuses inside the failure model
//   O-OUTLOG-REGEN      (final, after a power cut and recovery) the log equals a
//                       fresh regeneration from the journal, byte for byte
//                       (first_difference), and the reader serves every message
//   O-LIVE              after healing, the whole journal is in the log
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/hash.h"
#include "env/buggify.h"
#include "outlog/reader_impl.h"
#include "outlog/repair.h"
#include "outlog/writer_impl.h"
#include "sim/dist.h"
#include "sim/node.h"
#include "sim/worlds/outlog_fs.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

namespace {

namespace ol = lle::outlog;
using Writer = ol::BasicOutlogWriter<SimOutlogFs>;
using Reader = ol::BasicOutlogReader<SimOutlogFs>;

constexpr char kPath[] = "itch.bin";
constexpr char kRefPath[] = "itch.ref.bin";
constexpr std::size_t kMaxMsg = 9000;

std::size_t message_len(std::uint64_t seed, SeqNo seq) noexcept {
  const std::uint64_t h = mix64(seed ^ (seq * 0x9E3779B97F4A7C15ull));
  return (h & 63) == 0 ? 1000 + (h >> 8) % (kMaxMsg - 999) : 1 + (h >> 8) % 120;
}
void fill_message(std::uint64_t seed, SeqNo seq, std::span<std::byte> out) noexcept {
  std::uint64_t h = mix64(seed + seq);
  for (std::size_t i = 0; i < out.size(); ++i) {
    if (i % 8 == 0) h = mix64(h + i);
    out[i] = static_cast<std::byte>(h >> (8 * (i % 8)));
  }
}

struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_torn = 0, o_recovered = 0, o_regen = 0;
  std::uint64_t seed = 0;
  bool verbose = false;
  bool corruption = false;  // fault atlas on the io disk
  SeqNo total = 0;          // journal length at the end of the run
  Nanos journal_end = 0;    // the journal reaches `total` at this time
  std::size_t buffer_bytes = ol::OutlogWriter::kMinBufferBytes;
  SeqNo max_appended = 0;   // most messages any incarnation appended
  SeqNo durable_count = 0;  // log length after the last recovery or flush
  std::uint64_t recoveries = 0, cut_back = 0, regenerated = 0, writer_failures = 0, torn_kept = 0;
  std::array<std::byte, kMaxMsg> scratch{};

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  // The journal: messages released so far.
  [[nodiscard]] SeqNo journal_len(Nanos now) const {
    if (now >= journal_end) return total;
    return total * static_cast<SeqNo>(now) / static_cast<SeqNo>(journal_end);  // < 2^44: no overflow
  }

  std::span<const std::byte> message(SeqNo seq, std::span<std::byte> out) const {
    const std::size_t n = message_len(seed, seq);
    fill_message(seed, seq, out.first(n));
    return out.first(n);
  }

  // First kept message that differs from the journal (count + 1 if none).
  SeqNo first_mismatch(SimOutlogFs& fs, SeqNo count) {
    Reader r(fs);
    if (!r.open(kPath)) return 1;
    std::array<std::byte, kMaxMsg> want{};
    std::vector<std::byte> got(ol::kMaxMessageBytes);
    SeqNo seq = 1;
    for (; seq <= count; ++seq) {
      const auto m = r.read(seq, got);
      if (!m) return seq;
      const std::span<const std::byte> j = message(seq, want);
      if (m->size() != j.size() || std::memcmp(m->data(), j.data(), j.size()) != 0) return seq;
    }
    return seq;
  }

  // Recovery (06 §8): repair on open, cut back to what matches the journal,
  // regenerate the rest. False on an I/O error (the caller restarts).
  bool recover(Writer& wr, SimOutlogFs& fs, SeqNo journal) {
    ++recoveries;
    if (auto r = wr.open(kPath, buffer_bytes); !r) {
      log("recovery: open failed: %s", r.error().c_str());
      return false;
    }
    const SeqNo kept = wr.count();
    if (!corruption && kept > max_appended) {
      o->fail(o_torn, "repair kept " + std::to_string(kept) + " messages but only " + std::to_string(max_appended) +
                          " were ever appended");
    } else {
      o->pass(o_torn);
    }
    const SeqNo m = first_mismatch(fs, kept);
    if (m <= kept) {
      if (!corruption) {
        SIM_PROBE("outlog_world.repair_kept_torn_record");
        ++torn_kept;
      }
      SIM_PROBE("outlog_world.cut_back_to_journal");
      ++cut_back;
      (void)wr.close();
      if (const auto t = ol::truncate_to(fs, kPath, m - 1); !t) {
        log("recovery: truncate_to(%llu) failed", static_cast<unsigned long long>(m - 1));
        return false;
      }
      if (auto r = wr.open(kPath, buffer_bytes); !r) return false;
    }
    const SeqNo before = wr.count();
    const auto g = ol::regenerate(wr, [&](SeqNo seq, std::span<std::byte> out) -> std::span<const std::byte> {
      if (seq > journal) return {};
      return message(seq, out);
    });
    max_appended = std::max(max_appended, wr.count());  // also after a failure part way
    if (!g) return false;
    regenerated += *g;
    if (const auto f = wr.flush(); !f) return false;
    // With the corruption atlas, writes may be corrupted again while faults
    // are on; the final check covers those seeds.
    if (corruption && w->faults_active()) {
    } else if (const SeqNo bad = first_mismatch(fs, wr.count()); bad <= wr.count()) {
      o->fail(o_recovered, "after recovery message " + std::to_string(bad) + " differs from the journal");
    } else {
      o->pass(o_recovered);
    }
    log("recovery: kept %llu, cut to %llu, regenerated %llu to %llu", static_cast<unsigned long long>(kept),
        static_cast<unsigned long long>(before), static_cast<unsigned long long>(*g),
        static_cast<unsigned long long>(wr.count()));
    return true;
  }
};

class IoProc : public Process {
 public:
  IoProc(Node& n, Harness& h) : node_(n), h_(h), fs_(n), w_(fs_), rng_(n.rng(0x0A)) {
    if (!h_.recover(w_, fs_, h_.journal_len(n.clock().now_mono()))) {
      ++h_.writer_failures;
      n.request_crash();
      failed_ = true;
    }
    n.add_stage(stage_, "io");
  }

  bool poll() {
    if (failed_) return false;
    const Nanos now = node_.clock().now_mono();
    const SeqNo journal = h_.journal_len(now);
    bool did = false;
    for (int k = 0; k < 64 && w_.count() < journal; ++k) {
      const std::span<const std::byte> msg = h_.message(w_.count() + 1, buf_);
      if (const auto r = w_.append(msg); !r) return fail(now);
      h_.max_appended = std::max(h_.max_appended, w_.count());
      did = true;
    }
    if (now >= next_flush_ && w_.bytes() != w_.written_bytes()) {
      const bool sync = rng_.below(8) == 0;
      if (const auto r = sync ? w_.sync() : w_.flush(); !r) return fail(now);
      next_flush_ = now + static_cast<Nanos>(100 * kUs + rng_.below(3 * kMs));
      did = true;
    }
    return did;
  }

  [[nodiscard]] bool settled() const { return !failed_ && w_.is_open() && w_.bytes() == w_.written_bytes(); }
  [[nodiscard]] SeqNo count() const { return w_.count(); }

 private:
  struct Stage {
    IoProc* p;
    bool poll() { return p->poll(); }
  };

  bool fail(Nanos) {
    // A failed write is sticky (06 §6): restart and recover.
    ++h_.writer_failures;
    SIM_PROBE("outlog_world.writer_failed_restarts");
    failed_ = true;
    node_.request_crash();
    return true;
  }

  Node& node_;
  Harness& h_;
  SimOutlogFs fs_;
  Writer w_;
  Rng rng_;
  std::array<std::byte, kMaxMsg> buf_{};
  Nanos next_flush_ = 0;
  bool failed_ = false;
  Stage stage_{this};
};

}  // namespace

Report run_outlog(const Options& o) {
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x0B1);
  h->w = &w;
  h->o = &w.oracles();
  h->seed = o.seed;
  h->verbose = o.verbose;
  h->o_torn = w.oracles().activate("O-OUTLOG-TORN", "repair keeps only complete records, never more than were appended");
  h->o_recovered = w.oracles().activate("O-OUTLOG-RECOVERED", "after every recovery the log equals the journal's prefix");
  h->o_regen = w.oracles().activate("O-OUTLOG-REGEN", "after recovery the log equals regeneration from the journal");
  h->total = 1000 + wl.below(14001);
  h->journal_end = o.plan.safety_ns * (50 + static_cast<Nanos>(wl.below(50))) / 100;
  h->buffer_bytes = ol::OutlogWriter::kMinBufferBytes + static_cast<std::size_t>(wl.below(192 * 1024));
  h->corruption = wl.below(2) == 0;

  Node& n = w.add_node("io", NodeOptions{true, true});
  if (h->corruption) n.disk().set_atlas_replica(0, 2);  // the journal is the clean copy
  Harness* hp = h.get();
  n.set_boot([hp](Node& nd, BootReason) { nd.emplace_process<IoProc>(nd, *hp); });
  n.boot();

  // Final oracle: cut the power after convergence, recover, and compare with a
  // fresh regeneration written while faults are off.
  w.oracles().add_final_check(hp->o_regen, [&w, hp] {
    Node& nd = w.node(0);
    if (nd.alive()) {
      nd.crash(CrashKind::Host, /*injected=*/false);
    } else {
      nd.disk().crash_host();
    }
    SimOutlogFs fs(nd);
    Writer log(fs);
    if (!hp->recover(log, fs, hp->total)) {
      hp->o->fail(hp->o_regen, "recovery after the final power cut failed");
      return;
    }
    if (log.count() != hp->total) {
      hp->o->fail(hp->o_regen, "log holds " + std::to_string(log.count()) + " of " + std::to_string(hp->total));
      return;
    }
    (void)log.close();
    Writer ref(fs);
    if (!ref.open(kRefPath, hp->buffer_bytes) ||
        !ol::regenerate(ref, [&](SeqNo seq, std::span<std::byte> out) -> std::span<const std::byte> {
          return seq > hp->total ? std::span<const std::byte>{} : hp->message(seq, out);
        })) {
      hp->o->fail(hp->o_regen, "could not write the reference regeneration");
      return;
    }
    (void)ref.close();
    if (const auto d = ol::first_difference(fs, kPath, kRefPath)) {
      hp->o->fail(hp->o_regen, "log differs from regeneration at message " + std::to_string(*d));
      return;
    }
    if (hp->first_mismatch(fs, hp->total) != hp->total + 1) {
      hp->o->fail(hp->o_regen, "the reader does not serve the journal's bytes");
      return;
    }
    hp->o->pass(hp->o_regen);
  });

  return finish(
      w, WorldKind::Outlog, o,
      [&w, hp] {
        Process* p = w.node(0).process();
        const auto* io = dynamic_cast<IoProc*>(p);
        return io != nullptr && io->settled() && io->count() == hp->total && hp->journal_len(w.now()) == hp->total;
      },
      [hp] {
        return "messages=" + std::to_string(hp->total) + " corruption=" + std::to_string(hp->corruption ? 1 : 0) +
               " recoveries=" + std::to_string(hp->recoveries) + " cut_back=" + std::to_string(hp->cut_back) +
               " regenerated=" + std::to_string(hp->regenerated) + " torn_kept=" + std::to_string(hp->torn_kept) +
               " writer_failures=" + std::to_string(hp->writer_failures);
      });
}

}  // namespace lle::sim::worlds::detail
