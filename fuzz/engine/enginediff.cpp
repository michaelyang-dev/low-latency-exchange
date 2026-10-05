// enginediff: differential fuzzing of the matching engine against RefEngine
// (05-matching-engine §9, E-05/E-14): continuous trading, crosses, NOII,
// halts, LULD, IPO, MWCB, the risk gate and the extended order types (ledger
// mode "full").
//
//   enginediff --seed-start S --seeds N --records-per-seed M
//              [--check-every 1024] [--snapshot-every 8192] [--jobs J]
//              [--ledger fuzz/ledger/runs.jsonl] [--no-validate] [--verbose]
//
// Each seed drives one swarm generator (fuzz/engine/gen.hpp). Every record is
// applied to both engines and the FULL client-visible output (every ITCH and
// OUCH message, in order, with its destination session) is compared byte for
// byte. Every --check-every records and at the end of each seed the state
// hashes are compared (on mismatch the canonical encodings are diffed to name
// the first differing byte) and the engine's internal invariants are checked.
// Every --snapshot-every records the engine is snapshotted and replaced by a
// fresh engine restored from the payload, so restore is fuzzed too. Unless
// --no-validate, every emitted ITCH message passes the strict ITCH validator
// and every OUCH message passes validate_outbound. An "op" in the ledger is
// one record applied to both engines and compared.
//
// A lifecycle oracle independent of both engines (they share their reading of
// the spec, so the differential comparison cannot catch a shared misreading):
// after an 'A' or 'U' with Order State Dead, no OUCH message may refer to that
// order again (OUCH 5.0 §3.2-3.3). UserRefNums restart each day, so the set
// of dead orders does too.
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_set>
#include <vector>

#include "common/hash.h"
#include "engine/engine.h"
#include "gen.hpp"
#include "proto/itch50/validator.h"
#include "proto/ouch50/ouch50.h"
#include "ledger.hpp"
#include "ref_engine.hpp"

namespace {

using namespace lle::engine::harness;
using lle::engine::BufferSink;
using lle::engine::Dest;
using lle::engine::Engine;
using lle::engine::ref::RefEngine;
using lle::engine::ref::ROut;

struct Args {
  std::uint64_t seed_start = 1;
  std::uint64_t seeds = 10;
  std::uint64_t records = 20'000;
  std::uint64_t check_every = 1024;
  std::uint64_t snapshot_every = 8192;
  unsigned jobs = 1;
  std::string ledger;
  bool validate = true;
  bool verbose = false;
  bool stats = false;
};

struct Stats {
  std::uint64_t ops = 0;
  std::uint64_t state_checks = 0;
  std::uint64_t restores = 0;
  std::uint64_t messages = 0;
  std::uint64_t divergences = 0;
  std::uint64_t seeds_done = 0;
  std::uint64_t dead_orders = 0;  // 'A'/'U' with Order State Dead watched by the lifecycle oracle
  std::uint64_t itch_types[128] = {};
  std::uint64_t ouch_types[128] = {};
  std::uint64_t audits[32] = {};
  std::uint64_t rejects[72] = {};
  std::uint64_t cancels[128] = {};
  std::uint64_t liquidity[128] = {};
  char first_divergence[512] = {};
};

std::string hex(std::span<const std::byte> b) {
  static constexpr char k[] = "0123456789abcdef";
  std::string s;
  for (std::byte x : b) {
    s += k[std::to_integer<unsigned>(x) >> 4];
    s += k[std::to_integer<unsigned>(x) & 15];
  }
  return s;
}

void dump(const char* who, const std::vector<ROut>& v) {
  std::fprintf(stderr, "  %s (%zu):\n", who, v.size());
  for (const ROut& o : v)
    std::fprintf(stderr, "    %s s=%u %c %s\n", o.itch ? "ITCH" : "OUCH", o.session,
                 o.bytes.empty() ? '?' : static_cast<char>(o.bytes[0]), hex(o.bytes).c_str());
}

void note(Stats& st, std::uint64_t seed, std::uint64_t rec, const char* what) {
  ++st.divergences;
  if (st.first_divergence[0] == '\0')
    std::snprintf(st.first_divergence, sizeof st.first_divergence, "seed %llu record %llu: %s",
                  static_cast<unsigned long long>(seed), static_cast<unsigned long long>(rec), what);
  std::fprintf(stderr, "enginediff: DIVERGENCE seed %llu record %llu: %s\n", static_cast<unsigned long long>(seed),
               static_cast<unsigned long long>(rec), what);
}

// The OUCH lifecycle oracle: keys (session, UserRefIdx, UserRefNum) of orders
// whose 'A'/'U' said Order State Dead. Returns false on a message that refers
// to one of them. UserRefNums never repeat per (account, UserRefIdx) within a
// day; the set is cleared at each DayStart.
class DeadOrders {
 public:
  bool check(std::uint32_t session, std::span<const std::byte> b) {
    if (b.size() < 17) return true;
    const auto v = lle::ouch50::OutboundDecoder::decode(b);
    if (!v) return true;  // validate_outbound reports malformed messages
    std::uint8_t idx = 0;
    if (const auto tv = v->tags().find(lle::ouch50::Tag::UserRefIdx); tv && tv->value.size() == 1) idx = tv->u8();
    const char type = std::to_integer<char>(b[0]);
    const std::uint32_t urn = lle::load_be32(b.data() + 9);  // the referenced (for 'U': original) order
    switch (type) {
      case 'U':
      case 'C':
      case 'D':
      case 'E':
      case 'B':
      case 'P':
      case 'I':
      case 'T':
      case 'M':
      case 'R':
        if (dead_.contains(key(session, idx, urn))) return false;
        break;
      default: break;
    }
    if (type == 'A' && v->as<lle::ouch50::out::OrderAcceptedView>().order_state() == lle::ouch50::OrderState::Dead)
      dead_.insert(key(session, idx, urn));
    if (type == 'U' && v->as<lle::ouch50::out::OrderReplacedView>().order_state() == lle::ouch50::OrderState::Dead)
      dead_.insert(key(session, idx, lle::load_be32(b.data() + 13)));
    return true;
  }
  [[nodiscard]] std::size_t dead() const noexcept { return total_ + dead_.size(); }
  void new_day() {
    total_ += dead_.size();
    dead_.clear();
  }

 private:
  static std::uint64_t key(std::uint32_t s, std::uint8_t idx, std::uint32_t urn) {
    return (std::uint64_t{s} << 40) ^ (std::uint64_t{idx} << 32) ^ urn;
  }
  std::unordered_set<std::uint64_t> dead_;
  std::size_t total_ = 0;
};

void run_seed(const Args& a, std::uint64_t seed, Stats& st) {
  lle::engine::gen::Generator g(seed);
  auto eng = std::make_unique<Engine>();
  RefEngine ref;
  BufferSink sink;
  sink.reserve(1 << 12, 1 << 16);
  std::vector<ROut> got, want;
  lle::itch50::Validator itch_val(true);
  DeadOrders dead;
  std::vector<std::byte> snap;
  for (std::uint64_t i = 0; i < a.records; ++i) {
    const lle::engine::InputRecord& rec = g.next();
    if (rec.type == static_cast<std::uint16_t>(lle::engine::RecordType::DayStart)) dead.new_day();
    sink.clear();
    eng->apply(rec, sink);
    want.clear();
    ref.apply(rec, want);
    got.clear();
    for (const BufferSink::Entry& e : sink.entries()) {
      if (e.dest == Dest::Audit) {
        ++st.audits[static_cast<unsigned>(e.audit.code) & 31u];
        continue;
      }
      const auto b = sink.bytes(e);
      if (!b.empty()) ++(e.dest == Dest::Itch ? st.itch_types : st.ouch_types)[std::to_integer<unsigned>(b[0]) & 127u];
      if (e.dest == Dest::Ouch && b.size() >= 15 && b[0] == std::byte{'J'})
        ++st.rejects[std::min<unsigned>(lle::load_be16(b.data() + 13), 71u)];
      if (e.dest == Dest::Ouch && b.size() >= 18 && b[0] == std::byte{'C'})
        ++st.cancels[std::to_integer<unsigned>(b[17]) & 127u];
      if (e.dest == Dest::Ouch && b.size() >= 26 && b[0] == std::byte{'E'})
        ++st.liquidity[std::to_integer<unsigned>(b[25]) & 127u];
      got.push_back(ROut{e.dest == Dest::Itch, e.session, {b.begin(), b.end()}});
      if (e.dest == Dest::Ouch && !dead.check(e.session, b)) {
        note(st, seed, rec.index, "OUCH message for an order after its Order State Dead 'A'/'U'");
        dump("engine", got);
        return;
      }
      if (a.validate) {
        const bool ok = e.dest == Dest::Itch ? itch_val.check(b) == 0 : lle::ouch50::validate_outbound(b).has_value();
        if (!ok) {
          note(st, seed, rec.index, e.dest == Dest::Itch ? "ITCH message fails strict validation"
                                                         : "OUCH message fails validate_outbound");
          dump("engine", got);
          return;
        }
      }
    }
    ++st.ops;
    st.messages += got.size();
    if (got != want) {
      note(st, seed, rec.index, "output streams differ");
      std::fprintf(stderr, "  record type %u payload %s\n", rec.type, hex(rec.payload).c_str());
      dump("engine", got);
      dump("ref", want);
      return;
    }
    const bool last = i + 1 == a.records;
    if ((i + 1) % a.check_every == 0 || last) {
      ++st.state_checks;
      std::string err;
      if (!eng->check(&err)) {
        note(st, seed, rec.index, ("engine invariant: " + err).c_str());
        return;
      }
      if (eng->state_hash() != ref.state_hash()) {
        snap.clear();
        eng->snapshot(snap);
        const auto rc = ref.canonical();
        std::size_t k = 0;
        while (k < snap.size() && k < rc.size() && snap[k] == rc[k]) ++k;
        char buf[160];
        std::snprintf(buf, sizeof buf, "state hash differs (canonical bytes differ at offset %zu of %zu/%zu)", k,
                      snap.size(), rc.size());
        note(st, seed, rec.index, buf);
        return;
      }
    }
    if (a.snapshot_every != 0 && (i + 1) % a.snapshot_every == 0) {
      snap.clear();
      eng->snapshot(snap);
      auto fresh = std::make_unique<Engine>();
      if (!fresh->restore(snap) || fresh->state_hash() != eng->state_hash()) {
        note(st, seed, rec.index, "snapshot/restore round trip changed the state");
        return;
      }
      eng = std::move(fresh);
      ++st.restores;
    }
  }
  if (itch_val.violations() != 0) note(st, seed, a.records, "ITCH validator violations");
  st.dead_orders += dead.dead();
  ++st.seeds_done;
  if (a.verbose)
    std::fprintf(stderr, "seed %llu ok: %llu records, live orders %zu\n", static_cast<unsigned long long>(seed),
                 static_cast<unsigned long long>(a.records), eng->live_orders());
}

Stats run_range(const Args& a, std::uint64_t first, std::uint64_t count) {
  Stats st;
  for (std::uint64_t s = first; s < first + count; ++s) run_seed(a, s, st);
  return st;
}

void append_ledger(const Args& a, const Provenance& pv, unsigned worker, std::uint64_t first, std::uint64_t count,
                   const Stats& st, double wall_s) {
  if (a.ledger.empty()) return;
  std::filesystem::create_directories(std::filesystem::path(a.ledger).parent_path());
  FILE* f = std::fopen(a.ledger.c_str(), "a");
  if (f == nullptr) {
    std::fprintf(stderr, "enginediff: cannot open ledger %s\n", a.ledger.c_str());
    return;
  }
  char run_id[96];
  std::snprintf(run_id, sizeof run_id, "enginediff-%s-%d-%u-%llu", pv.date.c_str(), static_cast<int>(::getpid()),
                worker, static_cast<unsigned long long>(first));
  std::fprintf(f,
               "{\"run_id\":\"%s\",\"harness\":\"enginediff\",\"book\":\"engine\",\"mode\":\"full\","
               "\"sha\":\"%s\",\"dirty\":%s,\"tree\":\"%s\",\"build\":\"%s\",\"variant\":\"engine\","
               "\"seed_start\":%llu,\"seeds\":%llu,\"records_per_seed\":%llu,\"check_every\":%llu,"
               "\"snapshot_every\":%llu,\"ops\":%llu,\"messages\":%llu,\"state_checks\":%llu,\"restores\":%llu,"
               "\"divergences\":%llu,\"wall_s\":%.3f,\"host\":\"%s\",\"date\":\"%s\"%s%s%s}\n",
               run_id, json_escape(pv.sha).c_str(), pv.dirty ? "true" : "false", pv.tree.c_str(),
               json_escape(pv.build).c_str(), static_cast<unsigned long long>(first),
               static_cast<unsigned long long>(count), static_cast<unsigned long long>(a.records),
               static_cast<unsigned long long>(a.check_every), static_cast<unsigned long long>(a.snapshot_every),
               static_cast<unsigned long long>(st.ops), static_cast<unsigned long long>(st.messages),
               static_cast<unsigned long long>(st.state_checks), static_cast<unsigned long long>(st.restores),
               static_cast<unsigned long long>(st.divergences), wall_s, json_escape(pv.host).c_str(), pv.date.c_str(),
               st.divergences != 0 ? ",\"first_divergence\":\"" : "",
               st.divergences != 0 ? json_escape(st.first_divergence).c_str() : "", st.divergences != 0 ? "\"" : "");
  std::fclose(f);
}

std::uint64_t run(const Args& a, const Provenance& pv) {
  const unsigned jobs = static_cast<unsigned>(std::min<std::uint64_t>(a.jobs, a.seeds == 0 ? 1 : a.seeds));
  const auto t0 = std::chrono::steady_clock::now();
  Stats total;
  if (jobs <= 1) {
    total = run_range(a, a.seed_start, a.seeds);
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    append_ledger(a, pv, 0, a.seed_start, a.seeds, total, wall);
  } else {
    struct Worker {
      pid_t pid;
      int fd;
      std::uint64_t first, count;
    };
    std::vector<Worker> ws;
    std::uint64_t next = a.seed_start;
    for (unsigned j = 0; j < jobs; ++j) {
      const std::uint64_t count = a.seeds / jobs + (j < a.seeds % jobs ? 1 : 0);
      int fds[2];
      if (::pipe(fds) != 0) {
        std::perror("pipe");
        std::exit(2);
      }
      const pid_t pid = ::fork();
      if (pid == 0) {
        ::close(fds[0]);
        const Stats st = run_range(a, next, count);
        const char* p = reinterpret_cast<const char*>(&st);
        std::size_t left = sizeof st;
        while (left > 0) {
          const ssize_t w = ::write(fds[1], p, left);
          if (w <= 0) break;
          p += w;
          left -= static_cast<std::size_t>(w);
        }
        ::_exit(0);
      }
      ::close(fds[1]);
      ws.push_back(Worker{pid, fds[0], next, count});
      next += count;
    }
    unsigned idx = 0;
    for (const Worker& w : ws) {
      Stats st;
      char* p = reinterpret_cast<char*>(&st);
      std::size_t left = sizeof st;
      bool ok = true;
      while (left > 0) {
        const ssize_t r = ::read(w.fd, p, left);
        if (r <= 0) {
          ok = false;
          break;
        }
        p += r;
        left -= static_cast<std::size_t>(r);
      }
      ::close(w.fd);
      int status = 0;
      ::waitpid(w.pid, &status, 0);
      if (!ok || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "enginediff: worker %u (seeds %llu..+%llu) crashed\n", idx,
                     static_cast<unsigned long long>(w.first), static_cast<unsigned long long>(w.count));
        st = Stats{};
        st.divergences = 1;
        std::snprintf(st.first_divergence, sizeof st.first_divergence, "worker crashed (status %d)", status);
      }
      const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
      append_ledger(a, pv, idx, w.first, w.count, st, wall);
      total.ops += st.ops;
      total.messages += st.messages;
      total.state_checks += st.state_checks;
      total.restores += st.restores;
      total.divergences += st.divergences;
      total.seeds_done += st.seeds_done;
      total.dead_orders += st.dead_orders;
      for (int k = 0; k < 128; ++k) total.itch_types[k] += st.itch_types[k], total.ouch_types[k] += st.ouch_types[k];
      for (int k = 0; k < 32; ++k) total.audits[k] += st.audits[k];
      for (int k = 0; k < 72; ++k) total.rejects[k] += st.rejects[k];
      for (int k = 0; k < 128; ++k) total.cancels[k] += st.cancels[k];
      for (int k = 0; k < 128; ++k) total.liquidity[k] += st.liquidity[k];
      ++idx;
    }
  }
  const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  if (a.stats) {
    std::printf("ITCH:");
    for (int k = 0; k < 128; ++k)
      if (total.itch_types[k] != 0) std::printf(" %c=%llu", k, static_cast<unsigned long long>(total.itch_types[k]));
    std::printf("\nOUCH:");
    for (int k = 0; k < 128; ++k)
      if (total.ouch_types[k] != 0) std::printf(" %c=%llu", k, static_cast<unsigned long long>(total.ouch_types[k]));
    std::printf("\nreject codes:");
    for (int k = 0; k < 72; ++k)
      if (total.rejects[k] != 0) std::printf(" 0x%04x=%llu", k, static_cast<unsigned long long>(total.rejects[k]));
    std::printf("\ncancel reasons:");
    for (int k = 0; k < 128; ++k)
      if (total.cancels[k] != 0) std::printf(" %c=%llu", k, static_cast<unsigned long long>(total.cancels[k]));
    std::printf("\nliquidity flags:");
    for (int k = 0; k < 128; ++k)
      if (total.liquidity[k] != 0) std::printf(" %c=%llu", k, static_cast<unsigned long long>(total.liquidity[k]));
    std::printf("\naudit:");
    for (int k = 0; k < 32; ++k)
      if (total.audits[k] != 0) std::printf(" %d=%llu", k, static_cast<unsigned long long>(total.audits[k]));
    std::printf("\nOrder State Dead 'A'/'U' (lifecycle oracle): %llu\n",
                static_cast<unsigned long long>(total.dead_orders));
  }
  std::printf(
      "enginediff seeds %llu..%llu  ops %llu  messages %llu  state_checks %llu  restores %llu  divergences %llu  "
      "wall %.2fs  (%.2fM ops/s)\n",
      static_cast<unsigned long long>(a.seed_start), static_cast<unsigned long long>(a.seed_start + a.seeds - 1),
      static_cast<unsigned long long>(total.ops), static_cast<unsigned long long>(total.messages),
      static_cast<unsigned long long>(total.state_checks), static_cast<unsigned long long>(total.restores),
      static_cast<unsigned long long>(total.divergences), wall,
      wall > 0 ? static_cast<double>(total.ops) / wall / 1e6 : 0.0);
  std::fflush(stdout);
  return total.divergences;
}

bool parse(int argc, char** argv, Args& a) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    std::string val;
    auto take = [&](const char* name) {
      const std::string n = name;
      if (arg == n && i + 1 < argc) {
        val = argv[++i];
        return true;
      }
      if (arg.rfind(n + "=", 0) == 0) {
        val = arg.substr(n.size() + 1);
        return true;
      }
      return false;
    };
    if (take("--seed-start")) {
      a.seed_start = std::strtoull(val.c_str(), nullptr, 0);
    } else if (take("--seeds")) {
      a.seeds = std::strtoull(val.c_str(), nullptr, 0);
    } else if (take("--records-per-seed")) {
      a.records = std::strtoull(val.c_str(), nullptr, 0);
    } else if (take("--check-every")) {
      a.check_every = std::max<std::uint64_t>(1, std::strtoull(val.c_str(), nullptr, 0));
    } else if (take("--snapshot-every")) {
      a.snapshot_every = std::strtoull(val.c_str(), nullptr, 0);
    } else if (take("--jobs")) {
      a.jobs = static_cast<unsigned>(std::max<unsigned long>(1, std::strtoul(val.c_str(), nullptr, 0)));
    } else if (take("--ledger")) {
      a.ledger = val;
    } else if (arg == "--no-validate") {
      a.validate = false;
    } else if (arg == "--stats") {
      a.stats = true;
    } else if (arg == "--verbose") {
      a.verbose = true;
    } else {
      std::fprintf(stderr, "enginediff: unknown argument %s\n", argv[i]);
      return false;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  if (!parse(argc, argv, a)) return 2;
  const Provenance pv = provenance();
  return run(a, pv) == 0 ? 0 : 1;
}
