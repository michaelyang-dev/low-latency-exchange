// lob_replay: full-day ITCH 5.0 replay benchmark for the book variants
// (04-order-book §5 and §6; targets T11a, T11b, T12).
//
//   lob_replay --file data/itch/01302019.NASDAQ_ITCH50.bin --variant opt
//              --mode throughput|sampled|block|all [--prefetch D] [--runs R] [--cpu N]
//              [--out DIR [--run-name run-01]] [--expect-sha256 HEX] [--env-json PATH]
//
// Every pass replays the whole input into a freshly constructed book. Its
// BBO-change-stream digest and final-books digest must equal RefBook's, or the
// run is invalid. Published numbers come from campaigns (lab/run_campaign.sh)
// that start one fresh process per repetition (--runs 1). --runs > 1 repeats
// inside one process and is for development only.
//
// Timed region: parse the BinaryFILE length prefix, dispatch, apply to the
// book, update the BBO, for every record. The book's listener folds each BBO
// change into the stream digest inside the timed region. That stands in for a
// BBO consumer and makes the measurement slightly conservative.
#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__linux__)
#include <sched.h>
#endif

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "book/digested_book.h"
#include "book/itch_adapter.h"
#include "book/variants.h"
#include "common/endian.h"
#include "common/prng.h"
#include "common/sha256.h"
#include "input.h"
#include "reference.h"
#include "stamp.h"

#ifndef LLE_CXX_ID
#define LLE_CXX_ID "unknown"
#endif
#ifndef LLE_CXX_FLAGS
#define LLE_CXX_FLAGS ""
#endif
#ifndef LLE_BUILD_TYPE
#define LLE_BUILD_TYPE ""
#endif

namespace lle::replay {
namespace {

enum class Mode : std::uint8_t { kThroughput, kSampled, kBlock, kAll };

constexpr std::string_view mode_name(Mode m) {
  switch (m) {
    case Mode::kThroughput: return "throughput";
    case Mode::kSampled: return "sampled";
    case Mode::kBlock: return "block";
    case Mode::kAll: return "all";
  }
  return "?";
}

struct Options {
  std::string file;
  std::string variant = "opt";
  Mode mode = Mode::kThroughput;
  unsigned prefetch = 0;
  int runs = 1;
  int cpu = -1;
  std::string out;
  std::string run_name;
  std::uint64_t max_records = 0;
  std::uint64_t seed = 1;
  unsigned sample_shift = 6;  // 1 in 2^6 = 64 records stamped (sampled mode)
  bool verify_sha = true;
  std::string expect_sha;
  std::string ref = "auto";  // auto | compute | skip
  std::string ref_path;
  HugePolicy huge = HugePolicy::kAuto;
  std::size_t reserve_orders = 0;  // 0: 1.25 x the reference's peak live orders
  std::size_t reserve_levels = std::size_t{1} << 20;
  std::size_t levels_per_side = 0;  // per-book level reserve at stock_directory (X27); 0 = book default
  bool prefault = true;
  bool baseline = true;  // sampled mode: unstamped pass first, for the <=3% slowdown rule
  unsigned warmup = 0;   // untimed full passes into throwaway books before the measured pass
  bool strict_faults = false;
  bool check = false;
  int perf_ctl_fd = -1;
  int perf_ack_fd = -1;
  std::string env_json;
};

[[noreturn]] void usage(const char* msg = nullptr) {
  if (msg) std::fprintf(stderr, "lob_replay: %s\n", msg);
  std::fprintf(stderr,
               "usage: lob_replay --file PATH [--variant NAME|all] [--mode throughput|sampled|block|all]\n"
               "                  [--prefetch D (<=16)] [--runs R] [--cpu N] [--out DIR] [--run-name NAME]\n"
               "                  [--max-records N] [--seed S] [--sample-shift K] [--no-sha] [--expect-sha256 HEX]\n"
               "                  [--ref auto|compute|skip] [--ref-path PATH] [--huge auto|1g|2m|thp|none]\n"
               "                  [--reserve-orders N] [--reserve-levels N] [--levels-per-side N] [--no-prefault]\n"
               "                  [--no-baseline] [--warmup N] [--strict-faults] [--check] [--perf-ctl-fd N --perf-ack-fd N] [--env-json PATH]\n");
  std::exit(2);
}

Options parse(int argc, char** argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    auto val = [&]() -> std::string {
      if (i + 1 >= argc) usage("missing value");
      return argv[++i];
    };
    auto num = [&]() -> std::uint64_t {
      const std::string v = val();
      char* end = nullptr;
      const std::uint64_t x = std::strtoull(v.c_str(), &end, 0);
      if (end == v.c_str() || *end != '\0') usage("bad number");
      return x;
    };
    if (a == "--file") o.file = val();
    else if (a == "--variant") o.variant = val();
    else if (a == "--mode") {
      const std::string m = val();
      if (m == "throughput") o.mode = Mode::kThroughput;
      else if (m == "sampled") o.mode = Mode::kSampled;
      else if (m == "block") o.mode = Mode::kBlock;
      else if (m == "all") o.mode = Mode::kAll;
      else usage("bad --mode");
    } else if (a == "--prefetch") o.prefetch = static_cast<unsigned>(num());
    else if (a == "--runs") o.runs = static_cast<int>(num());
    else if (a == "--cpu") o.cpu = static_cast<int>(num());
    else if (a == "--out") o.out = val();
    else if (a == "--run-name") o.run_name = val();
    else if (a == "--max-records") o.max_records = num();
    else if (a == "--seed") o.seed = num();
    else if (a == "--sample-shift") o.sample_shift = static_cast<unsigned>(num());
    else if (a == "--no-sha") o.verify_sha = false;
    else if (a == "--expect-sha256") o.expect_sha = val();
    else if (a == "--ref") o.ref = val();
    else if (a == "--ref-path") o.ref_path = val();
    else if (a == "--huge") {
      if (!parse_huge_policy(val(), o.huge)) usage("bad --huge");
    } else if (a == "--reserve-orders") o.reserve_orders = num();
    else if (a == "--reserve-levels") o.reserve_levels = num();
    else if (a == "--levels-per-side") o.levels_per_side = num();
    else if (a == "--no-prefault") o.prefault = false;
    else if (a == "--no-baseline") o.baseline = false;
    else if (a == "--warmup") o.warmup = static_cast<unsigned>(num());
    else if (a == "--strict-faults") o.strict_faults = true;
    else if (a == "--check") o.check = true;
    else if (a == "--perf-ctl-fd") o.perf_ctl_fd = static_cast<int>(num());
    else if (a == "--perf-ack-fd") o.perf_ack_fd = static_cast<int>(num());
    else if (a == "--env-json") o.env_json = val();
    else if (a == "--help" || a == "-h") usage();
    else usage(("unknown option " + std::string(a)).c_str());
  }
  if (o.file.empty()) usage("--file is required");
  if (o.prefetch > 16) usage("--prefetch is limited to 16 records (04 §6 prefetch disclosure)");
  if (o.sample_shift > 16) usage("--sample-shift must be <= 16");
  if (o.ref != "auto" && o.ref != "compute" && o.ref != "skip") usage("bad --ref");
  if (o.runs < 1) usage("--runs must be >= 1");
  return o;
}

// perf stat --control fd:CTL,ACK -D -1: counters run only inside the timed region.
struct PerfControl {
  int ctl = -1, ack = -1;
  void send(const char* cmd) const {
    if (ctl < 0) return;
    if (::write(ctl, cmd, std::strlen(cmd)) < 0) return;
    if (ack >= 0) {
      char buf[16];
      if (::read(ack, buf, sizeof buf) < 0) return;
    }
  }
};

// Preallocated, pre-touched sample storage, so the timed region allocates nothing.
struct Samples {
  std::vector<std::uint64_t> at;     // sampled mode: record indices to stamp, ascending, sentinel last
  std::vector<std::uint32_t> delta;  // counter ticks per stamped record (or per 64-record block)
  std::vector<std::uint8_t> kind;    // ItchKind of each stamped record
  std::vector<std::uint32_t> floor;  // empty stamp pairs, one per 1,024 records
  std::size_t n_delta = 0;
  std::size_t n_floor = 0;
};

struct Pass {
  std::int64_t wall_ns = 0;
  std::uint64_t ticks = 0;
  std::uint64_t records = 0;
  std::uint64_t bad_status = 0;
  long minor_faults = 0;
  long major_faults = 0;
  std::uint64_t bbo_digest = 0;
  std::uint64_t bbo_events = 0;
  std::uint64_t books_digest = 0;
  std::uint64_t live_end = 0;
  bool invariants_ok = true;
};

template <Mode M, bool kPrefetch, class Book>
[[gnu::noinline]] Pass replay(Book& b, const std::byte* p, std::size_t n, unsigned dist, Samples& s,
                              const PerfControl& perf) {
  using Clock = std::chrono::steady_clock;
  std::size_t pos = 0, ahead = 0, k = 0, f = 0;
  std::uint64_t i = 0, bad = 0, next = M == Mode::kSampled ? s.at[0] : 0, block_t0 = 0;
  if constexpr (kPrefetch) {
    for (unsigned d = 0; d < dist && ahead + 2 <= n; ++d) ahead += 2u + load_be16(p + ahead);
  }
  rusage r0{}, r1{};
  getrusage(RUSAGE_SELF, &r0);
  perf.send("enable\n");
  const auto t0 = Clock::now();
  const std::uint64_t c0 = stamp_begin();
  while (pos < n) {
    if constexpr (kPrefetch) {
      // A hint only: never reads past the buffer, even for a short final record.
      if (ahead + 29 <= n) {
        prefetch_itch(b, p + ahead + 2);
        ahead += 2u + load_be16(p + ahead);
      }
    }
    if constexpr (M == Mode::kThroughput) {
      const std::size_t len = load_be16(p + pos);
      bad += book::apply_itch(b, p + pos + 2, len).status != book::Status::kOk;
      pos += 2 + len;
    } else if constexpr (M == Mode::kSampled) {
      if (i == next) [[unlikely]] {
        const std::uint64_t a = stamp_begin();
        const std::size_t len = load_be16(p + pos);
        const book::ItchResult r = book::apply_itch(b, p + pos + 2, len);
        const std::uint64_t z = stamp_end();
        s.delta[k] = static_cast<std::uint32_t>(z - a);
        s.kind[k] = static_cast<std::uint8_t>(r.kind);
        bad += r.status != book::Status::kOk;
        pos += 2 + len;
        next = s.at[++k];
      } else {
        const std::size_t len = load_be16(p + pos);
        bad += book::apply_itch(b, p + pos + 2, len).status != book::Status::kOk;
        pos += 2 + len;
      }
      if ((i & 1023) == 0) [[unlikely]] {
        const std::uint64_t a = stamp_begin();
        const std::uint64_t z = stamp_end();
        s.floor[f++] = static_cast<std::uint32_t>(z - a);
      }
    } else if constexpr (M == Mode::kAll) {
      const std::uint64_t a = stamp_begin();
      const std::size_t len = load_be16(p + pos);
      const book::ItchResult r = book::apply_itch(b, p + pos + 2, len);
      const std::uint64_t z = stamp_end();
      s.delta[k] = static_cast<std::uint32_t>(z - a);
      s.kind[k++] = static_cast<std::uint8_t>(r.kind);
      bad += r.status != book::Status::kOk;
      pos += 2 + len;
      if ((i & 1023) == 0) [[unlikely]] {
        const std::uint64_t a2 = stamp_begin();
        const std::uint64_t z2 = stamp_end();
        s.floor[f++] = static_cast<std::uint32_t>(z2 - a2);
      }
    } else {  // kBlock: 64-record blocks; a cross-check, not per-message percentiles
      if ((i & 63) == 0) block_t0 = stamp_begin();
      const std::size_t len = load_be16(p + pos);
      bad += book::apply_itch(b, p + pos + 2, len).status != book::Status::kOk;
      pos += 2 + len;
      if ((i & 63) == 63) s.delta[k++] = static_cast<std::uint32_t>(stamp_end() - block_t0);
    }
    ++i;
  }
  const std::uint64_t c1 = stamp_end();
  const auto t1 = Clock::now();
  perf.send("disable\n");
  getrusage(RUSAGE_SELF, &r1);
  s.n_delta = k;
  s.n_floor = f;
  Pass out;
  out.wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
  out.ticks = c1 - c0;
  out.records = i;
  out.bad_status = bad;
  out.minor_faults = r1.ru_minflt - r0.ru_minflt;
  out.major_faults = r1.ru_majflt - r0.ru_majflt;
  return out;
}

template <Mode M, class Book>
Pass replay_any(Book& b, const Input& in, unsigned dist, Samples& s, const PerfControl& perf) {
  return dist == 0 ? replay<M, false>(b, in.data(), in.size(), 0, s, perf)
                   : replay<M, true>(b, in.data(), in.size(), dist, s, perf);
}

// Excludes records of length 0 (end of session), which apply_itch never sees
// as messages; the reference counts messages the same way.
std::uint64_t count_messages(const Pass& p, const FrameScan& scan) { return p.records - scan.end_of_session; }

Samples make_samples(Mode m, std::uint64_t records, unsigned shift, std::uint64_t seed) {
  Samples s;
  s.floor.assign(records / 1024 + 2, 0);
  if (m == Mode::kSampled) {
    // Each record is stamped with probability 2^-shift, from a seeded xoshiro
    // sequence fixed before the run (04 §5).
    Prng rng(seed);
    const std::uint64_t mask = (std::uint64_t{1} << shift) - 1;
    s.at.reserve(records / (mask + 1) + records / (mask + 1) / 8 + 16);
    for (std::uint64_t i = 0; i < records; ++i)
      if ((rng.next_u64() & mask) == 0) s.at.push_back(i);
    s.at.push_back(~std::uint64_t{0});
    s.delta.assign(s.at.size(), 0);
    s.kind.assign(s.at.size(), 0);
  } else if (m == Mode::kAll) {
    s.delta.assign(records + 1, 0);
    s.kind.assign(records + 1, 0);
  } else if (m == Mode::kBlock) {
    s.delta.assign(records / 64 + 1, 0);
  }
  return s;
}

std::string hex64(std::uint64_t v) {
  char b[17];
  std::snprintf(b, sizeof b, "%016" PRIx64, v);
  return b;
}

std::string run_cmd(const char* cmd) {
  std::string out;
  if (FILE* f = popen(cmd, "r")) {
    char buf[256];
    while (std::fgets(buf, sizeof buf, f)) out += buf;
    pclose(f);
  }
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
  return out;
}

// Flat JSON object, as tools/results/summarize.py reads it: numbers are
// metrics; strings and booleans are metadata.
class Json {
 public:
  void num(const std::string& k, double v) {
    char b[64];
    std::snprintf(b, sizeof b, "%.6f", v);
    std::string s = b;
    while (s.back() == '0') s.pop_back();
    if (s.back() == '.') s.pop_back();
    add(k, s);
  }
  void integer(const std::string& k, std::uint64_t v) { add(k, std::to_string(v)); }
  void boolean(const std::string& k, bool v) { add(k, v ? "true" : "false"); }
  void str(const std::string& k, const std::string& v) {
    std::string e = "\"";
    for (char c : v) {
      if (c == '"' || c == '\\') e += '\\';
      if (static_cast<unsigned char>(c) < 0x20) continue;
      e += c;
    }
    add(k, e + "\"");
  }
  [[nodiscard]] std::string done() const { return "{\n" + body_ + "\n}\n"; }

 private:
  void add(const std::string& k, const std::string& v) {
    if (!body_.empty()) body_ += ",\n";
    body_ += "  \"" + k + "\": " + v;
  }
  std::string body_;
};

struct Context {
  Options opt;
  Input in;
  FrameScan scan;
  std::string sha;
  std::optional<Reference> ref;
  double hz = 0;
  Granularity gran;
  std::string git_sha, git_dirty, host, env_sha;
  PerfControl perf;
};

void add_quantiles(Json& j, const std::string& prefix, const Quantiles& q, double ns_per_tick, double floor_ns) {
  static constexpr std::pair<const char*, double> kQ[] = {{"p50", 0.5},   {"p90", 0.9},     {"p99", 0.99},
                                                          {"p999", 0.999}, {"p9999", 0.9999}};
  for (const auto& [name, x] : kQ) {
    const double raw = q.at(x) * ns_per_tick;
    j.num("raw_" + prefix + name + "_ns", raw);
    j.num("net_" + prefix + name + "_ns", raw - floor_ns);
  }
  j.num("raw_" + prefix + "max_ns", q.max() * ns_per_tick);
  j.num("raw_" + prefix + "mean_ns", q.mean() * ns_per_tick);
  j.num("net_" + prefix + "mean_ns", q.mean() * ns_per_tick - floor_ns);
  j.integer(prefix + "samples", q.size());
}

template <class V>
book::BookConfig book_config(const Context& c) {
  book::BookConfig cfg;
  const std::uint64_t peak = c.ref ? c.ref->peak_live : 0;
  cfg.reserve_orders = c.opt.reserve_orders != 0 ? c.opt.reserve_orders
                                                 : std::max<std::size_t>(std::size_t{1} << 16, peak + peak / 4);
  cfg.reserve_levels = c.opt.reserve_levels;
  cfg.levels_per_side = c.opt.levels_per_side;
  cfg.prefault = c.opt.prefault;
  return cfg;
}

template <class V, Mode M>
Pass one_pass(const Context& c, Samples& s) {
  auto db = std::make_unique<book::DigestedBook<V>>(book_config<V>(c));
  Pass p = replay_any<M>(db->book(), c.in, c.opt.prefetch, s, c.perf);
  p.bbo_digest = db->recorder().digest.value;
  p.bbo_events = db->recorder().digest.events;
  p.books_digest = db->book().books_digest();
  p.live_end = db->book().live_orders();
  if (c.opt.check) {
    std::string err;
    p.invariants_ok = db->book().check_invariants(&err);
    if (!p.invariants_ok) std::fprintf(stderr, "invariant check failed: %s\n", err.c_str());
  }
  return p;
}

std::string gate(const Context& c, const Pass& p) {
  if (p.bad_status != 0) return "book rejected " + std::to_string(p.bad_status) + " operations";
  if (!p.invariants_ok) return "invariant check failed";
  if (!c.ref) return "no reference digest (--ref skip)";
  const Reference& r = *c.ref;
  if (count_messages(p, c.scan) != r.records) return "record count differs from reference";
  if (p.bbo_digest != r.bbo_digest || p.bbo_events != r.bbo_events) return "BBO-stream digest differs from reference";
  if (p.books_digest != r.books_digest || p.live_end != r.live_end) return "final-books digest differs from reference";
  return {};
}

template <class V>
int run_variant(const Context& c, int run_idx) {
  const Options& o = c.opt;
  const double ns_per_tick = 1e9 / c.hz;
  Json j;
  j.str("tool", "lob_replay");
  j.str("variant", std::string(V::kName));
  j.str("mode", std::string(mode_name(o.mode)));
  j.str("file", o.file);
  j.str("file_sha256", c.sha);
  j.integer("max_records", o.max_records);
  j.integer("bytes", c.in.size());
  j.str("hugepages", c.in.pages());
  j.boolean("input_locked", c.in.locked());
  j.integer("prefetch", o.prefetch);
  j.integer("reserve_levels", o.reserve_levels);
  j.integer("levels_per_side", o.levels_per_side);
  j.num("cpu", o.cpu);
  j.integer("run_index", static_cast<std::uint64_t>(run_idx));
  j.num("tsc_hz", c.hz);
  j.num("tsc_min_step_ns", static_cast<double>(c.gran.min_step_ticks) * ns_per_tick);
  const bool coarse = static_cast<double>(c.gran.min_step_ticks) * ns_per_tick > 2.0;
  j.boolean("coarse_tsc", coarse);
  j.boolean("bbo_digest_in_timed_region", true);

  std::string invalid;
  // Warm-up passes (METHODOLOGY §LOB): identical for every variant. They leave
  // the allocator's heap grown and resident, which is the best configuration
  // for designs that allocate on demand (B0), and are digest-checked as well.
  for (unsigned w = 0; w < o.warmup; ++w) {
    Samples none = make_samples(Mode::kThroughput, 0, 0, 0);
    const Pass wp = one_pass<V, Mode::kThroughput>(c, none);
    if (const std::string g = gate(c, wp); !g.empty() && invalid.empty()) invalid = "warm-up pass: " + g;
  }
  j.integer("warmup_passes", o.warmup);
  double baseline_ns = 0;
  if (o.mode == Mode::kSampled && o.baseline) {
    Samples none = make_samples(Mode::kThroughput, c.scan.records + c.scan.end_of_session, 0, 0);
    const Pass b = one_pass<V, Mode::kThroughput>(c, none);
    if (const std::string g = gate(c, b); !g.empty()) invalid = "baseline pass: " + g;
    baseline_ns = static_cast<double>(b.wall_ns);
    j.num("baseline_wall_ns", baseline_ns);
    j.num("baseline_msgs_per_s", static_cast<double>(count_messages(b, c.scan)) * 1e9 / baseline_ns);
  }

  Samples s = make_samples(o.mode, c.scan.records + c.scan.end_of_session, o.sample_shift, o.seed + static_cast<std::uint64_t>(run_idx));
  Pass p;
  switch (o.mode) {
    case Mode::kThroughput: p = one_pass<V, Mode::kThroughput>(c, s); break;
    case Mode::kSampled: p = one_pass<V, Mode::kSampled>(c, s); break;
    case Mode::kBlock: p = one_pass<V, Mode::kBlock>(c, s); break;
    case Mode::kAll: p = one_pass<V, Mode::kAll>(c, s); break;
  }
  if (const std::string g = gate(c, p); !g.empty() && invalid.empty()) invalid = g;

  const std::uint64_t msgs = count_messages(p, c.scan);
  j.integer("records", msgs);
  j.num("wall_ns", static_cast<double>(p.wall_ns));
  j.num("msgs_per_s", static_cast<double>(msgs) * 1e9 / static_cast<double>(p.wall_ns));
  j.num("ns_per_msg_mean", static_cast<double>(p.wall_ns) / static_cast<double>(msgs));
  j.num("tsc_hz_from_run", static_cast<double>(p.ticks) * 1e9 / static_cast<double>(p.wall_ns));
  j.integer("minor_faults", static_cast<std::uint64_t>(p.minor_faults));
  j.integer("major_faults", static_cast<std::uint64_t>(p.major_faults));
  j.integer("bbo_events", p.bbo_events);
  j.str("bbo_digest", hex64(p.bbo_digest));
  j.str("books_digest", hex64(p.books_digest));
  if (c.ref) {
    j.str("ref_bbo_digest", hex64(c.ref->bbo_digest));
    j.str("ref_books_digest", hex64(c.ref->books_digest));
    j.integer("peak_live_orders", c.ref->peak_live);
  }
  if (o.strict_faults && (p.minor_faults != 0 || p.major_faults != 0) && invalid.empty())
    invalid = "page faults in the timed region";

  double floor_ns = 0;
  if (o.mode == Mode::kSampled || o.mode == Mode::kAll) {
    const Quantiles fl(std::vector<std::uint32_t>(s.floor.begin(), s.floor.begin() + static_cast<std::ptrdiff_t>(s.n_floor)));
    floor_ns = fl.at(0.5) * ns_per_tick;
    j.num("stamp_floor_ns", floor_ns);
    j.num("stamp_floor_mean_ns", fl.mean() * ns_per_tick);
    j.integer("stamp_floor_samples", fl.size());
    const Quantiles q(std::vector<std::uint32_t>(s.delta.begin(), s.delta.begin() + static_cast<std::ptrdiff_t>(s.n_delta)));
    add_quantiles(j, "", q, ns_per_tick, floor_ns);
    for (std::size_t kind = 0; kind < book::kItchKinds; ++kind) {
      std::vector<std::uint32_t> v;
      for (std::size_t x = 0; x < s.n_delta; ++x)
        if (s.kind[x] == kind) v.push_back(s.delta[x]);
      if (v.empty()) continue;
      const Quantiles qk(std::move(v));
      const std::string t = book::to_string(static_cast<book::ItchKind>(kind));
      j.num("net_p50_ns_" + t, qk.at(0.5) * ns_per_tick - floor_ns);
      j.num("net_p99_ns_" + t, qk.at(0.99) * ns_per_tick - floor_ns);
      j.num("net_mean_ns_" + t, qk.mean() * ns_per_tick - floor_ns);
      j.integer("samples_" + t, qk.size());
    }
    if (o.mode == Mode::kSampled && baseline_ns > 0) {
      const double slowdown = static_cast<double>(p.wall_ns) / baseline_ns - 1.0;
      j.num("stamp_slowdown", slowdown);
      if (slowdown > 0.03 && invalid.empty()) invalid = "sampled pass slowed throughput by more than 3%";
    }
  } else if (o.mode == Mode::kBlock) {
    std::vector<std::uint32_t> per(s.n_delta);
    for (std::size_t x = 0; x < s.n_delta; ++x) per[x] = (s.delta[x] + 32) / 64;
    const Quantiles q(std::move(per));
    j.num("block64_p50_ns_per_msg", q.at(0.5) * ns_per_tick);
    j.num("block64_p99_ns_per_msg", q.at(0.99) * ns_per_tick);
    j.integer("block64_samples", q.size());
  }

  j.boolean("valid", invalid.empty());
  j.str("invalid_reason", invalid);
  j.str("git_sha", c.git_sha);
  j.str("git_dirty", c.git_dirty);
  j.str("compiler", LLE_CXX_ID);
  j.str("cxx_flags", LLE_CXX_FLAGS);
  j.str("build_type", LLE_BUILD_TYPE);
  j.str("host", c.host);
  j.str("env_json_sha256", c.env_sha);
  const std::string doc = j.done();

  if (o.out.empty()) {
    std::fputs(doc.c_str(), stdout);
  } else {
    std::string name = o.run_name.empty() ? "run-" + std::to_string(run_idx + 1) : o.run_name;
    if (o.runs > 1 && !o.run_name.empty()) name += "-" + std::to_string(run_idx + 1);
    if (o.variant == "all") name += "-" + std::string(V::kName);
    const std::string path = o.out + "/" + name + ".json";
    std::ofstream f(path, std::ios::trunc);
    f << doc;
    if (!f) {
      std::fprintf(stderr, "lob_replay: cannot write %s\n", path.c_str());
      return 1;
    }
  }
  std::fprintf(stderr, "%-14s %-10s %12.0f msgs/s  %7.2f ns/msg mean  digest %s%s%s\n", std::string(V::kName).c_str(),
               std::string(mode_name(o.mode)).c_str(), static_cast<double>(msgs) * 1e9 / static_cast<double>(p.wall_ns),
               static_cast<double>(p.wall_ns) / static_cast<double>(msgs), invalid.empty() ? "ok" : "INVALID",
               invalid.empty() ? "" : ": ", invalid.c_str());
  return invalid.empty() ? 0 : 3;
}

int main_impl(int argc, char** argv) {
  Context c;
  c.opt = parse(argc, argv);
  const Options& o = c.opt;

#if defined(__linux__)
  if (o.cpu >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(static_cast<std::size_t>(o.cpu), &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0) std::fprintf(stderr, "lob_replay: cannot pin to CPU %d\n", o.cpu);
  }
#else
  if (o.cpu >= 0) std::fprintf(stderr, "lob_replay: --cpu is ignored on this platform\n");
#endif
  c.perf = PerfControl{o.perf_ctl_fd, o.perf_ack_fd};

  auto in = Input::load(o.file, o.max_records, o.huge);
  if (!in) {
    std::fprintf(stderr, "lob_replay: %s\n", in.error().c_str());
    return 1;
  }
  c.in = std::move(*in);
  c.scan = scan_frames(c.in.data(), c.in.size());
  if (c.scan.truncated) {
    std::fprintf(stderr, "lob_replay: input ends inside a record\n");
    return 1;
  }
  if (o.verify_sha) {
    c.sha = Sha256::hex(Sha256::of(c.in.data(), c.in.size()));
    if (!o.expect_sha.empty() && o.expect_sha != c.sha) {
      std::fprintf(stderr, "lob_replay: SHA-256 mismatch: got %s, expected %s\n", c.sha.c_str(), o.expect_sha.c_str());
      return 1;
    }
  } else {
    c.sha = "unverified";
  }
  std::fprintf(stderr, "input: %" PRIu64 " messages, %zu bytes, pages %s%s, sha256 %s\n", c.scan.records, c.in.size(),
               c.in.pages().c_str(), c.in.locked() ? " (locked)" : "", c.sha.c_str());

  if (o.ref != "skip") {
    const std::string ref_path =
        !o.ref_path.empty() ? o.ref_path
                            : o.file + ".lobref" + (o.max_records ? "-" + std::to_string(o.max_records) : "");
    if (o.ref == "auto" && o.verify_sha) c.ref = load_reference(ref_path, c.sha, o.max_records);
    if (!c.ref) {
      std::fprintf(stderr, "reference: replaying through RefBook (untimed)...\n");
      Reference r = compute_reference(c.in.data(), c.in.size());
      r.sha256 = c.sha;
      r.max_records = o.max_records;
      if (r.bad_status != 0) std::fprintf(stderr, "reference: RefBook rejected %" PRIu64 " operations\n", r.bad_status);
      if (o.verify_sha && !save_reference(ref_path, r))
        std::fprintf(stderr, "reference: cannot cache to %s\n", ref_path.c_str());
      c.ref = r;
    }
    std::fprintf(stderr, "reference: bbo %s (%" PRIu64 " events), books %s, peak live %" PRIu64 "\n",
                 hex64(c.ref->bbo_digest).c_str(), c.ref->bbo_events, hex64(c.ref->books_digest).c_str(),
                 c.ref->peak_live);
  }

  c.hz = counter_hz();
  c.gran = probe_granularity();
  if (const char* e = std::getenv("LLE_GIT_SHA")) c.git_sha = e;
  else c.git_sha = run_cmd("git rev-parse HEAD 2>/dev/null");
  c.git_dirty = run_cmd("git status --porcelain -- src apps bench 2>/dev/null | head -1").empty() ? "clean" : "dirty";
  utsname u{};
  if (uname(&u) == 0) c.host = std::string(u.nodename) + " " + u.sysname + " " + u.release + " " + u.machine;
  if (!o.env_json.empty()) {
    std::ifstream f(o.env_json, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    c.env_sha = Sha256::hex(Sha256::of(s.data(), s.size()));
  }

  int rc = 0;
  for (int r = 0; r < o.runs; ++r) {
    if (o.variant == "all") {
      book::for_each_variant([&]<class V>() { rc = std::max(rc, run_variant<V>(c, r)); });
    } else if (!book::visit_variant(o.variant, [&]<class V>() { rc = std::max(rc, run_variant<V>(c, r)); })) {
      usage(("unknown variant " + o.variant).c_str());
    }
  }
  return rc;
}

}  // namespace
}  // namespace lle::replay

int main(int argc, char** argv) { return lle::replay::main_impl(argc, argv); }
