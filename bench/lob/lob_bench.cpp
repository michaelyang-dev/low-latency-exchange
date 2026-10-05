// LOB microbenchmarks (04-order-book §7): pre-generated synthetic ITCH-book
// streams shaped like 01302019, applied to each variant.
//
// INDICATIVE ONLY. These are synthetic streams on a development host, not the
// T11/T12 measurement (full-day real ITCH via apps/lob_replay on the lab
// host, 04 §5-§6); never publish them as headline numbers.
//
// Stream shape (research/data/01302019.stats.txt):
//   mix          A+F 44.7%, D 43.0%, U 7.4%, E+C 2.2% (78% full fills), X 1.3%
//   level rank   new prices drawn so 48.3% land at the touch, 79.8% within 5
//                and 94.1% within 16 levels (the measured touched-level ranks)
//   live orders  warm-up adds build the books to ~1.7M live orders (the
//                measured peak, 1,742,866) before the timed phase
//   books        2,000 locates with a mild popularity skew (top-10 books carry
//                ~5% of messages on the real day), penny ticks, drifting touch
//   refs         rising by 4 (the dominant delta on the real day)
// Each timed iteration starts from a fresh, pre-sized book at the warm-up
// state; the digest of the final books is checked equal across variants.
#include <benchmark/benchmark.h>

#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "book/digested_book.h"
#include "book/variants.h"
#include "common/hash.h"
#include "common/prng.h"

namespace {

using lle::Locate;
using lle::OrderRef;
using lle::PxE4;
using lle::Qty;
using lle::Side;

struct BenchOp {
  enum Kind : std::uint8_t { kAdd, kReduce, kRemove, kReplace };
  Kind kind;
  Side side;
  Locate loc;
  Qty qty;
  OrderRef ref;
  OrderRef new_ref;
  PxE4 px;
};

struct Mix {
  const char* name;
  std::uint32_t add, del, rep, exec, cancel;  // per 10,000
};
constexpr Mix kItch2019{"itch2019", 4471, 4297, 739, 224, 127};
constexpr Mix kUStorm{"ustorm", 3800, 3500, 2300, 250, 150};

// Touched-level rank distribution from the 01302019 scan, in 1/10,000.
constexpr std::uint32_t kRankCum[] = {4825, 6133, 6817, 7288, 7658, 7984, 8263, 8490,
                                      8692, 8862, 9002, 9116, 9211, 9289, 9354, 9409, 10000};

class StreamGen {
 public:
  StreamGen(std::uint64_t seed, std::uint32_t locates) : rng_(seed), books_(locates) {
    for (std::uint32_t i = 0; i < locates; ++i) {
      books_[i].touch = (10 + static_cast<PxE4>(rng_.below(490))) * 10'000;
      cum_weight_.push_back((cum_weight_.empty() ? 0 : cum_weight_.back()) + 1'000'000 / (i + 50));
    }
  }

  void warmup(std::size_t live_target, std::vector<BenchOp>& out) {
    while (orders_.size() < live_target) out.push_back(add());
  }

  void run(const Mix& m, std::size_t n, std::vector<BenchOp>& out) {
    for (std::size_t i = 0; i < n; ++i) {
      std::uint64_t r = rng_.below(m.add + m.del + m.rep + m.exec + m.cancel);
      if (r < m.add || orders_.empty()) {
        out.push_back(add());
        continue;
      }
      r -= m.add;
      const std::uint32_t o = pick();
      if (r < m.del) {
        out.push_back(BenchOp{BenchOp::kRemove, Side::Buy, 0, 0, orders_[o].ref, 0, 0});
        kill(o);
      } else if ((r -= m.del) < m.rep) {
        Live& l = orders_[o];
        BenchOp op{BenchOp::kReplace, l.side, l.loc, l.qty, l.ref, next_ref_, 0};
        next_ref_ += 4;
        op.px = rng_.chance(2, 100) ? l.px : price(l.loc, l.side);
        if (!rng_.chance(98, 100)) op.qty = qty();
        l.ref = op.new_ref;
        l.px = op.px;
        l.qty = op.qty;
        out.push_back(op);
      } else if ((r -= m.rep) < m.exec) {
        Live& l = orders_[o];
        if (rng_.chance(78, 100) || l.qty == 1) {
          out.push_back(BenchOp{BenchOp::kReduce, Side::Buy, 0, l.qty, l.ref, 0, 0});
          kill(o);
        } else {
          const Qty d = 1 + static_cast<Qty>(rng_.below(l.qty - 1));
          out.push_back(BenchOp{BenchOp::kReduce, Side::Buy, 0, d, l.ref, 0, 0});
          l.qty -= d;
        }
      } else {
        Live& l = orders_[o];
        if (l.qty == 1) {
          out.push_back(BenchOp{BenchOp::kRemove, Side::Buy, 0, 0, l.ref, 0, 0});
          kill(o);
        } else {
          const Qty d = 1 + static_cast<Qty>(rng_.below(l.qty - 1));
          out.push_back(BenchOp{BenchOp::kReduce, Side::Buy, 0, d, l.ref, 0, 0});
          l.qty -= d;
        }
      }
    }
  }

  std::uint32_t locates() const { return static_cast<std::uint32_t>(books_.size()); }

 private:
  struct Live {
    OrderRef ref;
    PxE4 px;
    Qty qty;
    Locate loc;
    Side side;
  };
  struct Book {
    PxE4 touch;
  };

  BenchOp add() {
    const auto loc = static_cast<Locate>(pick_locate() + 1);
    const Side s = rng_.chance(1, 2) ? Side::Buy : Side::Sell;
    Book& b = books_[loc - 1];
    if (rng_.chance(1, 200)) b.touch += rng_.chance(1, 2) ? 100 : -100;  // the touch drifts
    const BenchOp op{BenchOp::kAdd, s, loc, qty(), next_ref_, 0, price(loc, s)};
    next_ref_ += 4;
    orders_.push_back(Live{op.ref, op.px, op.qty, loc, s});
    return op;
  }

  PxE4 price(Locate loc, Side s) {
    const std::uint64_t u = rng_.below(10'000);
    PxE4 rank = 0;
    while (u >= kRankCum[rank]) ++rank;
    if (rank == 16) rank = 16 + static_cast<PxE4>(rng_.below(300));  // the tail beyond 16 levels
    const PxE4 touch = books_[loc - 1].touch;
    return s == Side::Buy ? touch - rank * 100 : touch + 100 + rank * 100;
  }

  Qty qty() { return rng_.chance(1, 2) ? 100 * static_cast<Qty>(1 + rng_.below(10)) : 1 + static_cast<Qty>(rng_.below(999)); }

  std::uint32_t pick_locate() {
    const std::uint64_t r = rng_.below(cum_weight_.back());
    std::size_t lo = 0, hi = cum_weight_.size() - 1;
    while (lo < hi) {
      const std::size_t mid = (lo + hi) / 2;
      if (cum_weight_[mid] > r) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    return static_cast<std::uint32_t>(lo);
  }

  std::uint32_t pick() { return static_cast<std::uint32_t>(rng_.below(orders_.size())); }
  void kill(std::uint32_t o) {
    orders_[o] = orders_.back();
    orders_.pop_back();
  }

  lle::Prng rng_;
  std::vector<Book> books_;
  std::vector<std::uint64_t> cum_weight_;
  std::vector<Live> orders_;
  OrderRef next_ref_ = 92;
};

struct Streams {
  std::vector<BenchOp> warm;
  std::vector<BenchOp> timed;
  std::uint32_t locates = 0;
};

const Streams& streams(const Mix& m, std::size_t live, std::size_t timed) {
  static std::map<std::string, Streams> cache;
  const std::string key = std::string(m.name) + "/" + std::to_string(live) + "/" + std::to_string(timed);
  auto it = cache.find(key);
  if (it != cache.end()) return it->second;
  Streams s;
  StreamGen g(0xB0B, 2'000);
  s.locates = g.locates();
  s.warm.reserve(live);
  g.warmup(live, s.warm);
  s.timed.reserve(timed);
  g.run(m, timed, s.timed);
  return cache.emplace(key, std::move(s)).first->second;
}

template <class Book>
inline void apply(Book& b, const BenchOp& op) {
  switch (op.kind) {
    case BenchOp::kAdd: b.add(op.ref, op.loc, op.side, op.px, op.qty); break;
    case BenchOp::kReduce: b.reduce(op.ref, op.qty); break;
    case BenchOp::kRemove: b.remove(op.ref); break;
    case BenchOp::kReplace: b.replace(op.ref, op.new_ref, op.px, op.qty); break;
  }
}

std::map<std::string, std::uint64_t>& digests() {
  static std::map<std::string, std::uint64_t> d;
  return d;
}

template <class V>
void BM_Replay(benchmark::State& state, Mix mix, std::size_t live, std::size_t timed) {
  const Streams& s = streams(mix, live, timed);
  lle::book::BookConfig cfg;
  cfg.reserve_orders = live + live / 4;
  cfg.reserve_levels = 1 << 18;
  cfg.levels_per_side = 64;
  std::uint64_t digest = 0;
  for (auto _ : state) {
    state.PauseTiming();
    auto db = std::make_unique<lle::book::DigestedBook<V>>(cfg);
    auto& b = db->book();
    for (Locate l = 1; l <= s.locates; ++l) b.stock_directory(l);
    for (const BenchOp& op : s.warm) apply(b, op);
    state.ResumeTiming();
    for (const BenchOp& op : s.timed) apply(b, op);
    benchmark::DoNotOptimize(db->recorder().digest.value);
    state.PauseTiming();
    digest = lle::combine(db->recorder().digest.value, b.books_digest());
    db.reset();
    state.ResumeTiming();
  }
  state.counters["ns/op"] =
      benchmark::Counter(static_cast<double>(s.timed.size()),
                         benchmark::Counter::kIsIterationInvariantRate | benchmark::Counter::kInvert);
  state.counters["live_peak"] = static_cast<double>(live);
  auto& slot = digests()[std::string(mix.name) + "/" + std::to_string(live) + "/" + std::string(V::kName)];
  slot = digest;
}

template <class V>
void register_variant(const Mix& m, std::size_t live, std::size_t timed) {
  const std::string name = std::string("replay/") + m.name + "/live" + std::to_string(live) + "/" + std::string(V::kName);
  benchmark::RegisterBenchmark(name.c_str(), [m, live, timed](benchmark::State& st) { BM_Replay<V>(st, m, live, timed); })
      ->Unit(benchmark::kMillisecond)
      ->UseRealTime()
      ->Iterations(3);
}

}  // namespace

int main(int argc, char** argv) {
  constexpr std::size_t kTimed = 4'000'000;
  struct Config {
    Mix mix;
    std::size_t live;
  };
  const Config configs[] = {{kItch2019, 1'700'000}, {kUStorm, 1'700'000}, {kItch2019, 20'000}};
  for (const Config& c : configs) {
    lle::book::for_each_variant([&]<class V>() {
      if constexpr (V::kName != "win_list_flat") register_variant<V>(c.mix, c.live, kTimed);
    });
  }
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  // Correctness gate: identical stream + final-books digests across variants.
  int bad = 0;
  std::map<std::string, std::uint64_t> first;
  for (const auto& [key, d] : digests()) {
    const auto slash = key.rfind('/');
    const std::string group = key.substr(0, slash);
    auto [it, fresh] = first.emplace(group, d);
    if (!fresh && it->second != d) {
      std::fprintf(stderr, "DIGEST MISMATCH %s\n", key.c_str());
      ++bad;
    }
  }
  std::printf("digest check across variants: %s\n", bad == 0 ? "OK" : "MISMATCH");
  return bad == 0 ? 0 : 1;
}
