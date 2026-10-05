// M3 (in situ) machinery, plan 11 §2: the real cost of logging inside a workload,
// measured as the change in mean time per message with logging on vs off,
// divided by the log calls per message.
//
// The protocol's M3 host is the engine replay harness / exchanged with logging
// on vs off; that instrumentation lands with exchange assembly (T32). Until then
// this harness runs the same A/B on the ITCH order book (lle_book OptBook) fed a
// deterministic synthetic stream with the 01302019 message mix (adds 44.7%,
// deletes 43.0%, replaces 7.4%, executions/cancels 3.5%), with 1 or 2 log calls
// per message (NLOG_INFO with a counter read, plus NLOG_EV for 2), the backend
// draining live. The book replays at ~18M msgs/s on the dev laptop, far above
// the exchange's T20 rate (4.2M msgs/s), so 2 calls per message there exceeds
// the plan 11 §3 budget of 8.4M records/s and can outrun the drain; 1 call per
// message is the default. Runs alternate off/on/on/off (ABBA) to cancel drift; the
// medians over rounds are reported.
//
// INDICATIVE ONLY on a development machine.
//
//   nlog_insitu_bench [--ops N] [--live N] [--rounds R] [--calls-per-msg 1|2] [--out PATH] [--json PATH]
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "book/variants.h"
#include "common/prng.h"
#include "log/backend.h"
#include "log/nlog.h"

namespace {

using lle::Locate;
using lle::OrderRef;
using lle::PxE4;
using lle::Qty;
using lle::Side;
using namespace lle::nlog;

struct Op {
  enum Kind : std::uint8_t { kAdd, kRemove, kReplace, kReduce };
  Kind kind;
  Side side;
  Locate loc;
  Qty qty;
  OrderRef ref;
  OrderRef new_ref;
  PxE4 px;
};

struct Stream {
  std::vector<Op> warm;   // builds the books (untimed)
  std::vector<Op> timed;  // measured
  Locate locates;
};

struct Live {
  OrderRef ref;
  Locate loc;
  Side side;
  Qty qty;
};

Stream make_stream(std::size_t live, std::size_t ops, std::uint64_t seed) {
  lle::Prng rng(seed);
  Stream s;
  s.locates = 500;
  std::vector<Live> book;
  book.reserve(live * 2);
  OrderRef next_ref = 4;
  auto new_add = [&](std::vector<Op>& out) {
    const auto loc = static_cast<Locate>(1 + rng.below(s.locates));
    const Side side = rng.below(2) == 0 ? Side::Buy : Side::Sell;
    // Near the touch: ~50% within 1 tick, most within 16 ticks of $100.00.
    const auto off = static_cast<PxE4>(rng.below(2) == 0 ? rng.below(2) : rng.below(16)) * 100;
    const PxE4 px = side == Side::Buy ? 1'000'000 - off : 1'000'100 + off;
    const auto qty = static_cast<Qty>(100 * (1 + rng.below(10)));
    out.push_back(Op{Op::kAdd, side, loc, qty, next_ref, 0, px});
    book.push_back(Live{next_ref, loc, side, qty});
    next_ref += 4;
  };
  for (std::size_t i = 0; i < live; ++i) new_add(s.warm);
  s.timed.reserve(ops);
  while (s.timed.size() < ops) {
    const std::uint64_t r = rng.below(10'000);
    if (r < 4471 || book.size() < 16) {
      new_add(s.timed);
      continue;
    }
    const std::size_t i = static_cast<std::size_t>(rng.below(book.size()));
    Live& o = book[i];
    if (r < 4471 + 4297) {
      s.timed.push_back(Op{Op::kRemove, o.side, o.loc, 0, o.ref, 0, 0});
      o = book.back();
      book.pop_back();
    } else if (r < 4471 + 4297 + 739) {
      const PxE4 px = o.side == Side::Buy ? 1'000'000 - static_cast<PxE4>(rng.below(8)) * 100
                                          : 1'000'100 + static_cast<PxE4>(rng.below(8)) * 100;
      s.timed.push_back(Op{Op::kReplace, o.side, o.loc, o.qty, o.ref, next_ref, px});
      o.ref = next_ref;
      next_ref += 4;
    } else if (o.qty > 100) {
      s.timed.push_back(Op{Op::kReduce, o.side, o.loc, 100, o.ref, 0, 0});
      o.qty -= 100;
    } else {
      s.timed.push_back(Op{Op::kRemove, o.side, o.loc, 0, o.ref, 0, 0});
      o = book.back();
      book.pop_back();
    }
  }
  return s;
}

using Book = lle::book::OptBook<>;

[[gnu::always_inline]] inline lle::book::Status apply(Book& b, const Op& op) {
  switch (op.kind) {
    case Op::kAdd: return b.add(op.ref, op.loc, op.side, op.px, op.qty);
    case Op::kRemove: return b.remove(op.ref);
    case Op::kReplace: return b.replace(op.ref, op.new_ref, op.px, op.qty);
    case Op::kReduce: return b.reduce(op.ref, op.qty);
  }
  return lle::book::Status::kUnknownRef;
}

double now_ns() {
  return static_cast<double>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

// One run: fresh book at the warm-up state, then the timed stream. Returns ns/msg.
template <int kCalls>
double run(const Stream& s, std::uint64_t& checksum) {
  lle::book::BookConfig cfg;
  cfg.reserve_orders = s.warm.size() * 2;
  cfg.reserve_levels = 1 << 14;
  Book book(cfg);
  for (Locate l = 1; l <= s.locates; ++l) book.stock_directory(l);
  for (const Op& op : s.warm) (void)apply(book, op);
  std::uint64_t bad = 0;
  const double t0 = now_ns();
  for (std::size_t i = 0; i < s.timed.size(); ++i) {
    const Op& op = s.timed[i];
    const lle::book::Status st = apply(book, op);
    bad += st == lle::book::Status::kOk ? 0 : 1;
    if constexpr (kCalls >= 1) {
      NLOG_INFO("book op {} ref {} px {} qty {}", static_cast<std::uint8_t>(op.kind), op.ref, op.px, op.qty);
    }
    if constexpr (kCalls >= 2) {
      NLOG_EV(i, "book status {} loc {} side {:c}", static_cast<std::uint8_t>(st), op.loc, op.side);
    }
  }
  const double t1 = now_ns();
  checksum += bad;
  return (t1 - t0) / static_cast<double>(s.timed.size());
}

double median(std::vector<double> v) {
  std::sort(v.begin(), v.end());
  return v[v.size() / 2];
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t ops = 2'000'000;
  std::size_t live = 200'000;
  int rounds = 8;
  const char* tmp = std::getenv("TMPDIR");
  std::string out = std::string(tmp != nullptr ? tmp : "/tmp") + "/nlog_insitu.nlog";
  std::string json_path;
  int calls_per_msg = 1;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    const char* v = i + 1 < argc ? argv[i + 1] : nullptr;
    if (a == "--ops" && v != nullptr) {
      ops = std::strtoull(v, nullptr, 10), ++i;
    } else if (a == "--live" && v != nullptr) {
      live = std::strtoull(v, nullptr, 10), ++i;
    } else if (a == "--rounds" && v != nullptr) {
      rounds = std::atoi(v), ++i;
    } else if (a == "--calls-per-msg" && v != nullptr) {
      calls_per_msg = std::atoi(v) == 2 ? 2 : 1, ++i;
    } else if (a == "--out" && v != nullptr) {
      out = v, ++i;
    } else if (a == "--json" && v != nullptr) {
      json_path = v, ++i;
    } else {
      std::fprintf(stderr, "usage: nlog_insitu_bench [--ops N] [--live N] [--rounds R] [--calls-per-msg 1|2] [--out PATH] [--json PATH]\n");
      return 1;
    }
  }
  const double kCallsPerMsg = calls_per_msg;
  const Stream s = make_stream(live, ops, 20261002);
  auto run_on = [&](std::uint64_t& ck) { return calls_per_msg == 2 ? run<2>(s, ck) : run<1>(s, ck); };
  ThreadScope scope({.ring_bytes = std::size_t{4} << 20, .name = "insitu"});  // production size (1-4 MiB)
  Backend be;
  BackendOptions o;
  o.path = out;
  o.node = "insitu";
  o.idle_sleep_us = 0;
  if (auto r = be.start(o); !r) {
    std::fprintf(stderr, "backend: %s\n", r.error().c_str());
    return 1;
  }
  std::uint64_t checksum = 0;
  (void)run<0>(s, checksum);  // warm caches and page tables
  (void)run_on(checksum);
  std::vector<double> off, on;
  const std::uint64_t drops0 = thread_drops();
  for (int r = 0; r < rounds; ++r) {
    if (r % 2 == 0) {
      off.push_back(run<0>(s, checksum));
      on.push_back(run_on(checksum));
    } else {
      on.push_back(run_on(checksum));
      off.push_back(run<0>(s, checksum));
    }
  }
  const std::uint64_t drops = thread_drops() - drops0;
  be.stop();
  std::remove(out.c_str());
  const double m_off = median(off);
  const double m_on = median(on);
  const double delta = m_on - m_off;
  std::printf("INDICATIVE DEV-LAPTOP DATA - M3 proxy on the ITCH order book (engine/exchanged M3 comes with T32)\n");
  std::printf("M3    %zu msgs x %d rounds (ABBA), %zu live orders, %.0f log calls/msg, drain live\n", ops, rounds, live,
              kCallsPerMsg);
  std::printf("M3    logging off %.2f ns/msg | on %.2f ns/msg | delta %.2f ns/msg = %.2f ns per log call | "
              "overhead %.1f%% | drops %llu%s (rejects %llu)\n",
              m_off, m_on, delta, delta / kCallsPerMsg, 100.0 * delta / m_off, static_cast<unsigned long long>(drops),
              drops != 0 ? "  ** INVALID: drops > 0 **" : "", static_cast<unsigned long long>(checksum));
  if (!json_path.empty()) {
    std::FILE* f = std::fopen(json_path.c_str(), "w");
    if (f == nullptr) return 1;
    std::fprintf(f,
                 "{\"host_indicative_only\": true, \"valid\": %s, \"m3_proxy_off_ns_per_msg\": %.4f, "
                 "\"m3_proxy_on_ns_per_msg\": %.4f, \"m3_proxy_delta_ns_per_call\": %.4f, \"m3_proxy_overhead_pct\": %.4f, "
                 "\"m3_proxy_drops\": %llu}\n",
                 drops == 0 ? "true" : "false", m_off, m_on, delta / kCallsPerMsg, 100.0 * delta / m_off,
                 static_cast<unsigned long long>(drops));
    std::fclose(f);
  }
  return 0;
}
