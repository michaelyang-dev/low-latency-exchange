// loadgen v2: the T20 instrument (07 §3 "loadgen", METHODOLOGY §15; WPs N-05, N-16).
// Open-loop OUCH 5.0 load over K SoupBinTCP sessions with the pre-registered mix and
// risk profile, per-response accounting, latency from each message's scheduled send
// time (plan 12 §5), on any I/O variant (client/variant.h), on one or more generator
// threads.
//
//   loadgen [run] --server IP:PORT [--profile FILE] [--sessions K] [--rate MSGS_PER_S] [--duration DUR]
//                 [--warmup DUR] [--seed S] [--symbols N] [--prefill N] [--constant] [--depth TICKS]
//                 [--threads T] [--cpus A,B,...] [--start-delay DUR] [--drain DUR] [--user-base N]
//                 [--password P] [--nic-sample N] [--slo-p99 DUR] [--max-lateness DUR]
//                 [--metrics-node NODE [--metrics-interval DUR]] [--allow-risk-violations]
//                 [--out DIR] [--run-name NAME] [variant flags: --variant V --ifname IF --timestamps M ...]
//   loadgen serve --listen IP:PORT [--ack-only] [--sessions N] [--symbols N] [--symbols-from ITCH_FILE]
//                 [--start-time HH:MM:SS] [--max-runtime DUR] [--cod] [--clock]
//                 [--mirror IP:PORT [--fail-primary-after DUR | --fail-primary-after-inbound N]
//                  [--stall-primary DUR]] [--backend B]
//   loadgen search --rate-lo R --rate-step S --rate-hi R [--reps N] --out DIR [--results DIR]
//                  [--runner CMD] [--before-run CMD] [--after-run CMD] -- RUN_ARGS...
//   loadgen sample-metrics --node NODE [--interval DUR] [--duration DUR] --out FILE.jsonl
//   loadgen check-backlog --samples FILE.jsonl --run RUN.json [--out FILE]
//   loadgen profile --profile FILE [--exchanged-risk FIRST_ACCOUNT:COUNT]
//
// `run` writes DIR/NAME.json (flat metrics for tools/results), DIR/NAME.hdr (the
// HdrHistogram interval log of the ack latency, one interval per second of schedule
// time plus the whole run) and DIR/NAME.hgrm (its percentile distribution). Validity:
//   responses_valid  every message got its expected response (0 Rejected, 0 Cancel Reject,
//                    0 unexpected), none missing, all sessions logged in, no disconnect,
//                    every scheduled message sent;
//   lateness_ok      generator lateness p99.9 <= --max-lateness (1 us);
//   backlog_ok       METHODOLOGY §15 condition 3, from the exchange's metrics segment
//                    (--metrics-node when the node is local; else `sample-metrics` on its
//                    host and `check-backlog` + tools/results/merge_t20.py);
//   slo_ok           p99 <= --slo-p99 (the pre-registered solo SLO);
//   valid            all four, evaluated.
// The schedule is refused before the run if the profile's risk limits would reject
// any of its orders (lg::RiskCheck), unless --allow-risk-violations.
//
// `serve` is the loopback OUCH server (the real sequencer and engine in-process,
// client/ouch_server.h) or, with --ack-only, the engine-free ack server of the capacity
// self-test (client/ack_server.h); usernames U00001..U<N>.
#include <hdr/hdr_histogram.h>

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "client/ack_server.h"
#include "client/backlog.h"
#include "client/cli.h"
#include "client/client_io.h"
#include "client/histogram.h"
#include "client/loadgen.h"
#include "client/loadgen_profile.h"
#include "client/loadgen_runner.h"
#include "client/ouch_server.h"
#include "client/report.h"
#include "client/variant.h"
#include "env/prod_clock.h"
#include "net/common/stack.h"
#include "proto/itch50/binary_file.h"
#include "proto/soupbin/client_session.h"
#include "runtime/pinning.h"

namespace {

using namespace lle;
using client::cli::Args;
namespace lg = client::lg;

std::atomic<bool> g_stop{false};
extern "C" void on_signal(int) { g_stop.store(true); }

struct ServeOptions {
  client::OuchServerConfig cfg{};
  std::string symbols_from;
  net::BackendKind backend = net::BackendKind::Epoll;
  bool ack_only = false;
};

Nanos duration_or_die(Args& a) {
  const std::string v = a.value();
  const auto d = client::cli::parse_duration(v);
  if (!d) a.die("bad duration: " + v);
  return *d;
}

// --- run ------------------------------------------------------------------------------------
struct RunOptions {
  net::Endpoint server{};
  lg::ScheduleConfig sched{};
  std::string profile_path;
  std::string profile_status = "none";
  Nanos start_delay = 200'000'000;
  Nanos drain = 2 * kNsPerSec;
  std::uint32_t user_base = 1;
  std::string password = "password";
  std::string out = ".";
  std::string run_name = "run-01";
  client::VariantConfig v;
  std::vector<std::uint64_t> cpus;
  std::uint64_t nic_sample = 0;
  Nanos slo_p99 = 0;
  Nanos max_lateness = 1'000;
  std::string metrics_node;
  Nanos metrics_interval = 250'000'000;
  bool allow_risk = false;
};

std::string i128s(i128 v) {
  if (v == 0) return "0";
  const bool neg = v < 0;
  u128 u = neg ? static_cast<u128>(-v) : static_cast<u128>(v);
  std::string s;
  while (u != 0) {
    s.insert(s.begin(), static_cast<char>('0' + static_cast<int>(u % 10)));
    u /= 10;
  }
  return neg ? "-" + s : s;
}

template <class Io>
int run_io(RunOptions& o, const std::vector<lg::Schedule>& sched, const client::DeviceReport& dev) {
  const std::uint32_t T = static_cast<std::uint32_t>(sched.size());
  std::vector<std::unique_ptr<lg::LoadRunner<Io>>> runners;
  lg::RunnerConfig rc;
  rc.server = o.server;
  rc.user_base = o.user_base;
  rc.password = o.password;
  rc.drain = o.drain;
  rc.nic_sample = o.nic_sample;
  rc.phc = dev.phc_index;
  const std::uint32_t port_span = (std::uint32_t{o.v.xsk.port_hi} - o.v.xsk.port_lo + 1) / T;
  for (std::uint32_t t = 0; t < T; ++t) {
    client::VariantConfig vt = o.v;
    vt.cpu = t < o.cpus.size() ? static_cast<int>(o.cpus[t]) : (o.v.cpu >= 0 ? o.v.cpu + static_cast<int>(t) : -1);
    vt.xsk.queue = o.v.xsk.queue + t;
    vt.xsk.port_lo = static_cast<std::uint16_t>(o.v.xsk.port_lo + t * port_span);
    vt.xsk.port_hi = static_cast<std::uint16_t>(vt.xsk.port_lo + port_span - 1);
    runners.push_back(std::make_unique<lg::LoadRunner<Io>>(sched[t], rc, vt));
    if (auto r = runners.back()->open(); !r) {
      std::fprintf(stderr, "loadgen: thread %u: %s\n", t, r.error().c_str());
      return 1;
    }
  }
  // Metrics sampler (a local exchange node): a few samples per second.
  std::vector<client::MetricsSample> samples;
  std::atomic<bool> sampler_stop{false};
  std::thread sampler;
  if (!o.metrics_node.empty()) {
    std::string err;
    auto ms = client::MetricsSampler::open(o.metrics_node, &err);
    if (!ms) {
      std::fprintf(stderr, "loadgen: metrics segment of %s: %s\n", o.metrics_node.c_str(), err.c_str());
      return 1;
    }
    sampler = std::thread([&, m = std::move(*ms)]() {
      env::ProdClock c;
      while (!sampler_stop.load()) {
        samples.push_back(m.sample(c.now_real()));
        std::this_thread::sleep_for(std::chrono::nanoseconds(o.metrics_interval));
      }
      samples.push_back(m.sample(c.now_real()));
    });
  }
  std::atomic<std::uint32_t> logged{0}, failed{0};
  std::atomic<Nanos> t0{0};
  std::vector<std::thread> threads;
  for (std::uint32_t t = 0; t < T; ++t) {
    threads.emplace_back([&, t]() {
      auto& r = *runners[t];
      const int cpu = t < o.cpus.size() ? static_cast<int>(o.cpus[t]) : (o.v.cpu >= 0 ? o.v.cpu + static_cast<int>(t) : -1);
      if (cpu >= 0) (void)rt::pin_current_thread(cpu);
      if (!r.login(10 * kNsPerSec, g_stop)) {
        failed.fetch_add(1);
        return;
      }
      logged.fetch_add(1);
      Nanos start = 0;
      while ((start = t0.load(std::memory_order_acquire)) == 0) {
        if (failed.load() != 0 || g_stop.load()) return;
      }
      if (start < 0) return;
      r.run(start, g_stop);
    });
  }
  env::ProdClock clock;
  while (logged.load() + failed.load() < T) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  const bool all_in = failed.load() == 0;
  const Nanos start = clock.now_mono() + o.start_delay;
  const std::int64_t real_off = clock.now_real() - clock.now_mono();
  t0.store(all_in ? start : -1, std::memory_order_release);
  for (auto& th : threads) th.join();
  if (sampler.joinable()) {
    sampler_stop.store(true);
    sampler.join();
  }
  if (!all_in) {
    std::fprintf(stderr, "loadgen: not every session logged in\n");
    return 1;
  }

  // ---- merge -----------------------------------------------------------------------------
  lg::AccountingStats st{};
  client::Histogram lat, late, w2w;
  std::array<client::Histogram, lg::kKinds> by_kind;
  std::vector<std::unique_ptr<client::Histogram>> iv;
  net::hwts::IntervalAccounting probe_acc;
  std::uint64_t sent = 0, tx_blocked = 0, login_rejects = 0, disconnects = 0, scheduled = 0, prefill = 0;
  Nanos end = start;
  for (auto& rp : runners) {
    auto& r = *rp;
    r.finish_probes();
    const auto& a = r.accounting().stats();
    st.sent += a.sent;
    st.acked += a.acked;
    st.missing += a.missing;
    for (std::size_t k = 0; k < lg::kKinds; ++k) st.acked_by_kind[k] += a.acked_by_kind[k];
    st.ioc_fills += a.ioc_fills;
    st.ioc_shares += a.ioc_shares;
    st.passive_fills += a.passive_fills;
    st.passive_shares += a.passive_shares;
    st.system_events += a.system_events;
    st.unexpected += a.unexpected;
    st.rejected += a.rejected;
    st.cancel_rejects += a.cancel_rejects;
    st.ioc_dead += a.ioc_dead;
    st.ioc_remainder += a.ioc_remainder;
    st.unknown_urn += a.unknown_urn;
    st.duplicate_ack += a.duplicate_ack;
    st.wrong_state += a.wrong_state;
    st.other += a.other;
    for (std::size_t k = 0; k < 256; ++k) st.reject_reasons_low[k] += a.reject_reasons_low[k];
    (void)hdr_add(lat.raw(), r.accounting().latency().h);
    (void)hdr_add(late.raw(), r.accounting().lateness().h);
    for (std::size_t k = 0; k < lg::kKinds; ++k)
      (void)hdr_add(by_kind[k].raw(), r.accounting().latency(static_cast<lg::Kind>(k)).h);
    auto& res = r.result();
    sent += res.sent;
    tx_blocked += res.tx_blocked;
    login_rejects += res.login_rejects;
    disconnects += res.disconnects;
    w2w.add(res.w2w);
    probe_acc.ok += res.probe_acc.ok;
    probe_acc.missing += res.probe_acc.missing;
    probe_acc.software += res.probe_acc.software;
    probe_acc.cross_phc += res.probe_acc.cross_phc;
    for (std::size_t i = 0; i < res.intervals.size(); ++i) {
      if (iv.size() <= i) iv.push_back(std::make_unique<client::Histogram>());
      iv[i]->add(*res.intervals[i]);
    }
    end = std::max(end, r.end());
  }
  for (const auto& s : sched) {
    scheduled += s.items.size();
    prefill += s.stats.prefill;
  }
  // Backlog (local metrics) over the measured window.
  const std::int64_t from_real = start + o.sched.warmup + real_off;
  const std::int64_t to_real = end + real_off;
  client::BacklogVerdict bv;
  if (!samples.empty()) bv = client::check_backlog(samples, from_real, to_real);

  const bool responses_valid = st.missing == 0 && st.unexpected == 0 && login_rejects == 0 && disconnects == 0 &&
                               sent == scheduled;
  const bool lateness_ok = late.count() > 0 && late.percentile(99.9) <= o.max_lateness;
  const bool slo_evaluated = o.slo_p99 > 0;
  const bool slo_ok = slo_evaluated && lat.count() > 0 && lat.percentile(99.0) <= o.slo_p99;
  const bool valid = responses_valid && lateness_ok && bv.evaluated && bv.ok && slo_ok;

  const Nanos measured_span = std::max<Nanos>(1, end - start - o.sched.warmup);
  client::JsonObject j;
  j.boolean("valid", valid).boolean("responses_valid", responses_valid).boolean("lateness_ok", lateness_ok);
  j.boolean("backlog_evaluated", bv.evaluated).boolean("backlog_ok", bv.ok).str("backlog_reason", bv.reason);
  j.boolean("slo_evaluated", slo_evaluated).boolean("slo_ok", slo_ok).inum("slo_p99_ns", o.slo_p99);
  j.str("tool", "loadgen-v2").str("target", "t20").str("backend", client::to_string(o.v.variant));
  j.str("profile", o.profile_path).str("profile_status", o.profile_status);
  j.num("seed", o.sched.seed).num("sessions", o.sched.sessions).num("symbols", o.sched.symbols).num("threads", T);
  j.num("offered_rate", o.sched.rate).num("duration_ns", static_cast<std::uint64_t>(o.sched.duration));
  j.num("warmup_ns", static_cast<std::uint64_t>(o.sched.warmup));
  j.num("scheduled", scheduled).num("prefill", prefill).num("sent", sent);
  j.num("achieved_rate", static_cast<std::uint64_t>(static_cast<u128>(sent) * 1'000'000'000u /
                                                     static_cast<std::uint64_t>(std::max<Nanos>(1, end - start))));
  std::array<std::uint64_t, lg::kKinds> sk{};
  std::uint64_t fallbacks = 0, ioc_expected = 0, passive_expected = 0, dup_bumps = 0;
  lg::RiskCheck risk{};
  for (const auto& s : sched) {
    for (std::size_t k = 0; k < lg::kKinds; ++k) sk[k] += s.stats.kinds[k];
    fallbacks += s.stats.fallbacks;
    ioc_expected += s.stats.ioc_shares;
    passive_expected += s.stats.passive_fills;
    dup_bumps += s.dup_bumps;
    risk.checked += s.risk.checked;
    risk.over_qty += s.risk.over_qty;
    risk.over_notional += s.risk.over_notional;
    risk.over_port_rate += s.risk.over_port_rate;
    risk.over_symbol_rate += s.risk.over_symbol_rate;
    risk.over_gross += s.risk.over_gross;
    risk.over_symbol_notional += s.risk.over_symbol_notional;
    risk.dup_guard_short += s.risk.dup_guard_short;
    risk.over_kill += s.risk.over_kill;
    risk.dup_unresolved += s.risk.dup_unresolved;
    risk.dup_unresolved_rejects += s.risk.dup_unresolved_rejects;
    risk.peak_gross = std::max(risk.peak_gross, s.risk.peak_gross);
    risk.peak_symbol_notional = std::max(risk.peak_symbol_notional, s.risk.peak_symbol_notional);
    risk.peak_executed = std::max(risk.peak_executed, s.risk.peak_executed);
  }
  for (std::size_t kk = 0; kk < lg::kKinds; ++kk) {
    const auto kind = static_cast<lg::Kind>(kk);
    j.num(std::string("scheduled_") + lg::kind_name(kind), sk[kk]);
    j.num(std::string("acked_") + lg::kind_name(kind), st.acked_by_kind[kk]);
  }
  j.num("schedule_fallbacks", fallbacks).num("schedule_dup_bumps", dup_bumps).num("schedule_dup_unresolved", risk.dup_unresolved);
  j.num("risk_checked", risk.checked).num("risk_violations_predicted", risk.violations());
  j.str("risk_peak_gross", i128s(risk.peak_gross)).str("risk_peak_symbol_notional", i128s(risk.peak_symbol_notional));
  j.str("risk_peak_executed", i128s(risk.peak_executed));
  j.num("acked", st.acked).num("missing", st.missing).num("unexpected", st.unexpected);
  j.num("unexpected_rejected", st.rejected).num("unexpected_cancel_reject", st.cancel_rejects);
  j.num("unexpected_ioc_dead", st.ioc_dead).num("unexpected_ioc_remainder", st.ioc_remainder);
  j.num("unexpected_unknown_urn", st.unknown_urn).num("unexpected_duplicate_ack", st.duplicate_ack);
  j.num("unexpected_wrong_state", st.wrong_state).num("unexpected_other", st.other);
  j.num("ioc_fills", st.ioc_fills).num("ioc_shares", st.ioc_shares).num("ioc_shares_expected", ioc_expected);
  j.num("passive_fills", st.passive_fills).num("passive_fills_expected", passive_expected);
  j.num("passive_shares", st.passive_shares).num("system_events", st.system_events);
  j.num("tx_blocked", tx_blocked).num("login_rejects", login_rejects).num("disconnects", disconnects);
  j.num("latency_samples", static_cast<std::uint64_t>(lat.count()));
  j.inum("p50_ns", lat.percentile(50.0)).inum("p90_ns", lat.percentile(90.0)).inum("p99_ns", lat.percentile(99.0));
  j.inum("p999_ns", lat.percentile(99.9)).inum("p9999_ns", lat.percentile(99.99)).inum("max_ns", lat.max());
  for (std::size_t kk = 0; kk < lg::kKinds; ++kk) {
    const auto kind = static_cast<lg::Kind>(kk);
    j.inum(std::string("p50_ns_") + lg::kind_name(kind), by_kind[kk].percentile(50.0));
    j.inum(std::string("p99_ns_") + lg::kind_name(kind), by_kind[kk].percentile(99.0));
  }
  j.inum("lateness_p50_ns", late.percentile(50.0)).inum("lateness_p99_ns", late.percentile(99.0));
  j.inum("lateness_p999_ns", late.percentile(99.9)).inum("lateness_max_ns", late.max());
  j.num("w2w_probe_every", o.nic_sample).num("w2w_pairs_ok", probe_acc.ok).num("w2w_pairs_missing", probe_acc.missing);
  j.num("w2w_pairs_software", probe_acc.software).num("w2w_pairs_cross_phc", probe_acc.cross_phc);
  j.boolean("w2w_valid", probe_acc.valid());
  w2w.json(j, "w2w_ack_");
  j.inum("window_from_realtime_ns", from_real).inum("window_to_realtime_ns", to_real);
  j.num("measured_span_ns", static_cast<std::uint64_t>(measured_span));
  if (!samples.empty()) {
    j.num("metrics_samples", samples.size());
    for (const auto& r : bv.rings) {
      if (!r.present) continue;
      const std::string p = "ring_" + r.name + "_";
      j.num(p + "cap", r.cap).num(p + "first10_peak", r.first10).num(p + "last10_peak", r.last10);
      j.num(p + "max_peak", r.max_peak).num(p + "windows", r.windows).num(p + "skipped", r.skipped);
    }
    j.num("work_inbound", bv.inbound);
    j.inum("work_ns_per_msg_x1000", static_cast<std::int64_t>(bv.work_ns_per_msg * 1000.0));
  }
  client::variant_json(j, o.v, dev);
  runners.front()->io().stats_json(j);
  const std::string json = j.done();
  std::fputs(json.c_str(), stdout);
  const std::string base = o.out + "/" + o.run_name;
  bool ok = true;
  if (std::FILE* f = std::fopen((base + ".json").c_str(), "w")) {
    std::fputs(json.c_str(), f);
    ok = std::fclose(f) == 0;
  } else {
    ok = false;
  }
  if (std::FILE* f = std::fopen((base + ".hgrm").c_str(), "w")) {
    lat.print_percentiles(f);
    std::fclose(f);
  }
  std::vector<client::IntervalHistogram> ivs;
  for (std::size_t i = 0; i < iv.size(); ++i)
    ivs.push_back({static_cast<Nanos>(i) * kNsPerSec, static_cast<Nanos>(i + 1) * kNsPerSec, iv[i].get()});
  ok = client::write_hdr_log(base + ".hdr", ivs, lat, end - start, (start + real_off) / 1'000'000,
                             "loadgen-v2 ack latency from scheduled send, ns") && ok;
  if (!samples.empty()) {
    if (std::FILE* f = std::fopen((base + ".metrics.jsonl").c_str(), "w")) {
      for (const auto& smp : samples) std::fprintf(f, "%s\n", client::sample_json_line(smp).c_str());
      std::fclose(f);
    }
  }
  if (!ok) std::fprintf(stderr, "loadgen: cannot write the outputs under %s\n", base.c_str());
  return responses_valid && ok ? 0 : 1;
}

int run(RunOptions& o) {
  client::DeviceReport dev;
  std::string err;
  if (!client::prepare_variant(o.v, dev, err)) {
    std::fprintf(stderr, "loadgen: %s\n", err.c_str());
    return 2;
  }
  const std::uint32_t T = std::max<std::uint32_t>(1, o.sched.threads);
  if (T > o.sched.sessions) {
    std::fprintf(stderr, "loadgen: --threads %u > sessions %u\n", T, o.sched.sessions);
    return 2;
  }
  std::fprintf(stderr, "loadgen: building %u schedule(s) (seed %" PRIu64 ", %" PRIu64 " msgs/s)...\n", T, o.sched.seed,
               o.sched.rate);
  std::vector<lg::Schedule> sched(T);
  {
    std::vector<std::thread> b;
    for (std::uint32_t t = 0; t < T; ++t) {
      b.emplace_back([&, t]() {
        lg::ScheduleConfig c = o.sched;
        c.threads = T;
        c.thread_index = t;
        sched[t] = lg::build_schedule(c);
      });
    }
    for (auto& x : b) x.join();
  }
  std::uint64_t items = 0, violations = 0;
  for (const auto& s : sched) {
    items += s.items.size();
    violations += s.risk.violations();
  }
  std::fprintf(stderr, "loadgen: %" PRIu64 " messages over %u sessions, %u thread(s); predicted risk rejects %" PRIu64 "\n",
               items, o.sched.sessions, T, violations);
  if (violations != 0) {
    lg::RiskCheck r{};
    for (const auto& x : sched) {
      r.over_qty += x.risk.over_qty;
      r.over_notional += x.risk.over_notional;
      r.over_port_rate += x.risk.over_port_rate;
      r.over_symbol_rate += x.risk.over_symbol_rate;
      r.over_gross += x.risk.over_gross;
      r.over_symbol_notional += x.risk.over_symbol_notional;
      r.dup_guard_short += x.risk.dup_guard_short;
      r.over_kill += x.risk.over_kill;
      r.dup_unresolved_rejects += x.risk.dup_unresolved_rejects;
      r.peak_gross = std::max(r.peak_gross, x.risk.peak_gross);
      r.peak_executed = std::max(r.peak_executed, x.risk.peak_executed);
    }
    std::fprintf(stderr,
                 "loadgen: predicted rejects: max-order-qty %" PRIu64 ", max-order-notional %" PRIu64 ", port-rate %" PRIu64
                 ", symbol-rate %" PRIu64 ", gross-exposure %" PRIu64 " (peak %s), symbol-notional %" PRIu64
                 ", dup guard below 8: %" PRIu64 ", unresolved duplicates %" PRIu64 ", kill switch %" PRIu64
                 " (peak executed %s)\n",
                 r.over_qty, r.over_notional, r.over_port_rate, r.over_symbol_rate, r.over_gross, i128s(r.peak_gross).c_str(),
                 r.over_symbol_notional, r.dup_guard_short, r.dup_unresolved_rejects, r.over_kill,
                 i128s(r.peak_executed).c_str());
  }
  if (violations != 0 && !o.allow_risk) {
    std::fprintf(stderr,
                 "loadgen: refusing: the profile's risk limits would reject %" PRIu64
                 " orders of this schedule (T20 needs 0 Rejected; --allow-risk-violations for negative tests)\n",
                 violations);
    return 3;
  }
  int rc = 2;
  if (!client::with_variant_io(o.v, [&]<class Io>() { rc = run_io<Io>(o, sched, dev); })) {
    std::fprintf(stderr, "loadgen: variant %s not compiled in\n", client::to_string(o.v.variant));
    return 2;
  }
  return rc;
}

// --- serve ----------------------------------------------------------------------------------
template <net::BackendKind K>
int serve_ack(const ServeOptions& o) {
  client::AckServer<K> srv(o.cfg.listen);
  auto ep = srv.open();
  if (!ep) {
    std::fprintf(stderr, "loadgen serve: %s\n", net::to_string(ep.error()).c_str());
    return 1;
  }
  std::fprintf(stderr, "loadgen serve: listening on %s (ack-only)\n", net::to_string(*ep).c_str());
  srv.run(g_stop, o.cfg.max_runtime);
  const auto& s = srv.stats();
  client::JsonObject j;
  j.str("mode", "serve-ack-only").num("accepted", s.accepted).num("logins", s.logins).num("closed", s.closed);
  j.num("inbound", s.inbound).num("responses", s.responses).num("unknown", s.unknown);
  std::fputs(j.done().c_str(), stdout);
  return 0;
}

template <net::BackendKind K>
int serve(const ServeOptions& o) {
  if (o.ack_only) return serve_ack<K>(o);
  auto srv = std::make_unique<client::OuchServer<K>>(o.cfg);
  auto ep = srv->open();
  if (!ep) {
    std::fprintf(stderr, "loadgen serve: %s\n", net::to_string(ep.error()).c_str());
    return 1;
  }
  std::fprintf(stderr, "loadgen serve: listening on %s, %u sessions, %zu symbols\n", net::to_string(*ep).c_str(),
               o.cfg.sessions, o.cfg.symbols.size());
  srv->run(&g_stop);
  const auto& s = srv->stats();
  client::JsonObject j;
  j.str("mode", "serve").num("accepted", s.accepted).num("logins", s.logins).num("login_rejects", s.login_rejects);
  j.num("closed", s.closed).num("inbound", s.inbound).num("ouch_out", s.ouch_out).num("itch_out", s.itch_out);
  j.num("audits", s.audits).num("store_full", s.store_full).num("ouch_unattached", s.ouch_unattached);
  j.num("primary_failures", s.primary_failures);
  j.num("live_orders", srv->engine().live_orders());
  std::fputs(j.done().c_str(), stdout);
  return 0;
}

std::vector<Symbol8> symbols_from_itch(const std::string& path, Args& a) {
  itch50::BinaryFileReader rd;
  if (auto r = rd.open(path); !r) a.die(r.error());
  std::vector<Symbol8> out;
  for (std::uint64_t n = 0; n < 5'000'000; ++n) {
    const auto r = rd.next();
    if (r.status != itch50::RecordStatus::Message) break;
    if (r.data.size() == itch50::StockDirectoryView::kLen && static_cast<char>(r.data[0]) == 'R')
      out.push_back(itch50::StockDirectoryView(r.data.data()).stock());
  }
  return out;
}


// --- search: the T20 driver (METHODOLOGY §15) -------------------------------------------------
// Ascending ladder of pre-registered rate points; at each, R runs (each a child
// `loadgen run`, between optional --before-run / --after-run commands that restart the
// node, sample its metrics, merge the verdict, ...). A rate passes if every run's JSON
// says "valid": true. The result is the highest passing rate below the first failing one.
// --runner runs the child elsewhere (e.g. "ssh host-c /opt/lle/build/bench/apps/loadgen/loadgen";
// --out is then that host's directory) and --results names where the verdicts are read
// (the after-run command brings them there); both default to this host.
std::string shell_quote(const std::string& s) {
  std::string out = "'";
  for (char c : s) {
    if (c == '\'') out += "'\\''";
    else out += c;
  }
  return out + "'";
}

std::string subst(std::string s, const std::string& k, const std::string& v) {
  for (std::size_t p = s.find(k); p != std::string::npos; p = s.find(k, p + v.size())) s.replace(p, k.size(), v);
  return s;
}

int search(int argc, char** argv, const char* self) {
  std::vector<std::string> run_args;
  int split = argc;
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--") {
      split = i;
      break;
    }
  }
  for (int i = split + 1; i < argc; ++i) run_args.emplace_back(argv[i]);
  Args a(split, argv, "loadgen search");
  std::uint64_t lo = 0, step = 0, hi = 0, reps = 5;
  std::string out, results, runner, before, after;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--rate-lo") lo = a.u64();
    else if (f == "--rate-step") step = a.u64();
    else if (f == "--rate-hi") hi = a.u64();
    else if (f == "--reps") reps = a.u64();
    else if (f == "--out") out = a.value();
    else if (f == "--results") results = a.value();
    else if (f == "--runner") runner = a.value();
    else if (f == "--before-run") before = a.value();
    else if (f == "--after-run") after = a.value();
    else a.die("unknown flag " + f);
  }
  if (lo == 0 || step == 0 || hi < lo || out.empty() || reps == 0) a.die("--rate-lo, --rate-step, --rate-hi and --out are required");
  if (results.empty()) results = out;
  std::string base_cmd = (runner.empty() ? shell_quote(self) : runner) + " run";
  for (const auto& x : run_args) base_cmd += " " + shell_quote(x);
  client::JsonObject j;
  std::string points;
  std::uint64_t best = 0;
  bool failed = false;
  for (std::uint64_t rate = lo; rate <= hi && !failed && !g_stop.load(); rate += step) {
    std::uint64_t valid = 0;
    for (std::uint64_t r = 1; r <= reps && !g_stop.load(); ++r) {
      char name[64];
      std::snprintf(name, sizeof name, "rate-%" PRIu64 "-run-%02" PRIu64, rate, r);
      auto fill = [&](std::string c) {
        c = subst(c, "{rate}", std::to_string(rate));
        c = subst(c, "{rep}", std::to_string(r));
        c = subst(c, "{name}", name);
        c = subst(c, "{results}", results);
        return subst(c, "{out}", out);
      };
      if (!before.empty() && std::system(fill(before).c_str()) != 0)
        std::fprintf(stderr, "loadgen search: --before-run failed for %s\n", name);
      const std::string cmd = base_cmd + " --rate " + std::to_string(rate) + " --out " + shell_quote(out) + " --run-name " +
                              name + " > /dev/null";
      (void)std::system(cmd.c_str());
      if (!after.empty() && std::system(fill(after).c_str()) != 0)
        std::fprintf(stderr, "loadgen search: --after-run failed for %s\n", name);
      const auto m = client::read_flat_json(results + "/" + name + ".json");
      const bool ok = m && (*m).contains("valid") && (*m).at("valid") == "true";
      valid += ok ? 1u : 0u;
      std::fprintf(stderr, "loadgen search: %s: %s\n", name, ok ? "valid" : "not valid");
      if (!ok) break;  // the rate point fails
    }
    const bool pass = valid == reps;
    points += (points.empty() ? "" : ",") + std::string("{\"rate\": ") + std::to_string(rate) +
              ", \"valid_runs\": " + std::to_string(valid) + ", \"pass\": " + (pass ? "true" : "false") + "}";
    if (pass) best = rate;
    else failed = true;
  }
  j.str("mode", "search").str("target", "t20").num("rate_lo", lo).num("rate_step", step).num("rate_hi", hi);
  j.num("reps", reps).num("highest_valid_rate", best).boolean("stopped_at_failure", failed);
  j.raw("points", "[" + points + "]");
  const std::string json = j.done();
  std::fputs(json.c_str(), stdout);
  if (std::FILE* f = std::fopen((results + "/search.json").c_str(), "w")) {
    std::fputs(json.c_str(), f);
    std::fclose(f);
  }
  return 0;
}

// --- metrics sampling and the backlog verdict ---------------------------------------------------
int sample_metrics(int argc, char** argv) {
  Args a(argc, argv, "loadgen sample-metrics");
  std::string node, out;
  Nanos interval = 250'000'000, duration = 0;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--node") node = a.value();
    else if (f == "--interval") interval = duration_or_die(a);
    else if (f == "--duration") duration = duration_or_die(a);
    else if (f == "--out") out = a.value();
    else a.die("unknown flag " + f);
  }
  if (node.empty() || out.empty()) a.die("--node and --out are required");
  std::string err;
  std::optional<client::MetricsSampler> m;
  env::ProdClock clock;
  const Nanos start = clock.now_mono();
  // The node may still be starting: wait up to 30 s for its segment.
  while (!(m = client::MetricsSampler::open(node, &err))) {
    if (clock.now_mono() - start > 30 * kNsPerSec || g_stop.load()) a.die("metrics segment of " + node + ": " + err);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  std::FILE* f = std::fopen(out.c_str(), "w");
  if (f == nullptr) a.die("cannot write " + out);
  std::uint64_t n = 0;
  while (!g_stop.load() && (duration == 0 || clock.now_mono() - start < duration)) {
    std::fprintf(f, "%s\n", client::sample_json_line(m->sample(clock.now_real())).c_str());
    std::fflush(f);
    ++n;
    std::this_thread::sleep_for(std::chrono::nanoseconds(interval));
  }
  std::fprintf(f, "%s\n", client::sample_json_line(m->sample(clock.now_real())).c_str());
  std::fclose(f);
  std::fprintf(stderr, "loadgen sample-metrics: %" PRIu64 " samples of %s\n", n + 1, node.c_str());
  return 0;
}

int check_backlog(int argc, char** argv) {
  Args a(argc, argv, "loadgen check-backlog");
  std::string samples_path, run_path, out;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--samples") samples_path = a.value();
    else if (f == "--run") run_path = a.value();
    else if (f == "--out") out = a.value();
    else a.die("unknown flag " + f);
  }
  if (samples_path.empty() || run_path.empty()) a.die("--samples and --run are required");
  std::vector<client::MetricsSample> samples;
  std::string err;
  if (!client::read_samples(samples_path, samples, &err)) a.die(err);
  const auto run = client::read_flat_json(run_path);
  if (!run || !run->contains("window_from_realtime_ns")) a.die("no measured window in " + run_path);
  const std::int64_t from = std::stoll(run->at("window_from_realtime_ns"));
  const std::int64_t to = std::stoll(run->at("window_to_realtime_ns"));
  const client::BacklogVerdict v = client::check_backlog(samples, from, to);
  client::JsonObject j;
  j.boolean("backlog_evaluated", v.evaluated).boolean("backlog_ok", v.ok).str("backlog_reason", v.reason);
  j.boolean("node_restarted", v.restarted).num("metrics_samples", samples.size());
  for (const auto& r : v.rings) {
    if (!r.present) continue;
    const std::string p = "ring_" + r.name + "_";
    j.num(p + "cap", r.cap).num(p + "first10_peak", r.first10).num(p + "last10_peak", r.last10);
    j.num(p + "max_peak", r.max_peak).num(p + "windows", r.windows).num(p + "skipped", r.skipped);
  }
  j.num("work_inbound", v.inbound).inum("work_ns_per_msg_x1000", static_cast<std::int64_t>(v.work_ns_per_msg * 1000.0));
  const std::string json = j.done();
  std::fputs(json.c_str(), stdout);
  if (!out.empty()) {
    std::FILE* f = std::fopen(out.c_str(), "w");
    if (f == nullptr) a.die("cannot write " + out);
    std::fputs(json.c_str(), f);
    std::fclose(f);
  }
  return v.ok ? 0 : 1;
}

int profile_mode(int argc, char** argv) {
  Args a(argc, argv, "loadgen profile");
  std::string path, rows;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--profile") path = a.value();
    else if (f == "--exchanged-risk") rows = a.value();
    else a.die("unknown flag " + f);
  }
  if (path.empty()) a.die("--profile is required");
  const auto p = lg::load_profile(path);
  if (!p) a.die(p.error());
  if (!rows.empty()) {
    const auto colon = rows.find(':');
    if (colon == std::string::npos) a.die("--exchanged-risk FIRST_ACCOUNT:COUNT");
    std::fputs(lg::exchanged_risk_rows(*p, static_cast<std::uint32_t>(a.parse_u64(rows.substr(0, colon))),
                                       static_cast<std::uint32_t>(a.parse_u64(rows.substr(colon + 1))))
                   .c_str(),
               stdout);
    return 0;
  }
  const auto& c = p->base;
  client::JsonObject j;
  j.str("profile", path).str("status", p->status).boolean("registered", p->registered());
  j.num("sessions", c.sessions).num("symbols", c.symbols).num("enter_pct", c.mix.enter_pct);
  j.num("cancel_pct", c.mix.cancel_pct).num("replace_pct", c.mix.replace_pct).num("ioc_pct", c.mix.ioc_pct);
  j.num("lot", c.lot).num("lots_min", c.lots_min).num("lots_max", c.lots_max).num("ioc_unit", c.ioc_unit);
  j.num("ioc_min", c.ioc_min).num("ioc_max", c.ioc_max).num("dup_guard", c.dup_guard).num("risk_rows", p->risk_rows.size());
  std::fputs(j.done().c_str(), stdout);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  const std::string mode = argc > 1 ? argv[1] : "";
  if (mode == "search") return search(argc - 1, argv + 1, argv[0]);
  if (mode == "sample-metrics") return sample_metrics(argc - 1, argv + 1);
  if (mode == "check-backlog") return check_backlog(argc - 1, argv + 1);
  if (mode == "profile") return profile_mode(argc - 1, argv + 1);
  const bool serving = mode == "serve";
  const bool explicit_run = mode == "run";
  Args a(argc - (serving || explicit_run ? 1 : 0), argv + (serving || explicit_run ? 1 : 0), "loadgen");
  int rc = 2;
  if (serving) {
    ServeOptions o;
    std::uint32_t nsym = 2000;
    while (!a.done()) {
      const std::string f = a.flag();
      if (f == "--listen") o.cfg.listen = a.endpoint();
      else if (f == "--ack-only") o.ack_only = true;
      else if (f == "--sessions") o.cfg.sessions = static_cast<std::uint32_t>(a.u64());
      else if (f == "--symbols") nsym = static_cast<std::uint32_t>(a.u64());
      else if (f == "--symbols-from") o.symbols_from = a.value();
      else if (f == "--start-time") {
        const std::string v = a.value();
        int h = 0, m = 0, s = 0;
        if (std::sscanf(v.c_str(), "%d:%d:%d", &h, &m, &s) != 3) a.die("bad --start-time");
        o.cfg.start_time = hms_ns(h, m, s);
      } else if (f == "--max-runtime") o.cfg.max_runtime = duration_or_die(a);
      else if (f == "--cod") o.cfg.cancel_on_disconnect = true;
      else if (f == "--clock") o.cfg.clock_1hz = true;
      else if (f == "--mirror") o.cfg.mirror_listen = a.endpoint();
      else if (f == "--fail-primary-after") o.cfg.fail_primary_after = duration_or_die(a);
      else if (f == "--stall-primary") o.cfg.stall_primary = duration_or_die(a);
      else if (f == "--fail-primary-after-inbound") o.cfg.fail_primary_after_inbound = a.u64();
      else if (f == "--backend") {
        const auto kk = net::parse_backend(a.value());
        if (!kk) a.die("unknown --backend");
        o.backend = *kk;
      } else a.die("unknown flag " + f);
    }
    if (o.cfg.listen.port == 0) a.die("--listen is required");
    for (std::uint32_t i = 0; i < nsym; ++i) o.cfg.symbols.push_back(lg::symbol_name(i));
    if (!o.symbols_from.empty())
      for (const Symbol8& s : symbols_from_itch(o.symbols_from, a)) o.cfg.symbols.push_back(s);
    if (!net::with_backend(o.backend, [&]<net::BackendKind K>() { rc = serve<K>(o); })) a.die("backend not compiled in");
    return rc;
  }
  RunOptions o;
  // The profile first (its values are the defaults the other flags override).
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::string(argv[i]) != "--profile") continue;
    o.profile_path = argv[i + 1];
    const auto p = lg::load_profile(o.profile_path);
    if (!p) a.die(p.error());
    o.sched = p->base;
    o.user_base = p->user_base;
    o.profile_status = p->status;
  }
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--profile") (void)a.value();
    else if (f == "--server") o.server = a.endpoint();
    else if (f == "--sessions") o.sched.sessions = static_cast<std::uint32_t>(a.u64());
    else if (f == "--rate") o.sched.rate = a.u64();
    else if (f == "--duration") o.sched.duration = duration_or_die(a);
    else if (f == "--warmup") o.sched.warmup = duration_or_die(a);
    else if (f == "--seed") o.sched.seed = a.u64();
    else if (f == "--symbols") o.sched.symbols = static_cast<std::uint32_t>(a.u64());
    else if (f == "--prefill") o.sched.prefill = a.u64();
    else if (f == "--constant") o.sched.poisson = false;
    else if (f == "--depth") o.sched.depth_ticks = static_cast<std::uint32_t>(a.u64());
    else if (f == "--threads") o.sched.threads = static_cast<std::uint32_t>(a.u64());
    else if (f == "--cpus") o.cpus = client::cli::parse_u64_list(a, a.value());
    else if (f == "--start-delay") o.start_delay = duration_or_die(a);
    else if (f == "--drain") o.drain = duration_or_die(a);
    else if (f == "--user-base") o.user_base = static_cast<std::uint32_t>(a.u64());
    else if (f == "--password") o.password = a.value();
    else if (f == "--nic-sample") o.nic_sample = a.u64();
    else if (f == "--slo-p99") o.slo_p99 = duration_or_die(a);
    else if (f == "--max-lateness") o.max_lateness = duration_or_die(a);
    else if (f == "--metrics-node") o.metrics_node = a.value();
    else if (f == "--metrics-interval") o.metrics_interval = duration_or_die(a);
    else if (f == "--allow-risk-violations") o.allow_risk = true;
    else if (f == "--out") o.out = a.value();
    else if (f == "--run-name") o.run_name = a.value();
    else if (client::parse_variant_flag(a, f, o.v)) {
    } else a.die("unknown flag " + f);
  }
  if (o.server.port == 0) a.die("--server is required");
  return run(o);
}
