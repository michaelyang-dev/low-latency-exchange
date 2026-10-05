// The lab instruments' cores (M13; METHODOLOGY §12-§16): variant configuration, stream
// TX-timestamp attribution, the PHC map, ttt_harness's plan and verdict, the reflector
// calibration, the record files, loadgen v2's profile, schedule split, duplicate guard
// and risk budget, and the bounded-backlog check over metrics samples.
#include <gtest/gtest.h>

#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "client/backlog.h"
#include "client/hwts_log.h"
#include "client/loadgen.h"
#include "client/loadgen_profile.h"
#include "client/phc_clock.h"
#include "client/report.h"
#include "client/ttt.h"
#include "client/tx_stamps.h"
#include "client/variant.h"
#include "metrics/segment.h"
#include "net/utcp/wire.h"

namespace lle::client {
namespace {

// ---- variants ---------------------------------------------------------------------------------

TEST(Variant, NamesLabelsAndBackends) {
  for (const Variant v : kAllVariants) {
    const auto p = parse_variant(to_string(v));
    ASSERT_TRUE(p.has_value()) << to_string(v);
    EXPECT_EQ(*p, v);
  }
  EXPECT_STREQ(methodology_label(Variant::Epoll), "(i)");
  EXPECT_STREQ(methodology_label(Variant::BusyPollIrqSuspend), "(ii-s)");
  EXPECT_STREQ(methodology_label(Variant::UringNapi), "(iii-n)");
  EXPECT_STREQ(methodology_label(Variant::XskThreaded), "(iv-t)");
  EXPECT_EQ(parse_variant("iv-t"), Variant::XskThreaded);
  EXPECT_EQ(parse_variant("sock"), Variant::Epoll);
  EXPECT_FALSE(parse_variant("opt").has_value());  // a book variant, not an I/O variant
  EXPECT_EQ(backend_of(Variant::BusyPollIrqSuspend), net::BackendKind::BusyPoll);
  EXPECT_EQ(backend_of(Variant::XskThreaded), net::BackendKind::Xsk);
  EXPECT_TRUE(is_xsk(Variant::Xsk));
  EXPECT_FALSE(is_xsk(Variant::Uring));
  EXPECT_TRUE(variant_compiled(Variant::Epoll));
#if !defined(__linux__)
  EXPECT_FALSE(variant_compiled(Variant::Xsk));
#endif
}

TEST(Variant, ParsersAndPreparation) {
  const auto m = parse_mac("02:aa:0b:CC:00:ff");
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->b[0], 0x02);
  EXPECT_EQ(m->b[3], 0xCC);
  EXPECT_EQ(m->b[5], 0xFF);
  EXPECT_FALSE(parse_mac("02:aa:0b:cc:00").has_value());
  EXPECT_FALSE(parse_mac("02:aa:0b:cc:00:fg").has_value());
  EXPECT_EQ(parse_ts_mode("hw"), net::TsMode::Hardware);
  EXPECT_EQ(parse_ts_mode("software"), net::TsMode::Software);
  EXPECT_FALSE(parse_ts_mode("on").has_value());
  // Hardware timestamps without an interface, and xsk without one, are refused.
  VariantConfig v;
  v.timestamps = net::TsMode::Hardware;
  DeviceReport rep;
  std::string err;
  EXPECT_FALSE(prepare_variant(v, rep, err));
  EXPECT_NE(err.find("--ifname"), std::string::npos);
  VariantConfig x;
  x.variant = Variant::Xsk;
  err.clear();
  EXPECT_FALSE(prepare_variant(x, rep, err));
  VariantConfig e;
  err.clear();
  EXPECT_TRUE(prepare_variant(e, rep, err)) << err;
  EXPECT_EQ(rep.phc_index, -1);
}

// ---- stream TX stamps ----------------------------------------------------------------------

net::RxTimestamps hw(Nanos t) { return net::RxTimestamps{0, t}; }

TEST(StreamTxMatcher, ExactStampsAndMisses) {
  StreamTxMatcher m;
  m.init(16);
  m.on_written(60);                // a login: not an order
  m.expect(1, m.written() + 46);   // order 1's last byte
  m.on_written(47);
  m.expect(2, m.written() + 46);
  m.on_written(47);
  m.expect(3, m.written() + 46);
  m.on_written(47);
  std::map<std::uint64_t, Nanos> got;
  auto cb = [&](std::uint64_t tag, const net::RxTimestamps& t) { got[tag] = t.hw_ns; };
  m.on_stamp(StreamTxStamp{59, 59, hw(10)}, cb);  // the login's stamp: covers no order
  EXPECT_TRUE(got.empty());
  m.on_stamp(StreamTxStamp{153, 153, hw(30)}, cb);  // order 2's: order 1's stamp never came
  EXPECT_EQ(got.size(), 1u);
  EXPECT_EQ(got[2], 30);
  EXPECT_EQ(m.validity().missing, 1u);
  m.on_stamp(StreamTxStamp{200, 200, hw(40)}, cb);
  EXPECT_EQ(got[3], 40);
  EXPECT_EQ(m.validity().hw, 2u);
  EXPECT_EQ(m.outstanding(), 0u);
}

TEST(StreamTxMatcher, FrameRangesSoftwareAndWrap) {
  StreamTxMatcher m;
  m.init(16);
  std::vector<std::uint64_t> tags;
  auto cb = [&](std::uint64_t tag, const net::RxTimestamps&) { tags.push_back(tag); };
  // Two orders in one frame [0, 93]: both get its stamp.
  m.expect(7, 46);
  m.expect(8, 93);
  m.on_stamp(StreamTxStamp{0, 93, hw(5)}, cb);
  EXPECT_EQ(tags, (std::vector<std::uint64_t>{7, 8}));
  // Software stamps are matched and counted as software (never hardware).
  m.expect(9, 140);
  m.on_stamp(StreamTxStamp{94, 140, net::RxTimestamps{123, 0}}, cb);
  EXPECT_EQ(m.validity().sw, 1u);
  EXPECT_FALSE(m.validity().valid());
  // Offsets wrap at 2^32 (serial arithmetic).
  StreamTxMatcher w;
  w.init(4);
  int n = 0;
  w.expect(1, 0xFFFF'FFF0u);
  w.expect(2, 0x0000'0010u);
  w.on_stamp(StreamTxStamp{0xFFFF'FFE0u, 0x0000'0010u, hw(1)}, [&](std::uint64_t, const net::RxTimestamps&) { ++n; });
  EXPECT_EQ(n, 2);
  // reset(): what is pending never gets a stamp.
  w.expect(3, 100);
  w.reset();
  EXPECT_EQ(w.validity().missing, 1u);
  EXPECT_EQ(w.written(), 0u);
}

std::vector<std::byte> tcp_frame(std::uint16_t sport, std::uint32_t seq, std::uint8_t flags, std::size_t payload) {
  net::utcp::TcpHeaderSpec h;
  h.src_ip = 0x0A000001;
  h.dst_ip = 0x0A000002;
  h.src_port = sport;
  h.dst_port = 9000;
  h.seq = seq;
  h.flags = flags;
  h.window = 65535;
  std::vector<std::byte> data(payload, std::byte{0x41});
  std::vector<std::byte> out(2048);
  const std::size_t n = net::utcp::build_tcp(out, net::utcp::LinkType::Ethernet, h, data, {}, false);
  out.resize(n);
  return out;
}

TEST(FrameStampTracker, NewDataOnlyInRingOrder) {
  namespace tf = net::utcp::tcp_flag;
  FrameStampTracker t;
  t.init(64);
  const std::uint32_t isn = 0xFFFF'FF00u;  // the stream wraps the sequence space
  EXPECT_FALSE(t.on_tx(tcp_frame(40000, isn, tf::kSyn, 0)));
  EXPECT_FALSE(t.on_tx(tcp_frame(40000, isn + 1, tf::kAck, 0)));  // pure ACK
  EXPECT_TRUE(t.on_tx(tcp_frame(40000, isn + 1, tf::kAck | tf::kPsh, 100)));   // bytes 0..99
  EXPECT_TRUE(t.on_tx(tcp_frame(40000, isn + 101, tf::kAck | tf::kPsh, 47)));  // 100..146
  EXPECT_FALSE(t.on_tx(tcp_frame(40000, isn + 1, tf::kAck, 100)));             // retransmission
  EXPECT_TRUE(t.on_tx(tcp_frame(40000, isn + 101, tf::kAck, 100)));            // 100..199: only 147..199 new
  EXPECT_EQ(t.retransmissions(), 1u);
  EXPECT_FALSE(t.on_tx(tcp_frame(40001, 5, tf::kAck, 10)));  // a flow whose SYN was never seen
  t.on_completion(1000);
  t.on_completion(2000);
  t.on_completion(0);  // copy mode / unstamped completion
  std::vector<FrameStampTracker::Stamped> out;
  t.drain([&](const FrameStampTracker::Stamped& s) { out.push_back(s); });
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(out[0].stamp.first, 0u);
  EXPECT_EQ(out[0].stamp.last, 99u);
  EXPECT_EQ(out[0].stamp.ts.hw_ns, 1000);
  EXPECT_EQ(out[1].stamp.first, 100u);
  EXPECT_EQ(out[1].stamp.last, 146u);
  EXPECT_EQ(out[2].stamp.first, 147u);
  EXPECT_EQ(out[2].stamp.last, 199u);
  EXPECT_EQ(out[2].stamp.ts.hw_ns, 0);
  t.on_completion(5);
  EXPECT_EQ(t.unmatched_completions(), 1u);
  // A new connection on the same port starts a new stream at its SYN.
  t.forget(40000);
  EXPECT_FALSE(t.on_tx(tcp_frame(40000, 77, tf::kAck, 10)));
  EXPECT_FALSE(t.on_tx(tcp_frame(40000, 500, tf::kSyn, 0)));
  EXPECT_TRUE(t.on_tx(tcp_frame(40000, 501, tf::kAck, 10)));
  EXPECT_EQ(t.inflight(), 1u);
  t.discard_inflight();
  EXPECT_EQ(t.dropped(), 1u);
}

// ---- PHC map --------------------------------------------------------------------------------

TEST(PhcMap, InterpolatesAndReportsUncertainty) {
  PhcMap m;
  m.reserve(8);
  EXPECT_FALSE(m.valid());
  m.add(PhcSample{1'000'000'000, 5'000'000'000, 400});
  m.add(PhcSample{2'000'000'000, 6'000'000'100, 900});  // the PHC runs 100 ppb fast
  m.add(PhcSample{1'500'000'000, 0, 10});                // out of order: ignored
  ASSERT_TRUE(m.valid());
  EXPECT_EQ(m.size(), 2u);
  EXPECT_EQ(m.to_phc(1'500'000'000), 5'500'000'050);
  EXPECT_EQ(m.to_phc(3'000'000'000), 7'000'000'200);  // extrapolated
  EXPECT_EQ(m.uncertainty(), 450);
  EXPECT_EQ(m.drift_ppb(), 100);
  EXPECT_FALSE(PhcClock::open(-1).has_value());
}

// ---- ttt plan and verdict -------------------------------------------------------------------

TEST(TttPlan, SequenceNumbersFollowTheMergedSchedule) {
  ttt::PlanConfig c;
  c.seed = 42;
  c.trigger_rate = 20'000;
  c.background_rate = 1'000'000;
  c.duration = 100'000'000;  // 100 ms
  const ttt::Plan p = ttt::build_plan(c);
  EXPECT_EQ(p.background, 100'000u);
  ASSERT_GT(p.trigger_time.size(), 1500u);
  ASSERT_LT(p.trigger_time.size(), 2500u);
  // bg_before agrees with bg_time everywhere it matters.
  for (std::uint64_t i = 0; i < 2000; ++i) {
    const Nanos t = p.bg_time(i);
    EXPECT_EQ(p.bg_before(t), i + 1);
    EXPECT_EQ(p.bg_before(t - 1), i == 0 ? 0u : (p.bg_time(i - 1) <= t - 1 ? i : i - 1));
  }
  // Simulate the harness's merge (background first on ties): the sequence each trigger gets.
  SeqNo seq = 1;  // the directory
  std::size_t k = 0;
  std::uint64_t i = 0;
  while (k < p.trigger_time.size()) {
    if (i < p.background && p.bg_time(i) <= p.trigger_time[k]) {
      ++seq;
      ++i;
      continue;
    }
    ++seq;
    ASSERT_EQ(seq, p.trigger_seq[k]) << "trigger " << k;
    ++seq;  // its delete
    ++k;
  }
  EXPECT_EQ(p.trigger_of(p.trigger_seq[17]), 17);
  EXPECT_EQ(p.trigger_of(p.trigger_seq[17] + 1), -1);  // a delete
  EXPECT_EQ(p.messages(), 1 + p.background + 2 * p.trigger_seq.size());
  // Deterministic in the seed.
  EXPECT_EQ(ttt::build_plan(c).trigger_time, p.trigger_time);
  c.seed = 43;
  EXPECT_NE(ttt::build_plan(c).trigger_time, p.trigger_time);
}

struct Synthetic {
  ttt::Plan plan;
  std::vector<ttt::TriggerRecord> recs;
};

// n triggers 1 ms apart, all hardware-stamped on PHC 3: TTT_raw = 10,000 + (k % 100) ns.
Synthetic synthetic(std::size_t n) {
  Synthetic s;
  for (std::size_t k = 0; k < n; ++k) {
    s.plan.trigger_seq.push_back(10 + 2 * k);
    s.plan.trigger_time.push_back(static_cast<Nanos>(k) * 1'000'000);
    ttt::TriggerRecord r;
    r.seq = s.plan.trigger_seq.back();
    r.sched = s.plan.trigger_time.back();
    r.sched_phc = 1'000'000'000 + r.sched;
    r.tx_sw = r.sched + 300;
    r.tx_hw[0] = r.sched_phc + 400;
    r.tx_hw[1] = r.sched_phc + 600;
    r.rx_hw = r.tx_hw[0] + 10'000 + static_cast<std::int64_t>(k % 100);
    r.phc = 3;
    r.tx_flags = ttt::TriggerRecord::kSent;
    r.rx_flags = ttt::TriggerRecord::kOrder;
    s.recs.push_back(r);
  }
  return s;
}

ttt::AnalysisConfig small_cfg() {
  ttt::AnalysisConfig c;
  c.warmup = 10'000'000;  // the first 10 triggers
  c.min_triggers = 100;
  return c;
}

TEST(TttAnalysis, HardwareRunIsValid) {
  const Synthetic s = synthetic(2000);
  const ttt::Analysis a = ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, false);
  EXPECT_TRUE(a.valid) << a.invalid_reasons;
  EXPECT_EQ(a.measured, 1990u);
  EXPECT_EQ(a.raw_acc.ok, 1990u);
  EXPECT_GE(a.raw.percentile(50.0), 10'040);
  EXPECT_LE(a.raw.percentile(50.0), 10'060);
  EXPECT_NEAR(static_cast<double>(a.raw.max()), 10'099.0, 11.0);  // 3 significant digits
  EXPECT_TRUE(a.lateness_hw_available);
  EXPECT_EQ(a.lateness_hw.percentile(99.9), 400);
  EXPECT_FALSE(a.consistency_evaluated);
}

TEST(TttAnalysis, InvalidityRules) {
  {  // a software stamp anywhere invalidates the run, and is never computed as hardware
    Synthetic s = synthetic(2000);
    s.recs[500].rx_hw = 0;
    s.recs[500].rx_sw = 1'234;
    const auto a = ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, false);
    EXPECT_FALSE(a.valid);
    EXPECT_EQ(a.raw_acc.software, 1u);
    EXPECT_NE(a.invalid_reasons.find("software timestamps present"), std::string::npos);
  }
  {  // a port reporting software stamps (run-level flag)
    const Synthetic s = synthetic(2000);
    EXPECT_FALSE(ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, true).valid);
  }
  {  // 0.1% missing is still valid; more is not
    Synthetic s = synthetic(2000);
    s.recs[100].rx_hw = 0;
    s.recs[100].rx_flags = 0;
    EXPECT_TRUE(ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, false).valid);
    s.recs[200].tx_hw[1] = 0;  // one copy unstamped: the minimum is unknown -> missing
    s.recs[300].rx_hw = 0;
    const auto a = ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, false);
    EXPECT_EQ(a.raw_acc.missing, 3u);
    EXPECT_FALSE(a.valid);
  }
  {  // stamps from two PHCs
    Synthetic s = synthetic(2000);
    s.recs[50].phc = 4;
    s.recs[50].tx_hw[0] = 0;  // keep it consistent with first_tx using the record PHC
    auto a = ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, false);
    EXPECT_EQ(a.raw_acc.missing, 1u);
  }
  {  // generator lateness p99.9 above 1 us
    Synthetic s = synthetic(2000);
    for (std::size_t k = 0; k < 10 + 5; ++k) s.recs[1000 + k].sched_phc -= 5'000;
    const auto a = ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, false);
    EXPECT_FALSE(a.valid);
    EXPECT_NE(a.invalid_reasons.find("lateness"), std::string::npos);
  }
  {  // no PHC map: lateness unavailable -> invalid
    Synthetic s = synthetic(2000);
    for (auto& r : s.recs) r.sched_phc = 0;
    EXPECT_FALSE(ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), true, false).valid);
  }
  {  // TX attribution lost, too few triggers
    const Synthetic s = synthetic(2000);
    EXPECT_FALSE(ttt::analyze(s.plan, s.recs, {}, {}, small_cfg(), false, false).valid);
    auto c = small_cfg();
    c.min_triggers = 1'000'000;
    EXPECT_FALSE(ttt::analyze(s.plan, s.recs, {}, {}, c, true, false).valid);
  }
}

TEST(TttAnalysis, ClientLogCalibrationAndConsistency) {
  const Synthetic s = synthetic(2000);
  std::vector<OrderStampRecord> client;
  for (std::size_t k = 0; k < s.recs.size(); ++k) {
    OrderStampRecord c;
    c.trigger_seq = s.recs[k].seq;
    c.rx_hw = 50'000;
    c.tx_hw = 50'000 + 9'500;  // TTT_client 9.5 us
    c.phc = 7;
    c.flags = OrderStampRecord::kInPacket | OrderStampRecord::kTxSeen;
    client.push_back(c);
  }
  client[20].flags = 0;  // the trigger was delivered from the arbiter's buffer
  OrderStampRecord stray;
  stray.trigger_seq = 1;  // not a trigger
  client.push_back(stray);
  ttt::Calibration cal{true, true, 260};  // 2c = 520: raw 10,050 - client 9,500 - 520 = 30 ns
  auto a = ttt::analyze(s.plan, s.recs, client, cal, small_cfg(), true, false);
  EXPECT_TRUE(a.have_client);
  EXPECT_EQ(a.client_measured, 1990u);
  EXPECT_EQ(a.client_not_in_packet, 1u);
  EXPECT_EQ(a.client_unknown, 1u);
  EXPECT_EQ(a.client_acc.ok, 1989u);
  ASSERT_TRUE(a.consistency_evaluated);
  EXPECT_TRUE(a.consistency_ok) << a.consistency_ns;
  EXPECT_TRUE(a.valid) << a.invalid_reasons;
  JsonObject j;
  ttt::analysis_json(j, a);
  EXPECT_NE(j.done().find("\"ttt_cal_p50_ns\""), std::string::npos);
  cal.c = 1'000;  // 2c = 2,000: the rule fails by about 1.4 us
  a = ttt::analyze(s.plan, s.recs, client, cal, small_cfg(), true, false);
  EXPECT_FALSE(a.consistency_ok);
  EXPECT_FALSE(a.valid);
  EXPECT_NE(a.invalid_reasons.find("consistency"), std::string::npos);
}

TEST(TttCalibration, OneClockPerSubtraction) {
  std::vector<ttt::ProbeResult> probes;
  for (int i = 0; i < 1000; ++i) {
    ttt::ProbeResult p;
    p.a_tx = {1, 1'000'000 + i * 100'000};
    p.c_rx = {9, 77'000'000 + i * 100'000};                // C's clock: any offset
    p.c_tx = {9, p.c_rx.ns + 3'000 + (i % 10)};            // turnaround 3.0 us
    p.a_rx = {1, p.a_tx.ns + 3'000 + (i % 10) + 2 * 410};  // c = 410 ns each way
    probes.push_back(p);
  }
  auto r = ttt::calibrate(probes);
  EXPECT_TRUE(r.valid);
  EXPECT_EQ(r.c, 410);
  probes[3].c_tx = {-1, 5};  // a software stamp on the reflector
  r = ttt::calibrate(probes);
  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.turn_acc.software, 1u);
}

TEST(RecordFiles, RoundTrip) {
  const std::string dir = ::testing::TempDir();
  std::vector<OrderStampRecord> log(3);
  log[1].trigger_seq = 99;
  log[1].tx_hw = 5;
  ASSERT_TRUE(write_hwts_log(dir + "/c.hwts", log));
  std::vector<OrderStampRecord> back;
  std::string err;
  ASSERT_TRUE(read_hwts_log(dir + "/c.hwts", back, &err)) << err;
  ASSERT_EQ(back.size(), 3u);
  EXPECT_EQ(back[1].trigger_seq, 99u);
  EXPECT_EQ(back[1].tx_hw, 5);
  const Synthetic s = synthetic(10);
  ttt::RunHeader h;
  h.seed = 7;
  h.phc = 3;
  ASSERT_TRUE(ttt::write_triggers(dir + "/t.bin", h, s.recs));
  ttt::RunHeader h2;
  std::vector<ttt::TriggerRecord> r2;
  ASSERT_TRUE(ttt::read_triggers(dir + "/t.bin", h2, r2, &err)) << err;
  EXPECT_EQ(h2.seed, 7u);
  ASSERT_EQ(r2.size(), 10u);
  EXPECT_EQ(r2[4].rx_hw, s.recs[4].rx_hw);
  EXPECT_FALSE(read_hwts_log(dir + "/t.bin", back, &err));  // wrong magic
  EXPECT_FALSE(ttt::read_triggers(dir + "/c.hwts", h2, r2, &err));
}

TEST(FlatJson, TopLevelMembersOnly) {
  const auto m = parse_flat_json(
      "{\n  \"valid\": false,\n  \"n\": -12,\n  \"s\": \"a \\\"q\\\" b\",\n  \"nested\": {\"x\": {\"y\": [1, 2]}, \"z\": \"}\"},\n"
      "  \"after\": 3\n}\n");
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->at("valid"), "false");
  EXPECT_EQ(m->at("n"), "-12");
  EXPECT_EQ(m->at("s"), "a \"q\" b");
  EXPECT_FALSE(m->contains("nested"));
  EXPECT_FALSE(m->contains("x"));
  EXPECT_EQ(m->at("after"), "3");
  EXPECT_FALSE(parse_flat_json("[1, 2]").has_value());
  EXPECT_FALSE(parse_flat_json("{\"a\" 1}").has_value());
}

// ---- loadgen v2 -----------------------------------------------------------------------------

const char* kProfile = R"(# test profile
status = TBD_BY_PILOT
[mix]
enter = 45
cancel = 40
replace = 10
ioc = 5
[book]
symbols = 200
depth_ticks = 10
tick = 0.01
prefill_per_symbol = 4
lot = 100
lots = 1-10
ioc_unit = 100
ioc = 1-10
dup_guard = 16
[sessions]
count = 8
user_base = 101
account = per-session
[risk]
max-order-qty = 100000
gross-exposure = 5000000000000000
lop = 1
)";

TEST(LoadgenProfile, ParsesAndPrintsExchangeRows) {
  const auto p = lg::parse_profile(kProfile, "test");
  ASSERT_TRUE(p.has_value()) << p.error();
  EXPECT_FALSE(p->registered());
  EXPECT_EQ(p->base.sessions, 8u);
  EXPECT_EQ(p->base.symbols, 200u);
  EXPECT_EQ(p->base.prefill, 800u);
  EXPECT_EQ(p->base.tick, 100);
  EXPECT_EQ(p->base.dup_guard, 16u);
  EXPECT_EQ(p->base.ioc_max, 10u);
  EXPECT_EQ(p->user_base, 101u);
  EXPECT_EQ(p->base.risk.max_qty, 100'000);
  EXPECT_EQ(p->base.risk.gross, 5'000'000'000'000'000);
  ASSERT_EQ(p->risk_rows.size(), 3u);
  const std::string rows = lg::exchanged_risk_rows(*p, 5, 2);
  EXPECT_NE(rows.find("5 max-order-qty 100000\n"), std::string::npos);
  EXPECT_NE(rows.find("6 lop 1\n"), std::string::npos);
  std::string bad = kProfile;
  bad.replace(bad.find("ioc = 5"), 7, "ioc = 6");
  EXPECT_FALSE(lg::parse_profile(bad, "bad").has_value());
  EXPECT_FALSE(lg::parse_profile("[nope]\n", "bad").has_value());
  EXPECT_FALSE(lg::parse_profile("[book]\nlots = 5-2\n", "bad").has_value());
  std::string reg = kProfile;
  reg.replace(reg.find("status = TBD_BY_PILOT"), 21, "status = registered");
  const auto r = lg::parse_profile(reg, "ok");
  ASSERT_TRUE(r.has_value()) << r.error();
  EXPECT_TRUE(r->registered());
}

lg::ScheduleConfig v2_cfg() {
  auto p = lg::parse_profile(kProfile, "test");
  lg::ScheduleConfig c = p->base;
  c.rate = 200'000;
  c.duration = 200'000'000;
  c.seed = 11;
  return c;
}

TEST(LoadgenSchedule, ThreadsSplitSessionsAndKeepSymbolsOnOneSession) {
  lg::ScheduleConfig c = v2_cfg();
  c.threads = 3;
  std::uint64_t total = 0;
  std::set<std::uint16_t> sessions_seen;
  for (std::uint32_t t = 0; t < 3; ++t) {
    c.thread_index = t;
    const auto s = lg::build_schedule(c);
    total += s.items.size() - s.stats.prefill;
    Nanos last = 0;
    for (const auto& it : s.items) {
      EXPECT_TRUE(lg::session_of_thread(it.session, t, 3));
      EXPECT_EQ(it.symbol % c.sessions, it.session);
      EXPECT_GE(it.t, last);
      last = it.t;
      sessions_seen.insert(it.session);
    }
    EXPECT_EQ(s.stats.fallbacks, 0u);
  }
  EXPECT_EQ(sessions_seen.size(), 8u);
  EXPECT_NEAR(static_cast<double>(total), 40'000.0, 400.0);  // the rate is shared, not multiplied
}

TEST(LoadgenSchedule, DuplicateGuardKeepsEnterContentsDistinct) {
  lg::ScheduleConfig c = v2_cfg();
  c.symbols = 10;  // few symbols: collisions are frequent without the guard
  c.sessions = 2;
  c.prefill = 40;
  c.depth_ticks = 2;
  const auto s = lg::build_schedule(c);
  EXPECT_GT(s.dup_bumps, 0u);
  EXPECT_EQ(s.risk.dup_unresolved, 0u);
  std::map<std::uint16_t, std::vector<std::tuple<std::uint16_t, char, std::uint32_t, std::uint32_t, bool>>> last;
  for (const auto& it : s.items) {
    if (it.kind != lg::Kind::Enter && it.kind != lg::Kind::Ioc) continue;
    auto& v = last[it.session];
    const auto key = std::tuple{it.symbol, it.side, it.price, it.qty, it.kind == lg::Kind::Ioc};
    const std::size_t from = v.size() > 15 ? v.size() - 15 : 0;
    for (std::size_t i = from; i < v.size(); ++i) ASSERT_NE(v[i], key) << "duplicate within the guard";
    v.push_back(key);
  }
  // Too few sizes to stay distinct: the unresolved duplicates are counted (and refused
  // when the exchange's duplicate filter is on), never silent.
  c.lots_max = 2;
  c.risk.dup_window_sec = 1;
  const auto tight = lg::build_schedule(c);
  EXPECT_GT(tight.risk.dup_unresolved, 0u);
  EXPECT_GT(tight.risk.violations(), 0u);
  c.dup_guard = 0;
  c.risk.dup_window_sec = 0;
  EXPECT_EQ(lg::build_schedule(c).dup_bumps, 0u);
}

TEST(LoadgenSchedule, RiskBudgetPredictsRejects) {
  lg::ScheduleConfig c = v2_cfg();
  EXPECT_EQ(lg::build_schedule(c).risk.violations(), 0u);
  EXPECT_GT(lg::build_schedule(c).risk.checked, 0u);
  c.risk.gross = 1'000'000LL * 10'000;  // $1M gross: the prefill alone exceeds it
  auto s = lg::build_schedule(c);
  EXPECT_GT(s.risk.over_gross, 0u);
  c = v2_cfg();
  c.risk.port_rate = 1'000;  // 1,000 msgs/s per session against ~3,000 offered
  EXPECT_GT(lg::build_schedule(c).risk.over_port_rate, 0u);
  c = v2_cfg();
  c.risk.max_qty = 500;
  EXPECT_GT(lg::build_schedule(c).risk.over_qty, 0u);
  c = v2_cfg();
  c.risk.dup_window_sec = 1;
  c.dup_guard = 4;  // fewer than the engine's 8 slots per second
  EXPECT_EQ(lg::build_schedule(c).risk.dup_guard_short, 1u);
  c = v2_cfg();
  c.warmup = 100'000'000;
  s = lg::build_schedule(c);
  for (const auto& it : s.items)
    if (it.t < c.warmup) EXPECT_TRUE(it.warmup);
}

// ---- bounded backlog -------------------------------------------------------------------------

std::vector<MetricsSample> samples(std::size_t secs, std::uint64_t cap, auto peak_of) {
  std::vector<MetricsSample> v;
  for (std::size_t i = 0; i <= secs * 4; ++i) {
    MetricsSample s;
    s.t_ns = static_cast<std::int64_t>(i) * 250'000'000;
    s.v["node_start_ns"] = 1;
    s.v["writer_pid"] = 42;
    s.v["tsc_hz"] = 2'000'000'000;
    s.v["gw0_msgs_in"] = i * 1000;
    s.v["gw1_msgs_in"] = i * 1000;
    s.v["engine_work_tsc"] = i * 500'000;  // 250 us of work per 2,000 messages: 125 ns/msg
    for (const char* r : kRings) {
      const std::string p = std::string("ring_") + r + "_";
      const bool present = std::string(r) != "tee";
      s.v[p + "cap"] = present ? cap : 0;
      s.v[p + "window"] = i / 4;
      s.v[p + "peak"] = peak_of(i / 4);
    }
    v.push_back(std::move(s));
  }
  return v;
}

TEST(Backlog, BoundedGrowingSkippedAndRestarted) {
  const std::int64_t to = 60 * kNsPerSec;
  auto steady = samples(60, 4096, [](std::size_t) { return std::uint64_t{100}; });
  auto v = check_backlog(steady, 0, to);
  EXPECT_TRUE(v.evaluated) << v.reason;
  EXPECT_TRUE(v.ok) << v.reason;
  EXPECT_NEAR(v.work_ns_per_msg, 125.0, 0.01);
  for (const auto& r : v.rings) {
    if (r.name == "tee") EXPECT_FALSE(r.present);
    else EXPECT_GE(r.windows, 55u);
  }
  // Grows by more than 1% of capacity between the first and last 10 s.
  auto growing = samples(60, 4096, [](std::size_t w) { return std::uint64_t{100 + 2 * w}; });
  v = check_backlog(growing, 0, to);
  EXPECT_FALSE(v.ok);
  EXPECT_NE(v.reason.find("backlog grew"), std::string::npos);
  // Above 50% of capacity.
  auto high = samples(60, 4096, [](std::size_t) { return std::uint64_t{2100}; });
  EXPECT_FALSE(check_backlog(high, 0, to).ok);
  // A skipped window: not evaluable, never assumed bounded.
  auto skip = steady;
  for (std::size_t i = 120; i < skip.size(); ++i)
    for (const char* r : kRings) skip[i].v[std::string("ring_") + r + "_window"] += 1;
  v = check_backlog(skip, 0, to);
  EXPECT_FALSE(v.ok);
  EXPECT_NE(v.reason.find("skipped"), std::string::npos);
  // A restart of the node.
  auto restart = steady;
  for (std::size_t i = 100; i < restart.size(); ++i) restart[i].v["node_start_ns"] = 2;
  v = check_backlog(restart, 0, to);
  EXPECT_TRUE(v.restarted);
  EXPECT_FALSE(v.ok);
  // Too short a span; no ring fields at all.
  EXPECT_FALSE(check_backlog(steady, 0, 10 * kNsPerSec).evaluated);
  std::vector<MetricsSample> bare(3);
  EXPECT_NE(check_backlog(bare, 0, to).reason.find("absent"), std::string::npos);
  // JSON lines round trip.
  const std::string line = sample_json_line(steady[7]);
  const auto back = parse_sample_line(line);
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(back->t_ns, steady[7].t_ns);
  EXPECT_EQ(back->get("ring_l2_window"), steady[7].get("ring_l2_window"));
}

TEST(Backlog, SamplerReadsASegment) {
  metrics::Schema schema;
  schema.counters = {{"ring_l2_cap", metrics::CounterKind::kGauge},
                     {"ring_l2_window", metrics::CounterKind::kCounter},
                     {"gw0_msgs_in", metrics::CounterKind::kCounter}};
  const std::string node = "lleci" + std::to_string(::getpid() % 100000);
  auto seg = metrics::Segment::create_shm(node, schema);
  ASSERT_TRUE(seg.has_value()) << seg.error();
  seg->counter("ring_l2_cap").set(4096);
  seg->counter("ring_l2_window").set(3);
  std::string err;
  auto s = MetricsSampler::open(node, &err);
  ASSERT_TRUE(s.has_value()) << err;
  const MetricsSample m = s->sample(123);
  EXPECT_EQ(m.t_ns, 123);
  EXPECT_EQ(m.get("ring_l2_cap"), 4096u);
  EXPECT_EQ(m.get("ring_l2_window"), 3u);
  EXPECT_TRUE(m.has("writer_pid"));
  EXPECT_FALSE(MetricsSampler::open("lle-no-such-node", &err).has_value());
  (void)seg->unlink();
}

}  // namespace
}  // namespace lle::client
