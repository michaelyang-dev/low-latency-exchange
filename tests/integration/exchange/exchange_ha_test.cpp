// HA smoke (10 §3-§4; T24/T26 smoke): a primary, a backup and witnessd as processes on
// localhost. The clients hold a session on the primary and its mirror on the backup;
// the subscriber takes line A (primary) and line B (backup) and both re-request
// servers. The primary is SIGKILLed while orders are in flight; the backup suspects it,
// freezes, flushes, is granted the next epoch by the witness and takes over: the
// clients continue on their mirror sessions (re-sending, in order, the orders they never
// saw accepted), line A now comes from the new primary, and the client ledger shows no
// lost and no duplicated fill.
#include <gtest/gtest.h>

#include <map>
#include <set>

#include "dead_instances.h"
#include "describe.h"
#include "engine/scenario.h"
#include "ha_trial.h"
#include "harness.h"
#include "journal/posix_segment_dir.h"
#include "journal/reader.h"
#include "metrics/segment.h"
#include "verify.h"

namespace lle::exch::test {
namespace {

class Witness {
 public:
  explicit Witness(const std::filesystem::path& dir) {
    state_ = (dir / "witness.state").string();
    init_ = run_capture({LLE_WITNESSD, "--state", state_, "--init", "--primary", "0", "--inc0", "1", "--inc1", "1"});
    proc_ = std::make_unique<Process>(LLE_WITNESSD,
                                      std::vector<std::string>{"--state", state_, "--listen", "127.0.0.1:0",
                                                               "--tie-break-ms", "500"},
                                      (dir / "witness.out").string());
    if (proc_->wait_output("listening on port ", 10s)) {
      const std::string out = proc_->output();
      port_ = static_cast<std::uint16_t>(std::stoul(out.substr(out.find("listening on port ") + 18)));
    }
  }
  [[nodiscard]] std::uint16_t port() const { return port_; }
  [[nodiscard]] std::string output() const { return proc_->output(); }
  [[nodiscard]] const std::string& init_output() const { return init_; }

 private:
  std::string state_;
  std::string init_;
  std::unique_ptr<Process> proc_;
  std::uint16_t port_ = 0;
};

struct Ledger {
  std::map<std::uint32_t, int> accepted;
  std::map<std::uint64_t, int> executions;
  std::map<std::uint32_t, std::uint64_t> filled;
  void add(const Ouch& m) {
    if (m.type() == 'A') ++accepted[m.urn()];
    if (m.type() == 'E') {
      ++executions[m.e_match()];
      filled[m.urn()] += m.e_qty();
    }
  }
};

// A client's view of its session: the sequenced stream it assembled from its primary and
// mirror connections. Both carry the same released stream (10 §3), so where they overlap
// they must agree byte for byte; the session's stream is the longer of the two.
Bytes merged(const OuchClient& primary, const OuchClient& mirror, std::string* problem) {
  const std::vector<Received>& p = primary.received();
  const std::vector<Received>& m = mirror.received();
  const std::size_t n = std::min(p.size(), m.size());
  for (std::size_t i = 0; i < n; ++i) {
    if (p[i].seq != m[i].seq || p[i].msg != m[i].msg) {
      *problem = "primary and mirror streams differ at sequence " + std::to_string(p[i].seq);
      break;
    }
  }
  return p.size() > m.size() ? primary.stream() : mirror.stream();
}

TEST(ExchangeHa, PrimaryKilledBackupTakesOverExactlyOnce) {
  const auto dir = fresh_dir("ha");
  const ScopedDir cleanup(dir);
  Witness w(dir);
  ASSERT_NE(w.port(), 0) << w.init_output() << w.output();
  MoldSubscriber sub;
  const std::uint16_t repl_a = free_port(SOCK_DGRAM), repl_b = free_port(SOCK_DGRAM);
  auto node = [&](int id) {
    NodeSpec s;
    s.name = id == 0 ? "haA" : "haB";
    s.node_id = id;
    s.metrics = id == 1;  // the survivor's segment is checked at the end
    s.data_dir = (dir / s.name).string();
    s.mode = "paired";
    // Manual clock: walked to 09:31 one scheduled time per sequencer step, interleaved
    // with replication (the seq and repl stages share a thread, 10 §4). An offset clock
    // would make the first poll emit ~20,000 overdue 1 Hz timers in one burst.
    s.clock = "manual";
    s.start = "02:59:00";
    s.line_a = sub.port_a();
    s.line_b = sub.port_b();
    s.max_packet_b = 300;
    s.extra = {"[ha]",
               "bind = 127.0.0.1:" + std::to_string(id == 0 ? repl_a : repl_b),
               "peer = 127.0.0.1:" + std::to_string(id == 0 ? repl_b : repl_a),
               "witness = 127.0.0.1:" + std::to_string(w.port()),
               "primary = 0",
               "heartbeat_ms = 2",
               // Generous for sanitizer builds; the takeover time is not what this smoke measures.
               "t_d_ms = 1500",
               "t_ack_ms = 1000",
               "rto_ms = 20"};
    return s;
  };
  Exchange a(node(0), dir), b(node(1), dir);
  // Both nodes start together: a primary that hears no backup for T_ack goes solo
  // (10 §4), and a backup that then hears a newer epoch is deposed.
  a.launch();
  b.launch();
  ASSERT_TRUE(a.wait_ready()) << a.output();
  ASSERT_TRUE(b.wait_ready()) << b.output();
  sub.set_servers(a.port("rerequest"), b.port("rerequest"));
  // Roles: A paired primary, B backup.
  bool paired = false;
  for (int i = 0; i < 500 && !paired; ++i) {
    paired = a.status().find("role=P ") != std::string::npos && b.status().find("role=B ") != std::string::npos;
    if (!paired) std::this_thread::sleep_for(10ms);
  }
  ASSERT_TRUE(paired) << a.status() << "\n" << b.status();
  // Both clocks to 09:31 (the backup's matters once it takes over).
  b.clock("09:31:00");
  a.clock("09:31:00");
  ASSERT_NE(a.status().find("role=P "), std::string::npos) << a.status();

  // Each client: its session on the primary and the mirror-attached instance on the backup.
  OuchClient ap("ALPHA", "alpha-pw"), am("ALPHA", "alpha-pw"), bp("BRAVO", "bravo-pw"), bm("BRAVO", "bravo-pw");
  ASSERT_EQ(ap.login(a.port("gw0")), 'A');
  ASSERT_EQ(bp.login(a.port("gw1")), 'A');
  ASSERT_EQ(am.login(b.port("gw0")), 'A') << b.output();
  ASSERT_EQ(bm.login(b.port("gw1")), 'A');
  // A second login of a session on the same port is refused with 'S' (10 §3).
  OuchClient dup("ALPHA", "alpha-pw");
  EXPECT_EQ(dup.login(a.port("gw0")), 'S');

  auto enter = [](std::uint32_t urn, char side) {
    engine::EnterArgs e;
    e.urn = urn;
    e.side = static_cast<ouch50::Side>(side);
    e.qty = 100;
    e.symbol = "AAPL";
    e.price = 1'500'000;
    return engine::enter_msg(e);
  };
  auto pump = [&](int ms) {
    for (OuchClient* c : {&ap, &am, &bp, &bm}) c->poll(0);
    sub.poll(ms);
  };

  // Paired trading: 100 crossing pairs, all answered on the primary connections and
  // mirrored, byte for byte, on the backup's instances (released at commit_index).
  constexpr std::uint32_t kPhase1 = 100, kTotal = 300;
  for (std::uint32_t u = 1; u <= kPhase1; ++u) {
    ap.send(enter(u, 'S'));
    bp.send(enter(u, 'B'));
  }
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while ((ap.received().size() < 1 + 2 * kPhase1 || am.received().size() < 1 + 2 * kPhase1) &&
         std::chrono::steady_clock::now() < deadline)
    pump(1);
  ASSERT_GE(ap.received().size(), 1 + 2 * kPhase1) << a.status();
  ASSERT_GE(am.received().size(), 1 + 2 * kPhase1) << b.status();
  std::string problem;
  (void)merged(ap, am, &problem);
  EXPECT_TRUE(problem.empty()) << problem;
  // Line A from the primary, line B from the backup, from two different senders.
  for (int i = 0; i < 50; ++i) pump(2);
  ASSERT_EQ(sub.sources(0).size(), 1u) << sub.summary();
  ASSERT_EQ(sub.sources(1).size(), 1u) << sub.summary();
  const std::uint16_t sender_a = sub.sources(0).begin()->first, sender_b = sub.sources(1).begin()->first;
  EXPECT_NE(sender_a, sender_b);

  // In flight: the next 200 pairs, and the primary dies under them.
  for (std::uint32_t u = kPhase1 + 1; u <= kTotal; ++u) {
    ap.send(enter(u, 'S'));
    bp.send(enter(u, 'B'));
    if (u == kPhase1 + 120) break;
  }
  pump(0);
  a.kill9();
  ap.drop();
  bp.drop();

  // Takeover: B is granted the next epoch and becomes the solo primary.
  bool took_over = false;
  for (int i = 0; i < 1000 && !took_over; ++i) {
    took_over = b.status().find("role=SP ") != std::string::npos;
    if (!took_over) pump(5);
  }
  ASSERT_TRUE(took_over) << b.status() << "\n" << b.output() << "\n" << w.output();
  EXPECT_NE(w.output().find("PROMOTE granted"), std::string::npos) << w.output();
  for (int i = 0; i < 50; ++i) pump(2);

  // The clients continue on the mirror instances: re-send, in order, every order not
  // seen accepted on either connection (10 §3 client rule; UserRefNum dedupe makes it
  // exactly once, 10 §4 step 6), then the rest of the flow.
  auto acked = [](const OuchClient& p, const OuchClient& m) {
    std::set<std::uint32_t> s;
    for (const OuchClient* c : {&p, &m})
      for (const Received& r : c->received())
        if (Ouch{r.msg}.type() == 'A') s.insert(Ouch{r.msg}.urn());
    return s;
  };
  const auto seen_a = acked(ap, am), seen_b = acked(bp, bm);
  std::uint32_t resent = 0;
  for (std::uint32_t u = 1; u <= kTotal; ++u) {
    if (seen_a.count(u) == 0) {
      am.send(enter(u, 'S'));
      ++resent;
    }
    if (seen_b.count(u) == 0) {
      bm.send(enter(u, 'B'));
      ++resent;
    }
  }
  const auto end2 = std::chrono::steady_clock::now() + 15s;
  while ((am.received().size() < 1 + 2 * kTotal || bm.received().size() < 1 + 2 * kTotal) &&
         std::chrono::steady_clock::now() < end2)
    pump(1);
  for (int i = 0; i < 100; ++i) pump(2);
  std::printf("HA: %zu ALPHA / %zu BRAVO messages on the primary before the kill; %u orders re-sent on the mirrors\n",
              ap.received().size(), bp.received().size(), resent);

  // Exactly once: every order accepted once, every execution reported once per side.
  problem.clear();
  const Bytes sa = merged(ap, am, &problem);
  EXPECT_TRUE(problem.empty()) << "ALPHA: " << problem;
  const Bytes sb = merged(bp, bm, &problem);
  EXPECT_TRUE(problem.empty()) << "BRAVO: " << problem;
  Ledger la, lb;
  for (const Received& r : am.received()) la.add(Ouch{r.msg});
  for (const Received& r : bm.received()) lb.add(Ouch{r.msg});
  for (std::uint32_t u = 1; u <= kTotal; ++u) {
    EXPECT_EQ(la.accepted[u], 1) << "ALPHA urn " << u;
    EXPECT_EQ(lb.accepted[u], 1) << "BRAVO urn " << u;
    EXPECT_EQ(la.filled[u], 100u) << "ALPHA urn " << u;
    EXPECT_EQ(lb.filled[u], 100u) << "BRAVO urn " << u;
  }
  std::map<std::uint64_t, int> both = la.executions;
  for (const auto& [m, n] : lb.executions) both[m] += n;
  EXPECT_EQ(both.size(), kTotal);
  for (const auto& [m, n] : both) EXPECT_EQ(n, 2) << "match " << m;
  EXPECT_EQ(am.duplicates() + bm.duplicates() + am.gaps() + bm.gaps(), 0u);

  // Line A now comes from the new primary (it publishes both lines, 10 §4 step 4), and
  // the feed the subscriber assembled from both lines and both re-request servers is
  // complete and equal to the new primary's journal regeneration.
  EXPECT_EQ(sub.last_source(0), sender_b) << sub.summary();
  const std::string st = b.status();
  ASSERT_TRUE(sub.wait_messages(Control::field(st, "itch"), 10s)) << sub.summary() << "\n" << st;
  // The OUCH streams equal the regeneration of B's journal (which holds the replicated
  // history and its own epoch).
  const Regenerated r = regenerate(b.journal_dir(), dir / "regen");
  ASSERT_EQ(r.exit_code, 0) << r.report;
  EXPECT_TRUE(r.ouch.at(1) == sa) << "ALPHA";
  EXPECT_TRUE(r.ouch.at(2) == sb) << "BRAVO";
  std::vector<Bytes> feed = sub.messages();
  feed.resize(std::min(feed.size(), r.itch.size()));
  EXPECT_EQ(sub.messages().size(), r.itch.size()) << sub.summary();
  EXPECT_TRUE(feed == r.itch) << "feed differs from the new primary's journal";
  // B's metrics segment: replication and, after the takeover, sequencing recorded work
  // time (T32); the replica shares the seq thread here, so there is no tee ring.
  auto seg = metrics::Reader::open_shm("haB");
  ASSERT_TRUE(seg.has_value()) << seg.error();
  auto counter = [&](const char* name) -> std::uint64_t {
    const auto i = seg->find_counter(name);
    return i ? seg->counter(*i).value : ~std::uint64_t{0};
  };
  for (const char* c : {"repl_work_items", "repl_work_tsc", "seq_work_items", "seq_work_tsc", "engine_work_items",
                        "gw0_work_items", "gw1_work_items", "ring_l2_hwm"}) {
    EXPECT_GT(counter(c), 0u) << c;
    EXPECT_NE(counter(c), ~std::uint64_t{0}) << c;
  }
  EXPECT_EQ(counter("ring_tee_cap"), 0u);
  EXPECT_EQ(b.stop(), 0) << b.output();
}

// A mirror session's input is FORWARDed to the primary (10 §3). An over-long packet the
// backup's gateway truncated must be sequenced exactly as if it had been submitted to
// the primary directly: the same payload bytes and kFlagMalformedInput
// (wire::Forward::record_flags), so the engine answers it the same way.
TEST(ExchangeHa, ForwardedOverLongInputKeepsItsRecordFlags) {
  const auto dir = fresh_dir("ha-flags");
  const ScopedDir cleanup(dir);
  ha::TrialOptions o;
  ha::Witness w(dir, o.tie_break_ms);
  ASSERT_NE(w.port(), 0) << w.init_output() << w.output();
  ha::UdpRelay relay;
  const std::uint16_t bind[2] = {free_port(SOCK_DGRAM), free_port(SOCK_DGRAM)};
  relay.start(bind[0], bind[1]);
  MoldSubscriber sub;
  Exchange a(ha::paired_node(0, dir, sub, w.port(), relay, bind, o), dir);
  Exchange b(ha::paired_node(1, dir, sub, w.port(), relay, bind, o), dir);
  a.launch();
  b.launch();
  ASSERT_TRUE(a.wait_ready()) << a.output();
  ASSERT_TRUE(b.wait_ready()) << b.output();
  bool paired = false;
  for (int i = 0; i < 500 && !paired; ++i) {
    paired = a.status().find("role=P ") != std::string::npos && b.status().find("role=B ") != std::string::npos;
    if (!paired) std::this_thread::sleep_for(10ms);
  }
  ASSERT_TRUE(paired) << a.status() << "\n" << b.status();
  b.clock("09:31:00");
  a.clock("09:31:00");
  OuchClient ap("ALPHA", "alpha-pw"), am("ALPHA", "alpha-pw");
  ASSERT_EQ(ap.login(a.port("gw0")), 'A');
  ASSERT_EQ(am.login(b.port("gw0")), 'A');
  // An Enter Order padded to 200 bytes: over the 168-byte inbound slot, so the gateway
  // truncates it and flags the record.
  engine::EnterArgs e;
  e.urn = 77;
  e.side = ouch50::Side::Buy;
  e.qty = 100;
  e.symbol = "AAPL";
  e.price = 1'500'000;
  Bytes big = engine::enter_msg(e);
  big.resize(200, std::byte{0x20});
  e.urn = 78;  // the forwarded one (a repeated UserRefNum would be dropped as a duplicate)
  Bytes big2 = engine::enter_msg(e);
  big2.resize(200, std::byte{0x20});
  // Waits for more than `n` messages on the primary connection, then for quiet.
  auto settle = [&](std::size_t n) {
    const auto end = std::chrono::steady_clock::now() + 10s;
    while (ap.received().size() <= n && std::chrono::steady_clock::now() < end) {
      ap.poll(5);
      am.poll(1);
    }
    for (int i = 0; i < 20; ++i) {
      ap.poll(5);
      am.poll(5);
    }
  };
  ap.settle(100ms);
  const std::size_t before = ap.received().size();
  ap.send(big);  // direct submission on the primary
  settle(before);
  const std::size_t mid = ap.received().size();
  am.send(big2);  // the same kind of packet on the backup's mirror session: FORWARDed
  settle(mid);
  const std::size_t after = ap.received().size();
  ASSERT_GT(mid, before) << "no response to the direct submission";
  ASSERT_EQ(after - mid, mid - before) << "the forwarded submission got a different number of responses";
  for (std::size_t i = 0; i < mid - before; ++i) {
    const Bytes& d = ap.received()[before + i].msg;
    const Bytes& f = ap.received()[mid + i].msg;
    ASSERT_EQ(d.size(), f.size()) << i;
    // Equal but for the timestamp (bytes 1..8) and the UserRefNum (9..12).
    EXPECT_TRUE(std::equal(d.begin(), d.begin() + 1, f.begin()) && std::equal(d.begin() + 13, d.end(), f.begin() + 13))
        << "response " << i << ": direct " << Ouch{d}.str() << " vs forwarded " << Ouch{f}.str();
    EXPECT_EQ(Ouch{d}.urn(), 77u);
    EXPECT_EQ(Ouch{f}.urn(), 78u);
  }
  std::printf("over-long input answered with %zu message(s): %s\n", mid - before,
              Ouch{ap.received()[before].msg}.str().c_str());
  // The mirror connection saw the same stream.
  for (int i = 0; i < 40 && am.received().size() < after; ++i) am.poll(5);
  ASSERT_EQ(am.received().size(), after);
  EXPECT_EQ(Control::value(a.cmd("sync")) != 0, true);
  // Both nodes journaled both records: same payload (the first 168 bytes), the flag, and
  // the instance that received it (A's 0, B's 1 forwarded).
  const std::uint64_t seq_a = Control::field(a.status(), "seq");
  for (int i = 0; i < 200 && Control::field(b.status(), "seq") < seq_a; ++i) std::this_thread::sleep_for(10ms);
  EXPECT_EQ(a.stop(), 0);
  EXPECT_EQ(b.stop(), 0);
  for (const std::string& jdir : {a.journal_dir(), b.journal_dir()}) {
    SCOPED_TRACE(jdir);
    auto d = journal::PosixSegmentDir::open(jdir, false, journal::PosixDeviceOptions{.read_only = true});
    ASSERT_TRUE(d.has_value());
    std::vector<std::pair<std::uint16_t, Bytes>> overlong;  // (instance, payload) of flagged OUCH records
    std::uint64_t flagged = 0;
    journal::ReadOptions ro;
    ro.day = 20261001;
    (void)journal::read_journal(*d, ro, [&](const journal::RecordView& r, const journal::RecordLocation&) {
      if (r.type() != journal::RecordType::OuchInbound) return true;
      const auto in = journal::decode_ouch_inbound(r);
      if (!in || in->session_id != 1 || in->msg.size() < 160) return true;
      if ((r.flags() & journal::kFlagMalformedInput) != 0) ++flagged;
      overlong.emplace_back(in->instance, Bytes(in->msg.begin(), in->msg.end()));
      return true;
    });
    ASSERT_EQ(overlong.size(), 2u);
    EXPECT_EQ(flagged, 2u) << "both records carry kFlagMalformedInput";
    EXPECT_EQ(overlong[0].first, 0u);
    EXPECT_EQ(overlong[1].first, 1u) << "the second came from the backup's instance";
    EXPECT_EQ(overlong[0].second.size(), 168u);  // seq::InboundMsg::kMaxBytes
    // The payloads are the first 168 bytes of what each client sent.
    EXPECT_TRUE(std::equal(overlong[0].second.begin(), overlong[0].second.end(), big.begin()));
    EXPECT_TRUE(std::equal(overlong[1].second.begin(), overlong[1].second.end(), big2.begin()));
  }
}

// ADR-032 on the paired paths: the InstanceDown records of the dead instances are the
// first records after the new epoch's EpochStart, ahead of every Timer that came due
// meanwhile. CHARL (cancel-on-disconnect) and BRAVO rest crossing orders for the open on
// one node; that node dies while the survivor's clock is past 09:30. Parameter: the
// replica on its own thread (split: InstanceDown reaches the sequencer while the seq
// thread is parked).
class DeadInstancesFirst : public ::testing::TestWithParam<bool> {
 protected:
  void SetUp() override {
    o_.repl_thread = GetParam();
    dir_ = fresh_dir(std::string("ha-adr32-") + ::testing::UnitTest::GetInstance()->current_test_info()->name());
    cleanup_ = std::make_unique<ScopedDir>(dir_);
    w_ = std::make_unique<ha::Witness>(dir_, o_.tie_break_ms);
    ASSERT_NE(w_->port(), 0) << w_->init_output() << w_->output();
    bind_[0] = free_port(SOCK_DGRAM);
    bind_[1] = free_port(SOCK_DGRAM);
    relay_.start(bind_[0], bind_[1]);
    for (int n = 0; n < 2; ++n)
      ex_[n] = std::make_unique<Exchange>(ha::paired_node(n, dir_, sub_, w_->port(), relay_, bind_, o_), dir_);
    ex_[0]->launch();
    ex_[1]->launch();
    ASSERT_TRUE(ex_[0]->wait_ready()) << ex_[0]->output();
    ASSERT_TRUE(ex_[1]->wait_ready()) << ex_[1]->output();
    ASSERT_TRUE(wait_role(0, "P") && wait_role(1, "B")) << ex_[0]->status() << "\n" << ex_[1]->status();
    if (o_.repl_thread) ASSERT_NE(ex_[0]->output().find("replica on its own thread"), std::string::npos);
    ex_[1]->clock("09:00:00");
    ex_[0]->clock("09:00:00");
  }
  bool wait_role(int n, const std::string& role, std::chrono::milliseconds limit = 30s) {
    const auto end = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < end) {
      if (ex_[n] && ex_[n]->status().find("role=" + role + " ") != std::string::npos) return true;
      std::this_thread::sleep_for(5ms);
    }
    return false;
  }
  // CHARL buys and BRAVO sells 100 AAPL at 150.00 on node n's gateways, held for the
  // opening cross; both answered (released: committed on a pair, durable when solo).
  void rest_crossing_orders(int n) {
    for (OuchClient* c : {&charl_, &bravo_}) c->drop();
    ASSERT_EQ(charl_.login(ex_[n]->port("gw0")), 'A');
    ASSERT_EQ(bravo_.login(ex_[n]->port("gw1")), 'A');
    engine::EnterArgs e;
    e.urn = 1;
    e.qty = 100;
    e.symbol = "AAPL";
    e.price = 1'500'000;
    e.side = ouch50::Side::Buy;
    charl_.send(engine::enter_msg(e));
    e.side = ouch50::Side::Sell;
    bravo_.send(engine::enter_msg(e));
    for (OuchClient* c : {&charl_, &bravo_}) {
      bool accepted = false;
      for (int i = 0; i < 400 && !accepted; ++i) {
        c->poll(5);
        for (const Received& r : c->received()) accepted = accepted || Ouch{r.msg}.type() == 'A';
      }
      ASSERT_TRUE(accepted) << ex_[n]->status();
    }
  }
  // The survivor's journal and day: InstanceDown of `dead_instance` first after its last
  // EpochStart, CHARL's order cancelled, never crossed.
  void check(int survivor, std::uint16_t dead_instance) {
    ASSERT_NE(ex_[survivor]->sync(), 0u);
    const std::string jdir = ex_[survivor]->journal_dir();
    EXPECT_EQ(ex_[survivor]->stop(), 0) << ex_[survivor]->output();
    const std::vector<JournalRec> recs = journal_records(jdir);
    const std::uint64_t es = last_epoch_start(recs);
    ASSERT_GT(es, 0u);
    expect_dead_instances_first(recs, es, dead_instance, 3);
    const Regenerated r = regenerate(jdir, dir_ / "regen");
    ASSERT_EQ(r.exit_code, 0) << r.report;
    expect_cod_order_cancelled_before_the_cross(r, 3, 2);  // CHARL, BRAVO
  }

  ha::TrialOptions o_;
  std::filesystem::path dir_;
  std::unique_ptr<ScopedDir> cleanup_;
  std::unique_ptr<ha::Witness> w_;
  ha::UdpRelay relay_;
  std::uint16_t bind_[2] = {0, 0};
  MoldSubscriber sub_;
  std::unique_ptr<Exchange> ex_[2];
  OuchClient charl_{"CHARL", "charl-pw"}, bravo_{"BRAVO", "bravo-pw"};
};

// PROMOTE (10 §4 step 5): B takes over from the dead primary A; A's instances go down
// before the opening cross that came due while B was the backup.
TEST_P(DeadInstancesFirst, TakeoverCancelsTheDeadPrimarysOrdersBeforeAnOverdueCross) {
  if (HasFatalFailure()) return;
  rest_crossing_orders(0);
  if (HasFatalFailure()) return;
  // The backup does not sequence: its clock passes the open with no Timer, so at the
  // takeover the cross and every 1 Hz timer since 09:00 are overdue.
  ex_[1]->clock("09:31:00");
  ex_[0]->kill9();
  charl_.drop();
  bravo_.drop();
  ASSERT_TRUE(wait_role(1, "SP")) << ex_[1]->status() << "\n" << ex_[1]->output() << "\n" << w_->output();
  EXPECT_NE(w_->output().find("PROMOTE granted"), std::string::npos) << w_->output();
  check(1, 0);
}

// RESUME (10 §5): the solo primary of record A dies with CHARL's and BRAVO's
// connections and restarts with its clock past 09:30; its own old instances go down
// before the overdue cross.
TEST_P(DeadInstancesFirst, ResumeCancelsItsOwnDeadOrdersBeforeAnOverdueCross) {
  if (HasFatalFailure()) return;
  ex_[1]->kill9();  // A goes solo (SOLO after T_ack)
  ASSERT_TRUE(wait_role(0, "SP")) << ex_[0]->status() << "\n" << w_->output();
  rest_crossing_orders(0);
  if (HasFatalFailure()) return;
  ex_[0]->kill9();
  charl_.drop();
  bravo_.drop();
  NodeSpec s = ha::paired_node(0, dir_, sub_, w_->port(), relay_, bind_, o_);
  s.name = "haA-resumed";  // its own configuration and output files; the same data directory
  s.start = "09:31:00";
  ex_[0] = std::make_unique<Exchange>(s, dir_);
  ex_[0]->launch();
  ASSERT_TRUE(ex_[0]->wait_ready(30s)) << ex_[0]->output();
  ASSERT_NE(ex_[0]->output().find("rejoin: resumed as the solo primary at"), std::string::npos) << ex_[0]->output();
  ASSERT_TRUE(wait_role(0, "SP")) << ex_[0]->status();
  check(0, 0);
}

INSTANTIATE_TEST_SUITE_P(Adr032, DeadInstancesFirst, ::testing::Values(false, true),
                         [](const ::testing::TestParamInfo<bool>& i) { return i.param ? "Split" : "Combined"; });

}  // namespace
}  // namespace lle::exch::test
