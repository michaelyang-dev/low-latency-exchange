// The scripted day end to end (N-03): exact OUCH responses (scripted_day.h), the ITCH
// feed received through two lossy, independently packetized lines plus re-requests, our
// feed through itch_validate --strict (T06), and every output byte regenerated from the
// journal by journal_replay --emit, equal to what the clients, the feed and the output
// log hold (T05).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <string>

#include "md/glimpse_state.h"
#include "metrics/segment.h"
#include "proto/glimpse/glimpse.h"
#include "proto/glimpse/snapshot_server.h"
#include "scripted_day.h"
#include "verify.h"

namespace lle::exch::test {
namespace {

std::vector<std::string> feed_events(const std::vector<Bytes>& feed) {
  std::vector<std::string> v;
  for (const Bytes& m : feed) {
    const char t = type_of(m);
    if (t == 'S' || t == 'I') continue;  // system events and NOII are checked separately
    v.push_back(Itch{m}.str());
  }
  return v;
}

// Stage work time (METHODOLOGY §16, T32): every stage that handled items recorded the
// cycle-counter time of those polls and their items in the metrics segment, and lle_top
// shows ns per item for each.
template <class Counter>
void check_work_time(ScriptedDay& day, Counter&& counter) {
  EXPECT_GT(counter("tsc_hz"), 0u);
  const char* stages[] = {"gw0", "gw1", "seq", "engine", "io", "md", "glimpse"};
  for (const char* st : stages) {
    const std::string s(st);
    EXPECT_GT(counter((s + "_work_items").c_str()), 0u) << s;
    EXPECT_GT(counter((s + "_work_tsc").c_str()), 0u) << s;
  }
  EXPECT_EQ(counter("engine_work_items"), counter("engine_records")) << "engine items: the records applied";
  EXPECT_GT(counter("seq_work_items"), 0u);
  EXPECT_LE(counter("seq_work_items"), counter("seq_records")) << "seq items: records sequenced after the day start";
  EXPECT_GE(counter("io_work_items"), counter("io_records"));
  EXPECT_GE(counter("md_work_items"), counter("md_messages"));
  // Ring occupancy (T20 validity): capacities, and samples within them; no tee in solo mode.
  EXPECT_GT(counter("node_start_ns"), 0u);
  for (const char* r : {"l2", "egress", "ouch", "events"}) {
    const std::string p = std::string("ring_") + r + "_";
    const std::uint64_t cap = counter((p + "cap").c_str());
    EXPECT_GT(cap, 0u) << r;
    EXPECT_LE(counter((p + "used").c_str()), cap) << r;
    EXPECT_LE(counter((p + "hwm").c_str()), cap) << r;
    EXPECT_LE(counter((p + "peak").c_str()), counter((p + "hwm").c_str())) << r;
    EXPECT_LE(counter((p + "used").c_str()), counter((p + "hwm").c_str())) << r;
  }
  EXPECT_GT(counter("ring_l2_hwm"), 0u) << "the day's records passed through L2";
  EXPECT_GT(counter("ring_egress_hwm"), 0u);
  EXPECT_EQ(counter("ring_ouch_cap"), 4096u);
  EXPECT_EQ(counter("ring_tee_cap"), 0u);
#ifdef LLE_LLE_TOP
  const std::string top = run_capture({LLE_LLE_TOP, day.spec().name, "--once"});
  const std::size_t at = top.find("STAGE WORK");
  ASSERT_NE(at, std::string::npos) << top;
  for (const char* st : stages) {
    // "<stage> <items> <work_ms> <ns/item>" in the STAGE WORK section.
    const std::size_t line = top.find(std::string("\n") + st + " ", at);
    ASSERT_NE(line, std::string::npos) << "lle_top shows no work line for " << st << "\n" << top;
    char name[32] = {};
    unsigned long long items = 0;
    double ms = 0, ns_per_item = 0;
    ASSERT_EQ(std::sscanf(top.c_str() + line + 1, "%31s %llu %lf %lf", name, &items, &ms, &ns_per_item), 4) << top;
    EXPECT_EQ(items, counter((std::string(st) + "_work_items").c_str())) << st;
    EXPECT_GT(ns_per_item, 0.0) << st;
  }
#endif
}

// GLIMPSE (03 §8, N-18): a snapshot taken while AAPL is halted with two resting bids.
// The spin must equal the state the feed's messages 1..N-1 describe, where G carries N,
// and hold what the script left on the book.
void check_glimpse(ScriptedDay& day) {
  OuchClient g("GLIMPS", "glimpse-pw");
  ASSERT_EQ(g.login(day.ex().port("glimpse"), 1), 'A');
  bool done = false;
  for (int i = 0; i < 400 && !done; ++i) {
    g.poll(5);
    done = !g.received().empty() && type_of(g.received().back().msg) == glimpse::kEndOfSnapshotType;
  }
  ASSERT_TRUE(done) << "no End of Snapshot";
  g.settle(50ms);
  EXPECT_TRUE(g.ended()) << "the snapshot session ends after the spin";
  const auto next = glimpse::decode_end_of_snapshot(g.received().back().msg);
  ASSERT_TRUE(next.has_value());
  ASSERT_TRUE(day.sub().wait_messages(*next - 1, 5s));
  md::GlimpseState local(2);
  for (SeqNo s = 1; s < *next; ++s) local.apply(day.sub().messages()[s - 1]);
  std::vector<Bytes> want;
  (void)glimpse::SnapshotServer{}.emit(local, [&](std::span<const std::byte> m) { want.emplace_back(m.begin(), m.end()); });
  std::vector<Bytes> got;
  std::vector<std::string> orders;
  for (const Received& r : g.received()) {
    got.push_back(r.msg);
    if (type_of(r.msg) == 'A' || type_of(r.msg) == 'H') orders.push_back(Itch{r.msg}.str());
  }
  EXPECT_TRUE(got == want) << "the spin differs from the state of the feed at " << *next - 1;
  EXPECT_EQ(orders, (std::vector<std::string>{"H loc=1 AAPL state=H reason=T1", "A loc=1 ref=9 B 50 AAPL @1400000",
                                              "A loc=1 ref=10 B 100 AAPL @1505000"}));
}

TEST(ExchangeDay, ScriptedDayFeedAndRegeneration) {
  ScriptedDay::Options o = ScriptedDay::Options::named("day");
  o.drop_a = 5;
  o.drop_b = 7;
  o.max_packet_b = 72;
  o.drop_seq = 500;
  o.after_step = [](ScriptedDay& d, std::size_t step) {
    if (step == 8) check_glimpse(d);
  };
  o.glimpse = true;
  o.metrics = true;
  ScriptedDay day(o);
  day.run();
  if (::testing::Test::HasFatalFailure()) return;
  const std::vector<Bytes>& feed = day.sub().messages();
  if (dump_enabled())
    for (const Bytes& m : feed) std::printf("  ITCH %s\n", Itch{m}.str().c_str());

  // MoldUDP64: every released ITCH message exactly once and in sequence, although each
  // line lost packets: the arbiter filled them from the other line and by re-request.
  const std::string st = day.ex().status();
  if (dump_enabled()) std::printf("%s\n%s\n", day.sub().summary().c_str(), st.c_str());
  EXPECT_EQ(feed.size(), Control::field(st, "itch")) << st;
  // Lines A and B are packetized independently (07 §3): line B's 72-byte packets carry one
  // message each, line A batches. Every message reaches the arbiter on both lines, so the
  // later copy is dropped as a duplicate or a partial overlap (03 §7). How often each case
  // occurs depends on arrival timing; the arbiter's own tests cover both deterministically.
  const auto& am = day.sub().metrics();
  EXPECT_LT(day.sub().data_packets(0), day.sub().data_packets(1)) << day.sub().summary();
  EXPECT_GT(am.duplicate_packets[0] + am.duplicate_packets[1] + am.partial_overlaps[0] + am.partial_overlaps[1], 0u)
      << day.sub().summary();
  RecordProperty("arbitration", day.sub().summary());
  std::printf("arbiter: %s\n", day.sub().summary().c_str());
  // Message 500 was lost on both lines: the gap was filled from the re-request server.
  EXPECT_GE(day.sub().dropped_sequence_packets(), 1u) << day.sub().summary();
  EXPECT_GT(am.gaps_opened, 0u) << day.sub().summary();
  EXPECT_GT(am.gaps_filled_by_rerequest, 0u) << day.sub().summary();

  // The day's system events in order (06 §10): start of messages, start of system hours,
  // start of market hours, end of market hours, end of system hours, end of messages.
  std::string events;
  for (const Bytes& m : feed)
    if (type_of(m) == 'S') events += static_cast<char>(m[11]);
  EXPECT_EQ(events, "OSQMEC");

  // Order and trade messages, as the matching rules prescribe for the script.
  const std::vector<std::string> want = {
      "R loc=1 AAPL",
      "R loc=2 MSFT",
      "Y loc=1",
      "Y loc=2",
      "Q loc=1 shares=300 AAPL @1500000 match=3 type=O",  // opening cross (§9.7)
      "Q loc=2 shares=0 MSFT @0 match=4 type=O",          // always a Q for the open
      "A loc=2 ref=4 B 100 MSFT @2990000",                 // held Day order joins the book
      "A loc=1 ref=5 S 500 AAPL @1510000",
      "E loc=1 ref=5 shares=200 match=5",
      "U loc=1 orig=5 new=7 shares=200 @1515000",          // replace keeps resting: ITCH U
      "D loc=1 ref=7",                                     // cancel
      "E loc=2 ref=4 shares=100 match=6",
      "A loc=1 ref=9 B 50 AAPL @1400000",
      "H loc=1 AAPL state=H reason=T1",                    // halt (admin)
      "A loc=1 ref=10 B 100 AAPL @1505000",
      "H loc=1 AAPL state=T reason=",                      // operator release
      "D loc=1 ref=9",                                     // cancel-on-disconnect
      "Q loc=1 shares=100 AAPL @1505000 match=8 type=C",  // closing cross
      "Q loc=2 shares=0 MSFT @0 match=9 type=C",
      "D loc=1 ref=10",                                    // Day order expires after the close
  };
  EXPECT_EQ(feed_events(feed), want);
  // NOII during the opening and closing auction periods (§10.1).
  EXPECT_GT(std::count_if(feed.begin(), feed.end(), [](const Bytes& m) { return type_of(m) == 'I'; }), 100);

  // T06: 0 validator errors on our feed.
  const std::string file = (day.dir() / "feed.bin").string();
  ASSERT_TRUE(day.sub().write_binary_file(file));
  const ValidateResult v = itch_validate(file);
  EXPECT_EQ(v.exit_code, 0) << v.report;
  EXPECT_EQ(v.violations, 0u) << v.report;
  EXPECT_EQ(v.messages, feed.size()) << v.report;

  // T05: every output byte regenerates from the journal.
  check_regeneration(day, "live");

  // The metrics segment (11 §3) as lle-top reads it.
  auto reader = metrics::Reader::open_shm(day.spec().name);
  ASSERT_TRUE(reader.has_value()) << reader.error();
  auto counter = [&](const char* name) -> std::uint64_t {
    const auto i = reader->find_counter(name);
    return i ? reader->counter(*i).value : ~std::uint64_t{0};
  };
  EXPECT_EQ(counter("engine_rejects"), 1u);
  EXPECT_EQ(counter("engine_orders"), 11u);  // the script's 'A' responses
  EXPECT_EQ(counter("engine_itch"), feed.size());
  EXPECT_EQ(counter("md_messages"), feed.size());
  EXPECT_GT(counter("md_rerequests_served"), 0u);
  EXPECT_EQ(counter("gw0_msgs_in") + counter("gw1_msgs_in"), 14u);  // the script's OUCH messages
  EXPECT_EQ(counter("io_durable_index"), counter("seq_last_index"));
  check_work_time(day, counter);
  EXPECT_EQ(day.ex().stop(), 0) << day.ex().output();

  // nlog (11 §3, T32): the events of the gateway, sequencer, engine and md, decoded
  // offline from the binary log by nlog_decode.
  const std::string log = run_capture({LLE_NLOG_DECODE, day.spec().data_dir + "/logs/" + day.spec().name + "-20261001.nlog"});
  for (const char* event : {"gw0 login session 1 instance 0", "gw1 login session 2 instance 0",
                            "gw0 session 3 D (reason 0)", "cancel-on-disconnect trigger: session 3",
                            "gw0 session 3 sequence recovery", "engine reject session 3 urn 3 code 23",
                            "engine admin command 1", "engine trading action locate 1 state 'H'",
                            "engine cross locate 1 shares 300", "engine system event 'Q'", "seq day end",
                            "engine day end", "md end of session", "gw0 end of day", "glimpse: snapshot at"}) {
    EXPECT_NE(log.find(event), std::string::npos) << "nlog has no \"" << event << "\"";
  }
}

// tshark on the node's own MoldUDP64 packets (T08 interop, 03 §9): both lines as
// received, written to pcaps and dissected by Wireshark's MoldUDP64 dissector through
// tools/spec/mold_tshark_check.sh: no malformed packet, no expert warning, no sequence
// gap, every message counted. Needs tshark (the Linux VM has it).
TEST(ExchangeDay, TsharkDissectsOurMoldUdp64Lines) {
  if (run_capture({"sh", "-c", "command -v tshark"}).empty()) GTEST_SKIP() << "tshark not installed";
  ScriptedDay::Options o = ScriptedDay::Options::named("tshark");
  o.record = true;
  ScriptedDay day(o);
  day.run();
  if (::testing::Test::HasFatalFailure()) return;
  EXPECT_EQ(day.ex().stop(), 0);
  const std::size_t messages = day.sub().messages().size();
  for (int line = 0; line < 2; ++line) {
    const std::string pcap = (day.dir() / (line == 0 ? "line-a.pcap" : "line-b.pcap")).string();
    ASSERT_TRUE(day.sub().write_pcap(pcap, line));
    const std::string report = run_capture({std::string(LLE_SOURCE_DIR) + "/tools/spec/mold_tshark_check.sh", pcap});
    SCOPED_TRACE(report);
    EXPECT_NE(report.find("malformed or expert >= warning: 0"), std::string::npos);
    EXPECT_NE(report.find("sequence gaps: 0"), std::string::npos);
    EXPECT_NE(report.find("messages: " + std::to_string(messages) + ","), std::string::npos);
    EXPECT_NE(report.find("end-of-session: "), std::string::npos);
    std::printf("tshark line %c: %s", line == 0 ? 'A' : 'B', report.substr(report.find("messages:")).c_str());
  }
}

TEST(ExchangeDay, InlineRunnerSameJournalAsThreads) {
  // The same day on one thread (InlineRunner mode, 01 §7 "Dev") produces the same
  // outputs: the feed and every OUCH stream are byte-identical to the threaded run's.
  ScriptedDay a(ScriptedDay::Options::named("inl-thr"));
  a.run();
  if (::testing::Test::HasFatalFailure()) return;
  // One node at a time (the AF_XDP variant's stages own the veth's queues).
  EXPECT_EQ(a.ex().stop(), 0);
  ScriptedDay::Options ob = ScriptedDay::Options::named("inl-inl");
  ob.runner = "inline";
  ScriptedDay b(ob);
  b.run();
  if (::testing::Test::HasFatalFailure()) return;
  EXPECT_TRUE(a.sub().messages() == b.sub().messages());
  for (const auto& [user, id] : a.session_ids()) EXPECT_TRUE(a.c(user).stream() == b.c(user).stream()) << user;
  check_regeneration(b, "inline");
  EXPECT_EQ(b.ex().stop(), 0);
}

}  // namespace
}  // namespace lle::exch::test
