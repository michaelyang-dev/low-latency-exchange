// Gateway stage gwN (07 §3, N-17) over an in-memory stream port: login and
// authentication, mirror-attach, framing-only inbound, session events, release-gated
// egress, re-login replay (ring and output log), back-pressure, end of day, lingering
// close.
#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "concurrent/mpsc_scq.h"
#include "fake_net.h"
#include "gateway/credentials.h"
#include "gateway/gateway.h"
#include "gateway/session_table.h"
#include "md/egress.h"
#include "outlog/day.h"
#include "proto/soupbin/client_session.h"

namespace lle::gw {
namespace {

using testnet::Bytes;
using testnet::FakeClock;
using testnet::FakeNet;

template <std::size_t OuchCap>
struct Env {
  using Net = FakeNet;
  using OuchQueue = conc::MpscScqRing<seq::InboundMsg, OuchCap>;
  using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 64>;
  using Clock = FakeClock;
};

std::vector<std::uint8_t> salt() { return {9, 8, 7, 6}; }

SessionTable table() {
  std::vector<SessionSpec> v;
  v.push_back(SessionSpec{1, 100, "alpha", Credential::make("alpha-pw", salt()), 0, false});
  v.push_back(SessionSpec{2, 200, "BRAVO", Credential::make("bravo-pw", salt()), 0, true});
  v.push_back(SessionSpec{3, 300, "CHARL", Credential::make("charl-pw", salt()), 1, false});
  return *SessionTable::build(std::move(v), md::kGateways);
}

// A client: soup::ClientSession driven through the fake port.
struct Client {
  Client(testnet::FakeStreamPort& p, std::string user, std::string pw, SeqNo seq = 1) : port(&p) {
    soup::ClientConfig c;
    c.username = Alpha<soup::kUsernameLen>(user);
    c.password = Alpha<soup::kPasswordLen>(pw);
    c.sequence = seq;
    sess = std::make_unique<soup::ClientSession>(c);
    conn = port->accept();
  }
  void connect(Nanos now) { send_actions(sess->connect(now)); }
  void send(std::span<const std::byte> msg, Nanos now) { send_actions(sess->send_unsequenced(msg, now)); }
  void send_actions(const soup::Actions& a) {
    if (!a.write.empty()) {
      port->data(conn, a.write);
      sess->consume_tx(a.write.size());
    }
  }
  // Reads what the gateway wrote since the last call.
  void read(Nanos now) {
    const Bytes b = port->take(conn);
    std::size_t off = 0;
    while (off < b.size()) {
      const soup::Actions& a = sess->on_bytes(std::span<const std::byte>(b).subspan(off), now);
      for (const soup::Event& e : a.events) {
        if (e.kind == soup::EventKind::LoggedIn) logged_in = true;
        if (e.kind == soup::EventKind::LoginRejected) reject = e.code;
        if (e.kind == soup::EventKind::EndOfSession) ended = true;
      }
      for (const soup::Delivered& d : a.delivered)
        if (d.seq != 0) got.push_back({d.seq, Bytes(d.data.begin(), d.data.end())});
      off += a.consumed;
      if (a.consumed == 0) break;
    }
  }
  testnet::FakeStreamPort* port;
  std::unique_ptr<soup::ClientSession> sess;
  env::ConnId conn;
  bool logged_in = false;
  bool ended = false;
  char reject = 0;
  std::vector<std::pair<SeqNo, Bytes>> got;
};

Bytes msg(std::uint8_t tag, std::size_t n = 20) {
  Bytes b(n, std::byte{tag});
  b[0] = std::byte{'O'};
  return b;
}

template <std::size_t OuchCap = 64>
struct Fixture {
  explicit Fixture(std::uint8_t index = 0, std::string outlog_root = {}, std::size_t ring_msgs = 64) : tbl(table()) {
    egress.init(std::size_t{1} << 16);
    GatewayConfig c;
    c.index = index;
    c.instance = 0;
    c.soup.session = soup::SessionId::from("SESS000001");
    c.tcp.max_conns = 8;
    c.tcp.rx_buf_bytes = 1024;
    c.tcp.max_reads_per_poll = 2;
    c.rx_backlog_bytes = 8 * 1024;
    c.replay_ring_messages = ring_msgs;
    c.replay_ring_bytes = 64 * 1024;
    c.outlog_root = std::move(outlog_root);
    c.day = 20261001;
    gw = std::make_unique<Gateway<Env<OuchCap>>>(c, tbl, std::span<const std::pair<std::uint32_t, SeqNo>>{}, ouch,
                                                 events, clock, GatewayShared{&egress, &state, &mirror});
    EXPECT_TRUE(gw->start());
  }
  testnet::FakeStreamPort& port() { return gw->port(); }
  void poll(int n = 3) {
    for (int i = 0; i < n; ++i) (void)gw->poll();
  }
  void release(std::uint64_t w) {
    state.release.store(w);
    if (state.applied.load() < w) state.applied.store(w);
  }
  void out(std::uint64_t index, std::uint32_t session, std::span<const std::byte> m) {
    ASSERT_TRUE(egress.try_push(index, md::OutKind::Ouch, session, m));
  }
  std::vector<seq::SessionEventMsg> drain_events() {
    std::vector<seq::SessionEventMsg> v;
    seq::SessionEventMsg e;
    while (events.try_pop(e)) v.push_back(e);
    return v;
  }
  std::vector<seq::InboundMsg> drain_ouch() {
    std::vector<seq::InboundMsg> v;
    seq::InboundMsg m;
    while (ouch.try_pop(m)) v.push_back(m);
    return v;
  }

  SessionTable tbl;
  typename Env<OuchCap>::OuchQueue ouch;
  typename Env<OuchCap>::SessionQueue events;
  FakeClock clock;
  md::EgressRing egress;
  md::EgressState state;
  std::atomic<bool> mirror{false};
  std::unique_ptr<Gateway<Env<OuchCap>>> gw;
};

TEST(Credential, SaltedHashRoundTripAndNormalization) {
  const Credential c = Credential::make("Secret", salt());
  EXPECT_TRUE(c.verify("secret"));      // case-insensitive (SoupBinTCP §2.3.1)
  EXPECT_TRUE(c.verify("  SECRET   "));  // space padded
  EXPECT_FALSE(c.verify("secrets"));
  const auto parsed = Credential::parse(c.text());
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->verify("SECRET"));
  EXPECT_EQ(parsed->text(), c.text());
  EXPECT_FALSE(Credential::parse("plain:secret").has_value());
  EXPECT_FALSE(Credential::parse("sha256$zz$00").has_value());
  EXPECT_FALSE(Credential::parse("sha256$0102$0011").has_value());  // digest too short
  EXPECT_FALSE(Credential{}.verify(""));
}

TEST(SessionTable, ValidatesAndLooksUp) {
  const SessionTable t = table();
  ASSERT_EQ(t.size(), 3u);
  ASSERT_NE(t.find_user("ALPHA"), nullptr);
  EXPECT_EQ(t.find_user(" alpha ")->session_id, 1u);
  EXPECT_EQ(t.find_user("nobody"), nullptr);
  EXPECT_EQ(t.find_id(3)->gateway, 1);
  std::vector<SessionSpec> dup = {SessionSpec{1, 1, "A", Credential::make("x", salt()), 0, false},
                                  SessionSpec{2, 1, "a", Credential::make("x", salt()), 0, false}};
  EXPECT_FALSE(SessionTable::build(dup, 2).has_value());  // usernames equal after normalization
  std::vector<SessionSpec> bad = {SessionSpec{1, 1, "TOOLONGNAME", Credential::make("x", salt()), 0, false}};
  EXPECT_FALSE(SessionTable::build(bad, 2).has_value());
  std::vector<SessionSpec> gw = {SessionSpec{1, 1, "A", Credential::make("x", salt()), 5, false}};
  EXPECT_FALSE(SessionTable::build(gw, 2).has_value());
}

TEST(Gateway, LoginAuthenticatesAndJournalsTheSessionEvent) {
  Fixture f;
  Client c(f.port(), "ALPHA", "ALPHA-PW");
  c.connect(f.clock.mono);
  f.poll();
  c.read(f.clock.mono);
  EXPECT_TRUE(c.logged_in);
  const auto ev = f.drain_events();
  ASSERT_EQ(ev.size(), 1u);
  EXPECT_EQ(ev[0].session_id, 1u);
  EXPECT_EQ(ev[0].instance, 0u);
  EXPECT_EQ(ev[0].event, journal::SessionEventKind::Login);
  EXPECT_EQ(ev[0].requested_seq, 1u);
  EXPECT_EQ(f.gw->stats().logins, 1u);
}

TEST(Gateway, BadPasswordUnknownUserAndOtherGatewayAreNotAuthorized) {
  Fixture f;  // gw0
  Client bad(f.port(), "ALPHA", "wrong");
  Client nobody(f.port(), "NOBODY", "x");
  Client other(f.port(), "CHARL", "charl-pw");  // a gw1 session
  for (Client* c : {&bad, &nobody, &other}) c->connect(f.clock.mono);
  f.poll();
  for (Client* c : {&bad, &nobody, &other}) {
    c->read(f.clock.mono);
    EXPECT_FALSE(c->logged_in);
    EXPECT_EQ(c->reject, 'A');
  }
  EXPECT_TRUE(f.drain_events().empty());
  EXPECT_EQ(f.gw->stats().login_rejects, 3u);
}

TEST(Gateway, SecondLoginOfASessionOnThisPortGetsSessionUnavailable) {
  Fixture f;
  Client a(f.port(), "ALPHA", "alpha-pw"), b(f.port(), "ALPHA", "alpha-pw");
  a.connect(f.clock.mono);
  f.poll();
  b.connect(f.clock.mono);
  f.poll();
  a.read(f.clock.mono);
  b.read(f.clock.mono);
  EXPECT_TRUE(a.logged_in);
  EXPECT_FALSE(b.logged_in);
  EXPECT_EQ(b.reject, 'S');
  // The live connection is untouched: it still receives its stream.
  f.out(5, 1, msg(1));
  f.release(5);
  f.poll();
  a.read(f.clock.mono);
  ASSERT_EQ(a.got.size(), 1u);
}

TEST(Gateway, LoginOnANodeThatIsNotPrimaryIsAMirrorAttach) {
  Fixture f;
  f.mirror.store(true);
  Client c(f.port(), "BRAVO", "bravo-pw", 1);
  c.connect(f.clock.mono);
  f.poll();
  const auto ev = f.drain_events();
  ASSERT_EQ(ev.size(), 1u);
  EXPECT_EQ(ev[0].event, journal::SessionEventKind::MirrorAttach);
  EXPECT_EQ(f.gw->stats().mirror_attaches, 1u);
}

TEST(Gateway, InboundIsFramingOnlyWithRoutingMetadata) {
  Fixture f;
  Client c(f.port(), "BRAVO", "bravo-pw");
  c.connect(f.clock.mono);
  f.poll();
  c.read(f.clock.mono);
  ASSERT_TRUE(c.logged_in);
  (void)f.drain_events();
  const Bytes small = msg(7, 3);  // not a valid OUCH message: still the engine's to reject (ADR-027)
  const Bytes big = msg(8, 300);  // longer than any OUCH message: truncated, flagged
  c.send(small, f.clock.mono);
  c.send(big, f.clock.mono);
  f.poll();
  const auto in = f.drain_ouch();
  ASSERT_EQ(in.size(), 2u);
  EXPECT_EQ(in[0].session_id, 2u);
  EXPECT_EQ(in[0].account, 200u);
  EXPECT_EQ(in[0].instance, 0u);
  EXPECT_EQ(in[0].len, 3u);
  EXPECT_EQ(in[0].flags, 0u);
  EXPECT_TRUE(std::equal(small.begin(), small.end(), in[0].bytes));
  EXPECT_EQ(in[1].len, seq::InboundMsg::kMaxBytes);
  EXPECT_EQ(in[1].flags, journal::kFlagMalformedInput);
  EXPECT_EQ(f.gw->stats().truncated_in, 1u);
}

// Work time (METHODOLOGY §16, T32): a poll reads the work meter's counter twice when it
// handles something and not at all otherwise. (The fake clock also counts the receive
// timestamp each inbound message takes from tsc().)
TEST(Gateway, WorkTimeCoversOnlyPollsThatProcessedItems) {
  Fixture f;
  std::uint64_t reads = f.clock.tsc_reads;
  f.poll(5);
  EXPECT_EQ(f.clock.tsc_reads, reads) << "idle polls read no counter";
  EXPECT_EQ(f.gw->work().batches, 0u);
  Client c(f.port(), "BRAVO", "bravo-pw");
  c.connect(f.clock.mono);
  (void)f.gw->poll();
  c.read(f.clock.mono);
  ASSERT_TRUE(c.logged_in);
  EXPECT_EQ(f.clock.tsc_reads, reads + 2) << "the accept and login: one batch";
  EXPECT_EQ(f.gw->work().batches, 1u);
  EXPECT_GE(f.gw->work().items, 2u);
  EXPECT_GT(f.gw->work().tsc, 0u);
  reads = f.clock.tsc_reads;
  f.poll(5);
  EXPECT_EQ(f.clock.tsc_reads, reads);
  (void)f.drain_events();
  // Two inbound messages: one batch (two meter reads) plus their receive timestamps.
  const std::uint64_t items = f.gw->work().items;
  c.send(msg(1), f.clock.mono);
  c.send(msg(2), f.clock.mono);
  (void)f.gw->poll();
  ASSERT_EQ(f.drain_ouch().size(), 2u);
  EXPECT_EQ(f.clock.tsc_reads, reads + 2 + 2);
  EXPECT_EQ(f.gw->work().batches, 2u);
  EXPECT_GT(f.gw->work().items, items);
  // A released response: one more batch.
  reads = f.clock.tsc_reads;
  f.out(3, 2, msg(9));
  f.release(3);
  (void)f.gw->poll();
  c.read(f.clock.mono);
  ASSERT_EQ(c.got.size(), 1u);
  EXPECT_EQ(f.clock.tsc_reads, reads + 2);
  EXPECT_EQ(f.gw->work().batches, 3u);
  reads = f.clock.tsc_reads;
  f.poll(5);
  EXPECT_EQ(f.clock.tsc_reads, reads);
}

TEST(Gateway, EgressIsReleaseGatedAndNumberedPerSession) {
  Fixture f;
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  f.out(10, 1, msg(1));
  f.out(11, 2, msg(2));  // BRAVO: not logged in, kept for its login
  f.out(12, 1, msg(3));
  f.out(13, 3, msg(4));  // CHARL: another gateway's session
  f.release(9);
  f.poll();
  c.read(f.clock.mono);
  EXPECT_TRUE(c.got.empty()) << "nothing beyond the release watermark may leave (ADR-005)";
  EXPECT_EQ(f.state.done[md::kGw0].load(), 9u);
  f.release(10);
  f.poll();
  c.read(f.clock.mono);
  ASSERT_EQ(c.got.size(), 1u);
  EXPECT_EQ(c.got[0].first, 1u);
  EXPECT_EQ(c.got[0].second, msg(1));
  f.release(13);
  f.poll();
  c.read(f.clock.mono);
  ASSERT_EQ(c.got.size(), 2u);
  EXPECT_EQ(c.got[1].first, 2u);
  EXPECT_EQ(c.got[1].second, msg(3));
  EXPECT_EQ(f.state.done[md::kGw0].load(), 13u);
  // BRAVO logs in later and receives its message as sequence 1 (replay from the store).
  Client b(f.port(), "BRAVO", "bravo-pw");
  b.connect(f.clock.mono);
  f.poll();
  b.read(f.clock.mono);
  ASSERT_EQ(b.got.size(), 1u);
  EXPECT_EQ(b.got[0].first, 1u);
  EXPECT_EQ(b.got[0].second, msg(2));
}

TEST(Gateway, ReloginReplaysFromTheRequestedSequence) {
  Fixture f;
  {
    Client c(f.port(), "ALPHA", "alpha-pw");
    c.connect(f.clock.mono);
    f.poll();
    for (std::uint64_t i = 1; i <= 5; ++i) f.out(i, 1, msg(static_cast<std::uint8_t>(i)));
    f.release(5);
    f.poll();
    c.read(f.clock.mono);
    ASSERT_EQ(c.got.size(), 5u);
    f.port().peer_close(c.conn);
    f.poll();
  }
  const auto ev = f.drain_events();
  ASSERT_EQ(ev.size(), 2u);
  EXPECT_EQ(ev[1].event, journal::SessionEventKind::Disconnect);
  Client again(f.port(), "ALPHA", "alpha-pw", 3);
  again.connect(f.clock.mono);
  f.poll();
  again.read(f.clock.mono);
  ASSERT_EQ(again.got.size(), 3u);
  EXPECT_EQ(again.got[0].first, 3u);
  EXPECT_EQ(again.got[0].second, msg(3));
  EXPECT_EQ(again.got[2].second, msg(5));
  EXPECT_EQ(f.gw->stats().replays, 1u);
  EXPECT_EQ(f.drain_events().back().requested_seq, 3u);
}

TEST(Gateway, ReplayBeyondTheRingReadsTheOutputLog) {
  const auto root = std::filesystem::temp_directory_path() / ("lle-gw-outlog-" + std::to_string(::getpid()));
  std::filesystem::remove_all(root);
  {
    // The io stage's output log: session 1 holds messages 1..6.
    outlog::OutlogDay day;
    const std::uint32_t ids[] = {1, 2};
    ASSERT_TRUE(day.open(root.string(), 20261001, ids));
    for (std::uint8_t i = 1; i <= 6; ++i) ASSERT_TRUE(day.soup(1)->append(msg(i)));
    ASSERT_TRUE(day.close());
  }
  Fixture f(0, root.string(), 2);  // a ring of two messages
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  for (std::uint64_t i = 1; i <= 6; ++i) f.out(i, 1, msg(static_cast<std::uint8_t>(i)));
  f.release(6);
  f.poll();
  c.read(f.clock.mono);
  ASSERT_EQ(c.got.size(), 6u);
  f.port().peer_close(c.conn);
  f.poll();
  Client again(f.port(), "ALPHA", "alpha-pw", 1);
  again.connect(f.clock.mono);
  f.poll(6);
  again.read(f.clock.mono);
  ASSERT_EQ(again.got.size(), 6u);
  for (std::uint8_t i = 1; i <= 6; ++i) EXPECT_EQ(again.got[i - 1].second, msg(i)) << int(i);
  EXPECT_EQ(f.gw->store(1)->stats().log_reads, 4u);
  std::filesystem::remove_all(root);
}

TEST(Gateway, LogoutAndDisconnectAreJournaledAndCodTriggerCounted) {
  Fixture f;
  Client a(f.port(), "ALPHA", "alpha-pw"), b(f.port(), "BRAVO", "bravo-pw");
  a.connect(f.clock.mono);
  b.connect(f.clock.mono);
  f.poll();
  a.send_actions(a.sess->logout(f.clock.mono));
  f.port().peer_close(b.conn);
  f.poll();
  const auto ev = f.drain_events();
  ASSERT_EQ(ev.size(), 4u);
  EXPECT_EQ(ev[2].event, journal::SessionEventKind::Logout);
  EXPECT_EQ(ev[2].session_id, 1u);
  EXPECT_EQ(ev[3].event, journal::SessionEventKind::Disconnect);
  EXPECT_EQ(ev[3].session_id, 2u);
  EXPECT_EQ(f.gw->stats().cod_triggers, 1u);  // BRAVO has cancel-on-disconnect
}

TEST(Gateway, FullSequencerQueueStagesInputInOrderAndPausesThePort) {
  Fixture<4> f;  // an SCQ of four slots
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  c.read(f.clock.mono);
  ASSERT_TRUE(c.logged_in);
  for (std::uint8_t i = 0; i < 40; ++i) c.send(msg(i), f.clock.mono);
  f.poll(4);
  EXPECT_GT(f.gw->stats().mpsc_full, 0u);
  // Drain the queue a few slots at a time, as the sequencer would: nothing is lost and
  // the order is kept.
  std::vector<std::uint8_t> seen;
  for (int round = 0; round < 100 && seen.size() < 40; ++round) {
    seq::InboundMsg m;
    while (f.ouch.try_pop(m)) seen.push_back(std::to_integer<std::uint8_t>(m.bytes[1]));
    f.poll(1);
  }
  ASSERT_EQ(seen.size(), 40u);
  for (std::uint8_t i = 0; i < 40; ++i) EXPECT_EQ(seen[i], i);
  EXPECT_EQ(f.gw->stats().msgs_in, 40u);
}

TEST(Gateway, BacklogBeyondThePauseThresholdStopsReadingThePort) {
  Fixture<2> f;
  f.port().max_bytes_per_poll = 2 * 1024;  // tcp.max_reads_per_poll x tcp.rx_buf_bytes
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  c.read(f.clock.mono);
  ASSERT_TRUE(c.logged_in);
  // Fill: two queued, the rest staged until the backlog crosses the threshold.
  for (int i = 0; i < 400; ++i) c.send(msg(1, 100), f.clock.mono);
  for (int i = 0; i < 20; ++i) f.poll(1);
  EXPECT_GT(f.gw->stats().paused_polls, 0u);
  EXPECT_FALSE(f.port().events.empty()) << "unread input stays in the kernel (the fake port)";
  std::size_t n = 0;
  for (int round = 0; round < 5000 && n < 400; ++round) {
    seq::InboundMsg m;
    while (f.ouch.try_pop(m)) ++n;
    f.poll(1);
  }
  EXPECT_EQ(n, 400u);
}

TEST(Gateway, DayEndDeliversWhatIsLeftThenEndOfSession) {
  Fixture f;
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  f.out(1, 1, msg(1));
  ASSERT_TRUE(f.egress.try_push(2, md::OutKind::DayEnd, 0, {}));
  f.release(2);
  f.poll();
  c.read(f.clock.mono);
  EXPECT_EQ(c.got.size(), 1u);
  EXPECT_TRUE(c.ended);
  EXPECT_TRUE(f.gw->ended());
  (void)f.drain_events();
  // A late login receives the stream and End of Session, and journals nothing.
  Client late(f.port(), "BRAVO", "bravo-pw");
  late.connect(f.clock.mono);
  f.poll();
  late.read(f.clock.mono);
  EXPECT_TRUE(late.logged_in);
  EXPECT_TRUE(late.ended);
  EXPECT_TRUE(f.drain_events().empty());
}

TEST(Gateway, HeartbeatsAndIdleTimeoutFollowTheClock) {
  Fixture f;
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  (void)f.drain_events();
  const auto before = f.port().written[c.conn].size();
  f.clock.mono += 2 * kNsPerSec;  // heartbeat interval 1 s
  f.poll();
  EXPECT_GT(f.port().written[c.conn].size(), before) << "server heartbeat";
  f.clock.mono += 20 * kNsPerSec;  // idle timeout 15 s without client traffic
  f.poll();
  const auto ev = f.drain_events();
  ASSERT_EQ(ev.size(), 1u);
  EXPECT_EQ(ev[0].event, journal::SessionEventKind::Disconnect);
}

// A session that ends has just produced its last bytes ('Z'); the port is closed only
// once they are out, including bytes a port stages until a SEND completes (io_uring:
// close() cancels it).
TEST(Gateway, ClosingConnectionFlushesItsLastBytesBeforeThePortCloses) {
  Fixture f;
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  c.read(f.clock.mono);
  ASSERT_TRUE(c.logged_in);
  f.port().write_budget = 7;  // a few bytes per write, staged until completed
  f.port().stage_tx = true;
  for (std::uint64_t i = 1; i <= 3; ++i) f.out(i, 1, msg(static_cast<std::uint8_t>(i)));
  ASSERT_TRUE(f.egress.try_push(4, md::OutKind::DayEnd, 0, {}));
  f.release(4);
  int polls = 0;
  for (; polls < 200 && f.port().closed_by_stage.count(c.conn) == 0; ++polls) {
    f.poll(1);
    if (polls % 3 == 2) f.port().complete_tx();  // completions arrive later
  }
  ASSERT_EQ(f.port().closed_by_stage.count(c.conn), 1u) << "never closed";
  EXPECT_GT(polls, 3) << "closed on the poll that ended the session";
  EXPECT_TRUE(f.port().lost_at_close.empty()) << "closed with a SEND in flight";
  c.read(f.clock.mono);
  ASSERT_EQ(c.got.size(), 3u);
  for (std::size_t i = 0; i < 3; ++i) EXPECT_TRUE(c.got[i].second == msg(static_cast<std::uint8_t>(i + 1))) << i;
  EXPECT_TRUE(c.ended) << "End of Session lost";
  EXPECT_EQ(f.gw->stats().linger_timeouts, 0u);
  // The slot is free again: a new connection logs in.
  f.port().write_budget = ~std::size_t{0};
  f.port().stage_tx = false;
  Client again(f.port(), "ALPHA", "alpha-pw");
  again.connect(f.clock.mono);
  f.poll();
  again.read(f.clock.mono);
  EXPECT_TRUE(again.logged_in);
}

// A peer that stops reading cannot hold a closing connection: after close_linger the
// port is closed with the bytes unsent.
TEST(Gateway, ALingeringCloseIsBounded) {
  Fixture f;
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  f.port().write_budget = 0;
  ASSERT_TRUE(f.egress.try_push(1, md::OutKind::DayEnd, 0, {}));
  f.release(1);
  f.poll(5);
  EXPECT_EQ(f.port().closed_by_stage.count(c.conn), 0u) << "closed with 'Z' unsent";
  f.clock.mono += md::kDefaultCloseLinger - 1;
  f.poll();
  EXPECT_EQ(f.port().closed_by_stage.count(c.conn), 0u);
  f.clock.mono += 2;
  f.poll();
  EXPECT_EQ(f.port().closed_by_stage.count(c.conn), 1u);
  EXPECT_EQ(f.gw->stats().linger_timeouts, 1u);
}

// Input from a connection whose session closed is ignored while it lingers.
TEST(Gateway, ALingeringConnectionIgnoresInput) {
  Fixture f;
  Client c(f.port(), "ALPHA", "alpha-pw");
  c.connect(f.clock.mono);
  f.poll();
  (void)f.drain_events();
  f.port().write_budget = 0;
  ASSERT_TRUE(f.egress.try_push(1, md::OutKind::DayEnd, 0, {}));
  f.release(1);
  f.poll();
  c.send(msg(7), f.clock.mono);
  f.poll();
  EXPECT_TRUE(f.drain_ouch().empty());
  f.port().peer_close(c.conn);  // the peer goes away while the gateway lingers
  f.poll();
  EXPECT_TRUE(f.drain_events().empty()) << "after DayEnd nothing is journaled";
  EXPECT_EQ(f.gw->stats().closed, 1u);
}

}  // namespace
}  // namespace lle::gw
