// DST-020 (sim/ledger/bugs.yaml): the gateway lost session events. While the sequencer
// queue was full, every session event waited in the gateway's backlog, and every
// reconnect still logged in and queued its Login; a congested day with clients dropping
// and re-establishing connections (a deep book, two dozen sessions) filled the backlog
// with Login/Disconnect pairs, and the events after them were dropped (O-SEQ: "gateway 1
// dropped 105 session events"). A lost Disconnect leaves a cancel-on-disconnect
// session's orders resting; a lost Login breaks the order of a session's events.
//
// The fix: a connection that is not logged in waits, its input staged, while session
// events wait for the queue, so the backlog grows by at most one event per connection
// (its logout or disconnect); it holds twice the connection slots. After DayEnd nothing
// more is journaled, and waiting events are dropped so that logins go on.
//
// Production pieces: the gateway stage over the in-memory stream port of its unit tests,
// with a sequencer queue kept full.
#include <gtest/gtest.h>

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "concurrent/mpsc_scq.h"
#include "fake_net.h"
#include "gateway/credentials.h"
#include "gateway/gateway.h"
#include "gateway/session_table.h"
#include "md/egress.h"
#include "proto/soupbin/client_session.h"

namespace lle::gw {
namespace {

using testnet::Bytes;
using testnet::FakeClock;
using testnet::FakeNet;

struct Env {
  using Net = FakeNet;
  using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 4>;  // a sequencer queue of four slots
  using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 64>;
  using Clock = FakeClock;
};

SessionTable table() {
  const std::vector<std::uint8_t> salt{9, 8, 7, 6};
  std::vector<SessionSpec> v;
  v.push_back(SessionSpec{1, 100, "ALPHA", Credential::make("alpha-pw", salt), 0, true});
  v.push_back(SessionSpec{2, 200, "BRAVO", Credential::make("bravo-pw", salt), 0, true});
  v.push_back(SessionSpec{3, 300, "CHARL", Credential::make("charl-pw", salt), 0, true});
  return *SessionTable::build(std::move(v), md::kGateways);
}

// A connection accepted on `slot` (a new generation each time, as the port reuses its
// slots) that sends a Login Request.
env::ConnId login(testnet::FakeStreamPort& port, std::uint32_t slot, std::uint16_t generation, const std::string& user,
                  const std::string& pw, Nanos now) {
  const env::ConnId conn = net::make_conn_id(slot, generation);
  port.events.push_back(testnet::FakeStreamPort::Event{env::StreamEventKind::Accepted, conn, {}});
  soup::ClientConfig c;
  c.username = Alpha<soup::kUsernameLen>(user);
  c.password = Alpha<soup::kPasswordLen>(pw);
  c.sequence = 0;
  soup::ClientSession s(c);
  const soup::Actions& a = s.connect(now);
  port.data(conn, a.write);
  return conn;
}

TEST(DST020SessionEvents, ReconnectsWhileTheQueueIsFullLoseNoEvent) {
  const SessionTable tbl = table();
  Env::OuchQueue ouch;
  Env::SessionQueue unused;
  FakeClock clock;
  md::EgressRing egress;
  egress.init(std::size_t{1} << 16);
  md::EgressState state;
  std::atomic<bool> mirror{false};
  GatewayConfig cfg;
  cfg.index = 0;
  cfg.instance = 0;
  cfg.soup.session = soup::SessionId::from("SESS000001");
  cfg.tcp.max_conns = 8;
  cfg.tcp.rx_buf_bytes = 1024;
  cfg.tcp.max_reads_per_poll = 2;
  cfg.rx_backlog_bytes = 8 * 1024;
  cfg.session_event_backlog = 16;
  cfg.close_linger = 1'000'000;  // a closed connection's slot is free again 1 ms later
  cfg.day = 20261001;
  Gateway<Env> gw(cfg, tbl, std::span<const std::pair<std::uint32_t, SeqNo>>{}, ouch, unused, clock,
                  GatewayShared{&egress, &state, &mirror});
  ASSERT_TRUE(gw.start());
  const std::vector<std::pair<std::string, std::string>> users{
      {"ALPHA", "alpha-pw"}, {"BRAVO", "bravo-pw"}, {"CHARL", "charl-pw"}};

  // Four orders fill the sequencer queue; nothing drains it while the clients churn.
  const env::ConnId first = login(gw.port(), 0, 1, "ALPHA", "alpha-pw", clock.mono);
  for (int i = 0; i < 4; ++i) (void)gw.poll();
  std::vector<seq::InboundMsg> got;
  seq::InboundMsg m;
  while (ouch.try_pop(m)) got.push_back(m);  // ALPHA's Login
  ASSERT_EQ(got.size(), 1u);
  for (int i = 0; i < 4; ++i) {
    seq::InboundMsg o;
    o.session_id = 99;
    ASSERT_TRUE(ouch.try_push(o));
  }
  gw.port().peer_close(first);
  // Thirty rounds of every session connecting, logging in and dropping.
  std::uint16_t generation = 2;
  for (int round = 0; round < 30; ++round) {
    for (std::uint32_t k = 0; k < users.size(); ++k) {
      const env::ConnId c = login(gw.port(), 1 + k, generation++, users[k].first, users[k].second, clock.mono);
      for (int i = 0; i < 3; ++i) (void)gw.poll();
      gw.port().peer_close(c);
      for (int i = 0; i < 3; ++i) (void)gw.poll();
      clock.mono += 2'000'000;
      for (int i = 0; i < 3; ++i) (void)gw.poll();
    }
  }
  EXPECT_EQ(gw.stats().events_dropped, 0u) << "session events lost to a full backlog";

  // The queue drains: every event the gateway queued reaches it, and per session they
  // alternate, a Login (or mirror attach) before each Logout or Disconnect.
  for (int i = 0; i < 4; ++i) (void)ouch.try_pop(m);  // the four orders
  for (int round = 0; round < 2000; ++round) {
    while (ouch.try_pop(m)) got.push_back(m);
    (void)gw.poll();
  }
  while (ouch.try_pop(m)) got.push_back(m);
  std::map<std::uint32_t, bool> up;
  for (const seq::InboundMsg& q : got) {
    if (!seq::is_session_event(q)) continue;
    const seq::SessionEventMsg e = seq::session_event_of(q);
    const bool login_ev = e.event == journal::SessionEventKind::Login || e.event == journal::SessionEventKind::MirrorAttach;
    EXPECT_NE(up[e.session_id], login_ev) << "session " << e.session_id << ": " << (login_ev ? "a second Login" : "an end without a Login");
    up[e.session_id] = login_ev;
  }
}

// The day ends while a session event still waits for the queue (the sequencer takes no
// more after DayEnd) and a login waits behind it: the login goes on, receives the
// stream's end and End of Session, and journals nothing.
TEST(DST020SessionEvents, ALoginWaitingAtTheDayEndStillGetsEndOfSession) {
  const SessionTable tbl = table();
  Env::OuchQueue ouch;
  Env::SessionQueue unused;
  FakeClock clock;
  md::EgressRing egress;
  egress.init(std::size_t{1} << 16);
  md::EgressState state;
  std::atomic<bool> mirror{false};
  GatewayConfig cfg;
  cfg.index = 0;
  cfg.instance = 0;
  cfg.soup.session = soup::SessionId::from("SESS000001");
  cfg.tcp.max_conns = 8;
  cfg.tcp.rx_buf_bytes = 1024;
  cfg.tcp.max_reads_per_poll = 2;
  cfg.rx_backlog_bytes = 8 * 1024;
  cfg.day = 20261001;
  Gateway<Env> gw(cfg, tbl, std::span<const std::pair<std::uint32_t, SeqNo>>{}, ouch, unused, clock,
                  GatewayShared{&egress, &state, &mirror});
  ASSERT_TRUE(gw.start());
  const env::ConnId first = login(gw.port(), 0, 1, "ALPHA", "alpha-pw", clock.mono);
  for (int i = 0; i < 4; ++i) (void)gw.poll();
  seq::InboundMsg m;
  while (ouch.try_pop(m)) {
  }
  for (int i = 0; i < 4; ++i) {
    seq::InboundMsg o;
    o.session_id = 99;
    ASSERT_TRUE(ouch.try_push(o));
  }
  gw.port().peer_close(first);  // ALPHA's Disconnect waits for the full queue
  for (int i = 0; i < 4; ++i) (void)gw.poll();
  soup::ClientConfig bc;
  bc.username = Alpha<soup::kUsernameLen>("BRAVO");
  bc.password = Alpha<soup::kPasswordLen>("bravo-pw");
  bc.sequence = 0;
  soup::ClientSession bravo(bc);
  const env::ConnId b = net::make_conn_id(1, 2);
  gw.port().events.push_back(testnet::FakeStreamPort::Event{env::StreamEventKind::Accepted, b, {}});
  const soup::Actions& a = bravo.connect(clock.mono);
  gw.port().data(b, a.write);
  bravo.consume_tx(a.write.size());
  for (int i = 0; i < 4; ++i) (void)gw.poll();
  ASSERT_TRUE(egress.try_push(1, md::OutKind::DayEnd, 0, {}));
  state.applied.store(1);
  state.release.store(1);
  bool logged_in = false, ended = false;
  for (int round = 0; round < 20 && !ended; ++round) {
    (void)gw.poll();
    const Bytes w = gw.port().take(b);
    std::size_t off = 0;
    while (off < w.size()) {
      const soup::Actions& r = bravo.on_bytes(std::span<const std::byte>(w).subspan(off), clock.mono);
      for (const soup::Event& e : r.events) {
        logged_in = logged_in || e.kind == soup::EventKind::LoggedIn;
        ended = ended || e.kind == soup::EventKind::EndOfSession;
      }
      off += r.consumed;
      if (r.consumed == 0) break;
    }
  }
  EXPECT_TRUE(gw.ended());
  EXPECT_TRUE(logged_in) << "BRAVO's login waited for ever behind an event the queue would never take";
  EXPECT_TRUE(ended);
  EXPECT_EQ(gw.stats().events_dropped, 0u);
}

}  // namespace
}  // namespace lle::gw
