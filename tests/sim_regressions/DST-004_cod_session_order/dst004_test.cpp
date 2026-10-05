// DST-004 (sim/ledger/bugs.yaml): cancel-on-disconnect left orders of a dropped
// connection open. The gateway pushes a connection's OUCH messages into the OUCH SCQ and
// its Disconnect into the session-event SCQ; the sequencer took at most ouch_batch (64)
// OUCH per poll and then the session events, so with more OUCH queued ahead the
// Disconnect was journaled before OUCH the gateway had pushed earlier on that
// connection. Those orders were entered after the COD cancel and stayed open (and could
// execute); a reconnecting session's early orders were the mirror image, cancelled by
// the previous connection's late Disconnect.
//
// Production gateway (over the in-memory stream port of the gateway tests), sequencer
// and engine; no simulator. A COD session logs in, sends 100 orders in one TCP read and
// the connection closes in the same gateway poll (what the exchange world's clients
// do): after the journal is applied, none of the 100 may be open.
#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "concurrent/mpsc_scq.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "engine/records.h"
#include "engine/scenario.h"
#include "fake_net.h"
#include "gateway/credentials.h"
#include "gateway/gateway.h"
#include "gateway/session_table.h"
#include "journal/l2_ring.h"
#include "md/egress.h"
#include "proto/soupbin/client_session.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"

namespace lle {
namespace {

using testnet::Bytes;

// The node's queue capacities (apps/exchanged/shared.h).
using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 4096>;
using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 1024>;
using AdminQueue = conc::MpscScqRing<seq::AdminMsg, 256>;

struct GwEnv {
  using Net = testnet::FakeNet;
  using OuchQueue = lle::OuchQueue;
  using SessionQueue = lle::SessionQueue;
  using Clock = testnet::FakeClock;
};

struct SeqClock {
  Nanos real = 0;
  Nanos now_mono() const noexcept { return 0; }
  Nanos now_real() noexcept { return real += 1'000; }
  std::uint64_t tsc() const noexcept { return 0; }
};
struct SeqEnv {
  using Clock = SeqClock;
  using OuchQueue = lle::OuchQueue;
  using SessionQueue = lle::SessionQueue;
  using AdminQueue = lle::AdminQueue;
  using Ring = journal::L2Ring<2>;
};

constexpr Nanos kMidnight = engine::Scenario::kMidnight;
constexpr std::uint32_t kSession = 2;
constexpr std::uint32_t kAccount = 200;
constexpr std::uint64_t kNonce = 0x0DDBA11CAFEF00D5ull;

struct Sink {
  void itch(std::uint64_t, std::span<const std::byte>) {}
  void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte>) {}
  void audit(std::uint64_t, const engine::AuditEvent&) {}
};

// The day (one symbol, one COD session on gw0), the sequencer over the L2 ring with the
// clock past the open, the engine applying the journal, and the gateway as node.cpp
// configures it.
struct Rig {
  std::vector<engine::SymbolEntry> syms{1};
  std::vector<engine::AccountEntry> accts{1};
  std::vector<engine::SessionEntry> sess{engine::SessionEntry{kSession, kAccount}};
  std::vector<engine::ScheduleEntry> sched = engine::standard_schedule(false, false);
  std::unique_ptr<seq::EngineDay> day;
  OuchQueue ouch;
  SessionQueue events;
  AdminQueue admin;
  std::unique_ptr<std::uint64_t[]> mem = std::make_unique<std::uint64_t[]>((std::size_t{1} << 22) / 8);
  journal::L2Ring<2> ring;
  SeqClock sclock;
  std::unique_ptr<seq::Sequencer<SeqEnv>> sequencer;
  engine::Engine eng;
  Sink sink;
  gw::SessionTable table;
  md::EgressRing egress;
  md::EgressState state;
  std::atomic<bool> mirror{false};
  testnet::FakeClock gclock;
  std::unique_ptr<gw::Gateway<GwEnv>> gateway;

  Rig() {
    syms[0].symbol = Symbol8("AAPL");
    syms[0].prior_close = 1'000'000;
    accts[0].account_id = kAccount;
    accts[0].firms[0] = Mpid4("FRMA");
    sess[0].flags = engine::SessionEntry::kCancelOnDisconnect | engine::SessionEntry::kMarketOrders;
    day = std::make_unique<seq::EngineDay>(seq::EngineTables{syms, accts, sess, {}, sched}, kMidnight);
    ring.init(reinterpret_cast<std::byte*>(mem.get()), std::size_t{1} << 22, kNonce);
    sclock.real = kMidnight + hms_ns(10, 0, 0);
    sequencer = std::make_unique<seq::Sequencer<SeqEnv>>(sclock, ouch, events, admin, ring, day->timers(),
                                                         seq::SequencerConfig{});
    journal::DayStart ds;
    ds.trading_date = 20261001;
    ds.local_midnight_ns = kMidnight;
    EXPECT_TRUE(sequencer->start_day(ds, day->config(), 1, 1).has_value());
    run();
    std::vector<gw::SessionSpec> specs;
    const std::vector<std::uint8_t> salt = {9, 8, 7, 6};
    specs.push_back(gw::SessionSpec{kSession, kAccount, "BRAVO", gw::Credential::make("bravo-pw", salt), 0, true});
    table = *gw::SessionTable::build(std::move(specs), md::kGateways);
    egress.init(std::size_t{1} << 16);
    gw::GatewayConfig c;
    c.index = 0;
    c.instance = 1;
    c.soup.session = soup::SessionId::from("LLE0000001");
    c.tcp.max_conns = 8;
    c.tcp.max_reads_per_poll = 4;
    gateway = std::make_unique<gw::Gateway<GwEnv>>(c, table, std::span<const std::pair<std::uint32_t, SeqNo>>{}, ouch,
                                                   events, gclock, gw::GatewayShared{&egress, &state, &mirror});
    EXPECT_TRUE(gateway->start());
  }

  // Sequences everything queued and applies it.
  void run() {
    while (sequencer->poll()) {
    }
    (void)ring.drain(0, [&](const journal::RecordView& v) { eng.apply(engine::to_input(v), sink); }, 1u << 20);
    (void)ring.drain(1, [](const journal::RecordView&) {}, 1u << 20);
  }
  void poll_gateway(int n = 4) {
    for (int i = 0; i < n; ++i) (void)gateway->poll();
  }
  testnet::FakeStreamPort& port() { return gateway->port(); }

  static soup::ClientConfig login() {
    soup::ClientConfig cc;
    cc.username = Alpha<soup::kUsernameLen>("BRAVO");
    cc.password = Alpha<soup::kPasswordLen>("bravo-pw");
    return cc;
  }
  static std::vector<std::byte> order(UserRefNum urn) {
    return engine::enter_msg(
        {.urn = urn, .side = ouch50::Side::Buy, .qty = 100, .symbol = "AAPL", .price = 990'000 - 100 * (urn % 20)});
  }
  // A SoupBinTCP Unsequenced Data packet.
  static void packet(Bytes& out, std::span<const std::byte> payload) {
    const auto n = static_cast<std::uint16_t>(payload.size() + 1);
    out.push_back(static_cast<std::byte>(n >> 8));
    out.push_back(static_cast<std::byte>(n & 0xFF));
    out.push_back(std::byte{'U'});
    out.insert(out.end(), payload.begin(), payload.end());
  }
};

// A COD session logs in, sends 100 orders in one TCP read and the connection closes in
// the same gateway poll: after the journal is applied, none of the 100 may be open.
TEST(DST004, CancelOnDisconnectCoversEveryOrderSentBeforeTheDrop) {
  Rig r;
  soup::ClientSession client(Rig::login());
  const env::ConnId conn = r.port().accept();
  const soup::Actions& a = client.connect(r.gclock.mono);
  r.port().data(conn, a.write);
  client.consume_tx(a.write.size());
  r.poll_gateway();
  (void)client.on_bytes(r.port().take(conn), r.gclock.mono);  // Login Accepted
  ASSERT_EQ(client.state(), soup::ClientSession::State::Active);
  r.run();

  Bytes burst;
  for (UserRefNum urn = 1; urn <= 100; ++urn) Rig::packet(burst, Rig::order(urn));
  r.port().data(conn, burst);
  r.port().peer_close(conn);
  r.poll_gateway();
  r.run();

  ASSERT_EQ(r.gateway->stats().msgs_in, 100u);
  EXPECT_EQ(r.eng.live_orders(), 0u) << r.eng.live_orders()
                                     << " orders of the dropped COD connection are still open after its Disconnect";
}

// The mirror image: the session's next connection logs in and sends orders in the same
// gateway poll as the drop. Its orders are not the dropped connection's: the drop's
// Disconnect must not cancel them.
TEST(DST004, CancelOnDisconnectSparesTheNextConnectionsOrders) {
  Rig r;
  soup::ClientSession first(Rig::login());
  const env::ConnId c1 = r.port().accept();
  const soup::Actions& a = first.connect(r.gclock.mono);
  r.port().data(c1, a.write);
  first.consume_tx(a.write.size());
  r.poll_gateway();
  (void)first.on_bytes(r.port().take(c1), r.gclock.mono);
  ASSERT_EQ(first.state(), soup::ClientSession::State::Active);
  r.run();

  // First connection: 10 orders, then it drops. Second connection: its Login Request
  // and 10 orders in one read. One gateway poll sees all of it.
  Bytes burst;
  for (UserRefNum urn = 1; urn <= 10; ++urn) Rig::packet(burst, Rig::order(urn));
  r.port().data(c1, burst);
  r.port().peer_close(c1);
  soup::ClientConfig cc = Rig::login();
  cc.sequence = 0;  // the most recent message: no replay needed
  soup::ClientSession second(cc);
  const env::ConnId c2 = r.port().accept();
  const soup::Actions& b = second.connect(r.gclock.mono);
  Bytes in2(b.write.begin(), b.write.end());
  second.consume_tx(b.write.size());
  for (UserRefNum urn = 11; urn <= 20; ++urn) Rig::packet(in2, Rig::order(urn));
  r.port().data(c2, in2);
  r.poll_gateway();
  r.run();

  ASSERT_EQ(r.gateway->stats().msgs_in, 20u);
  EXPECT_EQ(r.eng.live_orders(), 10u) << "the second connection's 10 orders should be open; " << r.eng.live_orders()
                                      << " are";
}

}  // namespace
}  // namespace lle
