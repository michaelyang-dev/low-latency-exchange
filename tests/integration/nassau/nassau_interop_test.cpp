// Interop with an independent implementation (plan 03 §5; T08, T09): nassau's
// SoupBinTCP client against exchanged's order gateway, and nassau's MoldUDP64 client
// against exchanged's market-data publisher and re-request server, with induced loss on
// the multicast path. nassau (paritytrading/nassau 1.0.0, Java) shares no code with
// this repository. The test runs the real exchanged and two Java programs
// (SoupInterop.java, MoldInterop.java), and compares everything nassau received with
// what journal_replay regenerates from the day's journal.
#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>

#include "../exchange/verify.h"
#include "engine/scenario.h"

namespace lle::exch::test {
namespace {

std::string hex(std::span<const std::byte> b) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  for (std::byte x : b) {
    s += kDigits[std::to_integer<unsigned>(x) >> 4];
    s += kDigits[std::to_integer<unsigned>(x) & 0xF];
  }
  return s;
}

std::unique_ptr<Process> java(const std::string& main, std::vector<std::string> args, const std::string& log) {
  args.insert(args.begin(), {"-cp", std::string(LLE_NASSAU_CLASSPATH), main});
  return std::make_unique<Process>(LLE_JAVA, std::move(args), log);
}

TEST(NassauInterop, SoupBinTcpSessionAndMoldUdp64WithLoss) {
  const auto dir = fresh_dir("nassau");
  const ScopedDir cleanup(dir);
  MoldSubscriber sub;  // line B, and our own view of the feed
  NodeSpec spec;
  spec.name = "nsu";
  spec.data_dir = (dir / "data").string();
  const std::uint16_t relay = free_port(SOCK_DGRAM);
  const std::uint16_t client = free_port(SOCK_DGRAM);
  spec.line_a = relay;  // through MoldInterop's lossy relay to nassau
  spec.line_b = sub.port_b();
  spec.max_packet_b = 200;  // more packets, so the seeded loss makes more gaps
  spec.accounts.push_back("400 FRMD");
  spec.sessions.push_back({4, 400, "NASSU", "nassu-pw", 0, "market"});
  Exchange ex(spec, dir);
  ASSERT_TRUE(ex.start()) << ex.output();
  sub.set_servers(ex.port("rerequest"), ex.port("rerequest"));

  const std::string mold_out = (dir / "nassau-mold.bin").string();
  auto mold = java("MoldInterop",
                   {std::to_string(relay), std::to_string(client), "127.0.0.1", std::to_string(ex.port("rerequest")),
                    "100" /* 10% loss */, "20261002", mold_out, "240000"},
                   (dir / "mold.out").string());
  ASSERT_TRUE(mold->wait_output("ready", 30s)) << mold->output();
  ex.clock("09:31:00");

  // nassau's orders: resting MSFT buys below the market, one Accepted each.
  constexpr int kNassauOrders = 50;
  const std::string orders = (dir / "nassau-orders.hex").string();
  {
    std::ofstream f(orders);
    for (int i = 0; i < kNassauOrders; ++i) {
      engine::EnterArgs o;
      o.urn = static_cast<UserRefNum>(i + 1);
      o.side = ouch50::Side::Buy;
      o.qty = 100;
      o.symbol = "MSFT";
      o.price = 2'900'000 + static_cast<std::uint64_t>(i) * 100;  // $290.00 + i cents
      f << hex(engine::enter_msg(o)) << "\n";
    }
  }
  const std::string soup_out = (dir / "nassau-soup.bin").string();
  // Start of Day (replayed on login) + one Accepted per order.
  auto soup = java("SoupInterop",
                   {"127.0.0.1", std::to_string(ex.port("gw0")), "NASSU", "nassu-pw", orders,
                    std::to_string(kNassauOrders + 1), "17000" /* > nassau's 15 s heartbeat timeout */, soup_out,
                    "240000"},
                   (dir / "soup.out").string());

  // Market-data traffic: ALPHA and BRAVO cross AAPL repeatedly.
  OuchClient a("ALPHA", "alpha-pw"), b("BRAVO", "bravo-pw");
  ASSERT_EQ(a.login(ex.port("gw0")), 'A');
  ASSERT_EQ(b.login(ex.port("gw1")), 'A');
  constexpr int kPairs = 1500;
  for (int i = 0; i < kPairs; ++i) {
    engine::EnterArgs s;
    s.urn = static_cast<UserRefNum>(i + 1);
    s.side = ouch50::Side::Sell;
    s.qty = 100;
    s.symbol = "AAPL";
    s.price = 1'500'000;
    a.send(engine::enter_msg(s));
    engine::EnterArgs bb = s;
    bb.side = ouch50::Side::Buy;
    b.send(engine::enter_msg(bb));
    if (i % 25 == 24) {
      ex.sync();
      a.poll(0);
      b.poll(0);
    }
  }
  ex.sync();
  a.settle();
  b.settle();

  ASSERT_TRUE(soup->wait_output("replay-identical", 120s)) << soup->output() << ex.status();
  ex.clock("20:06:00");
  const std::string r = ex.cmd("end-day");
  EXPECT_EQ(r.rfind("ok ", 0), 0u) << r;
  EXPECT_EQ(soup->wait_exit(60s), 0) << soup->output();
  EXPECT_EQ(mold->wait_exit(60s), 0) << mold->output();
  a.settle();
  b.settle();
  EXPECT_EQ(ex.stop(), 0) << ex.output();

  const Regenerated regen = regenerate(ex.journal_dir(), dir / "regen");
  ASSERT_EQ(regen.exit_code, 0) << regen.report;

  // MoldUDP64: every message, in order, byte-identical, despite the dropped packets.
  const std::vector<Bytes> got = split_binary_file(slurp(mold_out));
  EXPECT_EQ(got.size(), regen.itch.size());
  EXPECT_TRUE(got == regen.itch) << "nassau's MoldUDP64 stream differs from the journal's ITCH";
  const std::string mo = mold->output();
  EXPECT_EQ(mo.find("dropped=0 "), std::string::npos) << "no packet was dropped: " << mo;
  EXPECT_EQ(mo.find("requests=0 "), std::string::npos) << "nassau never re-requested: " << mo;
  std::printf("nassau MoldUDP64: %s", mo.substr(mo.rfind("eos ")).c_str());

  // SoupBinTCP: nassau's whole session stream equals the journal's regeneration.
  ASSERT_TRUE(regen.ouch.contains(4));
  EXPECT_TRUE(slurp(soup_out) == regen.ouch.at(4)) << "nassau's SoupBinTCP stream differs from the journal's OUCH";
  std::printf("nassau SoupBinTCP:\n%s", soup->output().c_str());
}

}  // namespace
}  // namespace lle::exch::test
