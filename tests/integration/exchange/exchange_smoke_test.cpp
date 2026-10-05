// exchanged smoke: start, log in, trade once, end the day. The full scripted day,
// restart and HA tests build on the same harness.
#include <gtest/gtest.h>

#include "engine/scenario.h"
#include "harness.h"

namespace lle::exch::test {
namespace {

TEST(ExchangeSmoke, TradeOnceAndEndDay) {
  const auto dir = fresh_dir("smoke");
  const ScopedDir cleanup(dir);
  MoldSubscriber sub;
  NodeSpec spec;
  spec.name = "smk";
  spec.data_dir = (dir / "data").string();
  spec.line_a = sub.port_a();
  spec.line_b = sub.port_b();
  Exchange ex(spec, dir);
  ASSERT_TRUE(ex.start()) << ex.output();
  sub.set_servers(ex.port("rerequest"), ex.port("rerequest"));
  ex.clock("09:31:00");

  OuchClient a("ALPHA", "alpha-pw"), b("BRAVO", "bravo-pw");
  ASSERT_EQ(a.login(ex.port("gw0")), 'A');
  ASSERT_EQ(b.login(ex.port("gw1")), 'A');
  ex.sync();

  engine::EnterArgs s;
  s.urn = 1;
  s.side = ouch50::Side::Sell;
  s.qty = 100;
  s.symbol = "AAPL";
  s.price = 1'500'000;
  a.send(engine::enter_msg(s));
  engine::EnterArgs bb = s;
  bb.side = ouch50::Side::Buy;
  b.send(engine::enter_msg(bb));
  // Start of Day (system event at 03:00 is replayed on login), Accepted, Executed.
  ASSERT_TRUE(a.wait_count(3)) << ex.status();
  ASSERT_TRUE(b.wait_count(3)) << ex.status();
  EXPECT_EQ(static_cast<char>(a.received()[0].msg[0]), 'S');
  EXPECT_EQ(static_cast<char>(a.received()[1].msg[0]), 'A');
  EXPECT_EQ(static_cast<char>(a.received()[2].msg[0]), 'E');
  EXPECT_EQ(static_cast<char>(b.received()[2].msg[0]), 'E');

  ex.clock("20:06:00");
  const std::string r = ex.cmd("end-day");
  EXPECT_EQ(r.rfind("ok ", 0), 0u) << r;
  a.settle();
  EXPECT_TRUE(a.ended());
  EXPECT_TRUE(sub.wait_end());
  EXPECT_GT(sub.messages().size(), 5u);
  EXPECT_EQ(ex.stop(), 0) << ex.output();
}

}  // namespace
}  // namespace lle::exch::test
