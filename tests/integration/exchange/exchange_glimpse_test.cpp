// GLIMPSE late join with the reference client (03 §8; clients' refclient, WP N-04).
//
// A node with the snapshot service builds a book (levels on both sides, several orders
// per level), then refclient joins late: it misses the first messages, takes the
// GLIMPSE spin (the resting orders worst price to best per side, FIFO within a level,
// md/glimpse_state.h), splices at G - 1 and follows the lines while more orders trade.
// Its checkpoints (book digest, live orders, stream hash) must equal a direct replay
// of the node's own output log at the same sequences, the splice point included.
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

#include "engine/scenario.h"
#include "harness.h"

namespace lle::exch::test {
namespace {

Bytes order(std::uint32_t urn, char side, std::uint32_t qty, std::uint64_t price) {
  engine::EnterArgs e;
  e.urn = urn;
  e.side = static_cast<ouch50::Side>(side);
  e.qty = qty;
  e.symbol = "AAPL";
  e.price = price;
  return engine::enter_msg(e);
}

TEST(ExchangeGlimpse, RefclientLateJoinMatchesTheOutputLog) {
  const auto dir = fresh_dir("glimpse-join");
  const ScopedDir cleanup(dir);
  const std::uint16_t pa = free_port(SOCK_DGRAM), pb = free_port(SOCK_DGRAM);
  NodeSpec spec;
  spec.name = "glj";
  spec.data_dir = (dir / "data").string();
  spec.line_a = pa;
  spec.line_b = pb;
  spec.extra = {"[glimpse]", "listen = 127.0.0.1:0", "user = GLIMPS",
                "password = " + gw::Credential::make("glimpse-pw", std::vector<std::uint8_t>{1, 2, 3}).text()};
  Exchange ex(spec, dir);
  ASSERT_TRUE(ex.start()) << ex.output();
  ex.clock("09:31:00");
  OuchClient a("ALPHA", "alpha-pw"), b("BRAVO", "bravo-pw");
  ASSERT_EQ(a.login(ex.port("gw0")), 'A');
  ASSERT_EQ(b.login(ex.port("gw1")), 'A');
  // Four bid and four ask levels, three orders each.
  for (std::uint32_t k = 0; k < 12; ++k) {
    b.send(order(1 + k, 'B', 100, 1'490'000 + (k % 4) * 1000));
    a.send(order(1 + k, 'S', 100, 1'510'000 + (k % 4) * 1000));
  }
  (void)ex.sync();

  // The late joiner.
  const std::string ck = (dir / "client.ck").string(), direct_ck = (dir / "direct.ck").string();
  Process rc(LLE_REFCLIENT,
             {"--line-a", "127.0.0.1:" + std::to_string(pa), "--line-b", "127.0.0.1:" + std::to_string(pb), "--glimpse",
              "127.0.0.1:" + std::to_string(ex.port("glimpse")), "--glimpse-user", "GLIMPS", "--glimpse-password",
              "glimpse-pw", "--snapshot-gap", "1", "--checkpoint-every", "4", "--checkpoints-out", ck, "--max-runtime",
              "20s", "--report", (dir / "client.json").string()},
             (dir / "refclient.out").string());
  std::this_thread::sleep_for(1500ms);  // it binds, hears a heartbeat, takes the spin
  // Live traffic after the splice: deeper bid levels, then sells that take the best bids.
  for (std::uint32_t k = 0; k < 6; ++k) b.send(order(13 + k, 'B', 100, 1'480'000 + k * 1000));
  a.send(order(13, 'S', 450, 1'491'000));
  a.send(order(14, 'S', 100, 1'513'000));
  (void)ex.sync();
  // The end of the day ends the feed (MoldUDP64 end of session): refclient exits 0.
  const std::string end = ex.cmd("end-day");
  ASSERT_EQ(end.rfind("ok", 0), 0u) << end;
  ASSERT_EQ(rc.wait_exit(25s), 0) << rc.output();

  // The reference: the node's own output log as a BinaryFILE.
  Bytes feed = slurp(ex.outlog_dir() + "/itch.bin");
  feed.push_back(std::byte{0});
  feed.push_back(std::byte{0});
  const std::string feed_path = (dir / "feed.bin").string();
  std::ofstream(feed_path, std::ios::binary).write(reinterpret_cast<const char*>(feed.data()),
                                                   static_cast<std::streamsize>(feed.size()));
  std::string splices;
  std::ifstream in(ck);
  for (std::string line; std::getline(in, line);) {
    if (line.empty() || line[0] == '#') continue;
    std::istringstream w(line);
    std::string seq, f;
    w >> seq;
    std::string last;
    while (w >> f) last = f;
    if (last == "1") splices += (splices.empty() ? "" : ",") + seq;
  }
  ASSERT_FALSE(splices.empty()) << "refclient did not join through the GLIMPSE spin:\n" << rc.output();
  int code = 0;
  const std::string d = run_capture({LLE_REFCLIENT, "--direct", feed_path, "--checkpoint-every", "4",
                                     "--extra-checkpoints", splices, "--checkpoints-out", direct_ck},
                                    &code);
  ASSERT_EQ(code, 0) << d;
  const std::string cmp = run_capture({LLE_REFCLIENT, "--compare", ck, direct_ck}, &code);
  EXPECT_NE(cmp.find("\"match\": true"), std::string::npos) << cmp << "\n" << rc.output();
  std::printf("late join spliced at %s; %s\n", splices.c_str(), cmp.substr(0, cmp.find('\n')).c_str());
  EXPECT_EQ(ex.stop(), 0);
}

}  // namespace
}  // namespace lle::exch::test
