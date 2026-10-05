// SO_TIMESTAMPING plumbing on Linux loopback. Loopback (like veth) only produces
// SOFTWARE timestamps: these tests exercise the error-queue reader, OPT_ID/OPT_ID_TCP
// keys and the correlator end to end, and assert the stamps are classified as software
// (never as hardware), per 07 §2.5.
#include <gtest/gtest.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "../net_sock/test_util.h"
#include "net/hwts/abi.h"
#include "net/hwts/device.h"
#include "net/hwts/socket_ts.h"
#include "net/hwts/tx_correlator.h"
#include "net/sock/tcp_port.h"
#include "net/sock/udp_port.h"

namespace lle::net::hwts {
namespace {

using env::StreamEvent;
using env::StreamEventKind;
using test::bytes;

TEST(HwtsLoopback, SocketFlagsReadBack) {
  UdpConfig c;
  c.bind = Endpoint{kLoopbackV4, 0};
  c.rx_ts = TsMode::Hardware;
  c.tx_ts = TsMode::Hardware;
  sock::UdpPort p;
  ASSERT_TRUE(p.open(c).has_value());  // flags are accepted even without a PHC
  auto f = socket_timestamping_flags(p.fd());
  ASSERT_TRUE(f.has_value());
  EXPECT_NE(*f & abi::kRxHardware, 0u);
  EXPECT_NE(*f & abi::kTxHardware, 0u);
  EXPECT_NE(*f & abi::kOptId, 0u);
  EXPECT_NE(*f & abi::kOptTsonly, 0u);
  EXPECT_EQ(*f, p.timestamping_flags());
}

TEST(HwtsLoopback, UdpTxTimestampsCorrelateByOptId) {
  UdpConfig rc;
  rc.bind = Endpoint{kLoopbackV4, 0};
  UdpConfig tc = rc;
  tc.tx_ts = TsMode::Software;
  sock::UdpPort rx, tx;
  ASSERT_TRUE(rx.open(rc).has_value());
  ASSERT_TRUE(tx.open(tc).has_value());
  TxCorrelator corr;
  corr.init(KeyMode::Datagram, 64);
  constexpr int kN = 8;
  for (int i = 0; i < kN; ++i) {
    ASSERT_TRUE(tx.send(rx.local(), bytes("order-" + std::to_string(i))));
    EXPECT_EQ(corr.on_send(1000 + static_cast<std::uint64_t>(i), 7), static_cast<std::uint32_t>(i));
  }
  std::vector<std::uint64_t> tags;
  std::vector<TxStamp> seen;
  for (int it = 0; it < 100'000 && tags.size() < kN; ++it) {
    tx.drain_tx_timestamps([&](const TxStamp& s) {
      seen.push_back(s);
      (void)corr.on_stamp(s, [&](std::uint64_t tag, const TxStamp&) { tags.push_back(tag); });
    });
  }
  ASSERT_EQ(tags.size(), static_cast<std::size_t>(kN));
  for (int i = 0; i < kN; ++i) EXPECT_EQ(tags[static_cast<std::size_t>(i)], 1000u + static_cast<std::uint64_t>(i));
  for (const TxStamp& s : seen) {
    EXPECT_EQ(s.type, abi::kTstampSnd);
    EXPECT_EQ(s.kind(), TsKind::Software) << "loopback: software TX stamp, never hardware";
    EXPECT_GT(s.ts.sw_ns, 0);
    EXPECT_EQ(s.ts.hw_ns, 0);
  }
  EXPECT_EQ(corr.validity().sw, static_cast<std::uint64_t>(kN));
  EXPECT_EQ(corr.validity().hw, 0u);
  EXPECT_FALSE(corr.validity().valid());
}

TEST(HwtsLoopback, TcpTxTimestampsUseByteKeys) {
  TcpConfig cfg;
  cfg.tx_ts = TsMode::Software;
  cfg.rx_ts = TsMode::Software;
  sock::Poller poller;
  ASSERT_TRUE(poller.open().has_value());
  sock::TcpPort server, client;
  ASSERT_TRUE(server.open(cfg, &poller).has_value());
  ASSERT_TRUE(client.open(cfg, &poller).has_value());
  auto at = server.listen(Endpoint{kLoopbackV4, 0});
  ASSERT_TRUE(at.has_value());
  auto cid = client.connect(*at);
  ASSERT_TRUE(cid.has_value());
  bool connected = false, accepted = false;
  std::string rx;
  std::vector<Nanos> rx_hw;
  auto on_server = [&](const StreamEvent& e) {
    if (e.kind == StreamEventKind::Accepted) accepted = true;
    if (e.kind == StreamEventKind::Data) {
      rx += test::str(e.data);
      rx_hw.push_back(e.hw_rx_ns);
    }
  };
  auto on_client = [&](const StreamEvent& e) { connected |= e.kind == StreamEventKind::Connected; };
  ASSERT_TRUE(test::pump_until(
      [&] {
        (void)poller.poll(test::kWaitSlice);
        server.poll(on_server);
        client.poll(on_client);
      },
      [&] { return connected && accepted; }));
  auto f = socket_timestamping_flags(client.fd(*cid));
  ASSERT_TRUE(f.has_value());
  EXPECT_NE(*f & abi::kOptIdTcp, 0u) << "OPT_ID_TCP set once established";

  TxCorrelator corr;
  corr.init(KeyMode::Stream, 64);
  const std::vector<std::string> msgs = {std::string(49, 'E'), std::string(9, 'X'), std::string(31, 'U')};
  std::vector<std::uint32_t> keys;
  for (std::size_t i = 0; i < msgs.size(); ++i) {
    ASSERT_EQ(client.write(*cid, bytes(msgs[i])), msgs[i].size());  // one send(MSG_EOR) each
    keys.push_back(corr.on_send(i, msgs[i].size()));
  }
  EXPECT_EQ(keys, (std::vector<std::uint32_t>{48, 57, 88}));
  std::vector<std::uint64_t> tags;
  ASSERT_TRUE(test::pump_until(
      [&] {
        (void)poller.poll(test::kWaitSlice);
        server.poll(on_server);
        client.poll(on_client);
        client.drain_tx_timestamps(*cid, [&](const TxStamp& s) {
          EXPECT_EQ(s.kind(), TsKind::Software);
          (void)corr.on_stamp(s, [&](std::uint64_t tag, const TxStamp&) { tags.push_back(tag); });
        });
      },
      [&] { return tags.size() == msgs.size() && rx.size() == 89; }));
  EXPECT_EQ(tags, (std::vector<std::uint64_t>{0, 1, 2})) << "MSG_EOR + TCP_NODELAY: one stamp per write";
  EXPECT_EQ(corr.validity().missing, 0u);
  for (const Nanos hw : rx_hw) EXPECT_EQ(hw, 0) << "no hardware RX stamps on loopback";
  EXPECT_GE(server.stats().rx_ts.sw, 1u);
  EXPECT_EQ(server.stats().rx_ts.hw, 0u);
}

TEST(HwtsLoopback, ErrQueueReaderOnQuietSocketIsEmpty) {
  UdpConfig c;
  c.bind = Endpoint{kLoopbackV4, 0};
  sock::UdpPort p;
  ASSERT_TRUE(p.open(c).has_value());
  ErrQueueReader r;
  TxStamp s{};
  EXPECT_EQ(r.read_one(p.fd(), s), ErrQueueReader::Status::Empty);
  EXPECT_EQ(r.read_one(-1, s), ErrQueueReader::Status::Error);
}

TEST(HwtsDevice, LoopbackHasNoPhc) {
  auto info = get_ts_info("lo");
  ASSERT_TRUE(info.has_value()) << to_string(info.error());
  EXPECT_EQ(info->phc_index, -1) << "loopback: software timestamping only";
  EXPECT_NE(info->so_timestamping & abi::kRxSoftware, 0u);
  EXPECT_FALSE(info->hw_rx_all());
  // SIOCSHWTSTAMP must fail on loopback (EOPNOTSUPP), or EPERM when unprivileged.
  auto en = enable_hw_timestamping("lo");
  ASSERT_FALSE(en.has_value());
  EXPECT_NE(en.error().code, 0);
  EXPECT_FALSE(enable_hw_timestamping("this-name-is-too-long").has_value());
}

}  // namespace
}  // namespace lle::net::hwts
