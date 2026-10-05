// hwts parsers with handcrafted control buffers (portable: runs on macOS and Linux),
// the TX correlator and timestamping flag composition.
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <vector>

#include "net/hwts/abi.h"
#include "net/hwts/clock_domain.h"
#include "net/hwts/cmsg.h"
#include "net/hwts/socket_ts.h"
#include "net/hwts/tx_correlator.h"

namespace lle::net::hwts {
namespace {

template <class T>
std::span<const std::byte> as_bytes_of(const T& v) {
  return {reinterpret_cast<const std::byte*>(&v), sizeof(T)};
}

abi::ScmTimestamping stamps(Nanos sw, Nanos hw) {
  abi::ScmTimestamping t{};
  t.ts[0] = {sw / kNsPerSec, sw % kNsPerSec};
  t.ts[2] = {hw / kNsPerSec, hw % kNsPerSec};
  return t;
}

abi::SockExtendedErr tstamp_err(std::uint32_t id, std::uint32_t type) {
  abi::SockExtendedErr e{};
  e.ee_errno = static_cast<std::uint32_t>(abi::kEnomsg);
  e.ee_origin = abi::kSoEeOriginTimestamping;
  e.ee_info = type;
  e.ee_data = id;
  return e;
}

TEST(HwtsCmsg, ParsesScmTimestampingNewAndOld) {
  for (const int type : {abi::kSoTimestampingNew, abi::kSoTimestampingOld}) {
    alignas(16) std::array<std::byte, 256> buf{};
    const auto t = stamps(1'700'000'000'123'456'789, 42'000'000'007);
    const std::size_t len = put_cmsg(buf, 0, abi::kSolSocket, type, as_bytes_of(t));
    ASSERT_GT(len, 0u);
    ControlInfo ci{};
    parse_control(buf.data(), len, ci);
    EXPECT_TRUE(ci.has_timestamp);
    EXPECT_EQ(ci.ts.sw_ns, 1'700'000'000'123'456'789);
    EXPECT_EQ(ci.ts.hw_ns, 42'000'000'007);
    EXPECT_EQ(classify(ci.ts), TsKind::Hardware);
  }
}

TEST(HwtsCmsg, SoftwareOnlyStampClassifiesAsSoftware) {
  alignas(16) std::array<std::byte, 256> buf{};
  const auto t = stamps(5'000'000'001, 0);
  const std::size_t len = put_cmsg(buf, 0, abi::kSolSocket, abi::kSoTimestampingNew, as_bytes_of(t));
  ControlInfo ci{};
  parse_control(buf.data(), len, ci);
  EXPECT_EQ(classify(ci.ts), TsKind::Software);
  EXPECT_EQ(ci.ts.hw_ns, 0);
}

TEST(HwtsCmsg, ParsesTimestampnsAndPktinfo) {
  alignas(16) std::array<std::byte, 256> buf{};
  const abi::KernelTimespec ts{12, 345};
  abi::InPktinfo pi{};
  pi.ipi_ifindex = 7;
  std::memcpy(&pi.ipi_addr, "\xEF\x4D\x02\x01", 4);  // 239.77.2.1 in network order
  std::size_t len = put_cmsg(buf, 0, abi::kSolSocket, abi::kSoTimestampnsNew, as_bytes_of(ts));
  len = put_cmsg(buf, len, abi::kSolIp, abi::kIpPktinfo, as_bytes_of(pi));
  ASSERT_GT(len, 0u);
  ControlInfo ci{};
  parse_control(buf.data(), len, ci);
  EXPECT_EQ(ci.ts.sw_ns, 12 * kNsPerSec + 345);
  EXPECT_TRUE(ci.has_dst);
  EXPECT_EQ(ci.dst_ipv4, 0xEF4D0201u);
  EXPECT_EQ(ci.ifindex, 7u);
}

TEST(HwtsCmsg, ErrorQueueMessageBecomesTxStamp) {
  alignas(16) std::array<std::byte, 256> buf{};
  const auto t = stamps(0, 99'000'000'123);
  const auto e = tstamp_err(41, abi::kTstampSnd);
  // Kernel order: SCM_TIMESTAMPING first, then IP_RECVERR (sock_extended_err + offender).
  std::array<std::byte, sizeof(abi::SockExtendedErr) + 16> err_payload{};
  std::memcpy(err_payload.data(), &e, sizeof(e));
  std::size_t len = put_cmsg(buf, 0, abi::kSolSocket, abi::kSoTimestampingNew, as_bytes_of(t));
  len = put_cmsg(buf, len, abi::kSolIp, abi::kIpRecverr, err_payload);
  ASSERT_GT(len, 0u);
  ControlInfo ci{};
  parse_control(buf.data(), len, ci);
  TxStamp s{};
  ASSERT_TRUE(to_tx_stamp(ci, s));
  EXPECT_EQ(s.id, 41u);
  EXPECT_EQ(s.type, abi::kTstampSnd);
  EXPECT_EQ(s.ts.hw_ns, 99'000'000'123);
  EXPECT_EQ(s.kind(), TsKind::Hardware);
}

TEST(HwtsCmsg, Ipv6RecverrAlsoAccepted) {
  alignas(16) std::array<std::byte, 256> buf{};
  const auto t = stamps(77, 0);
  const auto e = tstamp_err(3, abi::kTstampSched);
  std::size_t len = put_cmsg(buf, 0, abi::kSolIpv6, abi::kIpv6Recverr, as_bytes_of(e));
  len = put_cmsg(buf, len, abi::kSolSocket, abi::kSoTimestampingOld, as_bytes_of(t));
  ControlInfo ci{};
  parse_control(buf.data(), len, ci);
  TxStamp s{};
  ASSERT_TRUE(to_tx_stamp(ci, s));
  EXPECT_EQ(s.type, abi::kTstampSched);
  EXPECT_EQ(s.kind(), TsKind::Software);
}

TEST(HwtsCmsg, RejectsNonTimestampErrors) {
  alignas(16) std::array<std::byte, 256> buf{};
  auto e = tstamp_err(1, 0);
  e.ee_errno = 111;  // ECONNREFUSED-style ICMP error
  e.ee_origin = 2;   // SO_EE_ORIGIN_ICMP
  const auto t = stamps(1, 2);
  std::size_t len = put_cmsg(buf, 0, abi::kSolIp, abi::kIpRecverr, as_bytes_of(e));
  len = put_cmsg(buf, len, abi::kSolSocket, abi::kSoTimestampingNew, as_bytes_of(t));
  ControlInfo ci{};
  parse_control(buf.data(), len, ci);
  TxStamp s{};
  EXPECT_FALSE(to_tx_stamp(ci, s));
  ControlInfo only_err{};
  parse_control(buf.data(), put_cmsg(buf, 0, abi::kSolIp, abi::kIpRecverr, as_bytes_of(tstamp_err(1, 0))), only_err);
  EXPECT_FALSE(to_tx_stamp(only_err, s)) << "no timestamp cmsg";
}

TEST(HwtsCmsg, ShortPayloadsAreCountedNotRead) {
  ControlInfo ci{};
  const std::array<std::byte, 8> tiny{};
  parse_cmsg(abi::kSolSocket, abi::kSoTimestampingNew, tiny, ci);
  parse_cmsg(abi::kSolIp, abi::kIpRecverr, tiny, ci);
  parse_cmsg(abi::kSolIp, abi::kIpPktinfo, tiny, ci);
  EXPECT_EQ(ci.malformed, 3u);
  EXPECT_FALSE(ci.has_timestamp);
  EXPECT_FALSE(ci.has_ext_err);
  EXPECT_FALSE(ci.has_dst);
  parse_cmsg(1234, 5, tiny, ci);  // unknown: ignored
  EXPECT_EQ(ci.malformed, 3u);
}

TEST(HwtsCmsg, OutOfRangeTimespecsReadAsAbsent) {
  // Found by fuzz/net/cmsg_fuzz under UBSan: a huge tv_sec overflowed the
  // nanosecond conversion (signed overflow, undefined behaviour).
  abi::ScmTimestamping t{};
  t.ts[0] = {442766114068391244, 0};      // overflows Nanos
  t.ts[2] = {5, 1'000'000'000};           // tv_nsec out of range
  ControlInfo ci{};
  parse_cmsg(abi::kSolSocket, abi::kSoTimestampingNew, as_bytes_of(t), ci);
  EXPECT_TRUE(ci.has_timestamp);
  EXPECT_EQ(ci.ts.sw_ns, 0);
  EXPECT_EQ(ci.ts.hw_ns, 0);
  EXPECT_EQ(ci.malformed, 1u);
  abi::KernelTimespec neg{-1, 0};
  ControlInfo c2{};
  parse_cmsg(abi::kSolSocket, abi::kSoTimestampnsNew, as_bytes_of(neg), c2);
  EXPECT_EQ(c2.ts.sw_ns, 0);
  EXPECT_EQ(c2.malformed, 1u);
  EXPECT_TRUE(valid_timespec({9'223'372'035, 999'999'999}));
  EXPECT_FALSE(valid_timespec({9'223'372'037, 0}));
}

TEST(HwtsCmsg, TruncatedControlBufferStopsCleanly) {
  alignas(16) std::array<std::byte, 256> buf{};
  const auto t = stamps(1, 2);
  const std::size_t len = put_cmsg(buf, 0, abi::kSolSocket, abi::kSoTimestampingNew, as_bytes_of(t));
  for (std::size_t cut = 0; cut < len; ++cut) {
    ControlInfo ci{};
    parse_control(buf.data(), cut, ci);  // must not read past `cut`
    EXPECT_FALSE(ci.has_timestamp && ci.ts.hw_ns != 2) << cut;
  }
  EXPECT_EQ(put_cmsg(std::span<std::byte>(buf.data(), 8), 0, 1, 1, as_bytes_of(t)), 0u) << "does not fit";
}

TEST(HwtsFlags, ComposesPerRequest) {
  EXPECT_EQ(timestamping_flags({}), 0u);
  EXPECT_EQ(timestamping_flags({TsMode::Software, TsMode::Off, false}), abi::kRxSoftware | abi::kSoftware);
  const auto hw_rx = timestamping_flags({TsMode::Hardware, TsMode::Off, false});
  EXPECT_NE(hw_rx & abi::kRxHardware, 0u);
  EXPECT_NE(hw_rx & abi::kRawHardware, 0u);
  const auto hw_tcp = timestamping_flags({TsMode::Off, TsMode::Hardware, true});
  EXPECT_EQ(hw_tcp, abi::kTxHardware | abi::kRawHardware | abi::kOptId | abi::kOptTsonly | abi::kOptIdTcp);
  const auto sw_udp = timestamping_flags({TsMode::Off, TsMode::Software, false});
  EXPECT_EQ(sw_udp, abi::kTxSoftware | abi::kSoftware | abi::kOptId | abi::kOptTsonly);
}

TxStamp stamp(std::uint32_t id, Nanos hw, std::uint32_t type = abi::kTstampSnd) {
  TxStamp s{};
  s.id = id;
  s.type = type;
  s.ts.hw_ns = hw;
  s.ts.sw_ns = hw != 0 ? 0 : 5;
  return s;
}

TEST(TxCorrelator, DatagramKeysCountSends) {
  TxCorrelator c;
  c.init(KeyMode::Datagram, 8);
  EXPECT_EQ(c.on_send(100, 60), 0u);
  EXPECT_EQ(c.on_send(101, 60), 1u);
  EXPECT_EQ(c.on_send(102, 60), 2u);
  std::vector<std::uint64_t> tags;
  auto cb = [&](std::uint64_t tag, const TxStamp&) { tags.push_back(tag); };
  EXPECT_TRUE(c.on_stamp(stamp(0, 10), cb));
  EXPECT_FALSE(c.on_stamp(stamp(1, 11, abi::kTstampSched), cb)) << "other report types ignored";
  EXPECT_TRUE(c.on_stamp(stamp(2, 12), cb)) << "key 1 never stamped: missing";
  EXPECT_EQ(tags, (std::vector<std::uint64_t>{100, 102}));
  EXPECT_EQ(c.validity().hw, 2u);
  EXPECT_EQ(c.validity().missing, 1u);
  EXPECT_FALSE(c.on_stamp(stamp(2, 12), cb)) << "duplicate";
  EXPECT_EQ(c.unmatched(), 1u);
}

TEST(TxCorrelator, StreamKeysAreLastByteOffsets) {
  TxCorrelator c;
  c.init(KeyMode::Stream, 8);
  EXPECT_EQ(c.on_send(1, 49), 48u);   // bytes 0..48
  EXPECT_EQ(c.on_send(2, 49), 97u);   // bytes 49..97
  EXPECT_EQ(c.on_send(3, 10), 107u);
  std::vector<std::uint64_t> tags;
  auto cb = [&](std::uint64_t tag, const TxStamp&) { tags.push_back(tag); };
  EXPECT_TRUE(c.on_stamp(stamp(48, 1), cb));
  // TCP merged send 2 into send 3's skb: only key 107 is reported.
  EXPECT_TRUE(c.on_stamp(stamp(107, 3), cb));
  EXPECT_EQ(tags, (std::vector<std::uint64_t>{1, 3}));
  EXPECT_EQ(c.validity().missing, 1u);
  EXPECT_EQ(c.outstanding(), 0u);
}

TEST(TxCorrelator, KeySpaceWrapsAndOverflowCountsMissing) {
  TxCorrelator c;
  c.init(KeyMode::Stream, 2);
  (void)c.on_send(1, 0xFFFF'FFF0u);  // key 0xFFFFFFEF
  const std::uint32_t k2 = c.on_send(2, 0x20);  // wraps: key 0x0F
  EXPECT_EQ(k2, 0x0Fu);
  int hits = 0;
  EXPECT_TRUE(c.on_stamp(stamp(k2, 9), [&](std::uint64_t tag, const TxStamp&) { hits += tag == 2 ? 1 : 0; }));
  EXPECT_EQ(hits, 1);
  EXPECT_EQ(c.validity().missing, 1u) << "the pre-wrap key is older than the post-wrap one";
  (void)c.on_send(3, 1);
  (void)c.on_send(4, 1);
  (void)c.on_send(5, 1);  // capacity 2: the oldest is dropped
  EXPECT_EQ(c.validity().missing, 2u);
  c.expire_all();
  EXPECT_EQ(c.validity().missing, 4u);
}

TEST(TxCorrelator, SoftwareStampsInvalidateTheRun) {
  TxCorrelator c;
  c.init(KeyMode::Datagram, 4);
  (void)c.on_send(1, 1);
  EXPECT_TRUE(c.on_stamp(stamp(0, 0), [](std::uint64_t, const TxStamp&) {}));
  EXPECT_EQ(c.validity().sw, 1u);
  EXPECT_FALSE(c.validity().valid());
}

TEST(ClockDomain, OnlySamePhcHardwareIntervals) {
  EXPECT_EQ(phc_interval({3, 1'500}, {3, 1'000}).value_or(-1), 500);
  EXPECT_EQ(phc_interval({3, 1'500}, {4, 1'000}).error(), IntervalError::CrossPhc);
  EXPECT_EQ(phc_interval({-1, 1'500}, {3, 1'000}).error(), IntervalError::Software);
  EXPECT_EQ(phc_interval({3, 0}, {3, 1'000}).error(), IntervalError::Missing);
  static_assert(phc_interval({0, 9}, {0, 4}).value() == 5);
}

TEST(ClockDomain, AccountingAppliesValidityRules) {
  IntervalAccounting a;
  for (int i = 0; i < 1999; ++i) (void)a.record({1, 100 + i}, {1, 50});
  (void)a.record({1, 0}, {1, 50});  // one missing pair in 2,000: 99.95% ok
  EXPECT_TRUE(a.valid());
  (void)a.record({2, 100}, {1, 50});
  EXPECT_EQ(a.cross_phc, 1u);
  EXPECT_FALSE(a.valid()) << "a cross-PHC subtraction invalidates the run";
  IntervalAccounting b;
  (void)b.record({1, 10}, {1, 5});
  (void)b.record({-1, 10}, {1, 5});
  EXPECT_FALSE(b.valid());
  EXPECT_EQ(b.software, 1u);
}

}  // namespace
}  // namespace lle::net::hwts
