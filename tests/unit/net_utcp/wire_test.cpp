// Golden and round-trip tests for checksums, Ethernet/IPv4/TCP/UDP framing, ARP, the
// neighbour table, sequence arithmetic and the byte ring. Expected bytes are hand-
// assembled from RFC 791 / RFC 9293 §3.1 / RFC 768 / RFC 826 (checksums cross-checked
// with an independent big-endian implementation).
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "net/utcp/arp.h"
#include "net/utcp/byte_ring.h"
#include "net/utcp/checksum.h"
#include "net/utcp/seq.h"
#include "net/utcp/wire.h"

namespace lle::net::utcp {
namespace {

template <std::size_t N>
std::vector<std::byte> bytes(const std::array<std::uint8_t, N>& a) {
  std::vector<std::byte> v(N);
  for (std::size_t i = 0; i < N; ++i) v[i] = std::byte{a[i]};
  return v;
}

std::span<const std::byte> as_bytes(const char* s, std::size_t n) {
  return {reinterpret_cast<const std::byte*>(s), n};
}

constexpr MacAddr kMacA{{0x02, 0, 0, 0, 0, 0x01}};
constexpr MacAddr kMacB{{0x02, 0, 0, 0, 0, 0x02}};

// RFC 1071 §3 numerical example: 00 01 f2 03 f4 f5 f6 f7 sums to dd f2.
TEST(Checksum, Rfc1071Example) {
  const auto b = bytes(std::array<std::uint8_t, 8>{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7});
  std::byte out[2];
  csum_store(out, csum_fold(csum_add(b)));
  EXPECT_EQ(std::to_integer<int>(out[0]), 0xdd);
  EXPECT_EQ(std::to_integer<int>(out[1]), 0xf2);
}

TEST(Checksum, OddLengthAndChaining) {
  const auto b = bytes(std::array<std::uint8_t, 5>{0x12, 0x34, 0x56, 0x78, 0x9a});
  std::byte out[2];
  csum_store(out, csum_fold(csum_add(b)));
  // 0x1234 + 0x5678 + 0x9a00 = 0x102ac -> 0x02ad
  EXPECT_EQ(std::to_integer<int>(out[0]), 0x02);
  EXPECT_EQ(std::to_integer<int>(out[1]), 0xad);
  const std::uint64_t chained = csum_add(std::span<const std::byte>(b).subspan(4), csum_add(std::span(b).first(4)));
  EXPECT_EQ(csum_fold(chained), csum_fold(csum_add(b)));
}

// The classic RFC 791 header example (checksum b861).
TEST(Ipv4, HeaderGolden) {
  std::array<std::byte, 20> h{};
  write_ipv4_header(h.data(), 0x73, 0, 0x40, 0x11, ipv4(192, 168, 0, 1), ipv4(192, 168, 0, 199));
  const auto want = bytes(std::array<std::uint8_t, 20>{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                                                      0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7});
  EXPECT_EQ(std::vector<std::byte>(h.begin(), h.end()), want);
}

const std::array<std::uint8_t, 58> kSynGolden{
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x2c, 0x00, 0x01,
    0x40, 0x00, 0x40, 0x06, 0x26, 0xc9, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x9c, 0x40, 0x1f, 0x90, 0x00, 0x00,
    0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0xff, 0xff, 0xc4, 0x6b, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4};

TEST(Tcp, BuildSynGolden) {
  TcpHeaderSpec h;
  h.src_mac = kMacA;
  h.dst_mac = kMacB;
  h.src_ip = ipv4(10, 0, 0, 1);
  h.dst_ip = ipv4(10, 0, 0, 2);
  h.src_port = 40000;
  h.dst_port = 8080;
  h.seq = 1000;
  h.window = 0xFFFF;
  h.mss_option = 1460;
  h.ip_id = 1;
  h.flags = tcp_flag::kSyn;
  std::array<std::byte, 128> out{};
  const std::size_t n = build_tcp(out, LinkType::Ethernet, h, {}, {}, false);
  ASSERT_EQ(n, kSynGolden.size());
  EXPECT_EQ(std::vector<std::byte>(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n)), bytes(kSynGolden));
}

TEST(Tcp, ParseSynGolden) {
  const auto f = bytes(kSynGolden);
  auto seg = parse_tcp(f, LinkType::Ethernet, true);
  ASSERT_TRUE(seg.has_value());
  EXPECT_EQ(seg->src_mac, kMacA);
  EXPECT_EQ(seg->dst_mac, kMacB);
  EXPECT_EQ(seg->src_ip, ipv4(10, 0, 0, 1));
  EXPECT_EQ(seg->dst_ip, ipv4(10, 0, 0, 2));
  EXPECT_EQ(seg->src_port, 40000);
  EXPECT_EQ(seg->dst_port, 8080);
  EXPECT_EQ(seg->seq, 1000u);
  EXPECT_EQ(seg->flags, tcp_flag::kSyn);
  EXPECT_EQ(seg->window, 0xFFFF);
  EXPECT_EQ(seg->mss, 1460);
  EXPECT_TRUE(seg->payload.empty());
  EXPECT_EQ(seg->seg_len(), 1u);
}

const std::array<std::uint8_t, 59> kDataGolden{
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x2d, 0x00, 0x02,
    0x40, 0x00, 0x40, 0x06, 0x26, 0xc7, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x9c, 0x40, 0x1f, 0x90, 0x00, 0x00,
    0x03, 0xe9, 0x00, 0x00, 0x13, 0x89, 0x50, 0x18, 0x10, 0x00, 0x74, 0xb0, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f};

TEST(Tcp, BuildDataGoldenWithSplitPayload) {
  TcpHeaderSpec h;
  h.src_mac = kMacA;
  h.dst_mac = kMacB;
  h.src_ip = ipv4(10, 0, 0, 1);
  h.dst_ip = ipv4(10, 0, 0, 2);
  h.src_port = 40000;
  h.dst_port = 8080;
  h.seq = 1001;
  h.ack = 5001;
  h.window = 4096;
  h.ip_id = 2;
  h.flags = tcp_flag::kAck | tcp_flag::kPsh;
  std::array<std::byte, 128> out{};
  // Odd-length first piece: the payload checksum must not depend on the split.
  const std::size_t n = build_tcp(out, LinkType::Ethernet, h, as_bytes("hel", 3), as_bytes("lo", 2), false);
  ASSERT_EQ(n, kDataGolden.size());
  EXPECT_EQ(std::vector<std::byte>(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n)), bytes(kDataGolden));
  auto seg = parse_tcp(std::span<const std::byte>(out.data(), n), LinkType::Ethernet, true);
  ASSERT_TRUE(seg.has_value());
  EXPECT_EQ(seg->payload.size(), 5u);
  EXPECT_EQ(seg->ack, 5001u);
}

TEST(Tcp, ChecksumOffloadLeavesPseudoHeaderSum) {
  TcpHeaderSpec h;
  h.src_mac = kMacA;
  h.dst_mac = kMacB;
  h.src_ip = ipv4(10, 0, 0, 1);
  h.dst_ip = ipv4(10, 0, 0, 2);
  h.src_port = 40000;
  h.dst_port = 8080;
  h.seq = 1001;
  h.ack = 5001;
  h.window = 4096;
  h.ip_id = 2;
  h.flags = tcp_flag::kAck | tcp_flag::kPsh;
  std::array<std::byte, 128> out{};
  const std::size_t n = build_tcp(out, LinkType::Ethernet, h, as_bytes("hello", 5), {}, true);
  ASSERT_EQ(n, kDataGolden.size());
  EXPECT_EQ(std::to_integer<int>(out[50]), 0x14);  // folded pseudo-header sum 0x1422
  EXPECT_EQ(std::to_integer<int>(out[51]), 0x22);
  EXPECT_FALSE(parse_tcp(std::span<const std::byte>(out.data(), n), LinkType::Ethernet, true).has_value());
  EXPECT_TRUE(parse_tcp(std::span<const std::byte>(out.data(), n), LinkType::Ethernet, false).has_value());
}

TEST(Tcp, ParseRejectsCorruption) {
  auto f = bytes(kDataGolden);
  f[56] ^= std::byte{1};
  EXPECT_EQ(parse_tcp(f, LinkType::Ethernet, true).error(), ParseError::BadL4Checksum);
  f = bytes(kDataGolden);
  f[24] ^= std::byte{1};
  EXPECT_EQ(parse_tcp(f, LinkType::Ethernet, true).error(), ParseError::BadIpChecksum);
  f = bytes(kDataGolden);
  f[20] = std::byte{0x20};  // MF set
  EXPECT_EQ(parse_tcp(f, LinkType::Ethernet, false).error(), ParseError::Fragment);
  f = bytes(kDataGolden);
  f.resize(40);
  EXPECT_EQ(parse_tcp(f, LinkType::Ethernet, false).error(), ParseError::Truncated);
  f = bytes(kDataGolden);
  f[23] = std::byte{17};
  EXPECT_EQ(parse_tcp(f, LinkType::Ethernet, false).error(), ParseError::NotTcp);
  f = bytes(kDataGolden);
  f[46] = std::byte{0x40};  // data offset 4 words < 5
  EXPECT_EQ(parse_tcp(f, LinkType::Ethernet, false).error(), ParseError::BadTcpHeader);
}

TEST(Tcp, ParseIgnoresEthernetPadding) {
  auto f = bytes(kSynGolden);
  f.resize(64, std::byte{0xAA});
  auto seg = parse_tcp(f, LinkType::Ethernet, true);
  ASSERT_TRUE(seg.has_value());
  EXPECT_TRUE(seg->payload.empty());
}

TEST(Tcp, OptionsParsing) {
  // SYN with NOP, NOP, unknown kind 8 len 10 (timestamps), MSS, EOL.
  TcpHeaderSpec h;
  h.src_ip = ipv4(10, 0, 0, 1);
  h.dst_ip = ipv4(10, 0, 0, 2);
  h.flags = tcp_flag::kSyn;
  std::array<std::byte, 128> out{};
  std::size_t n = build_tcp(out, LinkType::RawIp, h, {}, {}, false);
  ASSERT_EQ(n, 40u);
  // Rebuild by hand with 16 bytes of options.
  std::vector<std::byte> f(out.begin(), out.begin() + 40);
  const std::array<std::uint8_t, 16> opts{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 2, 4, 0x02, 0x18};
  for (auto o : opts) f.push_back(std::byte{o});
  f[3] = std::byte{56};    // IPv4 total length
  f[32] = std::byte{0x90};  // data offset 9 words
  f[10] = f[11] = std::byte{0};
  csum_store(&f[10], csum_finish(csum_add(std::span<const std::byte>(f).first(20))));
  f[36] = f[37] = std::byte{0};
  csum_store(&f[36], csum_finish(csum_add(std::span<const std::byte>(f).subspan(20),
                                          pseudo_header_sum(h.src_ip, h.dst_ip, kIpProtoTcp, 36))));
  auto seg = parse_tcp(f, LinkType::RawIp, true);
  ASSERT_TRUE(seg.has_value()) << to_string(seg.error());
  EXPECT_EQ(seg->mss, 0x0218);
  // A zero option length is malformed.
  f[43] = std::byte{0};
  EXPECT_EQ(parse_tcp(f, LinkType::RawIp, false).error(), ParseError::BadTcpOptions);
}

const std::array<std::uint8_t, 45> kUdpGolden{0x01, 0x00, 0x5e, 0x36, 0x0c, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                                              0x08, 0x00, 0x45, 0x00, 0x00, 0x1f, 0x00, 0x07, 0x40, 0x00, 0x40, 0x11,
                                              0x3b, 0x8f, 0x0a, 0x00, 0x00, 0x01, 0xe9, 0x36, 0x0c, 0x01, 0x13, 0x88,
                                              0x67, 0x20, 0x00, 0x0b, 0xc1, 0x94, 0x61, 0x62, 0x63};

TEST(Udp, BuildAndParseGolden) {
  std::array<std::byte, 64> out{};
  out[kUdpFrameOverhead] = std::byte{'a'};
  out[kUdpFrameOverhead + 1] = std::byte{'b'};
  out[kUdpFrameOverhead + 2] = std::byte{'c'};
  UdpHeaderSpec h;
  h.src_mac = kMacA;
  h.dst_mac = MacAddr::ipv4_multicast(ipv4(233, 54, 12, 1));
  h.src_ip = ipv4(10, 0, 0, 1);
  h.dst_ip = ipv4(233, 54, 12, 1);
  h.src_port = 5000;
  h.dst_port = 26400;
  h.ip_id = 7;
  const std::size_t n = finish_udp_in_place(out, h, 3, false);
  ASSERT_EQ(n, kUdpGolden.size());
  EXPECT_EQ(std::vector<std::byte>(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n)), bytes(kUdpGolden));
  auto d = parse_udp(std::span<const std::byte>(out.data(), n), LinkType::Ethernet, true);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->dst_port, 26400);
  EXPECT_EQ(d->payload.size(), 3u);
  auto bad = bytes(kUdpGolden);
  bad[44] ^= std::byte{4};
  EXPECT_EQ(parse_udp(bad, LinkType::Ethernet, true).error(), ParseError::BadL4Checksum);
}

TEST(Arp, RequestGolden) {
  std::array<std::byte, 64> out{};
  ASSERT_EQ(build_arp_request(out, kMacA, ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2)), kArpFrameLen);
  const auto want = bytes(std::array<std::uint8_t, 42>{
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
      0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02});
  EXPECT_EQ(std::vector<std::byte>(out.begin(), out.begin() + 42), want);
  auto p = parse_arp(std::span<const std::byte>(out.data(), 42));
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->op, ArpOp::Request);
  EXPECT_EQ(p->target_ip, ipv4(10, 0, 0, 2));
  std::array<std::byte, 64> rep{};
  ASSERT_EQ(build_arp_reply(rep, kMacB, ipv4(10, 0, 0, 2), *p), kArpFrameLen);
  auto r = parse_arp(std::span<const std::byte>(rep.data(), 42));
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->op, ArpOp::Reply);
  EXPECT_EQ(r->sender_mac, kMacB);
  EXPECT_EQ(r->target_mac, kMacA);
  EXPECT_EQ(std::to_integer<int>(rep[0]), 0x02);  // unicast back to the requester
  std::array<std::byte, 64> g{};
  ASSERT_EQ(build_gratuitous_arp(g, kMacA, ipv4(10, 0, 0, 1)), kArpFrameLen);
  auto gp = parse_arp(std::span<const std::byte>(g.data(), 42));
  ASSERT_TRUE(gp.has_value());
  EXPECT_EQ(gp->sender_ip, gp->target_ip);
}

TEST(Arp, NeighborTableStaticAndEviction) {
  NeighborTable t;
  EXPECT_TRUE(t.set(1, kMacA, true));
  EXPECT_TRUE(t.set(1, kMacB, false));  // learned does not override static
  EXPECT_EQ(t.lookup(1), kMacA);
  for (std::uint32_t i = 2; i < 2 + NeighborTable::kCapacity + 5; ++i) EXPECT_TRUE(t.set(i, kMacB, false));
  EXPECT_EQ(t.size(), NeighborTable::kCapacity);
  EXPECT_EQ(t.lookup(1), kMacA);  // static survived eviction
  EXPECT_TRUE(t.update_if_present(1, kMacB));
  EXPECT_EQ(t.lookup(1), kMacA);
  t.erase(1);
  EXPECT_FALSE(t.lookup(1).has_value());
}

TEST(Seq, WrapAround) {
  EXPECT_TRUE(seq_lt(0xFFFFFFF0u, 0x10u));
  EXPECT_TRUE(seq_gt(0x10u, 0xFFFFFFF0u));
  EXPECT_TRUE(seq_le(5u, 5u));
  EXPECT_TRUE(seq_in_window(2u, 0xFFFFFFFFu, 4u));
  EXPECT_FALSE(seq_in_window(3u, 0xFFFFFFFFu, 4u));
  EXPECT_EQ(seq_max(0xFFFFFFF0u, 0x10u), 0x10u);
}

TEST(ByteRing, WrapPeekConsume) {
  ByteRing r(8);
  const char* s = "abcdefgh";
  EXPECT_EQ(r.write(as_bytes(s, 6)), 6u);
  r.consume(4);
  EXPECT_EQ(r.write(as_bytes(s, 8)), 6u);  // only 6 free
  EXPECT_EQ(r.size(), 8u);
  auto sp = r.peek(0, 8);
  EXPECT_EQ(sp.first.size() + sp.second.size(), 8u);
  EXPECT_EQ(std::to_integer<char>(sp.first[0]), 'e');
  auto mid = r.peek(3, 4);
  EXPECT_EQ(mid.size(), 4u);
  EXPECT_EQ(r.peek(9, 1).size(), 0u);
  r.consume(100);
  EXPECT_TRUE(r.empty());
}

}  // namespace
}  // namespace lle::net::utcp
