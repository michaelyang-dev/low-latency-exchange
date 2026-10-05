#include "net/utcp/wire.h"

#include <cstring>

#include "common/endian.h"
#include "net/utcp/checksum.h"

namespace lle::net::utcp {
namespace {

MacAddr load_mac(const std::byte* p) noexcept {
  MacAddr m;
  std::memcpy(m.b.data(), p, 6);
  return m;
}

struct Ipv4View {
  std::uint32_t src = 0;
  std::uint32_t dst = 0;
  std::uint8_t proto = 0;
  std::span<const std::byte> l4;  // bounded by the IPv4 total length
};

// RFC 791 §3.1 header checks shared by TCP and UDP parsing.
std::expected<Ipv4View, ParseError> parse_ipv4(std::span<const std::byte> frame, LinkType link,
                                               bool verify) noexcept {
  std::size_t off = 0;
  if (link == LinkType::Ethernet) {
    if (frame.size() < kEthHeaderLen) return std::unexpected(ParseError::Truncated);
    if (load_be16(frame.data() + 12) != kEtherTypeIpv4) return std::unexpected(ParseError::NotIpv4);
    off = kEthHeaderLen;
  }
  if (frame.size() < off + kIpv4HeaderLen) return std::unexpected(ParseError::Truncated);
  const std::byte* ip = frame.data() + off;
  const auto vihl = std::to_integer<std::uint8_t>(ip[0]);
  if ((vihl >> 4) != 4) return std::unexpected(ParseError::NotIpv4);
  const std::size_t ihl = std::size_t{vihl & 0x0Fu} * 4;
  const std::size_t total = load_be16(ip + 2);
  if (ihl < kIpv4HeaderLen || total < ihl) return std::unexpected(ParseError::BadIpHeader);
  if (frame.size() - off < total) return std::unexpected(ParseError::Truncated);
  // More-fragments bit or a nonzero fragment offset: fragmentation is out of scope.
  if ((load_be16(ip + 6) & 0x3FFFu) != 0) return std::unexpected(ParseError::Fragment);
  if (verify && !csum_ok(csum_add(std::span<const std::byte>(ip, ihl)))) {
    return std::unexpected(ParseError::BadIpChecksum);
  }
  Ipv4View v;
  v.proto = std::to_integer<std::uint8_t>(ip[9]);
  v.src = load_be32(ip + 12);
  v.dst = load_be32(ip + 16);
  v.l4 = std::span<const std::byte>(ip + ihl, total - ihl);
  return v;
}

}  // namespace

const char* to_string(ParseError e) noexcept {
  switch (e) {
    case ParseError::Truncated: return "truncated";
    case ParseError::NotIpv4: return "not-ipv4";
    case ParseError::BadIpHeader: return "bad-ip-header";
    case ParseError::BadIpChecksum: return "bad-ip-checksum";
    case ParseError::Fragment: return "fragment";
    case ParseError::NotTcp: return "not-tcp";
    case ParseError::NotUdp: return "not-udp";
    case ParseError::BadTcpHeader: return "bad-tcp-header";
    case ParseError::BadTcpOptions: return "bad-tcp-options";
    case ParseError::BadL4Checksum: return "bad-l4-checksum";
  }
  return "?";
}

std::uint16_t ether_type(std::span<const std::byte> frame) noexcept {
  return frame.size() < kEthHeaderLen ? std::uint16_t{0} : load_be16(frame.data() + 12);
}

std::expected<TcpSegment, ParseError> parse_tcp(std::span<const std::byte> frame, LinkType link,
                                                bool verify_checksums) noexcept {
  auto ipr = parse_ipv4(frame, link, verify_checksums);
  if (!ipr) return std::unexpected(ipr.error());
  const Ipv4View& ip = *ipr;
  if (ip.proto != kIpProtoTcp) return std::unexpected(ParseError::NotTcp);
  const std::span<const std::byte> l4 = ip.l4;
  if (l4.size() < kTcpHeaderLen) return std::unexpected(ParseError::Truncated);
  const std::byte* t = l4.data();
  const std::size_t doff = static_cast<std::size_t>(std::to_integer<std::uint8_t>(t[12]) >> 4) * 4;
  if (doff < kTcpHeaderLen || doff > l4.size()) return std::unexpected(ParseError::BadTcpHeader);
  if (verify_checksums) {
    const std::uint64_t s =
        csum_add(l4, pseudo_header_sum(ip.src, ip.dst, kIpProtoTcp, static_cast<std::uint16_t>(l4.size())));
    if (!csum_ok(s)) return std::unexpected(ParseError::BadL4Checksum);
  }
  TcpSegment seg;
  if (link == LinkType::Ethernet) {
    seg.dst_mac = load_mac(frame.data());
    seg.src_mac = load_mac(frame.data() + 6);
  }
  seg.src_ip = ip.src;
  seg.dst_ip = ip.dst;
  seg.src_port = load_be16(t);
  seg.dst_port = load_be16(t + 2);
  seg.seq = load_be32(t + 4);
  seg.ack = load_be32(t + 8);
  seg.flags = static_cast<std::uint8_t>(std::to_integer<std::uint8_t>(t[13]) & 0x3Fu);
  seg.window = load_be16(t + 14);
  // RFC 9293 §3.1 options: EOL(0), NOP(1), MSS(2, len 4); unknown kinds are skipped by
  // their length. A malformed length makes the whole segment invalid (dropped).
  std::size_t i = kTcpHeaderLen;
  while (i < doff) {
    const auto kind = std::to_integer<std::uint8_t>(t[i]);
    if (kind == 0) break;
    if (kind == 1) {
      ++i;
      continue;
    }
    if (i + 1 >= doff) return std::unexpected(ParseError::BadTcpOptions);
    const std::size_t len = std::to_integer<std::uint8_t>(t[i + 1]);
    if (len < 2 || i + len > doff) return std::unexpected(ParseError::BadTcpOptions);
    if (kind == 2) {
      if (len != 4) return std::unexpected(ParseError::BadTcpOptions);
      seg.mss = load_be16(t + i + 2);
    }
    i += len;
  }
  seg.payload = l4.subspan(doff);
  return seg;
}

void write_eth_header(std::byte* p, const MacAddr& dst, const MacAddr& src, std::uint16_t ether_type) noexcept {
  std::memcpy(p, dst.b.data(), 6);
  std::memcpy(p + 6, src.b.data(), 6);
  store_be16(p + 12, ether_type);
}

void write_ipv4_header(std::byte* p, std::uint16_t total_len, std::uint16_t id, std::uint8_t ttl, std::uint8_t proto,
                       std::uint32_t src_ip, std::uint32_t dst_ip) noexcept {
  p[0] = std::byte{0x45};
  p[1] = std::byte{0};
  store_be16(p + 2, total_len);
  store_be16(p + 4, id);
  store_be16(p + 6, 0x4000);  // DF: we never fragment (07 §2.4)
  p[8] = std::byte{ttl};
  p[9] = std::byte{proto};
  store_be16(p + 10, 0);
  store_be32(p + 12, src_ip);
  store_be32(p + 16, dst_ip);
  csum_store(p + 10, csum_finish(csum_add(std::span<const std::byte>(p, kIpv4HeaderLen))));
}

std::size_t build_tcp(std::span<std::byte> out, LinkType link, const TcpHeaderSpec& h, std::span<const std::byte> p1,
                      std::span<const std::byte> p2, bool checksum_offload) noexcept {
  const bool mss = h.mss_option != 0;
  const std::size_t hdr = tcp_headers_len(link, mss);
  const std::size_t plen = p1.size() + p2.size();
  const std::size_t total = hdr + plen;
  if (out.size() < total) return 0;
  std::byte* p = out.data();
  if (link == LinkType::Ethernet) {
    write_eth_header(p, h.dst_mac, h.src_mac, kEtherTypeIpv4);
    p += kEthHeaderLen;
  }
  const std::size_t tcp_len = kTcpHeaderLen + (mss ? kTcpMssOptionLen : 0) + plen;
  write_ipv4_header(p, static_cast<std::uint16_t>(kIpv4HeaderLen + tcp_len), h.ip_id, h.ttl, kIpProtoTcp, h.src_ip,
                    h.dst_ip);
  std::byte* t = p + kIpv4HeaderLen;
  store_be16(t, h.src_port);
  store_be16(t + 2, h.dst_port);
  store_be32(t + 4, h.seq);
  store_be32(t + 8, h.ack);
  const std::size_t doff_words = (kTcpHeaderLen + (mss ? kTcpMssOptionLen : 0)) / 4;
  t[12] = std::byte(doff_words << 4);
  t[13] = std::byte{h.flags};
  store_be16(t + 14, h.window);
  store_be16(t + 16, 0);
  store_be16(t + 18, 0);  // urgent pointer: urgent data is not supported
  std::byte* d = t + kTcpHeaderLen;
  if (mss) {
    d[0] = std::byte{2};
    d[1] = std::byte{4};
    store_be16(d + 2, h.mss_option);
    d += kTcpMssOptionLen;
  }
  if (!p1.empty()) std::memcpy(d, p1.data(), p1.size());
  if (!p2.empty()) std::memcpy(d + p1.size(), p2.data(), p2.size());
  const std::uint64_t ph = pseudo_header_sum(h.src_ip, h.dst_ip, kIpProtoTcp, static_cast<std::uint16_t>(tcp_len));
  if (checksum_offload) {
    csum_store(t + 16, csum_fold(ph));
  } else {
    csum_store(t + 16, csum_finish(csum_add(std::span<const std::byte>(t, tcp_len), ph)));
  }
  return total;
}

std::expected<UdpDatagram, ParseError> parse_udp(std::span<const std::byte> frame, LinkType link,
                                                 bool verify_checksums) noexcept {
  auto ipr = parse_ipv4(frame, link, verify_checksums);
  if (!ipr) return std::unexpected(ipr.error());
  const Ipv4View& ip = *ipr;
  if (ip.proto != kIpProtoUdp) return std::unexpected(ParseError::NotUdp);
  if (ip.l4.size() < kUdpHeaderLen) return std::unexpected(ParseError::Truncated);
  const std::byte* u = ip.l4.data();
  const std::size_t ulen = load_be16(u + 4);
  if (ulen < kUdpHeaderLen || ulen > ip.l4.size()) return std::unexpected(ParseError::Truncated);
  // RFC 768: a zero checksum means "not computed".
  if (verify_checksums && load_be16(u + 6) != 0) {
    const std::uint64_t s = csum_add(ip.l4.first(ulen),
                                     pseudo_header_sum(ip.src, ip.dst, kIpProtoUdp, static_cast<std::uint16_t>(ulen)));
    if (!csum_ok(s)) return std::unexpected(ParseError::BadL4Checksum);
  }
  UdpDatagram d;
  if (link == LinkType::Ethernet) {
    d.dst_mac = load_mac(frame.data());
    d.src_mac = load_mac(frame.data() + 6);
  }
  d.src_ip = ip.src;
  d.dst_ip = ip.dst;
  d.src_port = load_be16(u);
  d.dst_port = load_be16(u + 2);
  d.payload = ip.l4.subspan(kUdpHeaderLen, ulen - kUdpHeaderLen);
  return d;
}

std::size_t finish_udp_in_place(std::span<std::byte> out, const UdpHeaderSpec& h, std::size_t payload_len,
                                bool checksum_offload) noexcept {
  const std::size_t total = kUdpFrameOverhead + payload_len;
  if (out.size() < total || payload_len > 0xFFFF - kIpv4HeaderLen - kUdpHeaderLen) return 0;
  std::byte* p = out.data();
  write_eth_header(p, h.dst_mac, h.src_mac, kEtherTypeIpv4);
  const auto ulen = static_cast<std::uint16_t>(kUdpHeaderLen + payload_len);
  write_ipv4_header(p + kEthHeaderLen, static_cast<std::uint16_t>(kIpv4HeaderLen + ulen), h.ip_id, h.ttl, kIpProtoUdp,
                    h.src_ip, h.dst_ip);
  std::byte* u = p + kEthHeaderLen + kIpv4HeaderLen;
  store_be16(u, h.src_port);
  store_be16(u + 2, h.dst_port);
  store_be16(u + 4, ulen);
  store_be16(u + 6, 0);
  const std::uint64_t ph = pseudo_header_sum(h.src_ip, h.dst_ip, kIpProtoUdp, ulen);
  if (checksum_offload) {
    csum_store(u + 6, csum_fold(ph));
  } else {
    std::uint16_t c = csum_finish(csum_add(std::span<const std::byte>(u, ulen), ph));
    if (c == 0) c = 0xFFFF;  // RFC 768: transmitted as all ones when the sum is zero
    csum_store(u + 6, c);
  }
  return total;
}

}  // namespace lle::net::utcp
