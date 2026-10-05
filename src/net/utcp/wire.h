#pragma once
// Ethernet II / IPv4 / TCP / UDP wire formats (IEEE 802.3, RFC 791, RFC 9293 §3.1,
// RFC 768). Parsing returns views into the caller's buffer; building writes into a
// caller-provided buffer. Nothing here allocates.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace lle::net::utcp {

struct MacAddr {
  std::array<std::uint8_t, 6> b{};
  friend constexpr bool operator==(const MacAddr&, const MacAddr&) = default;
  [[nodiscard]] constexpr bool is_zero() const noexcept {
    return (b[0] | b[1] | b[2] | b[3] | b[4] | b[5]) == 0;
  }
  [[nodiscard]] constexpr bool is_broadcast() const noexcept {
    return (b[0] & b[1] & b[2] & b[3] & b[4] & b[5]) == 0xFF;
  }
  [[nodiscard]] static constexpr MacAddr broadcast() noexcept { return MacAddr{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}; }
  // RFC 1112 §6.4: 01:00:5e + low 23 bits of the group address.
  [[nodiscard]] static constexpr MacAddr ipv4_multicast(std::uint32_t group) noexcept {
    return MacAddr{{0x01, 0x00, 0x5E, static_cast<std::uint8_t>((group >> 16) & 0x7F),
                    static_cast<std::uint8_t>(group >> 8), static_cast<std::uint8_t>(group)}};
  }
};

[[nodiscard]] constexpr std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
  return (std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | std::uint32_t{d};
}
[[nodiscard]] constexpr bool ipv4_is_multicast(std::uint32_t ip) noexcept { return (ip >> 28) == 0xE; }

inline constexpr std::size_t kEthHeaderLen = 14;
inline constexpr std::size_t kIpv4HeaderLen = 20;
inline constexpr std::size_t kTcpHeaderLen = 20;
inline constexpr std::size_t kUdpHeaderLen = 8;
inline constexpr std::size_t kTcpMssOptionLen = 4;
inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr std::uint16_t kEtherTypeArp = 0x0806;
inline constexpr std::uint8_t kIpProtoTcp = 6;
inline constexpr std::uint8_t kIpProtoUdp = 17;
inline constexpr std::uint16_t kDefaultMss = 536;  // RFC 9293 §3.7.1 (no MSS option received)

namespace tcp_flag {
inline constexpr std::uint8_t kFin = 0x01;
inline constexpr std::uint8_t kSyn = 0x02;
inline constexpr std::uint8_t kRst = 0x04;
inline constexpr std::uint8_t kPsh = 0x08;
inline constexpr std::uint8_t kAck = 0x10;
inline constexpr std::uint8_t kUrg = 0x20;
}  // namespace tcp_flag

// Ethernet frames on AF_XDP / AF_PACKET; raw IPv4 packets for tun-like links.
enum class LinkType : std::uint8_t { Ethernet, RawIp };

[[nodiscard]] constexpr std::size_t link_header_len(LinkType l) noexcept {
  return l == LinkType::Ethernet ? kEthHeaderLen : 0;
}

// Parsed TCP segment. `payload` points into the caller's frame.
struct TcpSegment {
  MacAddr src_mac;
  MacAddr dst_mac;
  std::uint32_t src_ip = 0;  // host order
  std::uint32_t dst_ip = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::uint32_t seq = 0;
  std::uint32_t ack = 0;
  std::uint16_t window = 0;
  std::uint16_t mss = 0;  // MSS option value; 0 when absent
  std::uint8_t flags = 0;
  std::span<const std::byte> payload;

  [[nodiscard]] constexpr bool has(std::uint8_t f) const noexcept { return (flags & f) != 0; }
  // Sequence space occupied: data plus one each for SYN and FIN.
  [[nodiscard]] std::uint32_t seg_len() const noexcept {
    return static_cast<std::uint32_t>(payload.size()) + (has(tcp_flag::kSyn) ? 1u : 0u) +
           (has(tcp_flag::kFin) ? 1u : 0u);
  }
};

enum class ParseError : std::uint8_t {
  Truncated,
  NotIpv4,
  BadIpHeader,
  BadIpChecksum,
  Fragment,
  NotTcp,
  NotUdp,
  BadTcpHeader,
  BadTcpOptions,
  BadL4Checksum,
};
[[nodiscard]] const char* to_string(ParseError e) noexcept;

// EtherType of an Ethernet frame (0 if too short).
[[nodiscard]] std::uint16_t ether_type(std::span<const std::byte> frame) noexcept;

// Parses Ethernet (optional) + IPv4 + TCP. IP options are skipped; fragments are
// rejected (07 §2.4: no IP fragmentation). Ethernet padding beyond the IPv4 total
// length is ignored. With verify_checksums the IPv4 header and TCP checksums are
// checked in software.
[[nodiscard]] std::expected<TcpSegment, ParseError> parse_tcp(std::span<const std::byte> frame, LinkType link,
                                                              bool verify_checksums) noexcept;

// Header fields for an outbound TCP segment (payload passed separately).
struct TcpHeaderSpec {
  MacAddr src_mac;
  MacAddr dst_mac;
  std::uint32_t src_ip = 0;
  std::uint32_t dst_ip = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::uint32_t seq = 0;
  std::uint32_t ack = 0;
  std::uint16_t window = 0;
  std::uint16_t mss_option = 0;  // nonzero: append the MSS option (SYN segments)
  std::uint16_t ip_id = 0;
  std::uint8_t flags = 0;
  std::uint8_t ttl = 64;
};

// Bytes needed for the headers of a segment (link + IPv4 + TCP + options).
[[nodiscard]] constexpr std::size_t tcp_headers_len(LinkType l, bool mss_option) noexcept {
  return link_header_len(l) + kIpv4HeaderLen + kTcpHeaderLen + (mss_option ? kTcpMssOptionLen : 0);
}

// Builds a complete frame; the payload is the concatenation p1 ++ p2 (a ring buffer may
// wrap). With checksum_offload the TCP checksum field holds the folded pseudo-header sum
// (CHECKSUM_PARTIAL convention, as XDP_TXMD_FLAGS_CHECKSUM expects) and the device
// finishes it; the IPv4 header checksum is always computed here. Returns the frame
// length, or 0 if `out` is too small.
std::size_t build_tcp(std::span<std::byte> out, LinkType link, const TcpHeaderSpec& h, std::span<const std::byte> p1,
                      std::span<const std::byte> p2, bool checksum_offload) noexcept;

// UDP over IPv4 (for the AF_XDP datagram port and tests).
struct UdpDatagram {
  MacAddr src_mac;
  MacAddr dst_mac;
  std::uint32_t src_ip = 0;
  std::uint32_t dst_ip = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::span<const std::byte> payload;
};

[[nodiscard]] std::expected<UdpDatagram, ParseError> parse_udp(std::span<const std::byte> frame, LinkType link,
                                                               bool verify_checksums) noexcept;

struct UdpHeaderSpec {
  MacAddr src_mac;
  MacAddr dst_mac;
  std::uint32_t src_ip = 0;
  std::uint32_t dst_ip = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::uint16_t ip_id = 0;
  std::uint8_t ttl = 64;
};

inline constexpr std::size_t kUdpFrameOverhead = kEthHeaderLen + kIpv4HeaderLen + kUdpHeaderLen;

// Writes Ethernet + IPv4 + UDP headers in front of a payload that the caller has already
// placed at out[kUdpFrameOverhead...]. Returns the frame length or 0 if it does not fit.
// checksum_offload: as for build_tcp (UDP checksum field = pseudo-header sum).
std::size_t finish_udp_in_place(std::span<std::byte> out, const UdpHeaderSpec& h, std::size_t payload_len,
                                bool checksum_offload) noexcept;

// Writes an IPv4 header (no options, DF set) and its checksum.
void write_ipv4_header(std::byte* p, std::uint16_t total_len, std::uint16_t id, std::uint8_t ttl, std::uint8_t proto,
                       std::uint32_t src_ip, std::uint32_t dst_ip) noexcept;
void write_eth_header(std::byte* p, const MacAddr& dst, const MacAddr& src, std::uint16_t ether_type) noexcept;

}  // namespace lle::net::utcp
