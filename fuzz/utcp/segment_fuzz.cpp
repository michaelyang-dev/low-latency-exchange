// Fuzzes the utcp wire parsers. Any frame that parses as TCP is rebuilt from the
// parsed fields and must re-parse (with checksums) to the same fields: the builder and
// parser agree, and the parser never reads out of bounds (ASan) on any input.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "common/assert.h"
#include "net/utcp/arp.h"
#include "net/utcp/wire.h"

namespace {

using namespace lle::net::utcp;

void round_trip(const TcpSegment& s, LinkType link) {
  TcpHeaderSpec h;
  h.src_mac = s.src_mac;
  h.dst_mac = s.dst_mac;
  h.src_ip = s.src_ip;
  h.dst_ip = s.dst_ip;
  h.src_port = s.src_port;
  h.dst_port = s.dst_port;
  h.seq = s.seq;
  h.ack = s.ack;
  h.window = s.window;
  h.mss_option = s.mss;
  h.flags = s.flags;
  static std::array<std::byte, 70000> out;
  const std::size_t n = build_tcp(out, link, h, s.payload, {}, false);
  LLE_ASSERT(n != 0, "rebuild failed");
  auto r = parse_tcp(std::span<const std::byte>(out.data(), n), link, true);
  LLE_ASSERT(r.has_value(), "rebuilt frame does not parse");
  LLE_ASSERT(r->seq == s.seq && r->ack == s.ack && r->flags == s.flags && r->window == s.window, "field mismatch");
  LLE_ASSERT(r->src_port == s.src_port && r->dst_port == s.dst_port, "port mismatch");
  LLE_ASSERT(r->src_ip == s.src_ip && r->dst_ip == s.dst_ip, "address mismatch");
  LLE_ASSERT(r->mss == s.mss, "mss mismatch");
  LLE_ASSERT(r->payload.size() == s.payload.size(), "payload size mismatch");
  LLE_ASSERT(s.payload.empty() || std::memcmp(r->payload.data(), s.payload.data(), s.payload.size()) == 0,
             "payload mismatch");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> f(reinterpret_cast<const std::byte*>(data), size);
  for (LinkType link : {LinkType::Ethernet, LinkType::RawIp}) {
    for (bool verify : {true, false}) {
      if (auto s = parse_tcp(f, link, verify)) {
        LLE_ASSERT(s->payload.data() >= f.data() && s->payload.data() + s->payload.size() <= f.data() + f.size(),
                   "payload outside the frame");
        if (s->payload.size() <= 65000) round_trip(*s, link);
      }
      if (auto u = parse_udp(f, link, verify)) {
        LLE_ASSERT(u->payload.data() + u->payload.size() <= f.data() + f.size(), "udp payload outside the frame");
      }
    }
  }
  if (auto a = parse_arp(f)) {
    std::array<std::byte, 64> out{};
    LLE_ASSERT(build_arp(out, MacAddr::broadcast(), *a) == kArpFrameLen, "arp rebuild");
    auto b = parse_arp(std::span<const std::byte>(out.data(), kArpFrameLen));
    LLE_ASSERT(b && b->sender_ip == a->sender_ip && b->target_ip == a->target_ip && b->op == a->op, "arp round trip");
  }
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  using namespace lle::net::utcp;
  std::array<std::byte, 256> out{};
  std::size_t n = 0;
  TcpHeaderSpec h;
  h.src_mac = MacAddr{{2, 0, 0, 0, 0, 1}};
  h.dst_mac = MacAddr{{2, 0, 0, 0, 0, 2}};
  h.src_ip = ipv4(10, 0, 0, 1);
  h.dst_ip = ipv4(10, 0, 0, 2);
  h.src_port = 40000;
  h.dst_port = 8080;
  h.seq = 1000;
  h.ack = 2000;
  h.window = 4096;
  static const char kPayload[] = "SoupBinTCP payload";
  const std::span<const std::byte> pl(reinterpret_cast<const std::byte*>(kPayload), sizeof(kPayload) - 1);
  switch (index) {
    case 0:
      h.flags = tcp_flag::kSyn;
      h.mss_option = 1460;
      n = build_tcp(out, LinkType::Ethernet, h, {}, {}, false);
      break;
    case 1:
      h.flags = tcp_flag::kAck | tcp_flag::kPsh;
      n = build_tcp(out, LinkType::Ethernet, h, pl, {}, false);
      break;
    case 2:
      h.flags = tcp_flag::kFin | tcp_flag::kAck;
      n = build_tcp(out, LinkType::RawIp, h, pl, {}, false);
      break;
    case 3: n = build_arp_request(out, h.src_mac, h.src_ip, h.dst_ip); break;
    case 4: {
      UdpHeaderSpec u;
      u.src_ip = h.src_ip;
      u.dst_ip = ipv4(233, 54, 12, 1);
      u.src_port = 5000;
      u.dst_port = 26400;
      std::memcpy(out.data() + kUdpFrameOverhead, kPayload, sizeof(kPayload) - 1);
      n = finish_udp_in_place(out, u, sizeof(kPayload) - 1, false);
      break;
    }
    default: return 0;
  }
  if (n > cap) return 0;
  std::memcpy(buf, out.data(), n);
  return n;
}
