#include "net/utcp/arp.h"

#include <cstring>

#include "common/endian.h"

namespace lle::net::utcp {

std::optional<ArpPacket> parse_arp(std::span<const std::byte> frame) noexcept {
  if (frame.size() < kArpFrameLen || load_be16(frame.data() + 12) != kEtherTypeArp) return std::nullopt;
  const std::byte* a = frame.data() + kEthHeaderLen;
  // htype 1 (Ethernet), ptype 0x0800, hlen 6, plen 4.
  if (load_be16(a) != 1 || load_be16(a + 2) != kEtherTypeIpv4 || std::to_integer<int>(a[4]) != 6 ||
      std::to_integer<int>(a[5]) != 4) {
    return std::nullopt;
  }
  const std::uint16_t op = load_be16(a + 6);
  if (op != 1 && op != 2) return std::nullopt;
  ArpPacket p;
  p.op = static_cast<ArpOp>(op);
  std::memcpy(p.sender_mac.b.data(), a + 8, 6);
  p.sender_ip = load_be32(a + 14);
  std::memcpy(p.target_mac.b.data(), a + 18, 6);
  p.target_ip = load_be32(a + 24);
  return p;
}

std::size_t build_arp(std::span<std::byte> out, const MacAddr& eth_dst, const ArpPacket& p) noexcept {
  if (out.size() < kArpFrameLen) return 0;
  std::byte* f = out.data();
  write_eth_header(f, eth_dst, p.sender_mac, kEtherTypeArp);
  std::byte* a = f + kEthHeaderLen;
  store_be16(a, 1);
  store_be16(a + 2, kEtherTypeIpv4);
  a[4] = std::byte{6};
  a[5] = std::byte{4};
  store_be16(a + 6, static_cast<std::uint16_t>(p.op));
  std::memcpy(a + 8, p.sender_mac.b.data(), 6);
  store_be32(a + 14, p.sender_ip);
  std::memcpy(a + 18, p.target_mac.b.data(), 6);
  store_be32(a + 24, p.target_ip);
  return kArpFrameLen;
}

std::size_t build_arp_request(std::span<std::byte> out, const MacAddr& my_mac, std::uint32_t my_ip,
                              std::uint32_t target_ip) noexcept {
  ArpPacket p;
  p.op = ArpOp::Request;
  p.sender_mac = my_mac;
  p.sender_ip = my_ip;
  p.target_ip = target_ip;
  return build_arp(out, MacAddr::broadcast(), p);
}

std::size_t build_gratuitous_arp(std::span<std::byte> out, const MacAddr& my_mac, std::uint32_t my_ip) noexcept {
  return build_arp_request(out, my_mac, my_ip, my_ip);
}

std::size_t build_arp_reply(std::span<std::byte> out, const MacAddr& my_mac, std::uint32_t my_ip,
                            const ArpPacket& req) noexcept {
  ArpPacket p;
  p.op = ArpOp::Reply;
  p.sender_mac = my_mac;
  p.sender_ip = my_ip;
  p.target_mac = req.sender_mac;
  p.target_ip = req.sender_ip;
  return build_arp(out, req.sender_mac, p);
}

bool NeighborTable::set(std::uint32_t ip, const MacAddr& mac, bool is_static) noexcept {
  Entry* free_slot = nullptr;
  for (auto& x : e_) {
    if (x.valid && x.ip == ip) {
      // A learned update never downgrades a static entry.
      if (x.is_static && !is_static) return true;
      x.mac = mac;
      x.is_static = is_static;
      return true;
    }
    if (!x.valid && free_slot == nullptr) free_slot = &x;
  }
  if (free_slot == nullptr) {
    // Evict a learned entry, round robin.
    for (std::size_t k = 0; k < kCapacity; ++k) {
      Entry& c = e_[(next_evict_ + k) % kCapacity];
      if (!c.is_static) {
        free_slot = &c;
        next_evict_ = (next_evict_ + k + 1) % kCapacity;
        break;
      }
    }
    if (free_slot == nullptr) return false;
  }
  *free_slot = Entry{ip, mac, true, is_static};
  return true;
}

bool NeighborTable::update_if_present(std::uint32_t ip, const MacAddr& mac) noexcept {
  for (auto& x : e_) {
    if (x.valid && x.ip == ip) {
      if (!x.is_static) x.mac = mac;
      return true;
    }
  }
  return false;
}

std::optional<MacAddr> NeighborTable::lookup(std::uint32_t ip) const noexcept {
  for (const auto& x : e_) {
    if (x.valid && x.ip == ip) return x.mac;
  }
  return std::nullopt;
}

void NeighborTable::erase(std::uint32_t ip) noexcept {
  for (auto& x : e_) {
    if (x.valid && x.ip == ip) x = Entry{};
  }
}

std::size_t NeighborTable::size() const noexcept {
  std::size_t n = 0;
  for (const auto& x : e_) n += x.valid ? 1u : 0u;
  return n;
}

}  // namespace lle::net::utcp
