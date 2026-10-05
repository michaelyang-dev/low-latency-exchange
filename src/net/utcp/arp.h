#pragma once
// ARP for Ethernet/IPv4 (RFC 826) and a fixed-capacity neighbour table (07 §2.4: static
// next hop, kernel neighbour table via netlink, gratuitous-ARP refresh).
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "net/utcp/wire.h"

namespace lle::net::utcp {

inline constexpr std::size_t kArpFrameLen = kEthHeaderLen + 28;

enum class ArpOp : std::uint16_t { Request = 1, Reply = 2 };

struct ArpPacket {
  ArpOp op = ArpOp::Request;
  MacAddr sender_mac;
  std::uint32_t sender_ip = 0;
  MacAddr target_mac;
  std::uint32_t target_ip = 0;
};

// Parses an Ethernet frame carrying Ethernet/IPv4 ARP; nullopt for anything else.
[[nodiscard]] std::optional<ArpPacket> parse_arp(std::span<const std::byte> frame) noexcept;

// Builds a full Ethernet ARP frame; returns kArpFrameLen or 0 if `out` is too small.
std::size_t build_arp(std::span<std::byte> out, const MacAddr& eth_dst, const ArpPacket& a) noexcept;

// Request for `target_ip`, broadcast.
std::size_t build_arp_request(std::span<std::byte> out, const MacAddr& my_mac, std::uint32_t my_ip,
                              std::uint32_t target_ip) noexcept;
// Gratuitous ARP announcement (RFC 5227 §3: request with sender IP = target IP).
std::size_t build_gratuitous_arp(std::span<std::byte> out, const MacAddr& my_mac, std::uint32_t my_ip) noexcept;
// Reply to `req` on behalf of (my_mac, my_ip).
std::size_t build_arp_reply(std::span<std::byte> out, const MacAddr& my_mac, std::uint32_t my_ip,
                            const ArpPacket& req) noexcept;

// IPv4 -> MAC table. Static entries (configuration, netlink snapshot) are never evicted
// by learned ones. Fixed capacity; lookups are linear (the table is tiny).
class NeighborTable {
 public:
  static constexpr std::size_t kCapacity = 32;

  // Inserts or updates. Returns false only when full of static entries.
  bool set(std::uint32_t ip, const MacAddr& mac, bool is_static) noexcept;
  // Updates an existing entry only (RFC 826 merge step).
  bool update_if_present(std::uint32_t ip, const MacAddr& mac) noexcept;
  [[nodiscard]] std::optional<MacAddr> lookup(std::uint32_t ip) const noexcept;
  void erase(std::uint32_t ip) noexcept;
  [[nodiscard]] std::size_t size() const noexcept;

 private:
  struct Entry {
    std::uint32_t ip = 0;
    MacAddr mac;
    bool valid = false;
    bool is_static = false;
  };
  std::array<Entry, kCapacity> e_{};
  std::size_t next_evict_ = 0;
};

}  // namespace lle::net::utcp
