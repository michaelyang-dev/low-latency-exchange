#pragma once
// Internet checksum (RFC 1071) and the IPv4 pseudo-header used by TCP (RFC 9293 §3.1)
// and UDP (RFC 768). Shared by utcp and the AF_XDP datagram port.
//
// RFC 1071 §2(B): the one's-complement sum is byte-order independent. We therefore sum
// native-order words loaded with memcpy and store the folded result natively; the bytes
// that land on the wire are the same as with a big-endian computation.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace lle::net::utcp {

// Partial sum over `b`, added to `sum`. When chaining, every span except the last must
// have even length (16-bit word alignment of the summed stream).
[[nodiscard]] inline std::uint64_t csum_add(std::span<const std::byte> b, std::uint64_t sum = 0) noexcept {
  const std::byte* p = b.data();
  std::size_t n = b.size();
  while (n >= 8) {
    std::uint32_t w0;
    std::uint32_t w1;
    std::memcpy(&w0, p, 4);
    std::memcpy(&w1, p + 4, 4);
    sum += w0;
    sum += w1;
    p += 8;
    n -= 8;
  }
  if (n >= 4) {
    std::uint32_t w;
    std::memcpy(&w, p, 4);
    sum += w;
    p += 4;
    n -= 4;
  }
  if (n >= 2) {
    std::uint16_t w;
    std::memcpy(&w, p, 2);
    sum += w;
    p += 2;
    n -= 2;
  }
  if (n != 0) {
    // Odd trailing byte: on the wire it is the high-order byte of a zero-padded word,
    // i.e. the byte at the lower address of the 16-bit word in memory.
    std::uint16_t w = 0;
    std::memcpy(&w, p, 1);
    sum += w;
  }
  return sum;
}

// Folds a partial sum to 16 bits (end-around carry), native order.
[[nodiscard]] constexpr std::uint16_t csum_fold(std::uint64_t s) noexcept {
  s = (s & 0xFFFF'FFFFull) + (s >> 32);
  s = (s & 0xFFFF'FFFFull) + (s >> 32);
  s = (s & 0xFFFFull) + (s >> 16);
  s = (s & 0xFFFFull) + (s >> 16);
  s = (s & 0xFFFFull) + (s >> 16);
  return static_cast<std::uint16_t>(s);
}

// Stores a native-order 16-bit checksum value at `p` (the bytes become network order).
inline void csum_store(void* p, std::uint16_t v) noexcept { std::memcpy(p, &v, 2); }

// The 12-byte IPv4 pseudo-header {src, dst, 0, proto, l4_len}; addresses in host order.
[[nodiscard]] inline std::uint64_t pseudo_header_sum(std::uint32_t src_ip, std::uint32_t dst_ip, std::uint8_t proto,
                                                     std::uint16_t l4_len) noexcept {
  std::byte ph[12];
  ph[0] = std::byte(src_ip >> 24);
  ph[1] = std::byte(src_ip >> 16);
  ph[2] = std::byte(src_ip >> 8);
  ph[3] = std::byte(src_ip);
  ph[4] = std::byte(dst_ip >> 24);
  ph[5] = std::byte(dst_ip >> 16);
  ph[6] = std::byte(dst_ip >> 8);
  ph[7] = std::byte(dst_ip);
  ph[8] = std::byte{0};
  ph[9] = std::byte{proto};
  ph[10] = std::byte(l4_len >> 8);
  ph[11] = std::byte(l4_len);
  return csum_add(std::span<const std::byte>(ph, sizeof(ph)));
}

// Checksum value to place in a header whose checksum field is zero during the sum.
[[nodiscard]] inline std::uint16_t csum_finish(std::uint64_t sum) noexcept {
  return static_cast<std::uint16_t>(~csum_fold(sum));
}

// True when a header/segment including its checksum field sums to 0xFFFF (RFC 1071 §1).
[[nodiscard]] inline bool csum_ok(std::uint64_t sum) noexcept { return csum_fold(sum) == 0xFFFF; }

}  // namespace lle::net::utcp
