#include "common/crc32c.h"

#include <array>
#include <bit>
#include <cstring>

#if defined(__x86_64__)
#include <cpuid.h>
#include <nmmintrin.h>
#elif defined(__aarch64__)
#include <arm_acle.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif
#endif

namespace lle {
namespace {

constexpr std::uint32_t kPoly = 0x82F63B78u;  // reflected Castagnoli

constexpr std::array<std::array<std::uint32_t, 256>, 8> make_tables() {
  std::array<std::array<std::uint32_t, 256>, 8> t{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1u) ? (c >> 1) ^ kPoly : c >> 1;
    t[0][i] = c;
  }
  for (std::size_t s = 1; s < 8; ++s)
    for (std::uint32_t i = 0; i < 256; ++i) t[s][i] = (t[s - 1][i] >> 8) ^ t[0][t[s - 1][i] & 0xFFu];
  return t;
}
constexpr auto kTables = make_tables();

std::uint32_t sw_raw(std::uint32_t c, const unsigned char* p, std::size_t n) noexcept {
  while (n >= 8) {
    std::uint64_t w;
    std::memcpy(&w, p, 8);
    if constexpr (std::endian::native == std::endian::big) w = std::byteswap(w);
    w ^= c;
    c = kTables[7][w & 0xFF] ^ kTables[6][(w >> 8) & 0xFF] ^ kTables[5][(w >> 16) & 0xFF] ^
        kTables[4][(w >> 24) & 0xFF] ^ kTables[3][(w >> 32) & 0xFF] ^ kTables[2][(w >> 40) & 0xFF] ^
        kTables[1][(w >> 48) & 0xFF] ^ kTables[0][w >> 56];
    p += 8;
    n -= 8;
  }
  while (n--) c = (c >> 8) ^ kTables[0][(c ^ *p++) & 0xFFu];
  return c;
}

#if defined(__x86_64__)
__attribute__((target("sse4.2"))) std::uint32_t hw_raw(std::uint32_t c, const unsigned char* p, std::size_t n) noexcept {
  std::uint64_t c64 = c;
  while (n >= 8) {
    std::uint64_t w;
    std::memcpy(&w, p, 8);
    c64 = _mm_crc32_u64(c64, w);
    p += 8;
    n -= 8;
  }
  c = static_cast<std::uint32_t>(c64);
  while (n--) c = _mm_crc32_u8(c, *p++);
  return c;
}
bool detect_hw() noexcept {
  unsigned a = 0, b = 0, cx = 0, d = 0;
  if (!__get_cpuid(1, &a, &b, &cx, &d)) return false;
  return (cx & bit_SSE4_2) != 0;
}
#elif defined(__aarch64__)
#if defined(__clang__)
#define LLE_TARGET_CRC __attribute__((target("crc")))
#else
#define LLE_TARGET_CRC __attribute__((target("+crc")))
#endif
LLE_TARGET_CRC std::uint32_t hw_raw(std::uint32_t c, const unsigned char* p, std::size_t n) noexcept {
  while (n >= 8) {
    std::uint64_t w;
    std::memcpy(&w, p, 8);
    c = __crc32cd(c, w);
    p += 8;
    n -= 8;
  }
  while (n--) c = __crc32cb(c, *p++);
  return c;
}
bool detect_hw() noexcept {
#if defined(__APPLE__)
  int v = 0;
  std::size_t sz = sizeof(v);
  if (sysctlbyname("hw.optional.armv8_crc32", &v, &sz, nullptr, 0) != 0) return false;
  return v != 0;
#elif defined(__linux__)
  return (getauxval(AT_HWCAP) & HWCAP_CRC32) != 0;
#else
  return false;
#endif
}
#else
std::uint32_t hw_raw(std::uint32_t c, const unsigned char* p, std::size_t n) noexcept { return sw_raw(c, p, n); }
bool detect_hw() noexcept { return false; }
#endif

const bool kHw = detect_hw();

}  // namespace

bool crc32c_hw_available() noexcept { return kHw; }

std::uint32_t crc32c_extend_sw(std::uint32_t crc, const void* data, std::size_t n) noexcept {
  return ~sw_raw(~crc, static_cast<const unsigned char*>(data), n);
}

std::uint32_t crc32c_extend(std::uint32_t crc, const void* data, std::size_t n) noexcept {
  const auto* p = static_cast<const unsigned char*>(data);
  return kHw ? ~hw_raw(~crc, p, n) : ~sw_raw(~crc, p, n);
}

}  // namespace lle
