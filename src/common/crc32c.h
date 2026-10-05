#pragma once
// CRC32C (Castagnoli). Hardware paths: SSE4.2 on x86-64, ARMv8 CRC on arm64.
// Convention: crc32c(data) == crc32c_extend(0, data); extend() handles the
// pre/post inversion so chained calls compose: extend(extend(0,a),b) == crc(a||b).
#include <cstddef>
#include <cstdint>
#include <span>

namespace lle {

[[nodiscard]] std::uint32_t crc32c_extend(std::uint32_t crc, const void* data, std::size_t n) noexcept;
[[nodiscard]] std::uint32_t crc32c_extend_sw(std::uint32_t crc, const void* data, std::size_t n) noexcept;
[[nodiscard]] bool crc32c_hw_available() noexcept;

[[nodiscard]] inline std::uint32_t crc32c(const void* data, std::size_t n) noexcept { return crc32c_extend(0, data, n); }
[[nodiscard]] inline std::uint32_t crc32c(std::span<const std::byte> s) noexcept { return crc32c_extend(0, s.data(), s.size()); }

}  // namespace lle
