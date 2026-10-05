#pragma once
// SHA-256 (FIPS 180-4). Cold path only: input identity checks for benchmark
// data and evidence files (04-order-book §5 "checked against its SHA-256").
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace lle {

class Sha256 {
 public:
  using Digest = std::array<std::uint8_t, 32>;

  Sha256() noexcept;
  void update(const void* data, std::size_t n) noexcept;
  [[nodiscard]] Digest finish() noexcept;  // the object must not be reused afterwards

  [[nodiscard]] static Digest of(const void* data, std::size_t n) noexcept;
  [[nodiscard]] static std::string hex(const Digest& d);

 private:
  void block(const std::uint8_t* p) noexcept;

  std::array<std::uint32_t, 8> h_;
  std::array<std::uint8_t, 64> buf_{};
  std::size_t used_ = 0;
  std::uint64_t total_ = 0;
};

}  // namespace lle
