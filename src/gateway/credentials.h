#pragma once
// SoupBinTCP login credentials stored as salted hashes (07 §3, N-17: "login
// authentication against salted credential hashes"). The configuration never holds a
// plain password.
//
//   text form:  sha256$<salt: 2..64 hex digits>$<digest: 64 hex digits>
//   digest   =  SHA-256(salt bytes || normalized password)
//
// Normalization follows SoupBinTCP 3.00 §2.3.1: usernames and passwords are
// case-insensitive and space padded, so both are compared trimmed and upper-cased.
// Cold path (configuration load and logins); verify() compares in constant time.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace lle::gw {

// Trimmed of spaces on both sides and ASCII upper-cased (SoupBinTCP §2.3.1).
[[nodiscard]] std::string normalize_credential(std::string_view s);

class Credential {
 public:
  static constexpr std::size_t kMaxSaltBytes = 32;

  Credential() = default;

  // Parses the text form; an error names what is wrong.
  [[nodiscard]] static std::expected<Credential, std::string> parse(std::string_view text);
  // Hashes `password` with `salt` (1..32 bytes).
  [[nodiscard]] static Credential make(std::string_view password, std::span<const std::uint8_t> salt);

  // True if `password` (as received: any case, any padding) matches.
  [[nodiscard]] bool verify(std::string_view password) const noexcept;
  [[nodiscard]] bool valid() const noexcept { return salt_len_ != 0; }
  [[nodiscard]] std::string text() const;

 private:
  std::array<std::uint8_t, kMaxSaltBytes> salt_{};
  std::size_t salt_len_ = 0;
  std::array<std::uint8_t, 32> digest_{};
};

// Hex helpers (lower-case output; either case accepted on input).
[[nodiscard]] std::string to_hex(std::span<const std::uint8_t> b);
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> from_hex(std::string_view hex);

}  // namespace lle::gw
