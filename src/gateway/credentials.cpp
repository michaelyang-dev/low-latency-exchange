#include "gateway/credentials.h"

#include <algorithm>

#include "common/sha256.h"

namespace lle::gw {

namespace {

int hex_digit(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

constexpr std::size_t kMaxPassword = 64;

// Normalizes into `out` without allocating; false if the trimmed text is too long.
bool normalize_into(std::string_view s, std::array<char, kMaxPassword>& out, std::size_t& n) noexcept {
  std::size_t b = 0, e = s.size();
  while (b < e && s[b] == ' ') ++b;
  while (e > b && s[e - 1] == ' ') --e;
  if (e - b > kMaxPassword) return false;
  n = e - b;
  for (std::size_t i = 0; i < n; ++i) {
    const char c = s[b + i];
    out[i] = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
  }
  return true;
}

bool digest_of(std::span<const std::uint8_t> salt, std::string_view password,
               std::array<std::uint8_t, 32>& out) noexcept {
  std::array<char, kMaxPassword> norm{};
  std::size_t n = 0;
  if (!normalize_into(password, norm, n)) return false;
  Sha256 h;
  h.update(salt.data(), salt.size());
  h.update(norm.data(), n);
  out = h.finish();
  return true;
}

}  // namespace

std::string normalize_credential(std::string_view s) {
  std::size_t b = 0, e = s.size();
  while (b < e && s[b] == ' ') ++b;
  while (e > b && s[e - 1] == ' ') --e;
  std::string out(s.substr(b, e - b));
  for (char& c : out) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  return out;
}

std::string to_hex(std::span<const std::uint8_t> b) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (std::uint8_t v : b) {
    s.push_back(kDigits[v >> 4]);
    s.push_back(kDigits[v & 0xF]);
  }
  return s;
}

std::expected<std::vector<std::uint8_t>, std::string> from_hex(std::string_view hex) {
  if (hex.size() % 2 != 0) return std::unexpected(std::string("odd number of hex digits"));
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = hex_digit(hex[i]), lo = hex_digit(hex[i + 1]);
    if (hi < 0 || lo < 0) return std::unexpected(std::string("not a hex digit"));
    out.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
  }
  return out;
}

std::expected<Credential, std::string> Credential::parse(std::string_view text) {
  constexpr std::string_view kScheme = "sha256$";
  if (!text.starts_with(kScheme)) return std::unexpected(std::string("credential must start with sha256$"));
  const std::string_view rest = text.substr(kScheme.size());
  const std::size_t dollar = rest.find('$');
  if (dollar == std::string_view::npos) return std::unexpected(std::string("credential: sha256$<salt>$<digest>"));
  auto salt = from_hex(rest.substr(0, dollar));
  if (!salt) return std::unexpected("credential salt: " + salt.error());
  if (salt->empty() || salt->size() > kMaxSaltBytes)
    return std::unexpected(std::string("credential salt must be 1..32 bytes"));
  auto digest = from_hex(rest.substr(dollar + 1));
  if (!digest) return std::unexpected("credential digest: " + digest.error());
  if (digest->size() != 32) return std::unexpected(std::string("credential digest must be 32 bytes"));
  Credential c;
  std::copy(salt->begin(), salt->end(), c.salt_.begin());
  c.salt_len_ = salt->size();
  std::copy(digest->begin(), digest->end(), c.digest_.begin());
  return c;
}

Credential Credential::make(std::string_view password, std::span<const std::uint8_t> salt) {
  Credential c;
  c.salt_len_ = std::min(salt.size(), kMaxSaltBytes);
  std::copy_n(salt.begin(), c.salt_len_, c.salt_.begin());
  if (c.salt_len_ == 0 || !digest_of(std::span<const std::uint8_t>(c.salt_.data(), c.salt_len_), password, c.digest_)) {
    c.salt_len_ = 0;  // invalid: verify() always fails
  }
  return c;
}

bool Credential::verify(std::string_view password) const noexcept {
  if (salt_len_ == 0) return false;
  std::array<std::uint8_t, 32> d{};
  if (!digest_of(std::span<const std::uint8_t>(salt_.data(), salt_len_), password, d)) return false;
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < d.size(); ++i) diff = static_cast<std::uint8_t>(diff | (d[i] ^ digest_[i]));
  return diff == 0;
}

std::string Credential::text() const {
  return "sha256$" + to_hex(std::span<const std::uint8_t>(salt_.data(), salt_len_)) + "$" + to_hex(digest_);
}

}  // namespace lle::gw
