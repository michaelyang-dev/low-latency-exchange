#pragma once
// Small command-line helpers shared by the client programs (mold_replay,
// refclient, loadgen, itch2ouch). Cold path only: parsing at startup and
// writing reports at the end.
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/types.h"
#include "net/common/endpoint.h"

namespace lle::client::cli {

// Walks argv as "--flag value" pairs and bare "--switch" flags.
class Args {
 public:
  Args(int argc, char** argv, const char* prog) : prog_(prog) {
    for (int i = 1; i < argc; ++i) a_.emplace_back(argv[i]);
  }
  [[nodiscard]] bool done() const noexcept { return i_ >= a_.size(); }
  // The next flag name (advances).
  std::string flag() { return a_[i_++]; }
  // The value of the flag just read.
  std::string value() {
    if (i_ >= a_.size()) die("missing value after " + a_[i_ - 1]);
    return a_[i_++];
  }
  std::uint64_t u64() { return parse_u64(value()); }
  std::int64_t i64() {
    const std::string v = value();
    std::int64_t x = 0;
    const auto r = std::from_chars(v.data(), v.data() + v.size(), x);
    if (r.ec != std::errc{} || r.ptr != v.data() + v.size()) die("bad integer: " + v);
    return x;
  }
  net::Endpoint endpoint() { return parse_endpoint_or_die(value()); }
  [[noreturn]] void die(const std::string& msg) const {
    std::fprintf(stderr, "%s: %s\n", prog_, msg.c_str());
    std::exit(2);
  }

  std::uint64_t parse_u64(const std::string& v) const {
    std::uint64_t x = 0;
    int base = 10;
    std::string_view s = v;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
      base = 16;
      s.remove_prefix(2);
    }
    const auto r = std::from_chars(s.data(), s.data() + s.size(), x, base);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) die("bad number: " + v);
    return x;
  }

  net::Endpoint parse_endpoint_or_die(const std::string& v) const {
    // ":port" means 127.0.0.1:port.
    const std::string full = !v.empty() && v[0] == ':' ? "127.0.0.1" + v : v;
    const auto e = net::parse_endpoint(full);
    if (!e) die("bad endpoint (a.b.c.d:port): " + v);
    return *e;
  }

 private:
  const char* prog_;
  std::vector<std::string> a_;
  std::size_t i_ = 0;
};

// "1.25" -> parts per million (fraction 0..1) or "2%" -> 20000 ppm.
[[nodiscard]] inline std::optional<std::uint32_t> parse_ppm(std::string_view s) {
  bool pct = false;
  if (!s.empty() && s.back() == '%') {
    pct = true;
    s.remove_suffix(1);
  }
  // Fixed-point parse with up to 6 fractional digits (no floating point).
  std::uint64_t whole = 0, frac = 0, scale = 1;
  std::size_t i = 0;
  for (; i < s.size() && s[i] != '.'; ++i) {
    if (s[i] < '0' || s[i] > '9') return std::nullopt;
    whole = whole * 10 + static_cast<std::uint64_t>(s[i] - '0');
    if (whole > 1'000'000) return std::nullopt;
  }
  if (i < s.size()) {
    for (++i; i < s.size(); ++i) {
      if (s[i] < '0' || s[i] > '9') return std::nullopt;
      if (scale < 100'000'000) {
        frac = frac * 10 + static_cast<std::uint64_t>(s[i] - '0');
        scale *= 10;
      }
    }
  }
  const std::uint64_t unit = pct ? 10'000 : 1'000'000;  // ppm per 1.0 of the input
  const std::uint64_t ppm = whole * unit + frac * unit / scale;
  if (ppm > 1'000'000) return std::nullopt;
  return static_cast<std::uint32_t>(ppm);
}

// "250us", "10ms", "2s", "500ns", or a bare number of nanoseconds.
[[nodiscard]] inline std::optional<Nanos> parse_duration(std::string_view s) {
  std::uint64_t mult = 1;
  if (s.ends_with("ns")) {
    s.remove_suffix(2);
  } else if (s.ends_with("us")) {
    mult = 1'000;
    s.remove_suffix(2);
  } else if (s.ends_with("ms")) {
    mult = 1'000'000;
    s.remove_suffix(2);
  } else if (s.ends_with("s")) {
    mult = 1'000'000'000;
    s.remove_suffix(1);
  }
  std::uint64_t v = 0;
  const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
  if (r.ec != std::errc{} || r.ptr != s.data() + s.size() || s.empty()) return std::nullopt;
  return static_cast<Nanos>(v * mult);
}

// "12.3456" -> PxE4 (4 implied decimals).
[[nodiscard]] inline std::optional<PxE4> parse_price(std::string_view s) {
  PxE4 whole = 0, frac = 0;
  int digits = 0;
  std::size_t i = 0;
  if (s.empty()) return std::nullopt;
  for (; i < s.size() && s[i] != '.'; ++i) {
    if (s[i] < '0' || s[i] > '9') return std::nullopt;
    whole = whole * 10 + (s[i] - '0');
    if (whole > 1'000'000'000) return std::nullopt;
  }
  if (i < s.size()) {
    for (++i; i < s.size(); ++i) {
      if (s[i] < '0' || s[i] > '9' || digits == 4) return std::nullopt;
      frac = frac * 10 + (s[i] - '0');
      ++digits;
    }
  }
  for (; digits < 4; ++digits) frac *= 10;
  return whole * kPxScale + frac;
}

// Comma-separated list of unsigned numbers.
[[nodiscard]] inline std::vector<std::uint64_t> parse_u64_list(const Args& a, const std::string& v) {
  std::vector<std::uint64_t> out;
  std::size_t start = 0;
  while (start <= v.size()) {
    const std::size_t comma = v.find(',', start);
    const std::string item = v.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
    if (!item.empty()) out.push_back(a.parse_u64(item));
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  return out;
}

}  // namespace lle::client::cli
