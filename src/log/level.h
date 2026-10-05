#pragma once
// nlog severity levels (11-logging-observability §1). Levels below
// LLE_NLOG_MIN_LEVEL are removed at compile time: the call site's arguments are
// not evaluated and no site is emitted into the linker section, but the format
// string is still checked against the arguments.
#include <cstdint>
#include <optional>
#include <string_view>

#ifndef LLE_NLOG_MIN_LEVEL
#ifdef NDEBUG
#define LLE_NLOG_MIN_LEVEL 1  // INFO and above in optimized builds
#else
#define LLE_NLOG_MIN_LEVEL 0  // everything in debug builds
#endif
#endif

namespace lle::nlog {

enum class Level : std::uint8_t { kDebug = 0, kInfo = 1, kWarn = 2, kError = 3 };
inline constexpr std::uint8_t kLevelCount = 4;

[[nodiscard]] constexpr std::string_view level_name(std::uint8_t level) noexcept {
  switch (level) {
    case 0: return "DEBUG";
    case 1: return "INFO";
    case 2: return "WARN";
    case 3: return "ERROR";
    default: return "L?";
  }
}
[[nodiscard]] constexpr std::string_view level_name(Level level) noexcept {
  return level_name(static_cast<std::uint8_t>(level));
}

// Accepts "debug", "info", "warn"/"warning", "error" (lower or upper case).
[[nodiscard]] constexpr std::optional<Level> parse_level(std::string_view s) noexcept {
  auto eq = [](std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
      char c = a[i];
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
      if (c != b[i]) return false;
    }
    return true;
  };
  if (eq(s, "debug")) return Level::kDebug;
  if (eq(s, "info")) return Level::kInfo;
  if (eq(s, "warn") || eq(s, "warning")) return Level::kWarn;
  if (eq(s, "error")) return Level::kError;
  return std::nullopt;
}

}  // namespace lle::nlog
