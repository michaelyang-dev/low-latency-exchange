#include "outlog/day.h"

#include <format>

namespace lle::outlog {

namespace detail {

bool plausible_day(std::uint32_t day) noexcept {
  const std::uint32_t year = day / 10'000;
  const std::uint32_t month = day / 100 % 100;
  const std::uint32_t dom = day % 100;
  return year >= 1 && year <= 9'999 && month >= 1 && month <= 12 && dom >= 1 && dom <= 31;
}

}  // namespace detail

std::string OutlogDayPaths::day_dir(const std::string& root, std::uint32_t day) {
  return std::format("{}/{:08}", root, day);
}

std::string OutlogDayPaths::itch_path(const std::string& root, std::uint32_t day) {
  return std::format("{}/{:08}/itch.bin", root, day);
}

std::string OutlogDayPaths::soup_path(const std::string& root, std::uint32_t day, std::uint32_t session_id) {
  return std::format("{}/{:08}/soup-{:06}.bin", root, day, session_id);
}

template class BasicOutlogDay<PosixFs>;

}  // namespace lle::outlog
