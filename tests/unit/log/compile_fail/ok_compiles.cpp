// Positive control for the compile-fail harness: must compile with the same flags.
#include <cstdint>
#include <string>
#include <string_view>

#include "log/nlog.h"

enum class Side : char { kBuy = 'B' };

void f(std::uint64_t ref, std::int64_t px, std::uint32_t qty, const std::string& s, const char* c) {
  NLOG_INFO("order {} accepted px {} qty {} side {}", ref, px, qty, Side::kBuy);
  NLOG_WARN("{:#x} {:>8.2f} {:c} {:s} {{}} {}", qty, 1.5, 'c', true, s);
  NLOG_ERROR("plain");
  NLOG_DEBUG("{} {}", c, std::string_view{"v"});
  NLOG_EV(ref, "ev {} {} {} {} {} {} {} {}", 1, 2u, 3l, 4ul, short{5}, static_cast<signed char>(6), 7.0f, false);
}
