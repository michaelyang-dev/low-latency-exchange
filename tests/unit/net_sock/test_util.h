#pragma once
// Helpers for socket tests: bounded event pumping (no sleeps; blocking waits on the
// reactor with a per-iteration timeout and an iteration cap).
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "common/types.h"

namespace lle::net::test {

inline constexpr Nanos kWaitSlice = 20'000'000;  // 20 ms per reactor wait
inline constexpr int kMaxIters = 250;            // ~5 s worst case before a test fails

inline std::span<const std::byte> bytes(std::string_view s) noexcept {
  return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

inline std::string str(std::span<const std::byte> b) {
  return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

// Calls step() until done() or the iteration cap; step() is expected to block briefly
// (e.g. Poller::poll(kWaitSlice)). Returns done().
template <class Step, class Done>
bool pump_until(Step&& step, Done&& done, int max_iters = kMaxIters) {
  for (int i = 0; i < max_iters && !done(); ++i) step();
  return done();
}

}  // namespace lle::net::test
