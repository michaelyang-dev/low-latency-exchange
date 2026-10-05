#pragma once
// LLE_ASSERT: always on (tests, simulator, release). Used for invariants whose
// violation means state is corrupt; cost is a predictable branch.
// LLE_DASSERT: debug-only.
#include <source_location>

namespace lle {
[[noreturn]] void assert_fail(const char* expr, const char* msg, std::source_location loc) noexcept;
}

#define LLE_ASSERT(cond, ...)                                                                  \
  do {                                                                                         \
    if (!(cond)) [[unlikely]]                                                                  \
      ::lle::assert_fail(#cond, "" __VA_ARGS__, std::source_location::current());              \
  } while (0)

#ifndef NDEBUG
#define LLE_DASSERT(cond, ...) LLE_ASSERT(cond, __VA_ARGS__)
#else
#define LLE_DASSERT(cond, ...) \
  do {                         \
  } while (0)
#endif

#define LLE_UNREACHABLE(msg) ::lle::assert_fail("unreachable", msg, std::source_location::current())
