#include "common/assert.h"

#include <cstdio>
#include <cstdlib>

namespace lle {

void assert_fail(const char* expr, const char* msg, std::source_location loc) noexcept {
  std::fprintf(stderr, "LLE_ASSERT failed: %s %s\n  at %s:%u (%s)\n", expr, msg, loc.file_name(),
               static_cast<unsigned>(loc.line()), loc.function_name());
  std::fflush(stderr);
  std::abort();
}

}  // namespace lle
