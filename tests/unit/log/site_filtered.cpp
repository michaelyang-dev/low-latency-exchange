// Compiled with LLE_NLOG_MIN_LEVEL=2 (see CMakeLists.txt): DEBUG and INFO sites
// are compiled out, their arguments are not evaluated and they do not appear in
// the nlog section; WARN and ERROR remain.
#include "site_helpers.h"

#if LLE_NLOG_MIN_LEVEL != 2
#error "site_filtered.cpp must be compiled with LLE_NLOG_MIN_LEVEL=2"
#endif

namespace lle::nlog::test {
// External linkage: with internal linkage clang notes that the function is "not
// needed" because its only uses are in compiled-out (unevaluated) calls.
int g_side_effects = 0;
int side_effect();
int side_effect() { return ++g_side_effects; }

void log_filtered_levels() {
  NLOG_DEBUG("filtered-debug-site {}", side_effect());
  NLOG_INFO("filtered-info-site {}", side_effect());
  NLOG_EV(123, "filtered-ev-site {}", side_effect());
  NLOG_WARN("filtered-warn-site {}", 1);
  NLOG_ERROR("filtered-error-site");
}

int filtered_side_effects() { return g_side_effects; }

}  // namespace lle::nlog::test
