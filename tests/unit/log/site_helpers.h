#pragma once
// Call sites defined outside site_test.cpp: an inline function used from two
// TUs (its site must be emitted once) and a TU compiled with
// LLE_NLOG_MIN_LEVEL=2 (DEBUG/INFO compiled out).
#include "log/nlog.h"

namespace lle::nlog::test {

inline void log_from_inline_function() { NLOG_INFO("inline-site-dedup {}", 7); }

void call_inline_from_a();
void call_inline_from_b();

// Defined in site_mixed.cpp: the inline site above and a plain one in one TU.
void log_from_mixed_tu();

// Defined in site_filtered.cpp (LLE_NLOG_MIN_LEVEL=2).
void log_filtered_levels();
int filtered_side_effects();

}  // namespace lle::nlog::test
