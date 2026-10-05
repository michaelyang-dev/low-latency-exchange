// Must NOT compile: a level compiled out by LLE_NLOG_MIN_LEVEL is still format-checked.
#define LLE_NLOG_MIN_LEVEL 3
#include "log/nlog.h"

void f() { NLOG_DEBUG("x {}"); }
