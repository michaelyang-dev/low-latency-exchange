// Must NOT compile: fewer arguments than {} placeholders.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("a {} b {}", 1); }
