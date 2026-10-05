// Must NOT compile: more arguments than {} placeholders.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("a {}", 1, 2); }
