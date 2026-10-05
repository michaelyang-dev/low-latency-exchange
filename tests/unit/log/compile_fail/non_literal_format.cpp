// Must NOT compile: the format must be a string literal.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f(const char* pattern) { NLOG_INFO(pattern); }
