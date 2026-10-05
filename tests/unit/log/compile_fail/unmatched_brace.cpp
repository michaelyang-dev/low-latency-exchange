// Must NOT compile: a lone closing brace.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("oops }"); }
