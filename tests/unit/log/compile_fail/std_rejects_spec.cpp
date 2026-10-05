// Must NOT compile: precision on an integer passes the type check but std::format rejects it.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("{:.3d}", 1); }
