// Must NOT compile: positional fields are not supported.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("{0}", 1); }
