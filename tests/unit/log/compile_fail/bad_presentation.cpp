// Must NOT compile: {:f} on a string argument.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("{:f}", std::string_view{"x"}); }
