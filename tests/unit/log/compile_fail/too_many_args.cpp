// Must NOT compile: more than 8 arguments.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("{} {} {} {} {} {} {} {} {}", 1, 2, 3, 4, 5, 6, 7, 8, 9); }
