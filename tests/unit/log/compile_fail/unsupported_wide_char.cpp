// Must NOT compile: wide characters cannot be logged.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { NLOG_INFO("c {}", L'x'); }
