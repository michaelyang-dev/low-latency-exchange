// Must NOT compile: class types cannot be logged.
#include <string>
#include <string_view>

#include "log/nlog.h"

struct S {}; void f() { NLOG_INFO("s {}", S{}); }
