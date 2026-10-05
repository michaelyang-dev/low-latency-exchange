// Must NOT compile: pointers other than char pointers cannot be logged.
#include <string>
#include <string_view>

#include "log/nlog.h"

void f() { int x = 0; NLOG_INFO("p {}", &x); }
