#pragma once
// Error vocabulary for the network backends (07-networking §2). Setup calls return
// Result<T>; hot-path calls return counts or bools and record failures in stats, so
// nothing on the data path throws or allocates.
#include <cerrno>
#include <expected>
#include <string>

namespace lle::net {

struct Error {
  int code = 0;          // errno value (positive)
  const char* op = "";   // static string naming the failed call, e.g. "bind"
};

template <class T = void>
using Result = std::expected<T, Error>;

[[nodiscard]] inline std::unexpected<Error> fail(const char* op, int code) noexcept {
  return std::unexpected(Error{code, op});
}

// Captures errno right after a failed system call.
[[nodiscard]] inline std::unexpected<Error> fail_errno(const char* op) noexcept { return fail(op, errno); }

// "op: strerror(code)" (cold path: logs, test messages).
std::string to_string(const Error& e);

}  // namespace lle::net
