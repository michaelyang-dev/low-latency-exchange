#include "net/common/port.h"

namespace lle::net {

const char* to_string(BackendKind k) noexcept {
  switch (k) {
    case BackendKind::Epoll: return "epoll";
    case BackendKind::BusyPoll: return "busypoll";
    case BackendKind::Uring: return "uring";
    case BackendKind::UringNapi: return "uring-napi";
    case BackendKind::Xsk: return "xsk";
  }
  return "?";
}

std::optional<BackendKind> parse_backend(std::string_view s) noexcept {
  if (s == "epoll" || s == "sock" || s == "kqueue") return BackendKind::Epoll;
  if (s == "busypoll") return BackendKind::BusyPoll;
  if (s == "uring") return BackendKind::Uring;
  if (s == "uring-napi") return BackendKind::UringNapi;
  if (s == "xsk") return BackendKind::Xsk;
  return std::nullopt;
}

bool backend_compiled(BackendKind k) noexcept {
  switch (k) {
    case BackendKind::Epoll: return true;
#if defined(__linux__)
    case BackendKind::BusyPoll: return true;
#if defined(LLE_HAVE_LIBURING)
    case BackendKind::Uring:
    case BackendKind::UringNapi: return true;
#endif
#endif
    default: return false;
  }
}

}  // namespace lle::net
