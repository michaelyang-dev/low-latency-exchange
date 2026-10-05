#include "net/sock/poller.h"

#include <fcntl.h>
#include <time.h>

#include <cerrno>

namespace lle::net::sock {

namespace {
timespec to_timespec(Nanos ns) noexcept {
  timespec ts{};
  ts.tv_sec = static_cast<time_t>(ns / kNsPerSec);
  ts.tv_nsec = static_cast<long>(ns % kNsPerSec);
  return ts;
}
}  // namespace

#if defined(__linux__)

namespace {
constexpr std::uint32_t ev(EPOLL_EVENTS e) noexcept { return static_cast<std::uint32_t>(e); }

std::uint32_t to_epoll(std::uint32_t interest) noexcept {
  std::uint32_t e = ev(EPOLLET);
  if ((interest & kReadable) != 0) e |= ev(EPOLLIN) | ev(EPOLLRDHUP);
  if ((interest & kWritable) != 0) e |= ev(EPOLLOUT);
  return e;
}
}  // namespace

Result<void> Poller::open(std::uint32_t max_events) {
  if (is_open()) return fail("Poller::open", EALREADY);
  if (max_events == 0) return fail("Poller::open", EINVAL);
  fd_.reset(::epoll_create1(EPOLL_CLOEXEC));
  if (!fd_) return fail_errno("epoll_create1");
  evbuf_ = std::make_unique<KernelEvent[]>(max_events);
  max_events_ = max_events;
  return {};
}

Result<void> Poller::add(int fd, std::uint32_t interest, Readiness& r) {
  epoll_event e{};
  e.events = to_epoll(interest);
  e.data.ptr = &r;
  if (::epoll_ctl(fd_.get(), EPOLL_CTL_ADD, fd, &e) != 0) return fail_errno("epoll_ctl(ADD)");
  r.interest = interest;
  return {};
}

Result<void> Poller::modify(int fd, std::uint32_t interest, Readiness& r) {
  epoll_event e{};
  e.events = to_epoll(interest);
  e.data.ptr = &r;
  if (::epoll_ctl(fd_.get(), EPOLL_CTL_MOD, fd, &e) != 0) return fail_errno("epoll_ctl(MOD)");
  r.interest = interest;
  return {};
}

void Poller::remove(int fd, Readiness& r) noexcept {
  epoll_event e{};
  (void)::epoll_ctl(fd_.get(), EPOLL_CTL_DEL, fd, &e);
  r.interest = 0;
}

int Poller::poll(Nanos timeout_ns) noexcept {
  ++polls_;
  int n;
  const int max = static_cast<int>(max_events_);
  if (timeout_ns <= 0) {
    n = ::epoll_wait(fd_.get(), evbuf_.get(), max, timeout_ns < 0 ? -1 : 0);
  } else {
    const timespec ts = to_timespec(timeout_ns);
    n = ::epoll_pwait2(fd_.get(), evbuf_.get(), max, &ts, nullptr);
  }
  if (n < 0) return errno == EINTR ? 0 : -errno;
  for (int i = 0; i < n; ++i) {
    const epoll_event& e = evbuf_[static_cast<std::size_t>(i)];
    auto* r = static_cast<Readiness*>(e.data.ptr);
    std::uint32_t bits = 0;
    if ((e.events & ev(EPOLLIN)) != 0) bits |= kReadable;
    if ((e.events & ev(EPOLLOUT)) != 0) bits |= kWritable;
    if ((e.events & (ev(EPOLLHUP) | ev(EPOLLRDHUP))) != 0) bits |= kHangup;
    if ((e.events & ev(EPOLLERR)) != 0) bits |= kErrored;
    r->events |= bits;
    if (r->list != nullptr) r->list->push(r);
  }
  events_total_ += static_cast<std::uint64_t>(n);
  return n;
}

#else  // kqueue

namespace {
struct kevent make_kev(int fd, int filter, unsigned flags, Readiness* r) noexcept {
  struct kevent k{};
  k.ident = static_cast<uintptr_t>(fd);
  k.filter = static_cast<std::int16_t>(filter);
  k.flags = static_cast<std::uint16_t>(flags);
  k.udata = r;
  return k;
}

// Applies the filter changes needed to go from `from` to `to` interest.
int change(int kq, int fd, std::uint32_t from, std::uint32_t to, Readiness* r) noexcept {
  struct kevent ch[2];
  int n = 0;
  const unsigned add = EV_ADD | EV_CLEAR;  // EV_CLEAR = edge-triggered
  if ((to & kReadable) != 0 && (from & kReadable) == 0) ch[n++] = make_kev(fd, EVFILT_READ, add, r);
  if ((to & kReadable) == 0 && (from & kReadable) != 0) ch[n++] = make_kev(fd, EVFILT_READ, EV_DELETE, r);
  if ((to & kWritable) != 0 && (from & kWritable) == 0) ch[n++] = make_kev(fd, EVFILT_WRITE, add, r);
  if ((to & kWritable) == 0 && (from & kWritable) != 0) ch[n++] = make_kev(fd, EVFILT_WRITE, EV_DELETE, r);
  if (n == 0) return 0;
  return ::kevent(kq, ch, n, nullptr, 0, nullptr);
}
}  // namespace

Result<void> Poller::open(std::uint32_t max_events) {
  if (is_open()) return fail("Poller::open", EALREADY);
  if (max_events == 0) return fail("Poller::open", EINVAL);
  fd_.reset(::kqueue());
  if (!fd_) return fail_errno("kqueue");
  if (::fcntl(fd_.get(), F_SETFD, FD_CLOEXEC) != 0) return fail_errno("fcntl(FD_CLOEXEC)");
  evbuf_ = std::make_unique<KernelEvent[]>(max_events);
  max_events_ = max_events;
  return {};
}

Result<void> Poller::add(int fd, std::uint32_t interest, Readiness& r) {
  if (change(fd_.get(), fd, 0, interest, &r) != 0) return fail_errno("kevent(EV_ADD)");
  r.interest = interest;
  return {};
}

Result<void> Poller::modify(int fd, std::uint32_t interest, Readiness& r) {
  if (change(fd_.get(), fd, r.interest, interest, &r) != 0) return fail_errno("kevent(modify)");
  r.interest = interest;
  return {};
}

void Poller::remove(int fd, Readiness& r) noexcept {
  (void)change(fd_.get(), fd, r.interest, 0, &r);
  r.interest = 0;
}

int Poller::poll(Nanos timeout_ns) noexcept {
  ++polls_;
  timespec ts = to_timespec(timeout_ns < 0 ? 0 : timeout_ns);
  const int n =
      ::kevent(fd_.get(), nullptr, 0, evbuf_.get(), static_cast<int>(max_events_), timeout_ns < 0 ? nullptr : &ts);
  if (n < 0) return errno == EINTR ? 0 : -errno;
  for (int i = 0; i < n; ++i) {
    const struct kevent& k = evbuf_[static_cast<std::size_t>(i)];
    auto* r = static_cast<Readiness*>(k.udata);
    std::uint32_t bits = 0;
    if (k.filter == EVFILT_READ) bits |= kReadable;
    if (k.filter == EVFILT_WRITE) bits |= kWritable;
    if ((k.flags & EV_EOF) != 0) bits |= kHangup;
    if ((k.flags & EV_ERROR) != 0) bits |= kErrored;
    r->events |= bits;
    if (r->list != nullptr) r->list->push(r);
  }
  events_total_ += static_cast<std::uint64_t>(n);
  return n;
}

#endif

}  // namespace lle::net::sock
