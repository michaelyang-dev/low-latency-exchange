#pragma once
// Edge-triggered readiness reactor: epoll on Linux, kqueue on macOS (07 §1 variant (i),
// and the dev-host backend).
//
// Each registered fd has a Readiness record owned by its port (stable address, passed to
// the kernel as the event cookie). poll() ORs the reported events into the record and,
// if the record has a ReadyList, queues it there once. Ports clear bits when a syscall
// shows the condition is gone (EAGAIN, short read), which is the edge-triggered contract:
// a bit stays set until the port has drained the fd.
//
// Wait strategy is the caller's: poll(-1) blocks (interrupt-driven, variant i), poll(0)
// returns at once (spin), poll(t) waits up to t ns. With EPIOCSPARAMS applied to fd()
// (net/busypoll) the same epoll_wait busy-polls NAPI first (variant ii).
#include <cstddef>
#include <cstdint>
#include <memory>

#include "common/assert.h"
#include "common/types.h"
#include "net/common/error.h"
#include "net/common/fd.h"
#include "net/common/fixed_queue.h"

#if defined(__linux__)
#include <sys/epoll.h>
#else
#include <sys/event.h>
#endif

namespace lle::net::sock {

#if defined(__linux__)
using KernelEvent = epoll_event;
#else
using KernelEvent = struct kevent;
#endif

inline constexpr std::uint32_t kReadable = 1u;
inline constexpr std::uint32_t kWritable = 2u;
inline constexpr std::uint32_t kHangup = 4u;
inline constexpr std::uint32_t kErrored = 8u;  // EPOLLERR / EV_ERROR (also: error queue non-empty)

class ReadyList;

struct Readiness {
  std::uint32_t events = 0;    // accumulated k* bits not yet consumed by the owner
  std::uint32_t token = 0;     // owner-defined (slot index)
  std::uint32_t interest = 0;  // kReadable|kWritable currently registered
  bool queued = false;         // on `list` right now
  ReadyList* list = nullptr;   // optional: owner's ready list
};

// Fixed-capacity FIFO of records with pending events (one entry per record at most).
class ReadyList {
 public:
  void init(std::size_t capacity) { q_.init(capacity); }
  void push(Readiness* r) noexcept {
    if (r->queued) return;
    r->queued = true;
    const bool ok = q_.push(r);
    LLE_ASSERT(ok, "ReadyList overflow");
  }
  [[nodiscard]] Readiness* pop() noexcept {
    if (q_.empty()) return nullptr;
    Readiness* r = q_.front();
    q_.pop();
    r->queued = false;
    return r;
  }
  [[nodiscard]] bool empty() const noexcept { return q_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return q_.size(); }

 private:
  FixedQueue<Readiness*> q_;
};

class Poller {
 public:
  Poller() = default;
  Poller(const Poller&) = delete;
  Poller& operator=(const Poller&) = delete;
  ~Poller() = default;

  // Creates the epoll/kqueue instance; `max_events` bounds events per poll() call.
  Result<void> open(std::uint32_t max_events = 64);
  [[nodiscard]] bool is_open() const noexcept { return fd_.valid(); }
  [[nodiscard]] int fd() const noexcept { return fd_.get(); }

  // Registers `fd` edge-triggered for `interest` (kReadable and/or kWritable). Hangup and
  // error conditions are always reported.
  Result<void> add(int fd, std::uint32_t interest, Readiness& r);
  Result<void> modify(int fd, std::uint32_t interest, Readiness& r);
  // Deregisters (closing the fd also does this implicitly).
  void remove(int fd, Readiness& r) noexcept;

  // timeout_ns < 0 blocks, 0 polls, > 0 waits up to that long. Returns the number of
  // events dispatched, 0 on timeout or EINTR, -errno on failure.
  int poll(Nanos timeout_ns) noexcept;

  [[nodiscard]] std::uint64_t polls() const noexcept { return polls_; }
  [[nodiscard]] std::uint64_t events() const noexcept { return events_total_; }

 private:
  UniqueFd fd_;
  std::unique_ptr<KernelEvent[]> evbuf_;
  std::uint32_t max_events_ = 0;
  std::uint64_t polls_ = 0;
  std::uint64_t events_total_ = 0;
};

}  // namespace lle::net::sock
