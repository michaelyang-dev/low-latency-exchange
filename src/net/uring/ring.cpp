#include "net/uring/ring.h"

#include <cerrno>
#include <cstring>

namespace lle::net::uring {

Result<void> Ring::open(const RingConfig& cfg) {
  if (open_) return fail("Ring::open", EALREADY);
  if (cfg.sq_entries == 0 || cfg.cq_entries < cfg.sq_entries || cfg.max_files == 0) return fail("Ring::open", EINVAL);
  cfg_ = cfg;
  io_uring_params p{};
  unsigned flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE;
  if (cfg.defer_taskrun) {
    flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
  } else {
    flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
  }
  if (cfg.cqe32) flags |= IORING_SETUP_CQE32;
  p.flags = flags;
  p.cq_entries = cfg.cq_entries;
  int rc = io_uring_queue_init_params(cfg.sq_entries, &ring_, &p);
  if (rc == -EINVAL) {
    // Older kernels: retry without TASKRUN_FLAG (poll(0) then always enters).
    p = io_uring_params{};
    p.flags = flags & ~IORING_SETUP_TASKRUN_FLAG;
    p.cq_entries = cfg.cq_entries;
    rc = io_uring_queue_init_params(cfg.sq_entries, &ring_, &p);
  }
  if (rc < 0) return fail("io_uring_queue_init_params", -rc);
  open_ = true;
  setup_flags_ = ring_.flags;
  idle_check_ = (setup_flags_ & IORING_SETUP_TASKRUN_FLAG) != 0;

  if (cfg.register_ring_fd) {
    rc = io_uring_register_ring_fd(&ring_);
    if (rc < 0) {
      close();
      return fail("io_uring_register_ring_fd", -rc);
    }
    ring_fd_registered_ = true;
  }
  rc = io_uring_register_files_sparse(&ring_, cfg.max_files);
  if (rc < 0) {
    close();
    return fail("io_uring_register_files_sparse", -rc);
  }
  file_used_ = std::make_unique<bool[]>(cfg.max_files);
  files_ = cfg.max_files;
  if (cfg.napi.enable) {
    io_uring_napi n{};
    n.busy_poll_to = cfg.napi.busy_poll_us;
    n.prefer_busy_poll = cfg.napi.prefer ? 1 : 0;
    rc = io_uring_register_napi(&ring_, &n);
    if (rc < 0) {
      close();
      return fail("io_uring_register_napi", -rc);
    }
    napi_ = true;
  }
  return {};
}

void Ring::close() noexcept {
  if (!open_) return;
  if (napi_) {
    io_uring_napi n{};
    (void)io_uring_unregister_napi(&ring_, &n);
    napi_ = false;
  }
  io_uring_queue_exit(&ring_);
  open_ = false;
  ring_fd_registered_ = false;
  sinks_.fill(nullptr);
  file_used_.reset();
  files_ = 0;
}

Result<std::uint32_t> Ring::register_file(int fd) {
  for (std::uint32_t i = 0; i < files_; ++i) {
    if (file_used_[i]) continue;
    int f = fd;
    const int rc = io_uring_register_files_update(&ring_, i, &f, 1);
    if (rc < 0) return fail("io_uring_register_files_update", -rc);
    file_used_[i] = true;
    return i;
  }
  return fail("io_uring_register_files_update", ENFILE);
}

void Ring::unregister_file(std::uint32_t idx) noexcept {
  if (idx >= files_ || !file_used_[idx]) return;
  int none = -1;
  (void)io_uring_register_files_update(&ring_, idx, &none, 1);
  file_used_[idx] = false;
}

Result<std::uint8_t> Ring::add_sink(Sink& q) {
  for (unsigned i = 0; i < kMaxSinks; ++i) {
    const unsigned id = (last_sink_ + i) % kMaxSinks + 1;
    if (sinks_[id] == nullptr) {
      sinks_[id] = &q;
      last_sink_ = id;
      return static_cast<std::uint8_t>(id);
    }
  }
  return fail("Ring::add_sink", ENOSPC);
}

void Ring::remove_sink(std::uint8_t id) noexcept {
  if (id != 0) sinks_[id] = nullptr;
}

io_uring_sqe* Ring::sqe() noexcept {
  io_uring_sqe* s = io_uring_get_sqe(&ring_);
  if (s != nullptr) return s;
  ++stats_.sq_full;
  (void)io_uring_submit(&ring_);
  return io_uring_get_sqe(&ring_);
}

int Ring::submit() noexcept {
  if (io_uring_sq_ready(&ring_) == 0) return 0;
  ++stats_.enters;
  return io_uring_submit(&ring_);
}

bool Ring::kernel_work_pending() const noexcept {
  // IORING_SQ_TASKRUN: deferred completions are waiting for GETEVENTS (TASKRUN_FLAG);
  // IORING_SQ_CQ_OVERFLOW: completions spilled into the overflow list.
  const unsigned f = __atomic_load_n(ring_.sq.kflags, __ATOMIC_ACQUIRE);
  return (f & (IORING_SQ_TASKRUN | IORING_SQ_CQ_OVERFLOW)) != 0;
}

int Ring::poll(Nanos timeout_ns) noexcept {
  int rc = 0;
  if (timeout_ns == 0) {
    if (io_uring_sq_ready(&ring_) > 0 || !idle_check_ || kernel_work_pending()) {
      ++stats_.enters;
      rc = io_uring_submit_and_get_events(&ring_);
    } else if (io_uring_cq_ready(&ring_) == 0) {
      ++stats_.idle_skips;
      return 0;
    }
  } else if (timeout_ns < 0) {
    ++stats_.enters;
    rc = io_uring_submit_and_wait(&ring_, 1);
  } else {
    __kernel_timespec ts{};
    ts.tv_sec = timeout_ns / kNsPerSec;
    ts.tv_nsec = timeout_ns % kNsPerSec;
    io_uring_cqe* unused = nullptr;
    ++stats_.enters;
    rc = io_uring_submit_and_wait_timeout(&ring_, &unused, 1, &ts, nullptr);
  }
  if (rc < 0 && rc != -ETIME && rc != -EINTR && rc != -EAGAIN && rc != -EBUSY) return rc;
  return route();
}

int Ring::route() noexcept {
  unsigned head = 0;
  unsigned n = 0;
  io_uring_cqe* cqe = nullptr;
  const bool big = cqe32();
  io_uring_for_each_cqe(&ring_, head, cqe) {
    Cqe c;
    c.user_data = cqe->user_data;
    c.res = cqe->res;
    c.flags = cqe->flags;
    if (big) std::memcpy(c.big, cqe->big_cqe, sizeof(c.big));
    const std::uint8_t id = ud_sink(c.user_data);
    if (id == 0) {
      ++stats_.ignored;
    } else if (sinks_[id] == nullptr || !sinks_[id]->push(c)) {
      ++stats_.dropped;
    }
    ++n;
  }
  io_uring_cq_advance(&ring_, n);
  stats_.cqes += n;
  return static_cast<int>(n);
}

Result<void> ProvidedBuffers::init(Ring& ring, std::uint32_t count, std::uint32_t size) {
  if (br_ != nullptr) return fail("ProvidedBuffers::init", EALREADY);
  if (count == 0 || count > 32768 || (count & (count - 1)) != 0 || size == 0) return fail("ProvidedBuffers::init", EINVAL);
  if (auto r = arena_.init(count, size, 4096); !r) return r;
  bgid_ = ring.alloc_buffer_group();
  int err = 0;
  br_ = io_uring_setup_buf_ring(ring.raw(), count, bgid_, 0, &err);
  if (br_ == nullptr) return fail("io_uring_setup_buf_ring", err < 0 ? -err : EINVAL);
  ring_ = &ring;
  mask_ = io_uring_buf_ring_mask(count);
  for (std::uint32_t i = 0; i < count; ++i) recycle(static_cast<std::uint16_t>(i));
  commit();
  return {};
}

void ProvidedBuffers::destroy() noexcept {
  if (br_ == nullptr) return;
  if (ring_ != nullptr && ring_->is_open()) (void)io_uring_free_buf_ring(ring_->raw(), br_, arena_.count(), bgid_);
  br_ = nullptr;
  ring_ = nullptr;
}

}  // namespace lle::net::uring
