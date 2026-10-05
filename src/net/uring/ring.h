#pragma once
// Variant (iii) reactor: one io_uring per thread (07 §2.2, R3a Q4). Linux only.
//
// Setup: IORING_SETUP_SINGLE_ISSUER | DEFER_TASKRUN | TASKRUN_FLAG | SUBMIT_ALL, the ring
// fd registered with itself (IORING_REGISTER_RING_FDS), a sparse registered-file table
// that ports fill with their sockets (IOSQE_FIXED_FILE), optional CQE32 (needed by
// SOCKET_URING_OP_TX_TIMESTAMP) and optional NAPI busy polling (variant iii-n,
// IORING_REGISTER_NAPI{busy_poll_to, prefer_busy_poll}).
//
// DEFER_TASKRUN runs completions only inside io_uring_enter(GETEVENTS) on the owning
// thread, so the application cannot simply spin on the CQ ring. poll(0) therefore
// enters the kernel whenever SQEs are pending or the kernel has flagged deferred work
// (IORING_SQ_TASKRUN, available because the ring is created with TASKRUN_FLAG), and
// otherwise only reads the CQ ring: an idle spin costs no syscall. poll(t > 0) waits for
// one completion with a timeout; that wait is where io_uring busy-polls NAPI in (iii-n),
// so the (iii-n) loop polls with a positive timeout. poll(-1) blocks.
//
// Several ports share one Ring. Completions are routed by the sink id in the top byte of
// user_data into per-port fixed-capacity queues (Sink), so one port's poll never runs
// another port's callbacks and nothing is allocated per completion. A sink's capacity
// bounds its outstanding operations (provided buffers + TX slots + armed requests).
//
// The Ring must be created on, and only used from, the thread that polls it
// (SINGLE_ISSUER: submissions from another task fail with -EEXIST).
#include <liburing.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "common/assert.h"
#include "common/types.h"
#include "net/common/buffer_arena.h"
#include "net/common/error.h"
#include "net/common/fixed_queue.h"

namespace lle::net::uring {

// Copy of one CQE (16 or 32 bytes on the ring). `big` holds the CQE32 extension.
struct Cqe {
  std::uint64_t user_data = 0;
  std::int32_t res = 0;
  std::uint32_t flags = 0;
  std::uint64_t big[2] = {0, 0};
};

using Sink = FixedQueue<Cqe>;

// user_data layout: [63:56] sink id, [55:48] op, [47:0] port-defined payload. Sink 0
// means "no completion wanted" (e.g. cancellations); the Ring discards those.
inline constexpr std::uint64_t kAuxMask = (std::uint64_t{1} << 48) - 1;
[[nodiscard]] constexpr std::uint64_t make_ud(std::uint8_t sink, std::uint8_t op, std::uint64_t aux) noexcept {
  return (std::uint64_t{sink} << 56) | (std::uint64_t{op} << 48) | (aux & kAuxMask);
}
[[nodiscard]] constexpr std::uint8_t ud_sink(std::uint64_t ud) noexcept { return static_cast<std::uint8_t>(ud >> 56); }
[[nodiscard]] constexpr std::uint8_t ud_op(std::uint64_t ud) noexcept { return static_cast<std::uint8_t>(ud >> 48); }
[[nodiscard]] constexpr std::uint64_t ud_aux(std::uint64_t ud) noexcept { return ud & kAuxMask; }

// Ports put their incarnation (Ring::next_epoch) in aux bits [47:32] and drop CQEs whose
// epoch differs: a completion from a closed port must never reach a later port that
// reuses its sink id (it could hand back a provided buffer of the wrong group).
[[nodiscard]] constexpr std::uint64_t make_aux(std::uint16_t epoch, std::uint32_t payload) noexcept {
  return (std::uint64_t{epoch} << 32) | payload;
}
[[nodiscard]] constexpr std::uint16_t aux_epoch(std::uint64_t ud) noexcept { return static_cast<std::uint16_t>(ud >> 32); }
[[nodiscard]] constexpr std::uint32_t aux_payload(std::uint64_t ud) noexcept { return static_cast<std::uint32_t>(ud); }

struct NapiOptions {
  bool enable = false;
  std::uint32_t busy_poll_us = 50;  // 07 §1 (iii-n)
  bool prefer = true;
};

struct RingConfig {
  std::uint32_t sq_entries = 256;
  std::uint32_t cq_entries = 4096;
  std::uint32_t max_files = 256;  // registered-file table (sparse)
  bool defer_taskrun = true;      // SINGLE_ISSUER|DEFER_TASKRUN (07 §2.2)
  bool register_ring_fd = true;
  bool cqe32 = false;             // required for io_uring TX timestamps
  NapiOptions napi{};
};

struct RingStats {
  std::uint64_t enters = 0;       // io_uring_enter calls made by poll()
  std::uint64_t idle_skips = 0;   // poll(0) calls answered from the CQ ring without a syscall
  std::uint64_t cqes = 0;
  std::uint64_t ignored = 0;      // sink-0 completions (cancellations)
  std::uint64_t dropped = 0;      // sink missing or full: a sizing bug, never expected
  std::uint64_t sq_full = 0;
};

class Ring {
 public:
  static constexpr std::uint8_t kMaxSinks = 255;

  Ring() = default;
  Ring(const Ring&) = delete;
  Ring& operator=(const Ring&) = delete;
  ~Ring() { close(); }

  Result<void> open(const RingConfig& cfg = {});
  void close() noexcept;
  [[nodiscard]] bool is_open() const noexcept { return open_; }

  // Registered files. The returned index is used with IOSQE_FIXED_FILE.
  [[nodiscard]] Result<std::uint32_t> register_file(int fd);
  void unregister_file(std::uint32_t idx) noexcept;

  // Completion routing.
  [[nodiscard]] Result<std::uint8_t> add_sink(Sink& q);
  void remove_sink(std::uint8_t id) noexcept;

  [[nodiscard]] std::uint16_t alloc_buffer_group() noexcept { return next_bgid_++; }
  [[nodiscard]] std::uint16_t next_epoch() noexcept { return ++epoch_; }

  // Next SQE; submits once to make room if the SQ is full. nullptr if still full.
  [[nodiscard]] io_uring_sqe* sqe() noexcept;
  // Submits pending SQEs without waiting (no GETEVENTS). Returns io_uring_submit's result.
  int submit() noexcept;

  // Reactor entry point: < 0 blocks for one completion, 0 never blocks, > 0 waits up to
  // that long. Routes every available CQE to its sink. Returns CQEs routed (>= 0) or
  // -errno on failure (-ETIME/-EINTR are reported as 0).
  int poll(Nanos timeout_ns) noexcept;

  [[nodiscard]] io_uring* raw() noexcept { return &ring_; }
  [[nodiscard]] const RingConfig& config() const noexcept { return cfg_; }
  [[nodiscard]] const RingStats& stats() const noexcept { return stats_; }
  [[nodiscard]] unsigned setup_flags() const noexcept { return setup_flags_; }
  [[nodiscard]] bool cqe32() const noexcept { return (setup_flags_ & IORING_SETUP_CQE32) != 0; }
  [[nodiscard]] bool napi_registered() const noexcept { return napi_; }
  [[nodiscard]] bool ring_fd_registered() const noexcept { return ring_fd_registered_; }
  [[nodiscard]] bool idle_check() const noexcept { return idle_check_; }

 private:
  int route() noexcept;
  [[nodiscard]] bool kernel_work_pending() const noexcept;

  io_uring ring_{};
  RingConfig cfg_{};
  RingStats stats_{};
  std::array<Sink*, 256> sinks_{};
  std::unique_ptr<bool[]> file_used_;
  std::uint32_t files_ = 0;
  unsigned setup_flags_ = 0;
  std::uint16_t next_bgid_ = 1;
  std::uint16_t epoch_ = 0;
  unsigned last_sink_ = 0;  // sink ids rotate so a freed id is not reused at once
  bool open_ = false;
  bool napi_ = false;
  bool ring_fd_registered_ = false;
  bool idle_check_ = false;  // TASKRUN_FLAG set: poll(0) may skip the syscall when idle
};

// A provided-buffer ring (IORING_REGISTER_PBUF_RING) over a BufferArena: the kernel picks
// a buffer per completion (IOSQE_BUFFER_SELECT) and the port hands it back after use.
class ProvidedBuffers {
 public:
  ProvidedBuffers() = default;
  ProvidedBuffers(const ProvidedBuffers&) = delete;
  ProvidedBuffers& operator=(const ProvidedBuffers&) = delete;
  ~ProvidedBuffers() { destroy(); }

  // `count` must be a power of two (≤ 32768).
  Result<void> init(Ring& ring, std::uint32_t count, std::uint32_t size);
  void destroy() noexcept;

  [[nodiscard]] std::uint16_t group() const noexcept { return bgid_; }
  [[nodiscard]] std::uint32_t size() const noexcept { return arena_.buf_size(); }
  [[nodiscard]] std::uint32_t count() const noexcept { return arena_.count(); }
  [[nodiscard]] std::byte* data(std::uint16_t bid) const noexcept { return arena_.data(bid); }

  // Returns buffer `bid` to the kernel; visible after commit().
  void recycle(std::uint16_t bid) noexcept {
    io_uring_buf_ring_add(br_, arena_.data(bid), arena_.buf_size(), bid, mask_, static_cast<int>(pending_));
    ++pending_;
  }
  void commit() noexcept {
    if (pending_ == 0) return;
    io_uring_buf_ring_advance(br_, static_cast<int>(pending_));
    pending_ = 0;
  }

 private:
  Ring* ring_ = nullptr;
  io_uring_buf_ring* br_ = nullptr;
  BufferArena arena_;
  int mask_ = 0;
  std::uint32_t pending_ = 0;
  std::uint16_t bgid_ = 0;
};

// Buffer id carried by a CQE that consumed a provided buffer, or -1.
[[nodiscard]] inline int cqe_buffer_id(const Cqe& c) noexcept {
  return (c.flags & IORING_CQE_F_BUFFER) != 0 ? static_cast<int>(c.flags >> IORING_CQE_BUFFER_SHIFT) : -1;
}
[[nodiscard]] inline bool cqe_more(const Cqe& c) noexcept { return (c.flags & IORING_CQE_F_MORE) != 0; }

}  // namespace lle::net::uring
