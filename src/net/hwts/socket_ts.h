#pragma once
// Per-socket timestamping (SO_TIMESTAMPING) and the error-queue TX timestamp reader
// (07 §2.5, R3a §3.1/§3.3).
//
// Linux: SO_TIMESTAMPING_NEW (falls back to _OLD), RX via cmsgs, TX via MSG_ERRQUEUE.
// macOS: only software RX timestamps (SO_TIMESTAMP); TX requests return ENOTSUP.
#include <cstddef>
#include <cstdint>

#include "net/common/error.h"
#include "net/common/timestamps.h"
#include "net/hwts/abi.h"

namespace lle::net::hwts {

struct SocketTsRequest {
  TsMode rx = TsMode::Off;
  TsMode tx = TsMode::Off;
  bool stream = false;  // TCP: adds OPT_ID_TCP so keys count bytes from write_seq
};

// SOF_TIMESTAMPING_* flags for a request:
//   RX Software  RX_SOFTWARE|SOFTWARE
//   RX Hardware  RX_HARDWARE|RAW_HARDWARE plus the software pair, so a missing HW stamp is
//                visible as a software one (counted, invalidating, 07 §2.5)
//   TX Software  TX_SOFTWARE|SOFTWARE|OPT_ID|OPT_TSONLY (+OPT_ID_TCP)
//   TX Hardware  TX_HARDWARE|RAW_HARDWARE|OPT_ID|OPT_TSONLY (+OPT_ID_TCP)
// OPT_TSONLY keeps payload copies out of the error queue and is required by io_uring's
// SOCKET_URING_OP_TX_TIMESTAMP.
[[nodiscard]] std::uint32_t timestamping_flags(const SocketTsRequest& r) noexcept;

// setsockopt(SO_TIMESTAMPING_NEW, flags), falling back to SO_TIMESTAMPING_OLD and, on
// pre-6.2 kernels, to dropping OPT_ID_TCP. Returns the flags actually set.
[[nodiscard]] Result<std::uint32_t> enable_socket_timestamping(int fd, std::uint32_t flags);
[[nodiscard]] Result<std::uint32_t> enable_socket_timestamping(int fd, const SocketTsRequest& r);

// getsockopt(SO_TIMESTAMPING) read-back.
[[nodiscard]] Result<std::uint32_t> socket_timestamping_flags(int fd);

// Reads TX timestamps from a socket's error queue (recvmsg(MSG_ERRQUEUE), non-blocking).
// The buffers are members: no allocation per read. Not thread-safe; one per reader.
class ErrQueueReader {
 public:
  enum class Status : std::uint8_t { Stamp, Other, Empty, Error };

  Status read_one(int fd, TxStamp& out) noexcept;

  // Reads up to `max` messages; calls cb(const TxStamp&) per timestamp. Returns the
  // number of timestamps delivered.
  template <class F>
  std::size_t drain(int fd, F&& cb, std::size_t max = 64) noexcept {
    std::size_t n = 0;
    for (std::size_t i = 0; i < max; ++i) {
      TxStamp s{};
      const Status st = read_one(fd, s);
      if (st == Status::Stamp) {
        cb(static_cast<const TxStamp&>(s));
        ++n;
      } else if (st != Status::Other) {
        break;
      }
    }
    return n;
  }

  [[nodiscard]] std::uint64_t others() const noexcept { return others_; }
  [[nodiscard]] std::uint64_t errors() const noexcept { return errors_; }
  [[nodiscard]] int last_errno() const noexcept { return last_errno_; }

 private:
  alignas(16) std::byte control_[512]{};
  std::byte data_[256]{};
  std::uint64_t others_ = 0;
  std::uint64_t errors_ = 0;
  int last_errno_ = 0;
};

}  // namespace lle::net::hwts
