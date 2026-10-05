#include "net/hwts/socket_ts.h"

#include <sys/socket.h>
#include <sys/uio.h>

#include <cerrno>

#include "net/common/sockopt.h"
#include "net/hwts/cmsg.h"

namespace lle::net::hwts {

std::uint32_t timestamping_flags(const SocketTsRequest& r) noexcept {
  std::uint32_t f = 0;
  if (r.rx == TsMode::Software) f |= abi::kRxSoftware | abi::kSoftware;
  if (r.rx == TsMode::Hardware) f |= abi::kRxHardware | abi::kRawHardware | abi::kRxSoftware | abi::kSoftware;
  if (r.tx != TsMode::Off) {
    f |= r.tx == TsMode::Hardware ? (abi::kTxHardware | abi::kRawHardware) : (abi::kTxSoftware | abi::kSoftware);
    f |= abi::kOptId | abi::kOptTsonly;
    if (r.stream) f |= abi::kOptIdTcp;
  }
  return f;
}

#if defined(__linux__)

Result<std::uint32_t> enable_socket_timestamping(int fd, std::uint32_t flags) {
  auto attempt = [fd](std::uint32_t f) {
    int v = static_cast<int>(f);
    if (::setsockopt(fd, SOL_SOCKET, abi::kSoTimestampingNew, &v, sizeof(v)) == 0) return 0;
    if (::setsockopt(fd, SOL_SOCKET, abi::kSoTimestampingOld, &v, sizeof(v)) == 0) return 0;
    return errno;
  };
  int err = attempt(flags);
  if (err == EINVAL && (flags & abi::kOptIdTcp) != 0) {
    // OPT_ID_TCP needs 6.2; without it TCP keys are relative to snd_una, which is still
    // correct when the option is set before the first byte is sent.
    flags &= ~abi::kOptIdTcp;
    err = attempt(flags);
  }
  if (err != 0) return fail("setsockopt(SO_TIMESTAMPING)", err);
  return flags;
}

Result<std::uint32_t> socket_timestamping_flags(int fd) {
  int v = 0;
  socklen_t len = sizeof(v);
  if (::getsockopt(fd, SOL_SOCKET, abi::kSoTimestampingOld, &v, &len) != 0)
    return fail_errno("getsockopt(SO_TIMESTAMPING)");
  return static_cast<std::uint32_t>(v);
}

#else

Result<std::uint32_t> enable_socket_timestamping(int fd, std::uint32_t flags) {
  // Darwin: software RX only (SO_TIMESTAMP → SCM_TIMESTAMP timeval).
  const std::uint32_t rx_sw = abi::kRxSoftware | abi::kSoftware;
  if ((flags & ~rx_sw) != 0) return fail("setsockopt(SO_TIMESTAMPING)", ENOTSUP);
  if (flags == 0) return flags;
  if (auto r = set_int_option(fd, SOL_SOCKET, SO_TIMESTAMP, 1, "setsockopt(SO_TIMESTAMP)"); !r)
    return std::unexpected(r.error());
  return flags;
}

Result<std::uint32_t> socket_timestamping_flags(int fd) {
  auto v = get_int_option(fd, SOL_SOCKET, SO_TIMESTAMP, "getsockopt(SO_TIMESTAMP)");
  if (!v) return std::unexpected(v.error());
  return *v != 0 ? (abi::kRxSoftware | abi::kSoftware) : 0u;
}

#endif

Result<std::uint32_t> enable_socket_timestamping(int fd, const SocketTsRequest& r) {
  return enable_socket_timestamping(fd, timestamping_flags(r));
}

ErrQueueReader::Status ErrQueueReader::read_one(int fd, TxStamp& out) noexcept {
#if defined(__linux__)
  iovec iov{data_, sizeof(data_)};
  msghdr m{};
  m.msg_iov = &iov;
  m.msg_iovlen = 1;
  m.msg_control = control_;
  m.msg_controllen = sizeof(control_);
  const ssize_t n = ::recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return Status::Empty;
    last_errno_ = errno;
    ++errors_;
    return Status::Error;
  }
  ControlInfo ci{};
  parse_control(m, ci);
  if (!to_tx_stamp(ci, out)) {
    ++others_;
    return Status::Other;
  }
  return Status::Stamp;
#else
  (void)fd;
  (void)out;
  return Status::Empty;
#endif
}

}  // namespace lle::net::hwts
