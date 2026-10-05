#include "net/hwts/cmsg.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>

#if defined(__linux__)
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

// The portable constants must match this platform's UAPI.
static_assert(lle::net::hwts::abi::kSolSocket == SOL_SOCKET);
static_assert(lle::net::hwts::abi::kSolIp == SOL_IP);
static_assert(lle::net::hwts::abi::kSolIpv6 == SOL_IPV6);
static_assert(lle::net::hwts::abi::kSoTimestampingOld == SO_TIMESTAMPING_OLD);
static_assert(lle::net::hwts::abi::kSoTimestampingNew == SO_TIMESTAMPING_NEW);
static_assert(lle::net::hwts::abi::kSoTimestampnsOld == SO_TIMESTAMPNS_OLD);
static_assert(lle::net::hwts::abi::kSoTimestampnsNew == SO_TIMESTAMPNS_NEW);
static_assert(lle::net::hwts::abi::kIpPktinfo == IP_PKTINFO);
static_assert(lle::net::hwts::abi::kIpRecverr == IP_RECVERR);
static_assert(lle::net::hwts::abi::kIpv6Recverr == IPV6_RECVERR);
static_assert(lle::net::hwts::abi::kEnomsg == ENOMSG);
static_assert(lle::net::hwts::abi::kSoEeOriginTimestamping == SO_EE_ORIGIN_TIMESTAMPING);
static_assert(lle::net::hwts::abi::kTstampSnd == SCM_TSTAMP_SND);
static_assert(lle::net::hwts::abi::kTstampSched == SCM_TSTAMP_SCHED);
static_assert(lle::net::hwts::abi::kTstampAck == SCM_TSTAMP_ACK);
static_assert(lle::net::hwts::abi::kOptIdTcp == SOF_TIMESTAMPING_OPT_ID_TCP);
static_assert(lle::net::hwts::abi::kRawHardware == SOF_TIMESTAMPING_RAW_HARDWARE);
static_assert(lle::net::hwts::abi::kOptTsonly == SOF_TIMESTAMPING_OPT_TSONLY);
static_assert(sizeof(lle::net::hwts::abi::SockExtendedErr) == sizeof(sock_extended_err));
static_assert(sizeof(lle::net::hwts::abi::InPktinfo) == sizeof(in_pktinfo));
#endif

namespace lle::net::hwts {

namespace {

template <class T>
bool load(std::span<const std::byte> p, T& out) noexcept {
  if (p.size() < sizeof(T)) return false;
  std::memcpy(&out, p.data(), sizeof(T));
  return true;
}

}  // namespace

void parse_cmsg(int level, int type, std::span<const std::byte> payload, ControlInfo& out) noexcept {
  if (level == abi::kSolSocket) {
    if (type == abi::kSoTimestampingOld || type == abi::kSoTimestampingNew) {
      abi::ScmTimestamping t{};
      if (!load(payload, t)) {
        ++out.malformed;
        return;
      }
      if (!valid_timespec(t.ts[0]) || !valid_timespec(t.ts[2])) ++out.malformed;  // the bad one reads as absent
      out.ts.sw_ns = to_ns(t.ts[0]);
      out.ts.hw_ns = to_ns(t.ts[2]);
      out.has_timestamp = true;
      return;
    }
    if (type == abi::kSoTimestampnsOld || type == abi::kSoTimestampnsNew) {
      abi::KernelTimespec t{};
      if (!load(payload, t)) {
        ++out.malformed;
        return;
      }
      if (!valid_timespec(t)) ++out.malformed;
      out.ts.sw_ns = to_ns(t);
      out.has_timestamp = true;
      return;
    }
  } else if (level == abi::kSolIp || level == abi::kSolIpv6) {
    if ((level == abi::kSolIp && type == abi::kIpRecverr) || (level == abi::kSolIpv6 && type == abi::kIpv6Recverr)) {
      // The extended error is followed by the offender address; only the header matters.
      if (!load(payload, out.ext_err)) {
        ++out.malformed;
        return;
      }
      out.has_ext_err = true;
      return;
    }
    if (level == abi::kSolIp && type == abi::kIpPktinfo) {
      abi::InPktinfo pi{};
      if (!load(payload, pi)) {
        ++out.malformed;
        return;
      }
      out.dst_ipv4 = ntohl(pi.ipi_addr);
      out.ifindex = static_cast<std::uint32_t>(pi.ipi_ifindex);
      out.has_dst = true;
      return;
    }
  }
#if defined(__APPLE__)
  // Native Darwin messages: SOL_SOCKET is 0xffff there, so they never collide with the
  // Linux values above.
  if (level == SOL_SOCKET && type == SCM_TIMESTAMP) {
    timeval tv{};
    if (!load(payload, tv)) {
      ++out.malformed;
      return;
    }
    out.ts.sw_ns = static_cast<Nanos>(tv.tv_sec) * kNsPerSec + static_cast<Nanos>(tv.tv_usec) * 1000;
    out.has_timestamp = true;
    return;
  }
  if (level == IPPROTO_IP && type == IP_RECVDSTADDR) {
    in_addr a{};
    if (!load(payload, a)) {
      ++out.malformed;
      return;
    }
    out.dst_ipv4 = ntohl(a.s_addr);
    out.has_dst = true;
    return;
  }
#endif
}

// CMSG_* are system macros built from C-style casts; confine them here.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wconversion"

void parse_control(const msghdr& m, ControlInfo& out) noexcept {
  if (m.msg_control == nullptr || m.msg_controllen == 0) return;
  for (const cmsghdr* c = CMSG_FIRSTHDR(&m); c != nullptr; c = CMSG_NXTHDR(const_cast<msghdr*>(&m), const_cast<cmsghdr*>(c))) {
    const std::size_t hdr = static_cast<std::size_t>(CMSG_LEN(0));
    if (static_cast<std::size_t>(c->cmsg_len) < hdr) break;
    const std::size_t n = static_cast<std::size_t>(c->cmsg_len) - hdr;
    const auto* data = reinterpret_cast<const std::byte*>(CMSG_DATA(c));
    parse_cmsg(c->cmsg_level, c->cmsg_type, {data, n}, out);
  }
}

void parse_control(const std::byte* control, std::size_t len, ControlInfo& out) noexcept {
  msghdr m{};
  m.msg_control = const_cast<std::byte*>(control);
  m.msg_controllen = len;
  parse_control(m, out);
}

std::size_t put_cmsg(std::span<std::byte> buf, std::size_t offset, int level, int type,
                     std::span<const std::byte> payload) noexcept {
  const std::size_t space = CMSG_SPACE(payload.size());
  if (offset + space > buf.size()) return 0;
  std::memset(buf.data() + offset, 0, space);
  cmsghdr h{};
  h.cmsg_len = CMSG_LEN(payload.size());
  h.cmsg_level = level;
  h.cmsg_type = type;
  std::memcpy(buf.data() + offset, &h, sizeof(h));
  const std::size_t data_off = CMSG_LEN(0);
  if (!payload.empty()) std::memcpy(buf.data() + offset + data_off, payload.data(), payload.size());
  return offset + space;
}

#pragma GCC diagnostic pop

bool to_tx_stamp(const ControlInfo& c, TxStamp& out) noexcept {
  if (!c.has_ext_err || !c.has_timestamp) return false;
  if (c.ext_err.ee_errno != static_cast<std::uint32_t>(abi::kEnomsg) ||
      c.ext_err.ee_origin != abi::kSoEeOriginTimestamping)
    return false;
  out.id = c.ext_err.ee_data;
  out.type = c.ext_err.ee_info;
  out.ts = c.ts;
  return true;
}

}  // namespace lle::net::hwts
