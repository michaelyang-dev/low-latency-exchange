#pragma once
// Linux UAPI values and layouts used by the timestamp parsers (R3a Q3).
//
// They are defined here, not taken from <linux/...>, so the parsers compile and are
// unit-tested on every platform (including the macOS dev host) with handcrafted control
// buffers. The values are the asm-generic ones, valid for x86-64 and arm64 (the only
// targets we support); hwts/cmsg.cpp static_asserts them against the system headers on
// Linux.
#include <cstdint>

namespace lle::net::hwts::abi {

inline constexpr int kSolSocket = 1;
inline constexpr int kSolIp = 0;
inline constexpr int kSolIpv6 = 41;

// SCM_TIMESTAMPING is SO_TIMESTAMPING_OLD (37) on LP64; SO_TIMESTAMPING_NEW (65) reports
// SCM_TIMESTAMPING_NEW with scm_timestamping64. The layouts are identical on LP64.
inline constexpr int kSoTimestampingOld = 37;
inline constexpr int kSoTimestampingNew = 65;
inline constexpr int kSoTimestampnsOld = 35;
inline constexpr int kSoTimestampnsNew = 64;

inline constexpr int kIpPktinfo = 8;
inline constexpr int kIpRecverr = 11;
inline constexpr int kIpv6Recverr = 25;

inline constexpr int kEnomsg = 42;
inline constexpr std::uint8_t kSoEeOriginTimestamping = 4;

// sock_extended_err.ee_info for timestamp reports (SCM_TSTAMP_*).
inline constexpr std::uint32_t kTstampSnd = 0;
inline constexpr std::uint32_t kTstampSched = 1;
inline constexpr std::uint32_t kTstampAck = 2;
inline constexpr std::uint32_t kTstampCompletion = 3;

// SOF_TIMESTAMPING_* (include/uapi/linux/net_tstamp.h).
inline constexpr std::uint32_t kTxHardware = 1u << 0;
inline constexpr std::uint32_t kTxSoftware = 1u << 1;
inline constexpr std::uint32_t kRxHardware = 1u << 2;
inline constexpr std::uint32_t kRxSoftware = 1u << 3;
inline constexpr std::uint32_t kSoftware = 1u << 4;
inline constexpr std::uint32_t kSysHardware = 1u << 5;
inline constexpr std::uint32_t kRawHardware = 1u << 6;
inline constexpr std::uint32_t kOptId = 1u << 7;
inline constexpr std::uint32_t kTxSched = 1u << 8;
inline constexpr std::uint32_t kTxAck = 1u << 9;
inline constexpr std::uint32_t kOptCmsg = 1u << 10;
inline constexpr std::uint32_t kOptTsonly = 1u << 11;
inline constexpr std::uint32_t kOptStats = 1u << 12;
inline constexpr std::uint32_t kOptPktinfo = 1u << 13;
inline constexpr std::uint32_t kOptTxSwhw = 1u << 14;
inline constexpr std::uint32_t kBindPhc = 1u << 15;
inline constexpr std::uint32_t kOptIdTcp = 1u << 16;
inline constexpr std::uint32_t kOptRxFilter = 1u << 17;
inline constexpr std::uint32_t kTxCompletion = 1u << 18;

// struct __kernel_timespec / scm_timestamping64.
struct KernelTimespec {
  std::int64_t tv_sec;
  std::int64_t tv_nsec;
};
struct ScmTimestamping {
  KernelTimespec ts[3];  // [0] software, [1] legacy (zero), [2] raw hardware
};
static_assert(sizeof(ScmTimestamping) == 48);

// struct sock_extended_err (include/uapi/linux/errqueue.h).
struct SockExtendedErr {
  std::uint32_t ee_errno;
  std::uint8_t ee_origin;
  std::uint8_t ee_type;
  std::uint8_t ee_code;
  std::uint8_t ee_pad;
  std::uint32_t ee_info;
  std::uint32_t ee_data;
};
static_assert(sizeof(SockExtendedErr) == 16);

// struct in_pktinfo (addresses in network byte order).
struct InPktinfo {
  std::int32_t ipi_ifindex;
  std::uint32_t ipi_spec_dst;
  std::uint32_t ipi_addr;
};
static_assert(sizeof(InPktinfo) == 12);

// SIOCSHWTSTAMP / ethtool values (include/uapi/linux/net_tstamp.h, ethtool.h).
inline constexpr int kHwtstampTxOff = 0;
inline constexpr int kHwtstampTxOn = 1;
inline constexpr int kHwtstampFilterNone = 0;
inline constexpr int kHwtstampFilterAll = 1;

}  // namespace lle::net::hwts::abi
