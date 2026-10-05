// Fuzz target for socket control-message parsing (net/hwts/cmsg.h, 07 §2.5).
// The bytes come from the kernel, but the parser must still never read out of
// bounds or misbehave on short, truncated or overlapping cmsgs: every known
// (level, type) payload parser gets arbitrary bytes, and the raw control-buffer
// walker gets arbitrary buffers.
#include <sys/socket.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <utility>

#include "net/hwts/abi.h"
#include "net/hwts/cmsg.h"

namespace hw = lle::net::hwts;

namespace {
constexpr std::pair<int, int> kKinds[] = {
    {hw::abi::kSolSocket, hw::abi::kSoTimestampingOld}, {hw::abi::kSolSocket, hw::abi::kSoTimestampingNew},
    {hw::abi::kSolSocket, hw::abi::kSoTimestampnsOld},  {hw::abi::kSolSocket, hw::abi::kSoTimestampnsNew},
    {hw::abi::kSolIp, hw::abi::kIpPktinfo},             {hw::abi::kSolIp, hw::abi::kIpRecverr},
    {hw::abi::kSolIpv6, hw::abi::kIpv6Recverr},
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  const auto [level, type] = kKinds[data[0] % (sizeof kKinds / sizeof kKinds[0])];
  const std::span<const std::byte> rest(reinterpret_cast<const std::byte*>(data + 1), size - 1);
  hw::ControlInfo one;
  hw::parse_cmsg(level, type, rest, one);

  alignas(alignof(cmsghdr)) std::byte buf[4096];
  const std::size_t n = std::min(rest.size(), sizeof buf);
  std::memcpy(buf, rest.data(), n);
  hw::ControlInfo all;
  hw::parse_control(buf, n, all);
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* out, std::size_t cap) {
  // Seed 0: one well-formed SO_TIMESTAMPING cmsg (three timespecs) in the native layout.
  if (index != 0) return 0;
  alignas(alignof(cmsghdr)) std::byte buf[CMSG_SPACE(48)] = {};
  auto* c = reinterpret_cast<cmsghdr*>(buf);
  c->cmsg_level = hw::abi::kSolSocket;
  c->cmsg_type = hw::abi::kSoTimestampingOld;
  c->cmsg_len = CMSG_LEN(48);
  const std::int64_t ts[6] = {1, 100, 0, 0, 2, 200};
  std::memcpy(CMSG_DATA(c), ts, sizeof ts);
  if (cap < sizeof buf + 1) return 0;
  out[0] = 0;
  std::memcpy(out + 1, buf, sizeof buf);
  return sizeof buf + 1;
}
