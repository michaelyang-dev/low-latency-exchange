#include "net/hwts/device.h"

#include <cerrno>
#include <cstring>
#include <vector>

#if defined(__linux__)
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net/hwts/abi.h"

static_assert(lle::net::hwts::abi::kHwtstampTxOn == HWTSTAMP_TX_ON);
static_assert(lle::net::hwts::abi::kHwtstampFilterAll == HWTSTAMP_FILTER_ALL);
#endif

namespace lle::net::hwts {

std::optional<std::uint32_t> find_gstring(std::span<const char> table, std::uint32_t count,
                                          std::string_view name) noexcept {
  constexpr std::size_t kLen = 32;  // ETH_GSTRING_LEN
  for (std::uint32_t i = 0; i < count; ++i) {
    const std::size_t off = static_cast<std::size_t>(i) * kLen;
    if (off + kLen > table.size()) break;
    const char* s = table.data() + off;
    const std::size_t n = ::strnlen(s, kLen);
    if (std::string_view(s, n) == name) return i;
  }
  return std::nullopt;
}

#if defined(__linux__)

namespace {

int real_ioctl(unsigned long req, void* ifr) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -errno;
  const int r = ::ioctl(fd, req, ifr);
  const int e = errno;
  ::close(fd);
  return r < 0 ? -e : 0;
}

int call(DeviceIo io, unsigned long req, ifreq& ifr) {
  return io.fn != nullptr ? io.fn(io.ctx, req, &ifr) : real_ioctl(req, &ifr);
}

Result<ifreq> make_ifreq(std::string_view name, void* data) {
  if (name.empty() || name.size() >= IFNAMSIZ) return fail("ifreq", EINVAL);
  ifreq ifr{};
  std::memcpy(ifr.ifr_name, name.data(), name.size());
  ifr.ifr_data = static_cast<char*>(data);
  return ifr;
}

// SIOCETHTOOL with `cmd` as the first u32 of `data`.
Result<void> ethtool(DeviceIo io, std::string_view name, void* data, const char* op) {
  auto ifr = make_ifreq(name, data);
  if (!ifr) return std::unexpected(ifr.error());
  if (const int rc = call(io, SIOCETHTOOL, *ifr); rc < 0) return fail(op, -rc);
  return {};
}

}  // namespace

Result<TsInfo> get_ts_info(std::string_view ifname, DeviceIo io) {
  ethtool_ts_info ti{};
  ti.cmd = ETHTOOL_GET_TS_INFO;
  if (auto r = ethtool(io, ifname, &ti, "ETHTOOL_GET_TS_INFO"); !r) return std::unexpected(r.error());
  TsInfo out;
  out.so_timestamping = ti.so_timestamping;
  out.phc_index = ti.phc_index;
  out.tx_types = ti.tx_types;
  out.rx_filters = ti.rx_filters;
  return out;
}

Result<std::string> driver_name(std::string_view ifname, DeviceIo io) {
  ethtool_drvinfo di{};
  di.cmd = ETHTOOL_GDRVINFO;
  if (auto r = ethtool(io, ifname, &di, "ETHTOOL_GDRVINFO"); !r) return std::unexpected(r.error());
  return std::string(di.driver, ::strnlen(di.driver, sizeof(di.driver)));
}

Result<std::optional<bool>> read_priv_flag(std::string_view ifname, std::string_view flag, DeviceIo io) {
  ethtool_drvinfo di{};
  di.cmd = ETHTOOL_GDRVINFO;
  if (auto r = ethtool(io, ifname, &di, "ETHTOOL_GDRVINFO"); !r) return std::unexpected(r.error());
  const std::uint32_t n = di.n_priv_flags;
  if (n == 0) return std::optional<bool>{};
  if (n > 32) return fail("ETHTOOL_GSTRINGS", EOVERFLOW);  // GPFLAGS is a 32-bit bitmap
  // u64 storage keeps the struct suitably aligned; startup-only allocation.
  std::vector<std::uint64_t> storage((sizeof(ethtool_gstrings) + std::size_t{n} * ETH_GSTRING_LEN + 7) / 8);
  auto* gs = reinterpret_cast<ethtool_gstrings*>(storage.data());
  gs->cmd = ETHTOOL_GSTRINGS;
  gs->string_set = ETH_SS_PRIV_FLAGS;
  gs->len = n;
  if (auto r = ethtool(io, ifname, gs, "ETHTOOL_GSTRINGS"); !r) return std::unexpected(r.error());
  const auto* table = reinterpret_cast<const char*>(reinterpret_cast<const std::byte*>(gs) + sizeof(ethtool_gstrings));
  const auto idx = find_gstring({table, std::size_t{n} * ETH_GSTRING_LEN}, gs->len < n ? gs->len : n, flag);
  if (!idx) return std::optional<bool>{};
  ethtool_value v{};
  v.cmd = ETHTOOL_GPFLAGS;
  if (auto r = ethtool(io, ifname, &v, "ETHTOOL_GPFLAGS"); !r) return std::unexpected(r.error());
  return std::optional<bool>{((v.data >> *idx) & 1u) != 0};
}

Result<HwTsConfig> get_hw_timestamping(std::string_view ifname, DeviceIo io) {
  hwtstamp_config cfg{};
  auto ifr = make_ifreq(ifname, &cfg);
  if (!ifr) return std::unexpected(ifr.error());
  if (const int rc = call(io, SIOCGHWTSTAMP, *ifr); rc < 0) return fail("SIOCGHWTSTAMP", -rc);
  return HwTsConfig{cfg.flags, cfg.tx_type, cfg.rx_filter};
}

Result<HwTsResult> enable_hw_timestamping(std::string_view ifname, DeviceIo io) {
  hwtstamp_config cfg{};
  cfg.flags = 0;
  cfg.tx_type = HWTSTAMP_TX_ON;
  cfg.rx_filter = HWTSTAMP_FILTER_ALL;
  auto ifr = make_ifreq(ifname, &cfg);
  if (!ifr) return std::unexpected(ifr.error());
  if (const int rc = call(io, SIOCSHWTSTAMP, *ifr); rc < 0) {
    // -ERANGE: the requested filter is unsupported (R3a §3.2). Never fall back to a
    // narrower filter: unstamped RX packets would silently invalidate the run.
    return fail(rc == -ERANGE ? "SIOCSHWTSTAMP(rx_filter=ALL unsupported)" : "SIOCSHWTSTAMP", -rc);
  }
  HwTsResult out;
  out.applied = HwTsConfig{cfg.flags, cfg.tx_type, cfg.rx_filter};
  if (cfg.tx_type != HWTSTAMP_TX_ON || cfg.rx_filter != HWTSTAMP_FILTER_ALL) return fail("SIOCSHWTSTAMP(applied)", EINVAL);
  auto info = get_ts_info(ifname, io);
  if (!info) return std::unexpected(info.error());
  out.info = *info;
  auto drv = driver_name(ifname, io);
  if (!drv) return std::unexpected(drv.error());
  out.driver = std::move(*drv);
  auto port_ts = read_priv_flag(ifname, "tx_port_ts", io);
  if (!port_ts) return std::unexpected(port_ts.error());
  out.tx_port_ts = *port_ts;
  if (out.tx_port_ts.value_or(false)) return fail("tx_port_ts", EINVAL);
  return out;
}

#else  // !__linux__

Result<TsInfo> get_ts_info(std::string_view, DeviceIo) { return fail("ETHTOOL_GET_TS_INFO", ENOTSUP); }
Result<std::string> driver_name(std::string_view, DeviceIo) { return fail("ETHTOOL_GDRVINFO", ENOTSUP); }
Result<std::optional<bool>> read_priv_flag(std::string_view, std::string_view, DeviceIo) {
  return fail("ETHTOOL_GPFLAGS", ENOTSUP);
}
Result<HwTsConfig> get_hw_timestamping(std::string_view, DeviceIo) { return fail("SIOCGHWTSTAMP", ENOTSUP); }
Result<HwTsResult> enable_hw_timestamping(std::string_view, DeviceIo) { return fail("SIOCSHWTSTAMP", ENOTSUP); }

#endif

}  // namespace lle::net::hwts
