#pragma once
// NIC hardware-timestamp configuration (07 §2.5, R3a §3.2/§3.4). Linux only; elsewhere
// every call returns ENOTSUP. Cold path (startup, needs CAP_NET_ADMIN for the set).
//
// The ioctls go through an injectable DeviceIo so the whole flow (including the -ERANGE
// fast failure and the mlx5 tx_port_ts check) is unit-tested with a fake device; the
// default DeviceIo issues real ioctls on a throwaway UDP socket.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "net/common/error.h"

namespace lle::net::hwts {

// ioctl(req, struct ifreq*) on an interface. Returns 0 or -errno.
struct DeviceIo {
  void* ctx = nullptr;
  int (*fn)(void* ctx, unsigned long req, void* ifreq) = nullptr;  // nullptr = real ioctl
};

// ETHTOOL_GET_TS_INFO (`ethtool -T`).
struct TsInfo {
  std::uint32_t so_timestamping = 0;  // SOF_TIMESTAMPING_* capabilities
  int phc_index = -1;                 // /dev/ptpN; -1 if the device has no PHC
  std::uint32_t tx_types = 0;         // bitmask of 1 << HWTSTAMP_TX_*
  std::uint32_t rx_filters = 0;       // bitmask of 1 << HWTSTAMP_FILTER_*

  [[nodiscard]] bool hw_rx_all() const noexcept { return (rx_filters & (1u << 1)) != 0; }
  [[nodiscard]] bool hw_tx_on() const noexcept { return (tx_types & (1u << 1)) != 0; }
};

struct HwTsConfig {
  int flags = 0;
  int tx_type = 0;
  int rx_filter = 0;
};

struct HwTsResult {
  HwTsConfig applied{};        // what the driver reports after SIOCSHWTSTAMP
  TsInfo info{};               // PHC index and capabilities
  std::string driver;          // ETHTOOL_GDRVINFO driver name ("mlx5_core", "ice", ...)
  std::optional<bool> tx_port_ts;  // mlx5 private flag; nullopt when the driver has none
};

// SIOCSHWTSTAMP{tx_type=HWTSTAMP_TX_ON, rx_filter=HWTSTAMP_FILTER_ALL}, then records the
// PHC index and checks mlx5 tx_port_ts. Errors:
//   ERANGE  the driver cannot timestamp all RX packets (e.g. i40e): fail fast;
//   EINVAL  op "SIOCSHWTSTAMP(applied)": the driver applied a different config;
//   EINVAL  op "tx_port_ts": an mlx5 port has tx_port_ts on (TX stamps must stay
//           CQE-based so TCP, UDP and AF_XDP stamps are comparable).
[[nodiscard]] Result<HwTsResult> enable_hw_timestamping(std::string_view ifname, DeviceIo io = {});

// SIOCGHWTSTAMP read-back.
[[nodiscard]] Result<HwTsConfig> get_hw_timestamping(std::string_view ifname, DeviceIo io = {});

[[nodiscard]] Result<TsInfo> get_ts_info(std::string_view ifname, DeviceIo io = {});
[[nodiscard]] Result<std::string> driver_name(std::string_view ifname, DeviceIo io = {});

// Reads one ethtool private flag by name (`ethtool --show-priv-flags`). nullopt if the
// driver does not expose a flag with that name.
[[nodiscard]] Result<std::optional<bool>> read_priv_flag(std::string_view ifname, std::string_view flag,
                                                         DeviceIo io = {});

// Index of `name` in an ETH_SS_PRIV_FLAGS string table (32-byte, NUL-padded entries).
[[nodiscard]] std::optional<std::uint32_t> find_gstring(std::span<const char> table, std::uint32_t count,
                                                        std::string_view name) noexcept;

}  // namespace lle::net::hwts
