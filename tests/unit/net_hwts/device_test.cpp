// enable_hw_timestamping() against a fake NIC (no hardware in CI or the VM): the
// SIOCSHWTSTAMP request contents, the -ERANGE fast failure, applied-config checks, the
// PHC index and the mlx5 tx_port_ts private-flag check (07 §2.5).
#include <gtest/gtest.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "net/hwts/device.h"

namespace lle::net::hwts {
namespace {

struct FakeNic {
  std::string ifname = "enp1s0f0np0";
  int set_errno = 0;                        // SIOCSHWTSTAMP failure (e.g. ERANGE)
  int applied_rx_filter = HWTSTAMP_FILTER_ALL;
  int phc = 3;
  std::string driver = "mlx5_core";
  std::vector<std::string> priv_flags = {"rx_cqe_moder", "tx_cqe_moder", "rx_cqe_compress", "tx_port_ts"};
  std::uint32_t flag_bits = 0;
  // observed
  std::vector<unsigned long> reqs;
  std::vector<std::uint32_t> ethtool_cmds;
  hwtstamp_config last_set{};

  static int io(void* ctx, unsigned long req, void* p) { return static_cast<FakeNic*>(ctx)->handle(req, *static_cast<ifreq*>(p)); }

  int handle(unsigned long req, ifreq& ifr) {
    reqs.push_back(req);
    if (ifname != ifr.ifr_name) return -ENODEV;
    if (req == SIOCSHWTSTAMP) {
      auto* cfg = reinterpret_cast<hwtstamp_config*>(ifr.ifr_data);
      last_set = *cfg;
      if (set_errno != 0) return -set_errno;
      cfg->rx_filter = applied_rx_filter;
      return 0;
    }
    if (req == SIOCGHWTSTAMP) {
      auto* cfg = reinterpret_cast<hwtstamp_config*>(ifr.ifr_data);
      *cfg = last_set;
      return 0;
    }
    if (req != SIOCETHTOOL) return -EOPNOTSUPP;
    std::uint32_t cmd = 0;
    std::memcpy(&cmd, ifr.ifr_data, sizeof(cmd));
    ethtool_cmds.push_back(cmd);
    switch (cmd) {
      case ETHTOOL_GET_TS_INFO: {
        auto* ti = reinterpret_cast<ethtool_ts_info*>(ifr.ifr_data);
        ti->phc_index = phc;
        ti->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
        ti->tx_types = (1u << HWTSTAMP_TX_OFF) | (1u << HWTSTAMP_TX_ON);
        ti->rx_filters = (1u << HWTSTAMP_FILTER_NONE) | (1u << HWTSTAMP_FILTER_ALL);
        return 0;
      }
      case ETHTOOL_GDRVINFO: {
        auto* di = reinterpret_cast<ethtool_drvinfo*>(ifr.ifr_data);
        std::strncpy(di->driver, driver.c_str(), sizeof(di->driver) - 1);
        di->n_priv_flags = static_cast<std::uint32_t>(priv_flags.size());
        return 0;
      }
      case ETHTOOL_GSTRINGS: {
        auto* gs = reinterpret_cast<ethtool_gstrings*>(ifr.ifr_data);
        if (gs->string_set != ETH_SS_PRIV_FLAGS || gs->len != priv_flags.size()) return -EINVAL;
        auto* table = reinterpret_cast<char*>(ifr.ifr_data) + sizeof(ethtool_gstrings);
        for (std::size_t i = 0; i < priv_flags.size(); ++i)
          std::strncpy(table + i * ETH_GSTRING_LEN, priv_flags[i].c_str(), ETH_GSTRING_LEN);
        return 0;
      }
      case ETHTOOL_GPFLAGS: {
        auto* v = reinterpret_cast<ethtool_value*>(ifr.ifr_data);
        v->data = flag_bits;
        return 0;
      }
      default:
        return -EOPNOTSUPP;
    }
  }
  DeviceIo dev() { return DeviceIo{this, &FakeNic::io}; }
};

TEST(HwtsDevice, Mlx5WithPortTsOffSucceeds) {
  FakeNic nic;
  auto r = enable_hw_timestamping(nic.ifname, nic.dev());
  ASSERT_TRUE(r.has_value()) << to_string(r.error());
  EXPECT_EQ(nic.last_set.tx_type, HWTSTAMP_TX_ON);
  EXPECT_EQ(nic.last_set.rx_filter, HWTSTAMP_FILTER_ALL);
  EXPECT_EQ(nic.last_set.flags, 0);
  EXPECT_EQ(r->applied.rx_filter, HWTSTAMP_FILTER_ALL);
  EXPECT_EQ(r->info.phc_index, 3);
  EXPECT_TRUE(r->info.hw_rx_all());
  EXPECT_TRUE(r->info.hw_tx_on());
  EXPECT_EQ(r->driver, "mlx5_core");
  ASSERT_TRUE(r->tx_port_ts.has_value());
  EXPECT_FALSE(*r->tx_port_ts);
  auto back = get_hw_timestamping(nic.ifname, nic.dev());
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(back->tx_type, HWTSTAMP_TX_ON);
}

TEST(HwtsDevice, Mlx5WithPortTsOnIsRejected) {
  FakeNic nic;
  nic.flag_bits = 1u << 3;  // "tx_port_ts"
  auto r = enable_hw_timestamping(nic.ifname, nic.dev());
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, EINVAL);
  EXPECT_STREQ(r.error().op, "tx_port_ts");
  auto flag = read_priv_flag(nic.ifname, "tx_port_ts", nic.dev());
  ASSERT_TRUE(flag.has_value());
  EXPECT_EQ(*flag, std::optional<bool>(true));
  auto other = read_priv_flag(nic.ifname, "rx_cqe_compress", nic.dev());
  ASSERT_TRUE(other.has_value());
  EXPECT_EQ(*other, std::optional<bool>(false));
}

TEST(HwtsDevice, FilterAllUnsupportedFailsFast) {
  FakeNic nic;
  nic.driver = "i40e";
  nic.set_errno = ERANGE;
  auto r = enable_hw_timestamping(nic.ifname, nic.dev());
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, ERANGE);
  EXPECT_TRUE(nic.ethtool_cmds.empty()) << "no further probing after -ERANGE";
  ASSERT_EQ(nic.reqs.size(), 1u);
}

TEST(HwtsDevice, NarrowedFilterIsRejected) {
  FakeNic nic;
  nic.applied_rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
  auto r = enable_hw_timestamping(nic.ifname, nic.dev());
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, EINVAL);
}

TEST(HwtsDevice, DriverWithoutPortTsFlag) {
  FakeNic nic;
  nic.driver = "ice";
  nic.priv_flags = {"link-down-on-close", "fw-lldp-agent"};
  nic.phc = 1;
  auto r = enable_hw_timestamping(nic.ifname, nic.dev());
  ASSERT_TRUE(r.has_value()) << to_string(r.error());
  EXPECT_FALSE(r->tx_port_ts.has_value());
  EXPECT_EQ(r->info.phc_index, 1);
}

TEST(HwtsDevice, PermissionErrorsPropagate) {
  FakeNic nic;
  nic.set_errno = EPERM;
  auto r = enable_hw_timestamping(nic.ifname, nic.dev());
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, EPERM);
  EXPECT_FALSE(enable_hw_timestamping("", nic.dev()).has_value());
  EXPECT_FALSE(get_ts_info("eth9", nic.dev()).has_value());  // ENODEV from the fake
}

TEST(HwtsDevice, FindGstring) {
  std::vector<char> table(3 * 32, '\0');
  std::strcpy(table.data(), "alpha");
  std::strcpy(table.data() + 32, "tx_port_ts");
  std::memset(table.data() + 64, 'x', 32);  // unterminated full-width entry
  EXPECT_EQ(find_gstring(table, 3, "tx_port_ts"), 1u);
  EXPECT_EQ(find_gstring(table, 3, std::string(32, 'x')), 2u);
  EXPECT_FALSE(find_gstring(table, 3, "tx_port").has_value());
  EXPECT_FALSE(find_gstring(table, 5, "beta").has_value()) << "count beyond the table is clamped";
}

}  // namespace
}  // namespace lle::net::hwts
