#pragma once
// Variant wiring of the client programs (07 §1, WP N-13; METHODOLOGY §14).
//
// Every variant runs the same binary, protocols, workload, pinning and NIC queue; only
// the I/O backend and its device settings change:
//
//   variant                 label    datagrams (feed, re-requests)   streams (SoupBinTCP)
//   epoll                   (i)      kernel UDP                      kernel TCP
//   busypoll                (ii)     kernel UDP + busy poll          kernel TCP + busy poll
//   busypoll-irq-suspend    (ii-s)   as (ii), plus per-NAPI irq-suspend-timeout (6.13);
//                                    a labelled extra sub-variant, not one of the six
//   uring                   (iii)    io_uring multishot recvmsg      io_uring recv/send
//   uring-napi              (iii-n)  as (iii) + IORING_REGISTER_NAPI
//   xsk                     (iv)     AF_XDP                          utcp over AF_XDP
//   xsk-threaded            (iv-t)   as (iv) with threaded NAPI busy polling (6.19)
//
// One VariantConfig carries everything the variant needs (interface, queue, timestamp
// mode, hot-thread CPU, AF_XDP addressing); the programs parse it with the same flags
// (parse_variant_flag) and report it with the same JSON block (variant_json), so a
// campaign changes exactly one argument (--variant) between cells.
//
// Device settings (busy-poll sysfs knobs, irq-suspend, threaded NAPI, NIC hardware
// timestamping) change host state and need CAP_NET_ADMIN. With --device-setup the
// program applies them itself; otherwise it only reads them back and reports whether
// they match the variant (device_ok), so a lab run under lab/tune.sh settings is checked,
// never assumed.
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "client/cli.h"
#include "net/common/port.h"
#include "net/common/stack.h"
#include "net/common/timestamps.h"
#include "net/utcp/wire.h"

namespace lle::client {

class JsonObject;

enum class Variant : std::uint8_t { Epoll, BusyPoll, BusyPollIrqSuspend, Uring, UringNapi, Xsk, XskThreaded };

inline constexpr std::array<Variant, 7> kAllVariants = {Variant::Epoll,     Variant::BusyPoll,
                                                        Variant::BusyPollIrqSuspend, Variant::Uring,
                                                        Variant::UringNapi, Variant::Xsk,
                                                        Variant::XskThreaded};

[[nodiscard]] const char* to_string(Variant v) noexcept;
// METHODOLOGY §14 label: "(i)", "(ii)", "(ii-s)", "(iii)", "(iii-n)", "(iv)", "(iv-t)".
[[nodiscard]] const char* methodology_label(Variant v) noexcept;
[[nodiscard]] std::optional<Variant> parse_variant(std::string_view s) noexcept;
[[nodiscard]] net::BackendKind backend_of(Variant v) noexcept;
[[nodiscard]] constexpr bool is_xsk(Variant v) noexcept { return v == Variant::Xsk || v == Variant::XskThreaded; }
// True if this build can run the variant (xsk needs Linux and libbpf; uring needs liburing).
[[nodiscard]] bool variant_compiled(Variant v) noexcept;

[[nodiscard]] std::optional<net::TsMode> parse_ts_mode(std::string_view s) noexcept;
[[nodiscard]] const char* to_string(net::TsMode m) noexcept;
[[nodiscard]] std::optional<net::utcp::MacAddr> parse_mac(std::string_view s) noexcept;
[[nodiscard]] const char* to_string(net::WaitPolicy w) noexcept;

struct XskSettings {
  std::uint32_t queue = 0;
  // Dev/test override (veth, virtio in the VM and CI): accept copy mode. Copy-mode
  // timestamps are never reported as hardware (07 §2.5), so such a run is invalid for
  // any hardware-timestamp measurement.
  bool allow_copy = false;
  bool busy_poll = true;              // socket busy polling, variant (iv); forced off for (iv-t)
  std::string bpf_object;             // md_steer.bpf.o; empty = the build's LLE_XSK_BPF_OBJECT
  bool allow_skb_mode = false;        // generic XDP if native attach fails (dev/test only)
  std::uint32_t local_ip = 0;         // host order; 0 = the interface's first IPv4 address
  std::optional<net::utcp::MacAddr> next_hop;  // static next hop (direct cable); else kernel neighbours
  std::uint16_t port_lo = 40000, port_hi = 40999;  // utcp local ports (ip_local_reserved_ports)
  std::uint16_t udp_port = 0;         // source / reply port of the datagram side; 0 = port_hi
  std::uint32_t umem_frames = 16384;
  bool checksum_offload = false;      // XDP_TXMD_FLAGS_CHECKSUM (mlx5 >= 6.8)
};

struct VariantConfig {
  Variant variant = Variant::Epoll;
  std::string ifname;                  // the NIC port: joins, device settings, AF_XDP, PHC
  net::TsMode timestamps = net::TsMode::Off;
  // The wait strategy: Default is the variant's own (07 §1: (i)/(ii) block in epoll_wait,
  // (iii) spins on the ring, (iii-n) waits so the kernel busy-polls, (iv) polls rings);
  // Spin and Block exist for labelled pilot runs only.
  net::WaitPolicy wait = net::WaitPolicy::Default;
  int cpu = -1;                        // the hot thread
  int napi_cpu = -1;                   // (iv-t): the NAPI busy-poll kthread
  bool device_setup = false;           // apply device settings (root) instead of checking them
  XskSettings xsk;
};

// Handles one of the shared variant flags; false if `f` is not one of them:
//   --variant V  --ifname IF  --timestamps off|software|hardware  --wait default|spin|block
//   --cpu N  --napi-cpu N
//   --device-setup  --xsk-queue Q  --xsk-allow-copy  --xsk-no-busy-poll  --xsk-bpf PATH
//   --xsk-skb-mode  --local-ip A.B.C.D  --next-hop-mac aa:bb:cc:dd:ee:ff
//   --utcp-ports LO-HI  --xsk-udp-port P  --umem-frames N  --xsk-csum-offload
bool parse_variant_flag(cli::Args& a, const std::string& f, VariantConfig& v);
// Usage text of those flags.
[[nodiscard]] const char* variant_flags_usage() noexcept;

// What prepare_variant found and did (reported with every run).
struct DeviceReport {
  bool device_ok = true;              // the device settings match the variant (or none apply)
  bool applied = false;               // settings were applied by this process (--device-setup)
  std::string notes;                  // what was checked, applied or missing (human readable)
  int phc_index = -1;                 // PHC of `ifname` (-1: none / no interface)
  std::string driver;
  bool hw_timestamping = false;       // SIOCGHWTSTAMP reports tx ON and rx ALL
  std::int64_t napi_defer_hard_irqs = -1, gro_flush_timeout_ns = -1, irq_suspend_timeout_ns = -1;
  std::int64_t busy_read = -1, busy_poll = -1;  // net.core sysctls
};

// Checks (or, with device_setup, applies) the variant's device settings and the NIC
// timestamping mode. Fails when a required setting cannot be applied or verified:
// hardware timestamps without an interface or with timestamping off; xsk without an
// interface. A mismatch in a busy-poll knob is reported (device_ok = false), not fatal.
[[nodiscard]] bool prepare_variant(VariantConfig& v, DeviceReport& rep, std::string& err);

// The variant block of a run report: variant, label, backend, interface, queue,
// timestamps, cpu and the device report.
void variant_json(JsonObject& j, const VariantConfig& v, const DeviceReport& rep);

// Pins thread `tid` (a kernel task id, e.g. a NAPI kthread) to `cpu`. Linux only.
bool pin_task(int tid, int cpu) noexcept;

}  // namespace lle::client
