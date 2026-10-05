#pragma once
// Loader for bpf/md_steer.bpf.c (07 §2.3) using libbpf. Loads the RX-metadata entry
// point device-bound (bpf_program__set_ifindex + BPF_F_XDP_DEV_BOUND_ONLY, as in the
// kernel selftest xdp_hw_metadata.c) and attaches it in driver mode; falls back to the
// non-metadata entry point when the device-bound load is refused, and to SKB (generic)
// mode only when explicitly allowed (generic XDP never gives zero-copy). Maps: md_ports,
// utcp_flows, utcp_ports, xsks. Detaches on destruction.
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include "net/xsk/umem.h"

struct bpf_object;

namespace lle::net::xsk {

struct SteerConfig {
  std::string object_path;  // md_steer.bpf.o
  std::string ifname;
  bool want_metadata = true;   // try the device-bound md_steer first
  bool allow_skb_mode = false; // dev/test: fall back to generic XDP if native attach fails
};

enum class AttachMode : std::uint8_t { Native, Skb };

struct SteerStats {
  std::uint64_t pass = 0;
  std::uint64_t redirect_udp = 0;
  std::uint64_t redirect_tcp = 0;
  std::uint64_t drop_tcp = 0;  // utcp flow on a queue without an AF_XDP socket
  std::uint64_t meta_ts = 0;
  std::uint64_t meta_nodata = 0;
  std::uint64_t meta_fail = 0;
  std::uint64_t udp_no_xsk = 0;
};

// Host-order utcp 5-tuple as seen on ingress (remote -> local).
struct UtcpFlow {
  std::uint32_t remote_ip = 0;
  std::uint32_t local_ip = 0;
  std::uint16_t remote_port = 0;
  std::uint16_t local_port = 0;
};

class SteerProgram {
 public:
  static std::expected<std::unique_ptr<SteerProgram>, Error> load(const SteerConfig& cfg);
  ~SteerProgram();
  SteerProgram(const SteerProgram&) = delete;
  SteerProgram& operator=(const SteerProgram&) = delete;

  [[nodiscard]] bool device_bound() const noexcept { return dev_bound_; }
  [[nodiscard]] bool metadata_kfunc() const noexcept { return dev_bound_; }
  [[nodiscard]] AttachMode attach_mode() const noexcept { return mode_; }
  [[nodiscard]] int ifindex() const noexcept { return ifindex_; }
  [[nodiscard]] int prog_fd() const noexcept { return prog_fd_; }
  [[nodiscard]] const std::string& load_note() const noexcept { return note_; }

  bool add_md_port(std::uint16_t udp_dst_port);
  bool remove_md_port(std::uint16_t udp_dst_port);
  bool add_utcp_flow(const UtcpFlow& f);
  bool remove_utcp_flow(const UtcpFlow& f);
  bool add_utcp_port(std::uint16_t tcp_local_port);
  // Registers the AF_XDP socket for rx queue `queue`.
  bool set_xsk(std::uint32_t queue, int xsk_fd);
  bool clear_xsk(std::uint32_t queue);
  SteerStats stats() const;

 private:
  SteerProgram() = default;
  bpf_object* obj_ = nullptr;
  int ifindex_ = 0;
  int prog_fd_ = -1;
  std::uint32_t attach_flags_ = 0;
  bool dev_bound_ = false;
  AttachMode mode_ = AttachMode::Native;
  int xsks_fd_ = -1;
  int md_ports_fd_ = -1;
  int flows_fd_ = -1;
  int tcp_ports_fd_ = -1;
  int stats_fd_ = -1;
  int ncpus_ = 1;
  std::string note_;
};

}  // namespace lle::net::xsk
