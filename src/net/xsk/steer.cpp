#include "net/xsk/steer.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace lle::net::xsk {
namespace {

// libbpf prints verifier logs at warning level; keep them for diagnosis on stderr only
// when LLE_XSK_LIBBPF_DEBUG is set, else stay quiet (failures are reported by value).
int libbpf_print(enum libbpf_print_level level, const char* fmt, va_list args) {
  static const bool debug = std::getenv("LLE_XSK_LIBBPF_DEBUG") != nullptr;
  if (!debug || level == LIBBPF_DEBUG) return 0;
  return std::vfprintf(stderr, fmt, args);
}

struct FlowKeyWire {
  std::uint32_t remote_ip;
  std::uint32_t local_ip;
  std::uint16_t remote_port;
  std::uint16_t local_port;
};

FlowKeyWire wire(const UtcpFlow& f) {
  return FlowKeyWire{htonl(f.remote_ip), htonl(f.local_ip), htons(f.remote_port), htons(f.local_port)};
}

// Opens the object with exactly one entry point enabled; device-bound when asked.
bpf_object* open_and_load(const std::string& path, int ifindex, bool meta, int* err) {
  bpf_object* obj = bpf_object__open_file(path.c_str(), nullptr);
  if (obj == nullptr) {
    *err = errno;
    return nullptr;
  }
  bpf_program* pm = bpf_object__find_program_by_name(obj, "md_steer");
  bpf_program* pn = bpf_object__find_program_by_name(obj, "md_steer_nometa");
  if (pm == nullptr || pn == nullptr) {
    bpf_object__close(obj);
    *err = ENOENT;
    return nullptr;
  }
  bpf_program__set_autoload(meta ? pn : pm, false);
  if (meta) {
    bpf_program__set_ifindex(pm, static_cast<__u32>(ifindex));
    bpf_program__set_flags(pm, BPF_F_XDP_DEV_BOUND_ONLY);
  }
  const int rc = bpf_object__load(obj);
  if (rc != 0) {
    *err = -rc;
    bpf_object__close(obj);
    return nullptr;
  }
  return obj;
}

}  // namespace

std::expected<std::unique_ptr<SteerProgram>, Error> SteerProgram::load(const SteerConfig& cfg) {
  libbpf_set_print(libbpf_print);
  std::unique_ptr<SteerProgram> p(new SteerProgram());
  p->ifindex_ = static_cast<int>(::if_nametoindex(cfg.ifname.c_str()));
  if (p->ifindex_ == 0) return std::unexpected(Error{errno != 0 ? errno : ENODEV, "if_nametoindex"});
  int err = 0;
  if (cfg.want_metadata) {
    p->obj_ = open_and_load(cfg.object_path, p->ifindex_, true, &err);
    p->dev_bound_ = p->obj_ != nullptr;
    if (p->obj_ == nullptr) p->note_ = "device-bound load refused (errno " + std::to_string(err) + "); ";
  }
  if (p->obj_ == nullptr) {
    p->obj_ = open_and_load(cfg.object_path, p->ifindex_, false, &err);
    if (p->obj_ == nullptr) return std::unexpected(Error{err, "bpf_object__load(md_steer.bpf.o)"});
    p->note_ += "loaded md_steer_nometa (no RX metadata)";
  } else {
    p->note_ = "loaded md_steer device-bound (RX metadata kfunc)";
  }
  bpf_program* prog = bpf_object__find_program_by_name(p->obj_, p->dev_bound_ ? "md_steer" : "md_steer_nometa");
  p->prog_fd_ = bpf_program__fd(prog);
  p->xsks_fd_ = bpf_object__find_map_fd_by_name(p->obj_, "xsks");
  p->md_ports_fd_ = bpf_object__find_map_fd_by_name(p->obj_, "md_ports");
  p->flows_fd_ = bpf_object__find_map_fd_by_name(p->obj_, "utcp_flows");
  p->tcp_ports_fd_ = bpf_object__find_map_fd_by_name(p->obj_, "utcp_ports");
  p->stats_fd_ = bpf_object__find_map_fd_by_name(p->obj_, "md_stats");
  p->ncpus_ = libbpf_num_possible_cpus();
  if (p->ncpus_ < 1) p->ncpus_ = 1;
  // Native (driver) mode; a device-bound program can only attach there.
  p->attach_flags_ = XDP_FLAGS_DRV_MODE;
  int rc = bpf_xdp_attach(p->ifindex_, p->prog_fd_, p->attach_flags_, nullptr);
  if (rc != 0 && cfg.allow_skb_mode && !p->dev_bound_) {
    p->attach_flags_ = XDP_FLAGS_SKB_MODE;
    rc = bpf_xdp_attach(p->ifindex_, p->prog_fd_, p->attach_flags_, nullptr);
    if (rc == 0) {
      p->mode_ = AttachMode::Skb;
      p->note_ += "; attached in SKB (generic) mode";
    }
  }
  if (rc != 0) {
    p->attach_flags_ = 0;
    return std::unexpected(Error{-rc, "bpf_xdp_attach"});
  }
  return p;
}

SteerProgram::~SteerProgram() {
  if (attach_flags_ != 0) (void)bpf_xdp_detach(ifindex_, attach_flags_, nullptr);
  if (obj_ != nullptr) bpf_object__close(obj_);
}

bool SteerProgram::add_md_port(std::uint16_t port) {
  const std::uint16_t k = htons(port);
  const std::uint8_t v = 1;
  return bpf_map_update_elem(md_ports_fd_, &k, &v, BPF_ANY) == 0;
}

bool SteerProgram::remove_md_port(std::uint16_t port) {
  const std::uint16_t k = htons(port);
  return bpf_map_delete_elem(md_ports_fd_, &k) == 0;
}

bool SteerProgram::add_utcp_flow(const UtcpFlow& f) {
  const FlowKeyWire k = wire(f);
  const std::uint8_t v = 1;
  return bpf_map_update_elem(flows_fd_, &k, &v, BPF_ANY) == 0;
}

bool SteerProgram::remove_utcp_flow(const UtcpFlow& f) {
  const FlowKeyWire k = wire(f);
  return bpf_map_delete_elem(flows_fd_, &k) == 0;
}

bool SteerProgram::add_utcp_port(std::uint16_t port) {
  const std::uint16_t k = htons(port);
  const std::uint8_t v = 1;
  return bpf_map_update_elem(tcp_ports_fd_, &k, &v, BPF_ANY) == 0;
}

bool SteerProgram::set_xsk(std::uint32_t queue, int xsk_fd) {
  const auto v = static_cast<std::uint32_t>(xsk_fd);
  return bpf_map_update_elem(xsks_fd_, &queue, &v, BPF_ANY) == 0;
}

bool SteerProgram::clear_xsk(std::uint32_t queue) { return bpf_map_delete_elem(xsks_fd_, &queue) == 0; }

SteerStats SteerProgram::stats() const {
  SteerStats s;
  std::vector<std::uint64_t> vals(static_cast<std::size_t>(ncpus_));
  auto sum = [&](std::uint32_t key) {
    std::uint64_t t = 0;
    if (bpf_map_lookup_elem(stats_fd_, &key, vals.data()) == 0) {
      for (auto v : vals) t += v;
    }
    return t;
  };
  s.pass = sum(0);
  s.redirect_udp = sum(1);
  s.redirect_tcp = sum(2);
  s.drop_tcp = sum(3);
  s.meta_ts = sum(4);
  s.meta_nodata = sum(5);
  s.meta_fail = sum(6);
  s.udp_no_xsk = sum(7);
  return s;
}

}  // namespace lle::net::xsk
