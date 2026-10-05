#include "client/variant.h"

#include <charconv>
#include <cstdio>
#include <fstream>

#include "client/report.h"
#include "net/hwts/device.h"
#if defined(__linux__)
#include <sched.h>

#include "net/busypoll/busypoll.h"
#endif

namespace lle::client {

const char* to_string(Variant v) noexcept {
  switch (v) {
    case Variant::Epoll: return "epoll";
    case Variant::BusyPoll: return "busypoll";
    case Variant::BusyPollIrqSuspend: return "busypoll-irq-suspend";
    case Variant::Uring: return "uring";
    case Variant::UringNapi: return "uring-napi";
    case Variant::Xsk: return "xsk";
    case Variant::XskThreaded: return "xsk-threaded";
  }
  return "?";
}

const char* methodology_label(Variant v) noexcept {
  switch (v) {
    case Variant::Epoll: return "(i)";
    case Variant::BusyPoll: return "(ii)";
    case Variant::BusyPollIrqSuspend: return "(ii-s)";
    case Variant::Uring: return "(iii)";
    case Variant::UringNapi: return "(iii-n)";
    case Variant::Xsk: return "(iv)";
    case Variant::XskThreaded: return "(iv-t)";
  }
  return "?";
}

std::optional<Variant> parse_variant(std::string_view s) noexcept {
  for (const Variant v : kAllVariants)
    if (s == to_string(v)) return v;
  if (s == "sock" || s == "kqueue" || s == "i") return Variant::Epoll;
  if (s == "ii") return Variant::BusyPoll;
  if (s == "ii-s" || s == "irq-suspend") return Variant::BusyPollIrqSuspend;
  if (s == "iii") return Variant::Uring;
  if (s == "iii-n") return Variant::UringNapi;
  if (s == "iv") return Variant::Xsk;
  if (s == "iv-t") return Variant::XskThreaded;
  return std::nullopt;
}

net::BackendKind backend_of(Variant v) noexcept {
  switch (v) {
    case Variant::Epoll: return net::BackendKind::Epoll;
    case Variant::BusyPoll:
    case Variant::BusyPollIrqSuspend: return net::BackendKind::BusyPoll;
    case Variant::Uring: return net::BackendKind::Uring;
    case Variant::UringNapi: return net::BackendKind::UringNapi;
    case Variant::Xsk:
    case Variant::XskThreaded: return net::BackendKind::Xsk;
  }
  return net::BackendKind::Epoll;
}

bool variant_compiled(Variant v) noexcept {
  if (is_xsk(v)) {
#if defined(LLE_CLIENT_HAVE_XSK)
    return true;
#else
    return false;
#endif
  }
  return net::backend_compiled(backend_of(v));
}

std::optional<net::TsMode> parse_ts_mode(std::string_view s) noexcept {
  if (s == "off" || s == "none") return net::TsMode::Off;
  if (s == "software" || s == "sw") return net::TsMode::Software;
  if (s == "hardware" || s == "hw") return net::TsMode::Hardware;
  return std::nullopt;
}

const char* to_string(net::TsMode m) noexcept {
  switch (m) {
    case net::TsMode::Off: return "off";
    case net::TsMode::Software: return "software";
    case net::TsMode::Hardware: return "hardware";
  }
  return "?";
}

const char* to_string(net::WaitPolicy w) noexcept {
  switch (w) {
    case net::WaitPolicy::Default: return "default";
    case net::WaitPolicy::Spin: return "spin";
    case net::WaitPolicy::Block: return "block";
  }
  return "?";
}

std::optional<net::utcp::MacAddr> parse_mac(std::string_view s) noexcept {
  net::utcp::MacAddr m;
  std::size_t pos = 0;
  for (std::size_t i = 0; i < 6; ++i) {
    if (pos + 2 > s.size()) return std::nullopt;
    unsigned v = 0;
    const auto r = std::from_chars(s.data() + pos, s.data() + pos + 2, v, 16);
    if (r.ec != std::errc{} || r.ptr != s.data() + pos + 2) return std::nullopt;
    m.b[i] = static_cast<std::uint8_t>(v);
    pos += 2;
    if (i < 5) {
      if (pos >= s.size() || (s[pos] != ':' && s[pos] != '-')) return std::nullopt;
      ++pos;
    }
  }
  if (pos != s.size()) return std::nullopt;
  return m;
}

bool parse_variant_flag(cli::Args& a, const std::string& f, VariantConfig& v) {
  if (f == "--variant" || f == "--backend") {
    const std::string s = a.value();
    const auto p = parse_variant(s);
    if (!p) a.die("unknown variant '" + s + "' (epoll busypoll busypoll-irq-suspend uring uring-napi xsk xsk-threaded)");
    v.variant = *p;
  } else if (f == "--ifname" || f == "--if") {
    v.ifname = a.value();
  } else if (f == "--timestamps") {
    const std::string s = a.value();
    const auto m = parse_ts_mode(s);
    if (!m) a.die("--timestamps: off | software | hardware");
    v.timestamps = *m;
  } else if (f == "--wait") {
    const std::string s = a.value();
    if (s == "default") v.wait = net::WaitPolicy::Default;
    else if (s == "spin") v.wait = net::WaitPolicy::Spin;
    else if (s == "block") v.wait = net::WaitPolicy::Block;
    else a.die("--wait: default | spin | block");
  } else if (f == "--cpu") {
    v.cpu = static_cast<int>(a.u64());
  } else if (f == "--napi-cpu") {
    v.napi_cpu = static_cast<int>(a.u64());
  } else if (f == "--device-setup") {
    v.device_setup = true;
  } else if (f == "--xsk-queue") {
    v.xsk.queue = static_cast<std::uint32_t>(a.u64());
  } else if (f == "--xsk-allow-copy") {
    v.xsk.allow_copy = true;
  } else if (f == "--xsk-no-busy-poll") {
    v.xsk.busy_poll = false;
  } else if (f == "--xsk-bpf") {
    v.xsk.bpf_object = a.value();
  } else if (f == "--xsk-skb-mode") {
    v.xsk.allow_skb_mode = true;
  } else if (f == "--local-ip") {
    const std::string s = a.value();
    const auto e = net::parse_endpoint(s + ":0");
    if (!e) a.die("bad --local-ip: " + s);
    v.xsk.local_ip = e->ipv4;
  } else if (f == "--next-hop-mac") {
    const std::string s = a.value();
    const auto m = parse_mac(s);
    if (!m) a.die("bad --next-hop-mac: " + s);
    v.xsk.next_hop = *m;
  } else if (f == "--utcp-ports") {
    const std::string s = a.value();
    const auto dash = s.find('-');
    if (dash == std::string::npos) a.die("--utcp-ports LO-HI");
    const std::uint64_t lo = a.parse_u64(s.substr(0, dash)), hi = a.parse_u64(s.substr(dash + 1));
    if (lo == 0 || hi < lo || hi > 65535) a.die("bad --utcp-ports: " + s);
    v.xsk.port_lo = static_cast<std::uint16_t>(lo);
    v.xsk.port_hi = static_cast<std::uint16_t>(hi);
  } else if (f == "--xsk-udp-port") {
    v.xsk.udp_port = static_cast<std::uint16_t>(a.u64());
  } else if (f == "--umem-frames") {
    v.xsk.umem_frames = static_cast<std::uint32_t>(a.u64());
  } else if (f == "--xsk-csum-offload") {
    v.xsk.checksum_offload = true;
  } else {
    return false;
  }
  return true;
}

const char* variant_flags_usage() noexcept {
  return "  variant: --variant epoll|busypoll|busypoll-irq-suspend|uring|uring-napi|xsk|xsk-threaded\n"
         "           [--ifname IF] [--timestamps off|software|hardware] [--wait default|spin|block]\n"
         "           [--cpu N] [--device-setup]\n"
         "           xsk: [--xsk-queue Q] [--xsk-allow-copy] [--xsk-no-busy-poll] [--napi-cpu N]\n"
         "                [--local-ip IP] [--next-hop-mac MAC] [--utcp-ports LO-HI] [--xsk-udp-port P]\n"
         "                [--umem-frames N] [--xsk-bpf PATH] [--xsk-skb-mode] [--xsk-csum-offload]\n";
}

namespace {

std::int64_t read_sysctl(const char* path) {
  std::ifstream in(path);
  std::int64_t v = -1;
  if (!(in >> v)) return -1;
  return v;
}

void note(DeviceReport& rep, const std::string& s) {
  if (!rep.notes.empty()) rep.notes += "; ";
  rep.notes += s;
}

}  // namespace

bool prepare_variant(VariantConfig& v, DeviceReport& rep, std::string& err) {
  if (!variant_compiled(v.variant)) {
    err = std::string("variant ") + to_string(v.variant) + " is not compiled into this build";
    return false;
  }
  if (is_xsk(v.variant) && v.ifname.empty()) {
    err = "the xsk variants need --ifname";
    return false;
  }
  if (v.variant == Variant::XskThreaded) v.xsk.busy_poll = false;  // the kthread polls NAPI
  rep.busy_read = read_sysctl("/proc/sys/net/core/busy_read");
  rep.busy_poll = read_sysctl("/proc/sys/net/core/busy_poll");

  // NIC timestamping and the PHC (07 §2.5).
  if (!v.ifname.empty()) {
    if (auto info = net::hwts::get_ts_info(v.ifname); info) rep.phc_index = info->phc_index;
    if (auto d = net::hwts::driver_name(v.ifname); d) rep.driver = *d;
    if (auto c = net::hwts::get_hw_timestamping(v.ifname); c) rep.hw_timestamping = c->tx_type == 1 && c->rx_filter == 1;
  }
  if (v.timestamps == net::TsMode::Hardware) {
    if (v.ifname.empty()) {
      err = "--timestamps hardware needs --ifname (the PHC of every stamp must be known)";
      return false;
    }
    if (!rep.hw_timestamping && v.device_setup) {
      auto r = net::hwts::enable_hw_timestamping(v.ifname);
      if (!r) {
        err = "enable_hw_timestamping(" + v.ifname + "): " + net::to_string(r.error());
        return false;
      }
      rep.hw_timestamping = true;
      rep.phc_index = r->info.phc_index;
      rep.applied = true;
      note(rep, "hardware timestamping enabled");
    }
    if (!rep.hw_timestamping) {
      err = "hardware timestamping is off on " + v.ifname + " (run lab/tune.sh, or --device-setup as root)";
      return false;
    }
    if (rep.phc_index < 0) {
      err = v.ifname + " has no PHC";
      return false;
    }
  }

  // Busy-poll knobs: variant (i) needs busy_read = busy_poll = 0 (07 §1).
  if (v.variant == Variant::Epoll && (rep.busy_read > 0 || rep.busy_poll > 0)) {
    rep.device_ok = false;
    note(rep, "net.core.busy_read/busy_poll are not 0 (variant (i) is interrupt-driven)");
  }
#if defined(__linux__)
  if (v.variant == Variant::BusyPoll || v.variant == Variant::BusyPollIrqSuspend) {
    net::busypoll::Config bc;
    bc.mode = v.variant == Variant::BusyPollIrqSuspend ? net::busypoll::Mode::IrqSuspend : net::busypoll::Mode::Plain;
    if (v.ifname.empty()) {
      if (v.variant == Variant::BusyPollIrqSuspend) {
        err = "busypoll-irq-suspend needs --ifname (per-NAPI irq-suspend-timeout)";
        return false;
      }
      note(rep, "no interface: per-device busy-poll settings not checked");
    } else {
      if (v.device_setup) {
        if (auto r = net::busypoll::configure_device(v.ifname, bc); !r) {
          err = "busypoll::configure_device(" + v.ifname + "): " + net::to_string(r.error());
          return false;
        }
        rep.applied = true;
        note(rep, "busy-poll device settings applied");
      }
      if (auto d = net::busypoll::napi_defer_hard_irqs(v.ifname); d) rep.napi_defer_hard_irqs = static_cast<std::int64_t>(*d);
      if (auto g = net::busypoll::gro_flush_timeout(v.ifname); g) rep.gro_flush_timeout_ns = static_cast<std::int64_t>(*g);
      if (rep.napi_defer_hard_irqs != static_cast<std::int64_t>(bc.napi_defer_hard_irqs) ||
          rep.gro_flush_timeout_ns != static_cast<std::int64_t>(bc.gro_flush_timeout_ns)) {
        rep.device_ok = false;
        note(rep, "napi_defer_hard_irqs/gro_flush_timeout differ from 07 §1 (2 / 200000)");
      }
      if (bc.mode == net::busypoll::Mode::IrqSuspend) {
        net::busypoll::NapiInfo napis[64];
        std::uint32_t idx = 0;
        {
          std::ifstream in("/sys/class/net/" + v.ifname + "/ifindex");
          in >> idx;
        }
        auto n = net::busypoll::list_napi(idx, std::span<net::busypoll::NapiInfo>(napis));
        if (!n || *n == 0) {
          rep.device_ok = false;
          note(rep, "no NAPI instances listed (irq-suspend-timeout not verifiable)");
        } else {
          rep.irq_suspend_timeout_ns = static_cast<std::int64_t>(napis[0].irq_suspend_timeout_ns);
          for (std::size_t i = 0; i < std::min<std::size_t>(*n, 64); ++i) {
            if (napis[i].irq_suspend_timeout_ns != bc.irq_suspend_timeout_ns) {
              rep.device_ok = false;
              note(rep, "irq-suspend-timeout differs from 20 ms on NAPI " + std::to_string(napis[i].id));
              break;
            }
          }
        }
      }
    }
  }
#endif
  return true;
}

void variant_json(JsonObject& j, const VariantConfig& v, const DeviceReport& rep) {
  JsonObject x;
  x.str("variant", to_string(v.variant)).str("label", methodology_label(v.variant));
  x.str("backend", net::to_string(backend_of(v.variant))).str("ifname", v.ifname);
  x.str("timestamps", to_string(v.timestamps)).str("wait", to_string(v.wait)).inum("cpu", v.cpu);
  if (is_xsk(v.variant)) {
    x.num("xsk_queue", v.xsk.queue).boolean("xsk_allow_copy", v.xsk.allow_copy).boolean("xsk_busy_poll", v.xsk.busy_poll);
    x.inum("napi_cpu", v.napi_cpu).boolean("xsk_checksum_offload", v.xsk.checksum_offload);
  }
  x.boolean("device_ok", rep.device_ok).boolean("device_setup_applied", rep.applied);
  x.inum("phc_index", rep.phc_index).str("driver", rep.driver).boolean("hw_timestamping", rep.hw_timestamping);
  x.inum("napi_defer_hard_irqs", rep.napi_defer_hard_irqs).inum("gro_flush_timeout_ns", rep.gro_flush_timeout_ns);
  x.inum("irq_suspend_timeout_ns", rep.irq_suspend_timeout_ns);
  x.inum("sysctl_busy_read", rep.busy_read).inum("sysctl_busy_poll", rep.busy_poll);
  x.str("device_notes", rep.notes);
  j.raw("variant", x.done());
}

bool pin_task(int tid, int cpu) noexcept {
#if defined(__linux__)
  if (tid <= 0 || cpu < 0) return false;
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(static_cast<unsigned>(cpu), &set);
  return ::sched_setaffinity(tid, sizeof set, &set) == 0;
#else
  (void)tid;
  (void)cpu;
  return false;
#endif
}

}  // namespace lle::client
