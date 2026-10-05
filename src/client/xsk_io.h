#pragma once
// XskIo: the client programs' I/O over AF_XDP (variants (iv) and (iv-t); 07 §1, §2.3,
// §2.4). One AF_XDP socket on (ifname, queue) carries both consumers:
//   - datagrams (XskDatagramPort, consumer 0): line A, line B and the request port's
//     replies, steered by md_steer's md_ports; multicast groups joined through
//     MulticastMembership (the kernel answers IGMP);
//   - streams (utcp over StampingFramePort, consumer 1): each connection's exact
//     5-tuple is registered in md_steer's utcp_flows before the SYN leaves.
// The kernel keeps the interface address and answers ARP; next hops come from
// --next-hop-mac (direct cable) or the kernel neighbour table, resolved at open().
// utcp's ISN key comes from the OS CSPRNG (env::os_entropy64; RFC 6528).
//
// TX timestamps (07 §2.5). StampingFramePort requests a TX-metadata timestamp only for
// frames carrying new stream data (FrameStampTracker), tags each with the tracker's
// frame id as its TX cookie, and registers itself as the socket's completion handler
// (XskSocket::set_tx_completion_handler): every reap path of the socket (flush(), the
// internal reaps of tx_acquire()/tx_commit(), explicit reaps) reports each stamped
// completion with its cookie, and the tracker matches it by id. A stamped frame whose
// completion is never reported is counted lost rather than shifting later stamps.
// check_tx_stamp_alignment() still compares the socket's count of timestamped
// completions with the ones delivered here. Copy mode (veth, virtio) reports no
// hardware stamps at all (TxCompletion::valid is false; the socket only counts them).
//
// Linux with libbpf only (LLE_CLIENT_HAVE_XSK).
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "client/report.h"
#include "client/tx_stamps.h"
#include "client/variant.h"
#include "common/endian.h"
#include "env/entropy.h"
#include "env/prod_clock.h"
#include "net/utcp/linux/af_packet_port.h"
#include "net/utcp/linux/neigh_netlink.h"
#include "net/utcp/stream_port.h"
#include "net/xsk/datagram_port.h"
#include "net/xsk/frame_port.h"
#include "net/xsk/multicast.h"
#include "net/xsk/napi.h"
#include "net/xsk/socket.h"
#include "net/xsk/steer.h"
#include "net/xsk/umem.h"

namespace lle::client {

// First IPv4 address of `ifname` (host order).
inline std::optional<std::uint32_t> interface_ipv4(const std::string& ifname) {
  ifaddrs* list = nullptr;
  if (::getifaddrs(&list) != 0) return std::nullopt;
  std::optional<std::uint32_t> out;
  for (ifaddrs* a = list; a != nullptr; a = a->ifa_next) {
    if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_INET || ifname != a->ifa_name) continue;
    sockaddr_in sin;
    std::memcpy(&sin, a->ifa_addr, sizeof sin);
    out = ntohl(sin.sin_addr.s_addr);
    break;
  }
  ::freeifaddrs(list);
  return out;
}

// The md_steer program of one interface, shared by every XskIo on it (one per thread).
class XskEnv {
 public:
  static std::shared_ptr<XskEnv> acquire(const VariantConfig& v, std::string& err) {
    static std::mutex mu;
    static std::vector<std::weak_ptr<XskEnv>> live;
    std::lock_guard<std::mutex> g(mu);
    for (auto& w : live) {
      if (auto p = w.lock(); p && p->ifname_ == v.ifname) return p;
    }
    net::xsk::SteerConfig sc;
#if defined(LLE_XSK_BPF_OBJECT)
    sc.object_path = v.xsk.bpf_object.empty() ? std::string(LLE_XSK_BPF_OBJECT) : v.xsk.bpf_object;
#else
    sc.object_path = v.xsk.bpf_object;
#endif
    sc.ifname = v.ifname;
    sc.want_metadata = true;
    sc.allow_skb_mode = v.xsk.allow_skb_mode;
    auto prog = net::xsk::SteerProgram::load(sc);
    if (!prog) {
      err = std::string("md_steer load on ") + v.ifname + ": " + prog.error().what + ": " + std::strerror(prog.error().err);
      return nullptr;
    }
    auto e = std::shared_ptr<XskEnv>(new XskEnv(v.ifname, std::move(*prog)));
    live.push_back(e);
    return e;
  }
  [[nodiscard]] net::xsk::SteerProgram& steer() noexcept { return *prog_; }

 private:
  XskEnv(std::string ifname, std::unique_ptr<net::xsk::SteerProgram> p) : ifname_(std::move(ifname)), prog_(std::move(p)) {}
  std::string ifname_;
  std::unique_ptr<net::xsk::SteerProgram> prog_;
};

// utcp FramePort over an XskSocket with selective TX timestamps (see the file comment).
class StampingFramePort {
 public:
  static constexpr int kConsumer = 1;

  StampingFramePort(net::xsk::XskSocket& s, FrameStampTracker& t, bool stamps, bool csum_offload, std::uint32_t tx_ring)
      : s_(s), t_(t), stamps_(stamps), csum_(csum_offload), tx_limit_(tx_ring > 64 ? tx_ring - 32 : tx_ring / 2) {
    s_.set_tx_completion_handler(&StampingFramePort::on_tx_done, this);
  }
  ~StampingFramePort() { s_.set_tx_completion_handler(nullptr, nullptr); }
  // The socket holds a pointer to this object.
  StampingFramePort(const StampingFramePort&) = delete;
  StampingFramePort& operator=(const StampingFramePort&) = delete;

  bool send_frame(std::span<const std::byte> f) noexcept {
    std::span<std::byte> b = tx_acquire();
    if (b.size() < f.size()) {
      if (!b.empty()) tx_commit(0);
      return false;
    }
    std::memcpy(b.data(), f.data(), f.size());
    tx_commit(f.size());
    return true;
  }

  // Empty while the TX ring is nearly full (utcp retries later), so a stamped frame is
  // never refused by a full ring.
  std::span<std::byte> tx_acquire() noexcept {
    if (outstanding() >= tx_limit_) {
      reap();
      if (outstanding() >= tx_limit_) {
        ++throttled_;
        return {};
      }
    }
    pending_ = s_.tx_acquire();
    return pending_;
  }

  void tx_commit(std::size_t n) noexcept {
    net::xsk::TxOptions o;
    if (n != 0 && n <= pending_.size()) {
      const std::span<const std::byte> frame = pending_.first(n);
      if (stamps_ && t_.on_tx(frame)) {
        o.timestamp = true;
        o.cookie = t_.last_id();
      }
      if (csum_) set_tcp_csum(o, frame);
    }
    const bool ok = s_.tx_commit(n, o);
    pending_ = {};
    if (n == 0) return;
    if (ok) {
      dirty_ = true;
    } else {
      // A stamped frame that never left: its id is skipped (counted lost) when a later
      // stamped completion is matched.
      ++commit_failed_;
    }
  }

  void flush() noexcept {
    if (dirty_) {
      dirty_ = false;
      ++kicks_;
    }
    s_.flush();  // kicks TX when needed; its reap reports stamps through on_tx_done
  }

  template <class Cb>
  std::size_t poll_frames(Cb&& cb, std::uint32_t budget = 64) {
    return s_.poll_rx(
        kConsumer,
        [&](std::span<const std::byte> f, const net::xsk::RxMeta& m) {
          if (net::xsk::XskFramePort::is_ipv4_proto(f, net::utcp::kIpProtoUdp)) return false;  // the datagram consumer's
          cb(f, m.hw_rx_ns);
          return true;
        },
        budget);
  }

  void reap() noexcept { (void)s_.reap(); }

  [[nodiscard]] std::uint64_t outstanding() const noexcept { return s_.tx_outstanding(); }
  [[nodiscard]] std::uint64_t stamped_completions() const noexcept { return stamped_completions_; }
  [[nodiscard]] std::uint64_t throttled() const noexcept { return throttled_; }
  [[nodiscard]] std::uint64_t commit_failed() const noexcept { return commit_failed_; }
  [[nodiscard]] std::uint64_t kicks() const noexcept { return kicks_; }
  [[nodiscard]] net::xsk::XskSocket& socket() noexcept { return s_; }

 private:
  // Every stamped completion, from whichever socket call reaped it. hw_tx_ns is 0 unless
  // the socket reports a hardware timestamp (zero-copy only).
  static void on_tx_done(void* ctx, const net::xsk::TxCompletion& c) noexcept {
    auto* self = static_cast<StampingFramePort*>(ctx);
    if (!c.ts_requested) return;
    ++self->stamped_completions_;
    self->t_.on_completion_for(c.cookie, c.valid ? c.hw_tx_ns : Nanos{0});
  }

  void set_tcp_csum(net::xsk::TxOptions& o, std::span<const std::byte> b) noexcept {
    if (!net::xsk::XskFramePort::is_ipv4_proto(b, net::utcp::kIpProtoTcp)) return;
    const std::size_t ihl = std::size_t{std::to_integer<std::uint8_t>(b[net::utcp::kEthHeaderLen]) & 0x0Fu} * 4;
    o.checksum = true;
    o.csum_start = static_cast<std::uint16_t>(net::utcp::kEthHeaderLen + ihl);
    o.csum_offset = 16;
  }

  net::xsk::XskSocket& s_;
  FrameStampTracker& t_;
  bool stamps_, csum_;
  std::uint64_t tx_limit_;
  std::span<std::byte> pending_{};
  bool dirty_ = false;
  std::uint64_t stamped_completions_ = 0;
  std::uint64_t throttled_ = 0, commit_failed_ = 0, kicks_ = 0;
};

class XskIo {
 public:
  static constexpr bool kIsXsk = true;
  using Stack = net::utcp::UtcpStreamPort<StampingFramePort, env::ProdClock>;

  explicit XskIo(const VariantConfig& v) : v_(v) {}
  XskIo(const XskIo&) = delete;
  XskIo& operator=(const XskIo&) = delete;
  ~XskIo() {
    if (env_ && sock_) {
      for (const Conn& c : conns_)
        if (c.id != env::kNoConn) (void)env_->steer().remove_utcp_flow(c.flow);
      (void)env_->steer().clear_xsk(v_.xsk.queue);
    }
  }

  std::expected<void, std::string> open(const IoSpec& s) {
    spec_ = s;
    std::string err;
    env_ = XskEnv::acquire(v_, err);
    if (!env_) return std::unexpected(err);
    auto mac = net::utcp::interface_mac(v_.ifname);
    if (!mac) return std::unexpected("interface_mac(" + v_.ifname + "): " + std::strerror(mac.error()));
    mac_ = *mac;
    if (v_.xsk.local_ip == 0) {
      const auto ip = interface_ipv4(v_.ifname);
      if (!ip) return std::unexpected(v_.ifname + " has no IPv4 address (or pass --local-ip)");
      v_.xsk.local_ip = *ip;
    }
    ifindex_ = static_cast<int>(::if_nametoindex(v_.ifname.c_str()));
    udp_port_ = v_.xsk.udp_port != 0 ? v_.xsk.udp_port : v_.xsk.port_hi;

    net::xsk::UmemConfig uc;
    uc.frame_count = v_.xsk.umem_frames;
    auto umem = net::xsk::Umem::create(uc);
    if (!umem) return std::unexpected(std::string("umem: ") + umem.error().what + ": " + std::strerror(umem.error().err));
    umem_ = std::move(*umem);
    net::xsk::XskConfig xc;
    xc.ifname = v_.ifname;
    xc.queue = v_.xsk.queue;
    xc.mode = v_.xsk.allow_copy ? net::xsk::BindMode::AllowCopy : net::xsk::BindMode::ZeroCopyRequired;
    xc.busy_poll = v_.xsk.busy_poll;
    xc.rx_metadata = true;
    // Receive headroom: 4,096 frames on FILL/RX ride out a stall of the polling thread of
    // about 200 ms at 20k packets/s before the kernel drops (rx_fill_ring_empty).
    xc.rx_size = 4096;
    xc.fill_size = 4096;
    xc.fill_frames = 4096;
    auto sock = net::xsk::XskSocket::create(*umem_, xc);
    if (!sock)
      return std::unexpected(std::string("xsk socket on ") + v_.ifname + " queue " + std::to_string(v_.xsk.queue) + ": " +
                             sock.error().what + ": " + std::strerror(sock.error().err));
    sock_ = std::move(*sock);
    if (!env_->steer().set_xsk(v_.xsk.queue, sock_->fd())) return std::unexpected("md_steer: set_xsk failed");

    if (v_.variant == Variant::XskThreaded) {
      if (auto r = threaded_napi(); !r) return r;
    }

    // Datagrams.
    const DatagramSpec& d = s.dgram;
    const bool want_dgram = d.line_a.port != 0 || d.line_b.port != 0 || d.request_port;
    if (want_dgram) {
      net::xsk::XskDatagramConfig dc;
      dc.local_mac = mac_;
      dc.local_ip = v_.xsk.local_ip;
      dc.local_port = udp_port_;
      dc.static_next_hop = v_.xsk.next_hop;
      std::size_t k = 0;
      for (const net::Endpoint& ep : {d.line_a, d.line_b}) {
        if (ep.port == 0) continue;
        dc.rx_ports[k++] = ep.port;
        if (!env_->steer().add_md_port(ep.port)) return std::unexpected("md_steer: add_md_port failed");
        if (net::is_multicast(ep.ipv4)) {
          auto j = net::xsk::MulticastMembership::join(v_.ifname, ep.ipv4);
          if (!j) return std::unexpected(std::string("multicast join: ") + j.error().what);
          joins_.push_back(std::move(*j));
        }
      }
      if (d.request_port) {
        dc.rx_ports[k++] = udp_port_;
        if (!env_->steer().add_md_port(udp_port_)) return std::unexpected("md_steer: add_md_port failed");
        for (std::size_t i = 0; i < 2; ++i) {
          const net::Endpoint& srv = d.request_servers[i];
          if (srv.port == 0) continue;
          const auto m = next_hop(srv.ipv4);
          if (!m) return std::unexpected("no next hop for request server " + net::to_string(srv));
          req_mac_[i] = *m;
        }
      }
      dc.share_with_frames = true;
      dc.checksum_offload = false;
      dport_.emplace(*sock_, dc);
      line_ep_[0] = d.line_a;
      line_ep_[1] = d.line_b;
    }

    // Streams.
    tracker_.init(s.stream.tx_stamp_capacity);
    fport_.emplace(*sock_, tracker_, v_.timestamps != net::TsMode::Off, v_.xsk.checksum_offload, xc.tx_size);
    if (s.stream.enabled) {
      net::utcp::StackConfig sc;
      sc.local_mac = mac_;
      sc.local_ip = v_.xsk.local_ip;
      sc.static_next_hop = v_.xsk.next_hop;
      sc.arp_reply = false;  // the kernel owns the address and answers ARP
      sc.max_connections = static_cast<std::uint16_t>(std::min<std::uint32_t>(s.stream.max_conns, 1024));
      sc.ephemeral_lo = v_.xsk.port_lo;
      sc.ephemeral_hi = v_.xsk.port_hi;
      sc.conn.tx_checksum_offload = v_.xsk.checksum_offload;
      sc.conn.tx_buffer = std::max<std::uint32_t>(sc.conn.tx_buffer, s.stream.tx_staging_bytes * 4);
      sc.isn_secret = env::os_entropy64();  // RFC 6528 F() key: never the compiled-in default
      stack_ = std::make_unique<Stack>(*fport_, clock_, sc);
      for (const net::Endpoint& p : s.stream.peers) {
        if (p.port == 0 || v_.xsk.next_hop) continue;
        const auto m = next_hop(p.ipv4);
        if (!m) return std::unexpected("no next hop for " + net::to_string(p) + " (kernel neighbour resolution failed)");
        (void)stack_->neighbors().set(p.ipv4, *m, true);
      }
      next_port_ = v_.xsk.port_lo;
    }
    return {};
  }

  int wait(Nanos) noexcept { return 0; }  // ring polling (with socket or threaded busy polling)

  template <class F>
  std::size_t poll_datagrams(F&& f) {
    if (!dport_) return 0;
    return dport_->poll_rx([&](const env::RxDatagram& r) {
      const net::RxTimestamps ts{0, r.hw_rx_ns};
      if (line_ep_[0].port != 0 && r.dst == line_ep_[0]) {
        f(Chan::LineA, r, ts);
      } else if (line_ep_[1].port != 0 && r.dst == line_ep_[1]) {
        f(Chan::LineB, r, ts);
      } else if (r.dst.port == udp_port_) {
        f(Chan::Request, r, ts);
      }
    });
  }

  // A datagram from the request port, built in a UMEM frame through the stamping port
  // (it shares the stream port's TX throttle; UDP frames never request a stamp).
  bool send_request(net::Endpoint dst, std::span<const std::byte> payload) noexcept {
    if (!dport_ || !fport_ || dst.port == 0) return false;  // no re-request server configured
    // The resolved next hop of the server addressed (both servers may share an address).
    const net::utcp::MacAddr m = dst.ipv4 == spec_.dgram.request_servers[0].ipv4 ? req_mac_[0] : req_mac_[1];
    if (m.is_zero() && !v_.xsk.next_hop) return false;
    std::span<std::byte> b = fport_->tx_acquire();
    if (b.size() < net::utcp::kUdpFrameOverhead + payload.size()) {
      if (!b.empty()) fport_->tx_commit(0);
      return false;
    }
    std::memcpy(b.data() + net::utcp::kUdpFrameOverhead, payload.data(), payload.size());
    net::utcp::UdpHeaderSpec h;
    h.src_mac = mac_;
    h.dst_mac = v_.xsk.next_hop ? *v_.xsk.next_hop : m;
    h.src_ip = v_.xsk.local_ip;
    h.dst_ip = dst.ipv4;
    h.src_port = udp_port_;
    h.dst_port = dst.port;
    h.ip_id = ip_id_++;
    const std::size_t n = net::utcp::finish_udp_in_place(b, h, payload.size(), false);
    fport_->tx_commit(n);
    fport_->flush();
    return n != 0;
  }

  std::optional<env::ConnId> connect(net::Endpoint dst) {
    if (!stack_) return std::nullopt;
    const std::uint32_t span = std::uint32_t{v_.xsk.port_hi} - v_.xsk.port_lo + 1;
    for (std::uint32_t k = 0; k < span; ++k) {
      const std::uint16_t port = next_port_;
      next_port_ = port >= v_.xsk.port_hi ? v_.xsk.port_lo : static_cast<std::uint16_t>(port + 1);
      if (port == udp_port_ || port_in_use(port)) continue;
      const net::xsk::UtcpFlow flow{dst.ipv4, v_.xsk.local_ip, dst.port, port};
      if (!env_->steer().add_utcp_flow(flow)) return std::nullopt;  // flow table full
      auto c = stack_->connect_from(dst, port);
      if (!c) {
        (void)env_->steer().remove_utcp_flow(flow);
        continue;
      }
      for (Conn& x : conns_) {
        if (x.id == env::kNoConn) {
          x = Conn{*c, port, flow};
          return *c;
        }
      }
      stack_->abort(*c);
      (void)env_->steer().remove_utcp_flow(flow);
      return std::nullopt;
    }
    return std::nullopt;
  }

  std::size_t write(env::ConnId c, std::span<const std::byte> b) { return stack_ ? stack_->write(c, b) : 0; }

  void close(env::ConnId c) {
    if (!stack_) return;
    stack_->close(c);
    release(c);
  }

  template <class F>
  std::size_t poll_streams(F&& f) {
    if (!stack_) {
      if (fport_) fport_->flush();
      return 0;
    }
    return stack_->poll([&](const env::StreamEvent& ev) {
      if (ev.kind == env::StreamEventKind::Closed) release(ev.conn);
      f(ev);
    });
  }

  template <class F>
  std::size_t drain_tx_stamps(F&& f) {
    if (!fport_) return 0;
    fport_->reap();
    return tracker_.drain([&](const FrameStampTracker::Stamped& s) {
      for (const Conn& c : conns_) {
        if (c.id != env::kNoConn && c.port == s.local_port) {
          f(c.id, s.stamp);
          return;
        }
      }
    });
  }

  // False when timestamped completions were reaped outside StampingFramePort (their
  // stamps are lost and the in-flight attribution cannot be trusted). Reads the socket's
  // counters (one getsockopt): call it at the end of a run, off the hot path.
  [[nodiscard]] bool check_tx_stamp_alignment() const {
    if (!sock_ || !fport_) return true;
    const net::xsk::XskStats st = sock_->stats();
    return st.tx_ts_completions == fport_->stamped_completions() && st.tx_ring_full == 0;
  }

  void stats_json(JsonObject& j) const {
    if (!sock_) return;
    const net::xsk::XskStats st = sock_->stats();
    j.boolean("xsk_zero_copy", sock_->zero_copy()).boolean("xsk_busy_poll_enabled", sock_->busy_poll_enabled());
    j.num("xsk_rx_frames", st.rx_frames).num("xsk_tx_frames", st.tx_frames).num("xsk_drops", st.drops());
    j.num("xsk_rx_dropped", st.rx_dropped).num("xsk_rx_ring_full", st.rx_ring_full);
    j.num("xsk_fill_ring_empty", st.rx_fill_ring_empty_descs).num("xsk_tx_ring_full", st.tx_ring_full);
    j.num("xsk_tx_no_frame", st.tx_no_frame).num("xsk_stash_dropped", st.stash_dropped);
    j.num("xsk_rx_meta_ts_valid", st.rx_meta_ts_valid).num("xsk_rx_meta_ts_copy_mode", st.rx_meta_ts_copy_mode);
    j.num("xsk_tx_ts_completions", st.tx_ts_completions);
    if (fport_) {
      j.num("xsk_stamped_completions_seen", fport_->stamped_completions()).num("xsk_tx_throttled", fport_->throttled());
      j.num("xsk_tx_commit_failed", fport_->commit_failed()).num("xsk_tx_kicks", fport_->kicks());
      j.boolean("xsk_tx_stamps_aligned", check_tx_stamp_alignment());
    }
    j.num("tx_stamp_retransmissions", tracker_.retransmissions()).num("tx_stamp_dropped", tracker_.dropped());
    j.num("tx_stamp_unmatched_completions", tracker_.unmatched_completions());
    j.num("tx_stamp_lost_completions", tracker_.lost_completions());
    if (env_) {
      const net::xsk::SteerStats ss = env_->steer().stats();
      j.str("steer_mode", env_->steer().attach_mode() == net::xsk::AttachMode::Native ? "native" : "skb");
      j.boolean("steer_metadata_kfunc", env_->steer().metadata_kfunc());
      j.num("steer_redirect_udp", ss.redirect_udp).num("steer_redirect_tcp", ss.redirect_tcp);
      j.num("steer_drop_tcp", ss.drop_tcp).num("steer_pass", ss.pass).num("steer_udp_no_xsk", ss.udp_no_xsk);
    }
    if (dport_) {
      const auto& ds = dport_->stats();
      j.num("xsk_udp_received", ds.received).num("xsk_udp_filtered", ds.rx_filtered).num("xsk_udp_bad", ds.rx_bad);
    }
    if (stack_) {
      const auto& us = stack_->stats();
      j.num("utcp_frames_in", us.frames_in).num("utcp_frames_out", us.frames_out).num("utcp_rst_sent", us.rst_sent);
      j.num("utcp_tx_full", us.tx_full).num("utcp_closed_reset", us.closed_reset);
      j.num("utcp_closed_timeout", us.closed_timeout);
    }
    j.inum("napi_kthread_pid", napi_pid_);
  }

  [[nodiscard]] const VariantConfig& variant() const noexcept { return v_; }
  [[nodiscard]] bool zero_copy() const noexcept { return sock_ && sock_->zero_copy(); }

 private:
  struct Conn {
    env::ConnId id = env::kNoConn;
    std::uint16_t port = 0;
    net::xsk::UtcpFlow flow{};
  };

  std::optional<net::utcp::MacAddr> next_hop(std::uint32_t ip) const {
    if (v_.xsk.next_hop) return v_.xsk.next_hop;
    return net::utcp::resolve_via_kernel(v_.ifname, ip, 3000);
  }

  bool port_in_use(std::uint16_t p) const noexcept {
    for (const Conn& c : conns_)
      if (c.id != env::kNoConn && c.port == p) return true;
    return false;
  }

  void release(env::ConnId id) {
    for (Conn& c : conns_) {
      if (c.id != id) continue;
      (void)env_->steer().remove_utcp_flow(c.flow);
      tracker_.forget(c.port);
      c = Conn{};
    }
  }

  // (iv-t): the queue's NAPI instance polled by its own kthread (napi-set threaded=
  // busy-poll, 6.19), pinned to --napi-cpu. Applied with --device-setup, else verified.
  std::expected<void, std::string> threaded_napi() {
    const auto id = net::xsk::napi_id_for_rx_queue(ifindex_, v_.xsk.queue);
    if (!id) return std::unexpected("(iv-t): no NAPI id for queue " + std::to_string(v_.xsk.queue) + ": " +
                                    std::strerror(id.error()));
    if (v_.device_setup) {
      if (auto r = net::xsk::napi_set_threaded(*id, net::xsk::NapiThreaded::BusyPoll); !r)
        return std::unexpected(std::string("(iv-t): napi-set threaded=busy-poll: ") + std::strerror(r.error()));
    }
    const auto info = net::xsk::napi_get(*id);
    if (!info) return std::unexpected(std::string("(iv-t): napi-get: ") + std::strerror(info.error()));
    if (info->threaded != static_cast<std::int32_t>(net::xsk::NapiThreaded::BusyPoll))
      return std::unexpected("(iv-t): NAPI " + std::to_string(*id) + " is not in threaded busy-poll mode");
    napi_pid_ = info->pid;
    if (v_.napi_cpu >= 0 && !pin_task(info->pid, v_.napi_cpu))
      return std::unexpected("(iv-t): cannot pin the NAPI kthread to CPU " + std::to_string(v_.napi_cpu));
    return {};
  }

  VariantConfig v_;
  IoSpec spec_{};
  std::shared_ptr<XskEnv> env_;
  net::utcp::MacAddr mac_{};
  int ifindex_ = 0;
  std::uint16_t udp_port_ = 0;
  std::unique_ptr<net::xsk::Umem> umem_;
  std::unique_ptr<net::xsk::XskSocket> sock_;
  std::vector<net::xsk::MulticastMembership> joins_;
  std::optional<net::xsk::XskDatagramPort> dport_;
  net::Endpoint line_ep_[2]{};
  net::utcp::MacAddr req_mac_[2]{};
  std::uint16_t ip_id_ = 0;
  FrameStampTracker tracker_;
  std::optional<StampingFramePort> fport_;
  env::ProdClock clock_;
  std::unique_ptr<Stack> stack_;
  std::array<Conn, 64> conns_{};
  std::uint16_t next_port_ = 0;
  std::int32_t napi_pid_ = -1;
};

}  // namespace lle::client
