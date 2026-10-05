#pragma once
// The I/O of the client programs behind one interface for every variant (07 §1, WP
// N-13): refclient's feed lines, re-request socket and SoupBinTCP connections, and
// loadgen's sessions, over kernel sockets (SockIo<K>: epoll, busypoll, uring,
// uring-napi) or AF_XDP with utcp (XskIo, client/xsk_io.h).
//
//   open(IoSpec)                         ports per the spec, timestamps per the variant
//   wait(max_ns)                         one wait per the variant's strategy
//   poll_datagrams(f)                    f(Chan, const env::RxDatagram&, const net::RxTimestamps&)
//   send_request(dst, bytes) -> bool     a datagram from the request port (re-requests)
//   connect(dst) -> optional<ConnId>     an active TCP open
//   write(c, bytes) -> size_t            bytes accepted (flow control: retry the rest)
//   close(c)                             local close, no event
//   poll_streams(f)                      f(const env::StreamEvent&)
//   drain_tx_stamps(f)                   f(ConnId, const StreamTxStamp&) (client/tx_stamps.h)
//   stats_json(JsonObject&)              port counters and timestamp accounting
//
// with_variant_io(v, f) calls f.template operator()<Io>() with the Io type of v's
// variant. The program code above it is identical for every variant; the pinning is
// applied by the caller from VariantConfig::cpu, so it is identical too.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

#include "client/report.h"
#include "client/tx_stamps.h"
#include "client/variant.h"
#include "env/concepts.h"
#include "net/common/endpoint.h"
#include "net/common/stack.h"
#include "net/hwts/abi.h"

namespace lle::client {

enum class Chan : std::uint8_t { LineA = 0, LineB = 1, Request = 2 };

struct DatagramSpec {
  net::Endpoint line_a{}, line_b{};  // unicast ip:port (bound) or group:port (joined); port 0: absent
  bool mcast_loop = true;            // kernel sockets: receive multicast sent on this host (tests)
  bool request_port = false;         // open the request socket (re-requests and their replies)
  bool request_loopback = false;     // bind it to 127.0.0.1 (loopback tests)
  // Re-request servers the request port talks to (AF_XDP resolves their MACs at open).
  net::Endpoint request_servers[2]{};
  int rcvbuf = 8 << 20;
  std::uint32_t batch = 32;
};

struct StreamSpec {
  bool enabled = false;
  std::uint32_t max_conns = 8;
  std::uint32_t rx_buf_bytes = 256 * 1024;
  int rcvbuf = 4 << 20;
  int sndbuf = 0;
  std::uint32_t max_reads_per_poll = 8;
  std::uint32_t tx_staging_bytes = 64 * 1024;
  // TCP destinations (AF_XDP resolves their next hops at open; kernel sockets ignore it).
  std::array<net::Endpoint, 4> peers{};
  std::size_t tx_stamp_capacity = 1 << 16;
};

struct IoSpec {
  DatagramSpec dgram;
  StreamSpec stream;
};

// ---- kernel sockets: epoll (i), busypoll (ii, ii-s), uring (iii), uring-napi (iii-n) ----
template <net::BackendKind K>
class SockIo {
 public:
  using StackT = net::Stack<K>;
  using UdpPort = typename StackT::DatagramPort;
  using TcpPort = typename StackT::StreamPort;
  static constexpr bool kIsXsk = false;
  static constexpr std::size_t kMaxConns = 64;

  explicit SockIo(const VariantConfig& v) : v_(v), stack_(v.wait) {}
  SockIo(const SockIo&) = delete;
  SockIo& operator=(const SockIo&) = delete;

  std::expected<void, std::string> open(const IoSpec& s) {
    spec_ = s;
    if (auto r = stack_.open(); !r) return fail("reactor", r.error());
    const DatagramSpec& d = s.dgram;
    if (d.line_a.port != 0) {
      if (auto r = open_line(line_[0], d.line_a); !r) return fail("line A", r.error());
      has_line_[0] = true;
    }
    if (d.line_b.port != 0) {
      if (auto r = open_line(line_[1], d.line_b); !r) return fail("line B", r.error());
      has_line_[1] = true;
    }
    if (d.request_port) {
      net::UdpConfig rq;
      rq.bind = net::Endpoint{d.request_loopback ? net::kLoopbackV4 : net::kAnyV4, 0};
      rq.rcvbuf = d.rcvbuf;
      rq.rx_ts = v_.timestamps;
      if (auto r = stack_.open(rereq_, rq); !r) return fail("request port", r.error());
      has_rereq_ = true;
    }
    if (s.stream.enabled) {
      net::TcpConfig tc;
      tc.max_conns = s.stream.max_conns;
      tc.rx_buf_bytes = s.stream.rx_buf_bytes;
      tc.rcvbuf = s.stream.rcvbuf;
      tc.sndbuf = s.stream.sndbuf;
      tc.max_reads_per_poll = s.stream.max_reads_per_poll;
      tc.tx_staging_bytes = s.stream.tx_staging_bytes;
      tc.rx_ts = v_.timestamps;
      tc.tx_ts = v_.timestamps;
      if (auto r = stack_.open(tcp_, tc); !r) return fail("tcp", r.error());
      has_tcp_ = true;
    }
    return {};
  }

  int wait(Nanos max_ns) noexcept { return stack_.wait(max_ns); }

  template <class F>
  std::size_t poll_datagrams(F&& f) {
    std::size_t n = 0;
    if (has_line_[0])
      n += line_[0].poll_rx_ts([&](const env::RxDatagram& d, const net::RxTimestamps& t) { f(Chan::LineA, d, t); });
    if (has_line_[1])
      n += line_[1].poll_rx_ts([&](const env::RxDatagram& d, const net::RxTimestamps& t) { f(Chan::LineB, d, t); });
    if (has_rereq_)
      n += rereq_.poll_rx_ts([&](const env::RxDatagram& d, const net::RxTimestamps& t) { f(Chan::Request, d, t); });
    return n;
  }

  bool send_request(net::Endpoint dst, std::span<const std::byte> b) noexcept {
    return has_rereq_ && dst.port != 0 && rereq_.send(dst, b);
  }

  std::optional<env::ConnId> connect(net::Endpoint dst) {
    if (!has_tcp_) return std::nullopt;
    auto c = tcp_.connect(dst);
    if (!c) return std::nullopt;
    track(*c);
    return *c;
  }
  std::size_t write(env::ConnId c, std::span<const std::byte> b) noexcept { return tcp_.write(c, b); }
  void close(env::ConnId c) noexcept {
    untrack(c);
    tcp_.close(c);
  }
  template <class F>
  std::size_t poll_streams(F&& f) {
    if (!has_tcp_) return 0;
    return tcp_.poll([&](const env::StreamEvent& ev) {
      if (ev.kind == env::StreamEventKind::Closed) untrack(ev.conn);
      f(ev);
    });
  }

  // Kernel TX timestamps (OPT_ID_TCP): one per send(), keyed by its last byte.
  template <class F>
  std::size_t drain_tx_stamps(F&& f) {
    if (!has_tcp_ || v_.timestamps == net::TsMode::Off) return 0;
    std::size_t n = 0;
    for (const env::ConnId c : conns_) {
      if (c == env::kNoConn) continue;
      n += tcp_.drain_tx_timestamps(c, [&](const net::TxStamp& s) {
        if (s.type != net::hwts::abi::kTstampSnd) return;
        f(c, StreamTxStamp{s.id, s.id, s.ts});
      });
    }
    return n;
  }

  void stats_json(JsonObject& j) const {
    for (int l = 0; l < 2; ++l) {
      if (!has_line_[l]) continue;
      const auto& us = line_[l].stats();
      const std::string p = l == 0 ? "udp_line_a_" : "udp_line_b_";
      j.num(p + "rx_packets", us.rx_packets).num(p + "rx_truncated", us.rx_truncated).num(p + "rx_errors", us.rx_errors);
      j.num(p + "rx_ts_hw", us.rx_ts.hw).num(p + "rx_ts_sw", us.rx_ts.sw).num(p + "rx_ts_missing", us.rx_ts.missing);
    }
    if (has_tcp_) {
      const auto& ts = tcp_.stats();
      j.num("tcp_rx_bytes", ts.rx_bytes).num("tcp_tx_bytes", ts.tx_bytes).num("tcp_tx_short", ts.tx_short);
      j.num("tcp_errors", ts.errors).num("tcp_connected", ts.connected).num("tcp_closed", ts.closed);
    }
  }

  [[nodiscard]] const VariantConfig& variant() const noexcept { return v_; }
  [[nodiscard]] StackT& stack() noexcept { return stack_; }

 private:
  std::expected<void, std::string> fail(const char* what, const net::Error& e) {
    return std::unexpected(std::string(what) + ": " + net::to_string(e));
  }

  net::Result<void> open_line(UdpPort& p, const net::Endpoint& ep) {
    net::UdpConfig c;
    c.rcvbuf = spec_.dgram.rcvbuf;
    c.batch = spec_.dgram.batch;
    c.rx_ts = v_.timestamps;
    if (net::is_multicast(ep.ipv4)) {
      c.bind = net::Endpoint{net::kAnyV4, ep.port};
      c.groups = {ep.ipv4};
      c.ifname = v_.ifname;
      c.mcast_loop = spec_.dgram.mcast_loop;
      c.reuse_port = true;
    } else {
      c.bind = ep;
    }
    return stack_.open(p, c);
  }

  void track(env::ConnId c) noexcept {
    for (auto& x : conns_) {
      if (x == env::kNoConn) {
        x = c;
        return;
      }
    }
  }
  void untrack(env::ConnId c) noexcept {
    for (auto& x : conns_)
      if (x == c) x = env::kNoConn;
  }

  VariantConfig v_;
  IoSpec spec_{};
  StackT stack_;
  UdpPort line_[2];
  UdpPort rereq_;
  TcpPort tcp_;
  bool has_line_[2]{false, false};
  bool has_rereq_ = false, has_tcp_ = false;
  std::array<env::ConnId, kMaxConns> conns_ = [] {
    std::array<env::ConnId, kMaxConns> a{};
    a.fill(env::kNoConn);
    return a;
  }();
};

}  // namespace lle::client

#if defined(LLE_CLIENT_HAVE_XSK)
#include "client/xsk_io.h"
#endif

namespace lle::client {

// f.template operator()<Io>() with the Io of v's variant; false if not compiled in.
template <class F>
bool with_variant_io(const VariantConfig& v, F&& f) {
  if (is_xsk(v.variant)) {
#if defined(LLE_CLIENT_HAVE_XSK)
    f.template operator()<XskIo>();
    return true;
#else
    return false;
#endif
  }
  return net::with_backend(backend_of(v.variant), [&]<net::BackendKind K>() { f.template operator()<SockIo<K>>(); });
}

}  // namespace lle::client
