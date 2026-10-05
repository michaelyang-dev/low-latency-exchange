// net_peer: one end of the cross-namespace integration test (veth_netns_test.sh).
// Runs the same scenario on any backend so every variant is exercised over a real
// (virtual) link: a UDP multicast feed, a UDP unicast echo and a TCP echo session.
//
//   net_peer <mode> --backend epoll|busypoll|uring|uring-napi [--wait default|spin|block]
//     mcast-sub        --group G --port P --ifname IF --count N --ready-file F
//                      [--expect-busy-poll 1]  (fail unless BusyPollRxPackets rose)
//     mcast-pub        --group G --port P --ifname IF --count N [--gap-us U]
//     udp-echo         --bind A:P --count N --ready-file F
//     udp-ping         --peer A:P --count N
//     tcp-echo-server  --bind A:P --ready-file F
//     tcp-echo-client  --peer A:P --count N
//     probe            (exit 0 if the backend is compiled and its reactor opens)
//   net_peer napi-list --ifname IF   (NAPI instances of a device, netdev netlink)
//   net_peer napi-config --ifname IF [--mode irq-suspend|plain]   (root; variant ii device setup)
//   common: [--timeout-ms T] (default 20000)
//
// Exit status: 0 pass, 1 fail, 77 backend not compiled into this build.
#include <time.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "net/common/endpoint.h"
#include "net/common/iface.h"
#include "net/common/stack.h"
#if defined(__linux__)
#include "net/busypoll/busypoll.h"
#endif

namespace {

using namespace lle;
using namespace lle::net;

Nanos now_ns() {
  timespec ts{};
  ::clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<Nanos>(ts.tv_sec) * kNsPerSec + ts.tv_nsec;
}

struct Args {
  std::string mode;
  std::map<std::string, std::string, std::less<>> kv;
  [[nodiscard]] std::string get(std::string_view k, std::string_view def = "") const {
    auto it = kv.find(k);
    return it == kv.end() ? std::string(def) : it->second;
  }
  [[nodiscard]] long num(std::string_view k, long def) const {
    const std::string v = get(k);
    return v.empty() ? def : std::strtol(v.c_str(), nullptr, 10);
  }
};

std::span<const std::byte> as_bytes(const void* p, std::size_t n) { return {static_cast<const std::byte*>(p), n}; }

int fail(const char* what) {
  std::fprintf(stderr, "net_peer: FAIL: %s\n", what);
  return 1;
}

void touch(const std::string& path) {
  if (!path.empty()) std::ofstream(path) << "ready\n";
}

template <BackendKind K>
int run(const Args& a, WaitPolicy w) {
  Stack<K> st(w);
  if (auto r = st.open(); !r) return fail(to_string(r.error()).c_str());
  if (a.mode == "probe") return 0;  // the backend is compiled and its reactor opens
  const Nanos deadline = now_ns() + a.num("--timeout-ms", 20'000) * 1'000'000;
  const auto count = static_cast<std::uint64_t>(a.num("--count", 1000));
  const std::string mode = a.mode;

  if (mode == "mcast-sub" || mode == "mcast-pub") {
    const auto group = parse_ipv4(a.get("--group", "239.77.0.1"));
    if (!group) return fail("--group");
    const auto port = static_cast<std::uint16_t>(a.num("--port", 26400));
    UdpConfig c;
    c.ifname = a.get("--ifname");
    c.rcvbuf = 4 << 20;
    if (mode == "mcast-sub") {
      c.bind = Endpoint{kAnyV4, port};
      c.groups = {*group};
    } else {
      c.bind = Endpoint{kAnyV4, 0};
    }
    typename Stack<K>::DatagramPort p;
    if (auto r = st.open(p, c); !r) return fail(to_string(r.error()).c_str());
    if (mode == "mcast-sub") {
#if defined(__linux__)
      const std::uint64_t bp_before = busypoll::busy_poll_rx_packets().value_or(0);
#endif
      touch(a.get("--ready-file"));
      std::uint64_t next = 0;
      bool bad = false;
      while (next < count && now_ns() < deadline && !bad) {
        (void)st.wait(1'000'000);
        p.poll_rx([&](const env::RxDatagram& d) {
          std::uint64_t seq = 0;
          if (d.data.size() < sizeof(seq) || d.dst.ipv4 != *group) {
            bad = true;
            return;
          }
          std::memcpy(&seq, d.data.data(), sizeof(seq));
          if (seq != next) bad = true;
          ++next;
        });
      }
      std::printf("mcast-sub backend=%s received=%llu rx_calls=%llu rearms=%llu no_buffers=%llu\n", to_string(K),
                  static_cast<unsigned long long>(next), static_cast<unsigned long long>(p.stats().rx_calls),
                  static_cast<unsigned long long>(p.stats().rearms), static_cast<unsigned long long>(p.stats().no_buffers));
#if defined(__linux__)
      const std::uint32_t napi = busypoll::incoming_napi_id(p.fd()).value_or(0);
      const std::uint64_t bp = busypoll::busy_poll_rx_packets().value_or(0) - bp_before;
      std::printf("mcast-sub napi_id=%u busy_poll_rx_packets=%llu\n", napi, static_cast<unsigned long long>(bp));
      if (a.get("--expect-busy-poll") == "1" && bp == 0) return fail("BusyPollRxPackets did not increase");
#endif
      if (bad) return fail("out-of-order, foreign or malformed datagram");
      return next == count ? 0 : fail("timeout waiting for the feed");
    }
    const Nanos gap = a.num("--gap-us", 20) * 1000;
    std::array<std::byte, 64> msg{};
    Nanos t = now_ns();
    for (std::uint64_t seq = 0; seq < count; ++seq) {
      std::memcpy(msg.data(), &seq, sizeof(seq));
      while (!p.send(Endpoint{*group, port}, msg)) {
        if (now_ns() > deadline) return fail("send stalled");
        (void)st.wait(0);
        p.poll_rx([](const env::RxDatagram&) {});
      }
      t += gap;
      while (now_ns() < t) p.poll_rx([](const env::RxDatagram&) {});  // paced, reaps completions
    }
    for (int i = 0; i < 100; ++i) {
      (void)st.wait(100'000);
      p.poll_rx([](const env::RxDatagram&) {});
    }
    std::printf("mcast-pub backend=%s sent=%llu dropped=%llu errors=%llu\n", to_string(K),
                static_cast<unsigned long long>(p.stats().tx_packets), static_cast<unsigned long long>(p.stats().tx_dropped),
                static_cast<unsigned long long>(p.stats().tx_errors));
    return 0;
  }

  if (mode == "udp-echo" || mode == "udp-ping") {
    UdpConfig c;
    typename Stack<K>::DatagramPort p;
    std::optional<Endpoint> peer;
    if (mode == "udp-echo") {
      const auto b = parse_endpoint(a.get("--bind"));
      if (!b) return fail("--bind");
      c.bind = *b;
    } else {
      peer = parse_endpoint(a.get("--peer"));
      if (!peer) return fail("--peer");
    }
    if (auto r = st.open(p, c); !r) return fail(to_string(r.error()).c_str());
    std::uint64_t n = 0;
    if (mode == "udp-echo") {
      touch(a.get("--ready-file"));
      while (n < count && now_ns() < deadline) {
        (void)st.wait(1'000'000);
        p.poll_rx([&](const env::RxDatagram& d) {
          if (p.send(d.src, d.data)) ++n;
        });
      }
      std::printf("udp-echo backend=%s echoed=%llu\n", to_string(K), static_cast<unsigned long long>(n));
      return n == count ? 0 : fail("udp-echo timeout");
    }
    for (std::uint64_t seq = 0; seq < count && now_ns() < deadline; ++seq) {
      if (!p.send(*peer, as_bytes(&seq, sizeof(seq)))) return fail("udp-ping send");
      bool got = false;
      while (!got && now_ns() < deadline) {
        (void)st.wait(1'000'000);
        p.poll_rx([&](const env::RxDatagram& d) {
          std::uint64_t v = 0;
          if (d.data.size() == sizeof(v)) std::memcpy(&v, d.data.data(), sizeof(v));
          got = v == seq;
        });
      }
      if (got) ++n;
    }
    std::printf("udp-ping backend=%s answered=%llu\n", to_string(K), static_cast<unsigned long long>(n));
    return n == count ? 0 : fail("udp-ping lost replies");
  }

  if (mode == "tcp-echo-server" || mode == "tcp-echo-client") {
    TcpConfig c;
    c.max_conns = 4;
    typename Stack<K>::StreamPort p;
    if (auto r = st.open(p, c); !r) return fail(to_string(r.error()).c_str());
    std::string pending;  // bytes not yet accepted by write()
    std::string received;
    ConnId conn = kNoConn;
    bool closed = false;
    auto flush = [&] {
      if (conn == kNoConn || pending.empty()) return;
      pending.erase(0, p.write(conn, as_bytes(pending.data(), pending.size())));
    };
    if (mode == "tcp-echo-server") {
      const auto b = parse_endpoint(a.get("--bind"));
      if (!b) return fail("--bind");
      if (auto r = p.listen(*b); !r) return fail(to_string(r.error()).c_str());
      touch(a.get("--ready-file"));
      std::uint64_t echoed = 0;
      while (!closed && now_ns() < deadline) {
        (void)st.wait(1'000'000);
        p.poll([&](const env::StreamEvent& e) {
          if (e.kind == env::StreamEventKind::Accepted && conn == kNoConn) conn = e.conn;
          if (e.kind == env::StreamEventKind::Data && e.conn == conn) {
            pending.append(reinterpret_cast<const char*>(e.data.data()), e.data.size());
            echoed += e.data.size();
          }
          if (e.kind == env::StreamEventKind::Closed && e.conn == conn) closed = true;
        });
        flush();
      }
      std::printf("tcp-echo-server backend=%s echoed_bytes=%llu tx_sends=%llu\n", to_string(K),
                  static_cast<unsigned long long>(echoed), static_cast<unsigned long long>(p.stats().tx_sends));
      return closed ? 0 : fail("tcp-echo-server: client never closed");
    }
    const auto peer = parse_endpoint(a.get("--peer"));
    if (!peer) return fail("--peer");
    auto id = p.connect(*peer);
    if (!id) return fail(to_string(id.error()).c_str());
    std::string sent;
    for (std::uint64_t i = 0; i < count; ++i) sent += "ORDER-" + std::to_string(i) + std::string(i % 37, 'x') + ";";
    pending = sent;
    bool connected = false;
    while (received.size() < sent.size() && !closed && now_ns() < deadline) {
      (void)st.wait(1'000'000);
      p.poll([&](const env::StreamEvent& e) {
        if (e.kind == env::StreamEventKind::Connected) {
          connected = true;
          conn = e.conn;
        }
        if (e.kind == env::StreamEventKind::Data) received.append(reinterpret_cast<const char*>(e.data.data()), e.data.size());
        if (e.kind == env::StreamEventKind::Closed) closed = true;
      });
      // Write message-sized pieces (one OUCH-like message per send).
      while (connected && !pending.empty()) {
        const std::size_t cut = pending.find(';') + 1;
        const std::size_t n = p.write(conn, as_bytes(pending.data(), cut));
        if (n == 0) break;
        pending.erase(0, n);
      }
    }
    if (conn != kNoConn) p.close(conn);
    std::printf("tcp-echo-client backend=%s sent=%zu received=%zu tx_sends=%llu\n", to_string(K), sent.size(),
                received.size(), static_cast<unsigned long long>(p.stats().tx_sends));
    if (!connected) return fail("tcp-echo-client: no connection");
    return received == sent ? 0 : fail("tcp-echo-client: echo mismatch");
  }
  return fail("unknown mode");
}

}  // namespace

// Lists the NAPI instances of an interface (netdev netlink napi-get): busy polling
// (variants ii and iii-n) only has something to poll when the device runs NAPI.
int napi_list(const Args& a) {
#if defined(__linux__)
  const auto ifc = lookup_iface(a.get("--ifname"));
  if (!ifc || ifc->index == 0) return fail("--ifname");
  std::array<busypoll::NapiInfo, 64> napis{};
  auto n = busypoll::list_napi(ifc->index, napis);
  if (!n) return fail(to_string(n.error()).c_str());
  std::printf("napi-list ifname=%s instances=%zu\n", a.get("--ifname").c_str(), *n);
  for (std::size_t i = 0; i < *n && i < napis.size(); ++i)
    std::printf("  napi id=%u irq=%d defer_hard_irqs=%u gro_flush_timeout=%llu irq_suspend_timeout=%llu\n", napis[i].id,
                napis[i].irq, napis[i].defer_hard_irqs, static_cast<unsigned long long>(napis[i].gro_flush_timeout_ns),
                static_cast<unsigned long long>(napis[i].irq_suspend_timeout_ns));
  return 0;
#else
  (void)a;
  return 77;
#endif
}

// Applies the variant (ii) device settings (busypoll::configure_device) and reads them
// back: sysfs napi_defer_hard_irqs / gro_flush_timeout and, with --mode irq-suspend, the
// per-NAPI irq-suspend-timeout via netdev napi-set (6.13). Root; meant for a namespace's
// own veth so the host is untouched.
int napi_config(const Args& a) {
#if defined(__linux__)
  const std::string ifname = a.get("--ifname");
  const auto ifc = lookup_iface(ifname);
  if (!ifc || ifc->index == 0) return fail("--ifname");
  busypoll::Config c;
  c.mode = a.get("--mode", "irq-suspend") == "irq-suspend" ? busypoll::Mode::IrqSuspend : busypoll::Mode::Plain;
  if (auto r = busypoll::configure_device(ifname, c); !r) return fail(to_string(r.error()).c_str());
  const auto defer = busypoll::napi_defer_hard_irqs(ifname);
  const auto gro = busypoll::gro_flush_timeout(ifname);
  if (!defer || !gro || *defer != c.napi_defer_hard_irqs || *gro != c.gro_flush_timeout_ns) return fail("sysfs read-back");
  std::array<busypoll::NapiInfo, 64> napis{};
  const auto n = busypoll::list_napi(ifc->index, napis);
  if (!n || *n == 0) return fail("no NAPI instance to configure");
  for (std::size_t i = 0; i < *n && i < napis.size(); ++i) {
    const auto& x = napis[i];
    std::printf("napi-config id=%u defer_hard_irqs=%u gro_flush_timeout=%llu irq_suspend_timeout=%llu\n", x.id,
                x.defer_hard_irqs, static_cast<unsigned long long>(x.gro_flush_timeout_ns),
                static_cast<unsigned long long>(x.irq_suspend_timeout_ns));
    if (x.defer_hard_irqs != c.napi_defer_hard_irqs || x.gro_flush_timeout_ns != c.gro_flush_timeout_ns) return fail("napi read-back");
    if (c.mode == busypoll::Mode::IrqSuspend && x.irq_suspend_timeout_ns != c.irq_suspend_timeout_ns)
      return fail("irq-suspend-timeout read-back");
  }
  return 0;
#else
  (void)a;
  return 77;
#endif
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: net_peer <mode> --backend B [options]\n");
    return 2;
  }
  Args a;
  a.mode = argv[1];
  for (int i = 2; i + 1 < argc; i += 2) a.kv[argv[i]] = argv[i + 1];
  if (a.mode == "napi-list") return napi_list(a);
  if (a.mode == "napi-config") return napi_config(a);
  const auto kind = parse_backend(a.get("--backend", "epoll"));
  if (!kind) return fail("--backend");
  const std::string w = a.get("--wait", "default");
  const WaitPolicy wait = w == "spin" ? WaitPolicy::Spin : (w == "block" ? WaitPolicy::Block : WaitPolicy::Default);
  int rc = 77;
  const bool compiled = with_backend(*kind, [&]<BackendKind K>() { rc = run<K>(a, wait); });
  if (!compiled) std::fprintf(stderr, "net_peer: backend %s not compiled in this build\n", to_string(*kind));
  return rc;
}
