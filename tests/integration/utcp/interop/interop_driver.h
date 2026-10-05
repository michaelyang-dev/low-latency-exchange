#pragma once
// utcp side of the kernel-interop suite (07 §2.4 Utcp.InteropLinuxPeer): drives one
// connection to (or from) a Linux kernel TCP echo peer over any FramePort, streams a
// deterministic byte pattern in phases, and verifies the echoed stream byte for byte.
//
// Phases: bulk (large writes), messages (one write per small message, pipelined),
// ping-pong (one message in flight, RTT recorded); in soak mode the three repeat until
// the duration ends. Then a teardown mode: utcp closes, the peer closes (FIN), or the
// peer resets. Prints a one-line summary; returns 0 on success.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "common/hash.h"
#include "common/prng.h"
#include "env/prod_clock.h"
#include "net/utcp/stream_port.h"

namespace lle::net::utcp::interop {

struct Options {
  std::string ifname;
  std::uint32_t local_ip = 0;
  std::uint32_t peer_ip = 0;
  std::uint16_t port = 7000;
  bool server = false;             // utcp listens; the kernel peer connects
  std::uint64_t bulk_bytes = 0;
  std::uint64_t messages = 0;
  std::uint32_t max_msg = 200;
  std::uint64_t pingpong = 0;
  std::uint64_t pipeline_bytes = 32768;
  std::string close_mode = "utcp";  // utcp | peer | peer-rst
  double duration_s = 0;           // soak: repeat phases this long
  Nanos min_rto = 10'000'000;
  Nanos stall_report = 2'000'000'000;   // a gap without echo progress counted as a stall
  Nanos fail_after = 120'000'000'000;   // no progress for this long: failure
  std::uint64_t seed = 1;
  std::uint16_t mss = 1460;
};

inline std::byte pattern(std::uint64_t seed, std::uint64_t i) noexcept {
  return std::byte{static_cast<unsigned char>(mix64(seed ^ ((i >> 3) * 0x9E3779B97F4A7C15ull)) >> (8 * (i & 7)))};
}

inline StackConfig stack_config(const Options& o, const MacAddr& mac) {
  StackConfig c;
  c.local_mac = mac;
  c.local_ip = o.local_ip;
  c.netmask = 0xFFFFFF00u;
  c.conn.mss = o.mss;
  c.conn.min_rto = o.min_rto;
  c.conn.initial_rto = 200'000'000;
  c.conn.max_rto = 2'000'000'000;
  c.conn.max_retransmits = 20;
  c.conn.time_wait = 500'000'000;
  c.conn.rx_buffer = 65535;
  c.conn.tx_buffer = 1 << 20;
  c.max_connections = 4;
  c.arp_retry = 100'000'000;
  c.arp_attempts = 30;
  c.garp_interval = 0;
  c.isn_secret = o.seed * 0x9E3779B97F4A7C15ull;
  return c;
}

template <class Port>
class Driver {
 public:
  Driver(UtcpStreamPort<Port, env::ProdClock>& stack, const Options& o) : st_(stack), o_(o), rng_(o.seed) {}

  int run() {
    const Nanos t0 = clock_.now_mono();
    if (o_.server) {
      if (!st_.listen(env::Endpoint{0, o_.port})) return fail("listen failed");
    } else {
      auto c = st_.connect(env::Endpoint{o_.peer_ip, o_.port});
      if (!c) return fail("connect failed");
      conn_ = *c;
    }
    while (!connected_) {
      poll();
      if (closed_) return fail("closed before the connection was established");
      if (clock_.now_mono() - t0 > 30'000'000'000) return fail("handshake timeout");
    }
    const Nanos start = clock_.now_mono();
    last_progress_ = start;
    bool ok = true;
    do {
      ok = ok && bulk(o_.bulk_bytes) && messages(o_.messages) && pingpong(o_.pingpong);
    } while (ok && o_.duration_s > 0 && static_cast<double>(clock_.now_mono() - start) / 1e9 < o_.duration_s);
    if (!ok) return fail(err_);
    const Nanos data_end = clock_.now_mono();
    if (const Connection* c = st_.connection(conn_)) last_conn_stats_ = c->stats();
    if (!teardown()) return fail(err_);
    report("ok", data_end - start);
    return 0;
  }

 private:
  void poll() {
    (void)st_.poll([this](const env::StreamEvent& e) { on_event(e); });
  }

  void on_event(const env::StreamEvent& e) {
    switch (e.kind) {
      case env::StreamEventKind::Accepted:
        conn_ = e.conn;
        connected_ = true;
        break;
      case env::StreamEventKind::Connected: connected_ = true; break;
      case env::StreamEventKind::Data:
        for (std::size_t i = 0; i < e.data.size(); ++i) {
          if (e.data[i] != pattern(o_.seed, echoed_ + i)) {
            if (mismatch_ == ~0ull) mismatch_ = echoed_ + i;
            break;
          }
        }
        echoed_ += e.data.size();
        break;
      case env::StreamEventKind::Closed: closed_ = true; break;
    }
  }

  // Writes up to `n` more pattern bytes; returns bytes accepted.
  std::size_t write_some(std::size_t n) {
    n = std::min(n, wbuf_.size());
    for (std::size_t i = 0; i < n; ++i) wbuf_[i] = pattern(o_.seed, sent_ + i);
    const std::size_t w = st_.write(conn_, std::span<const std::byte>(wbuf_.data(), n));
    sent_ += w;
    return w;
  }

  // Polls once and checks liveness and integrity.
  bool step() {
    const std::uint64_t before = echoed_;
    poll();
    const Nanos now = clock_.now_mono();
    if (echoed_ != before) {
      const Nanos gap = now - last_progress_;
      if (gap > o_.stall_report) ++stalls_;
      max_gap_ = std::max(max_gap_, gap);
      last_progress_ = now;
    } else if (echoed_ < sent_ && now - last_progress_ > o_.fail_after) {
      err_ = "no progress for " + std::to_string((now - last_progress_) / 1'000'000) + " ms";
      return false;
    }
    if (echoed_ >= sent_) last_progress_ = now;
    if (mismatch_ != ~0ull) {
      err_ = "echo mismatch at byte " + std::to_string(mismatch_);
      return false;
    }
    if (closed_ && !close_expected()) {
      err_ = "connection closed unexpectedly";
      return false;
    }
    return true;
  }

  // The peer may close (or reset) as soon as it has echoed everything; with a reset the
  // tail of the echo can be discarded by the peer's kernel.
  [[nodiscard]] bool close_expected() const noexcept {
    if (o_.close_mode == "peer") return echoed_ == sent_;
    return o_.close_mode == "peer-rst";
  }
  [[nodiscard]] bool done_by_close() const noexcept { return closed_ && close_expected(); }

  bool bulk(std::uint64_t bytes) {
    const std::uint64_t target = sent_ + bytes;
    while (echoed_ < target && !done_by_close()) {
      if (sent_ < target) (void)write_some(static_cast<std::size_t>(std::min<std::uint64_t>(target - sent_, 65536)));
      if (!step()) return false;
    }
    return true;
  }

  bool messages(std::uint64_t count) {
    std::uint64_t done = 0;
    std::size_t pending = 0;  // rest of the current message
    while ((done < count || pending != 0 || echoed_ < sent_) && !done_by_close()) {
      if (sent_ - echoed_ < o_.pipeline_bytes) {
        if (pending == 0 && done < count) {
          pending = 1 + static_cast<std::size_t>(rng_.below(o_.max_msg));
          ++done;
          ++msgs_;
        }
        if (pending != 0) pending -= write_some(pending);
      }
      if (!step()) return false;
    }
    return true;
  }

  bool pingpong(std::uint64_t count) {
    for (std::uint64_t k = 0; k < count; ++k) {
      std::size_t pending = 1 + static_cast<std::size_t>(rng_.below(o_.max_msg));
      const Nanos t = clock_.now_mono();
      while (pending != 0) {
        pending -= write_some(pending);
        if (!step()) return false;
      }
      while (echoed_ < sent_) {
        if (!step()) return false;
      }
      rtts_.push_back(clock_.now_mono() - t);
      ++msgs_;
    }
    return true;
  }

  bool teardown() {
    const Nanos t0 = clock_.now_mono();
    if (o_.close_mode == "utcp") {
      st_.close(conn_);
    }
    while (clock_.now_mono() - t0 < 30'000'000'000) {
      poll();
      if (mismatch_ != ~0ull) {
        err_ = "echo mismatch during teardown";
        return false;
      }
      if (st_.slots_in_use() == 0) break;
    }
    const StackStats& s = st_.stats();
    if (st_.slots_in_use() != 0) {
      err_ = "connection not reclaimed after teardown";
      return false;
    }
    if (o_.close_mode == "peer-rst") {
      if (!closed_ || s.closed_reset != 1) {
        err_ = "expected a reset from the peer";
        return false;
      }
      return true;
    }
    if (o_.close_mode == "peer" && !closed_) {
      err_ = "expected Closed (peer FIN)";
      return false;
    }
    if (s.closed_normal != 1) {
      err_ = "teardown was not an orderly close";
      return false;
    }
    if (echoed_ != sent_) {
      err_ = "echoed " + std::to_string(echoed_) + " of " + std::to_string(sent_);
      return false;
    }
    return true;
  }

  int fail(const std::string& why) {
    if (const Connection* c = st_.connection(conn_)) {
      std::printf("utcp_interop: state=%s snd_una=%u snd_nxt=%u snd_max=%u snd_wnd=%u rcv_nxt=%u rcv_wnd=%u rto_ms=%lld\n",
                  to_string(c->state()), c->snd_una(), c->snd_nxt(), c->snd_max(), c->snd_wnd(), c->rcv_nxt(),
                  c->rcv_window(), static_cast<long long>(c->rto() / 1'000'000));
    }
    report(("FAIL: " + why).c_str(), clock_.now_mono());
    return 1;
  }

  void report(const char* result, Nanos data_ns) {
    std::vector<Nanos> r = rtts_;
    std::sort(r.begin(), r.end());
    auto pct = [&](std::size_t p) -> long long {
      return r.empty() ? 0 : static_cast<long long>(r[std::min(r.size() - 1, r.size() * p / 100)] / 1000);
    };
    const StackStats& s = st_.stats();
    std::uint64_t rtx = 0, rto = 0, fast = 0, ooo = 0, zwp = 0;
    if (const Connection* c = st_.connection(conn_)) {
      rtx = c->stats().retransmit_segs;
      rto = c->stats().rto_expiries;
      fast = c->stats().fast_retransmits;
      ooo = c->stats().ooo_dropped;
      zwp = c->stats().zero_window_probes;
      last_conn_stats_ = c->stats();
    } else {
      rtx = last_conn_stats_.retransmit_segs;
      rto = last_conn_stats_.rto_expiries;
      fast = last_conn_stats_.fast_retransmits;
      ooo = last_conn_stats_.ooo_dropped;
      zwp = last_conn_stats_.zero_window_probes;
    }
    const double secs = static_cast<double>(data_ns) / 1e9;
    std::printf(
        "utcp_interop: %s role=%s close=%s sent=%llu echoed=%llu msgs=%llu secs=%.2f MBps=%.1f "
        "pingpong_us p50=%lld p99=%lld max=%lld stalls=%llu max_gap_ms=%lld frames_in=%llu frames_out=%llu "
        "rtx_segs=%llu rto=%llu fast_rtx=%llu ooo_dropped=%llu zw_probes=%llu arp_req=%llu arp_rep=%llu "
        "closed_normal=%llu closed_reset=%llu\n",
        result, o_.server ? "server" : "client", o_.close_mode.c_str(), static_cast<unsigned long long>(sent_),
        static_cast<unsigned long long>(echoed_), static_cast<unsigned long long>(msgs_), secs,
        secs > 0 ? static_cast<double>(echoed_) / secs / 1e6 : 0.0, pct(50), pct(99),
        r.empty() ? 0LL : static_cast<long long>(r.back() / 1000), static_cast<unsigned long long>(stalls_),
        static_cast<long long>(max_gap_ / 1'000'000), static_cast<unsigned long long>(s.frames_in),
        static_cast<unsigned long long>(s.frames_out), static_cast<unsigned long long>(rtx),
        static_cast<unsigned long long>(rto), static_cast<unsigned long long>(fast),
        static_cast<unsigned long long>(ooo), static_cast<unsigned long long>(zwp),
        static_cast<unsigned long long>(s.arp_requests), static_cast<unsigned long long>(s.arp_replies),
        static_cast<unsigned long long>(s.closed_normal), static_cast<unsigned long long>(s.closed_reset));
    std::fflush(stdout);
  }

  UtcpStreamPort<Port, env::ProdClock>& st_;
  Options o_;
  env::ProdClock clock_;
  Prng rng_;
  env::ConnId conn_ = env::kNoConn;
  bool connected_ = false;
  bool closed_ = false;
  std::uint64_t sent_ = 0;
  std::uint64_t echoed_ = 0;
  std::uint64_t msgs_ = 0;
  std::uint64_t mismatch_ = ~0ull;
  std::uint64_t stalls_ = 0;
  Nanos last_progress_ = 0;
  Nanos max_gap_ = 0;
  std::vector<Nanos> rtts_;
  std::vector<std::byte> wbuf_ = std::vector<std::byte>(65536);
  std::string err_;
  ConnStats last_conn_stats_{};
};

// Parses the shared command line; returns false on error.
inline bool parse_options(int argc, char** argv, Options& o, std::string& port_kind) {
  auto ip = [](const std::string& s) -> std::uint32_t {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
  };
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--if") o.ifname = next();
    else if (a == "--local-ip") o.local_ip = ip(next());
    else if (a == "--peer-ip") o.peer_ip = ip(next());
    else if (a == "--port") o.port = static_cast<std::uint16_t>(std::stoul(next()));
    else if (a == "--server") o.server = true;
    else if (a == "--bulk") o.bulk_bytes = std::stoull(next());
    else if (a == "--messages") o.messages = std::stoull(next());
    else if (a == "--max-msg") o.max_msg = static_cast<std::uint32_t>(std::stoul(next()));
    else if (a == "--pingpong") o.pingpong = std::stoull(next());
    else if (a == "--close") o.close_mode = next();
    else if (a == "--duration-s") o.duration_s = std::stod(next());
    else if (a == "--min-rto-ms") o.min_rto = static_cast<Nanos>(std::stoll(next())) * 1'000'000;
    else if (a == "--seed") o.seed = std::stoull(next());
    else if (a == "--mss") o.mss = static_cast<std::uint16_t>(std::stoul(next()));
    else if (a == "--port-kind") port_kind = next();
    else {
      std::fprintf(stderr, "utcp_interop: unknown argument %s\n", a.c_str());
      return false;
    }
  }
  return !o.ifname.empty() && o.local_ip != 0 && (o.server || o.peer_ip != 0);
}

}  // namespace lle::net::utcp::interop
