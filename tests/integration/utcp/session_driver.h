#pragma once
// A seeded two-endpoint utcp session over SimLink: a client UtcpStreamPort connects to a
// server UtcpStreamPort, both stream deterministic pseudo-random bytes at each other in
// random write sizes (with random read pauses for zero-window backpressure), then close
// gracefully or abort. The driver is event-driven: simulated time jumps to the next frame
// delivery, timer deadline or application wake-up. It checks byte-stream exactness and
// ordering, liveness (no deadlock within the time and step budgets) and teardown.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "common/hash.h"
#include "common/prng.h"
#include "net/utcp/stream_port.h"
#include "sim_link.h"

namespace lle::net::utcp::test {

inline std::byte stream_byte(std::uint64_t seed, std::uint64_t i) noexcept {
  return std::byte{static_cast<unsigned char>(mix64(seed ^ (i >> 3) * 0x9E3779B97F4A7C15ull) >> (8 * (i & 7)))};
}

struct SessionParams {
  std::uint64_t seed = 1;
  Impairments imp;
  ConnConfig client_conn;
  ConnConfig server_conn;
  std::uint64_t client_bytes = 0;  // client -> server
  std::uint64_t server_bytes = 0;  // server -> client
  std::uint32_t max_write = 4000;
  bool abort_mode = false;
  bool client_aborts = true;
  std::uint64_t abort_at = 0;      // bytes sent by the aborter before it aborts
  std::uint32_t pause_ppm = 0;     // per app step, chance to pause reading
  Nanos max_pause = 0;
  Nanos idle_before_close = 0;     // abort mode: non-aborter waits this long before closing
  Nanos time_limit = 3'600'000'000'000;
  std::uint64_t step_limit = 20'000'000;
};

struct SessionResult {
  bool ok = false;
  std::string error;
  Nanos sim_time = 0;
  std::uint64_t steps = 0;
  std::uint64_t bytes_c2s = 0;
  std::uint64_t bytes_s2c = 0;
  std::uint64_t retransmits = 0;
  std::uint64_t rto_expiries = 0;
  std::uint64_t fast_retransmits = 0;
  std::uint64_t zero_window_probes = 0;
  std::uint64_t ooo_dropped = 0;
  LinkStats link;
};

// Draws a randomized parameter set from `seed`.
inline SessionParams random_params(std::uint64_t seed) {
  Prng r(seed * 0x2545F4914F6CDD1Dull + 17);
  SessionParams p;
  p.seed = seed;
  static constexpr std::uint32_t kLoss[] = {0, 0, 1'000, 10'000, 30'000, 100'000};
  static constexpr std::uint32_t kDup[] = {0, 0, 1'000, 20'000};
  static constexpr std::uint32_t kReorder[] = {0, 0, 10'000, 100'000};
  p.imp.loss_ppm = kLoss[r.below(6)];
  p.imp.dup_ppm = kDup[r.below(4)];
  p.imp.reorder_ppm = kReorder[r.below(4)];
  p.imp.corrupt_ppm = r.chance(1, 4) ? 2'000 : 0;
  p.imp.delay = r.range(5'000, 2'000'000);
  p.imp.jitter = r.chance(1, 2) ? r.range(0, 500'000) : 0;
  p.imp.reorder_delay = r.range(0, 5'000'000);
  for (ConnConfig* c : {&p.client_conn, &p.server_conn}) {
    c->mss = static_cast<std::uint16_t>(r.chance(1, 3) ? r.range(64, 600) : r.range(600, 1460));
    c->rx_buffer = static_cast<std::uint32_t>(r.chance(1, 4) ? r.range(256, 4096) : r.range(4096, 65535));
    c->tx_buffer = static_cast<std::uint32_t>(r.range(1024, 131072));
    c->max_inflight = static_cast<std::uint32_t>(r.chance(1, 4) ? r.range(c->mss, 16384) : 65535);
    c->min_rto = r.range(1'000'000, 50'000'000);
    c->initial_rto = r.range(c->min_rto, 300'000'000);
    c->max_rto = 4'000'000'000;
    c->time_wait = r.range(5'000'000, 100'000'000);
    c->dupack_threshold = static_cast<std::uint8_t>(r.chance(1, 5) ? 0 : 3);
    c->max_retransmits = 30;
    c->max_syn_retransmits = 30;
  }
  auto size = [&r]() -> std::uint64_t {
    const std::uint64_t k = r.below(20);
    if (k < 2) return 0;
    if (k < 10) return r.below(2'000);
    if (k < 18) return r.below(20'000);
    return r.below(200'000);
  };
  p.client_bytes = size();
  p.server_bytes = size();
  p.max_write = static_cast<std::uint32_t>(r.range(1, 6000));
  p.abort_mode = r.chance(1, 8);
  p.client_aborts = r.chance(1, 2);
  p.abort_at = r.below((p.client_aborts ? p.client_bytes : p.server_bytes) + 1);
  p.pause_ppm = r.chance(1, 3) ? static_cast<std::uint32_t>(r.range(1'000, 50'000)) : 0;
  p.max_pause = r.range(1'000'000, 200'000'000);
  p.idle_before_close = r.range(0, 50'000'000);
  return p;
}

class SessionDriver {
 public:
  using Port = UtcpStreamPort<MemFramePort, SimClock>;

  explicit SessionDriver(const SessionParams& p)
      : p_(p),
        link_(p.seed, p.imp),
        cport_(link_, 0, clock_),
        sport_(link_, 1, clock_),
        client_(cport_, clock_, stack_cfg(true)),
        server_(sport_, clock_, stack_cfg(false)),
        rng_(p.seed ^ 0xA5A5'5A5A'1234'5678ull) {
    c_.out_seed = p.seed * 2 + 1;
    s_.out_seed = p.seed * 2 + 2;
    c_.to_send = p.client_bytes;
    s_.to_send = p.server_bytes;
    c_.expect = p.server_bytes;
    s_.expect = p.client_bytes;
    c_.in_seed = s_.out_seed;
    s_.in_seed = c_.out_seed;
    c_.aborter = p.abort_mode && p.client_aborts;
    s_.aborter = p.abort_mode && !p.client_aborts;
    wbuf_.resize(p.max_write);
  }

  SessionResult run() {
    SessionResult res;
    (void)server_.listen(env::Endpoint{0, 8080});
    c_.conn = client_.connect(env::Endpoint{kServerIp, 8080}).value_or(env::kNoConn);
    if (c_.conn == env::kNoConn) return fail(res, "connect failed");
    // The client may abort before the handshake completes.
    if (c_.aborter && p_.abort_at == 0 && rng_.chance(1, 2)) {
      client_.abort(c_.conn);
      c_.app_closed = true;
      c_.done = true;
    }
    std::uint64_t steps = 0;
    while (true) {
      if (++steps > p_.step_limit) return fail(res, "step limit");
      app_step(c_, client_);
      app_step(s_, server_);
      (void)client_.poll([this](const env::StreamEvent& e) { on_event(c_, e); });
      (void)server_.poll([this](const env::StreamEvent& e) { on_event(s_, e); });
      if (!error_.empty()) return fail(res, error_);
      app_step(c_, client_);
      app_step(s_, server_);
      if (finished()) break;
      Nanos t = std::min({link_.next_delivery(), client_.next_deadline(), server_.next_deadline(), wake(c_), wake(s_)});
      if (t == kNoDeadline) return fail(res, "deadlock: nothing scheduled");
      if (t <= clock_.t) t = clock_.t + 1;  // writes may have queued frames due "now"
      clock_.t = t;
      if (clock_.t > p_.time_limit) return fail(res, "time limit");
    }
    res.ok = true;
    res.sim_time = clock_.t;
    res.steps = steps;
    res.bytes_c2s = s_.received;
    res.bytes_s2c = c_.received;
    res.link = link_.stats();
    res.retransmits = retx_;
    res.rto_expiries = rto_;
    res.fast_retransmits = fast_;
    res.zero_window_probes = zwp_;
    res.ooo_dropped = ooo_;
    return res;
  }

  static constexpr std::uint32_t kClientIp = 0x0A000001;
  static constexpr std::uint32_t kServerIp = 0x0A000002;

 private:
  struct Side {
    env::ConnId conn = env::kNoConn;
    std::uint64_t out_seed = 0;
    std::uint64_t in_seed = 0;
    std::uint64_t to_send = 0;
    std::uint64_t sent = 0;
    std::uint64_t expect = 0;
    std::uint64_t received = 0;
    bool connected = false;
    bool closed_event = false;
    bool app_closed = false;
    bool aborter = false;
    bool done = false;
    bool paused = false;
    Nanos pause_end = kNoDeadline;
    Nanos close_at = kNoDeadline;  // abort mode: non-aborter's delayed close
  };

  static Nanos wake(const Side& s) noexcept {
    if (s.done) return kNoDeadline;
    return std::min(s.pause_end, s.close_at);
  }

  StackConfig stack_cfg(bool client) const {
    StackConfig s;
    s.local_mac = MacAddr{{0x02, 0, 0, 0, 0, static_cast<std::uint8_t>(client ? 1 : 2)}};
    s.local_ip = client ? kClientIp : kServerIp;
    s.conn = client ? p_.client_conn : p_.server_conn;
    s.max_connections = 2;
    s.arp_retry = 50'000'000;
    s.arp_attempts = 20;
    s.isn_secret = p_.seed * 7 + (client ? 1 : 2);
    return s;
  }

  SessionResult& fail(SessionResult& r, const std::string& why) {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "seed %llu: %s (t=%lld ns, c sent %llu/%llu recv %llu/%llu closed=%d app_closed=%d, s sent %llu/%llu "
                  "recv %llu/%llu closed=%d app_closed=%d, slots c=%zu s=%zu, abort=%d)",
                  static_cast<unsigned long long>(p_.seed), why.c_str(), static_cast<long long>(clock_.t),
                  static_cast<unsigned long long>(c_.sent), static_cast<unsigned long long>(c_.to_send),
                  static_cast<unsigned long long>(c_.received), static_cast<unsigned long long>(c_.expect),
                  c_.closed_event, c_.app_closed, static_cast<unsigned long long>(s_.sent),
                  static_cast<unsigned long long>(s_.to_send), static_cast<unsigned long long>(s_.received),
                  static_cast<unsigned long long>(s_.expect), s_.closed_event, s_.app_closed, client_.slots_in_use(),
                  server_.slots_in_use(), p_.abort_mode);
    r.ok = false;
    r.error = buf;
    for (const Port* port : {&client_, &server_}) {
      const StackStats& st = port->stats();
      std::snprintf(buf, sizeof(buf),
                    "\n  %s: frames in %llu out %llu ignored %llu parse_err %llu rst %llu syn_drop %llu arp in %llu",
                    port == &client_ ? "client" : "server", static_cast<unsigned long long>(st.frames_in),
                    static_cast<unsigned long long>(st.frames_out), static_cast<unsigned long long>(st.frames_ignored),
                    static_cast<unsigned long long>(st.parse_errors), static_cast<unsigned long long>(st.rst_sent),
                    static_cast<unsigned long long>(st.syn_dropped), static_cast<unsigned long long>(st.arp_in));
      r.error += buf;
    }
    std::snprintf(buf, sizeof(buf), "\n  mss c=%u s=%u rx c=%u s=%u delay %lld jitter %lld",
                  p_.client_conn.mss, p_.server_conn.mss, p_.client_conn.rx_buffer, p_.server_conn.rx_buffer,
                  static_cast<long long>(p_.imp.delay), static_cast<long long>(p_.imp.jitter));
    r.error += buf;
    return r;
  }

  void collect(const Connection* c) {
    if (c == nullptr) return;
    retx_ += c->stats().retransmit_segs;
    rto_ += c->stats().rto_expiries;
    fast_ += c->stats().fast_retransmits;
    zwp_ += c->stats().zero_window_probes;
    ooo_ += c->stats().ooo_dropped;
  }

  void on_event(Side& s, const env::StreamEvent& e) {
    switch (e.kind) {
      case env::StreamEventKind::Accepted:
        if (s.conn != env::kNoConn) error_ = "second Accepted";
        s.conn = e.conn;
        s.connected = true;
        break;
      case env::StreamEventKind::Connected:
        if (e.conn != s.conn) error_ = "Connected for unknown conn";
        s.connected = true;
        break;
      case env::StreamEventKind::Data:
        if (e.conn != s.conn) error_ = "Data for unknown conn";
        if (s.closed_event) error_ = "Data after Closed";
        if (s.app_closed) error_ = "Data after app close";
        for (std::size_t i = 0; i < e.data.size(); ++i) {
          if (s.received + i >= s.expect || e.data[i] != stream_byte(s.in_seed, s.received + i)) {
            error_ = "byte stream mismatch at offset " + std::to_string(s.received + i);
            return;
          }
        }
        s.received += e.data.size();
        break;
      case env::StreamEventKind::Closed:
        if (e.conn != s.conn) error_ = "Closed for unknown conn";
        if (s.closed_event) error_ = "duplicate Closed";
        collect(s.conn == c_.conn ? client_.connection(e.conn) : server_.connection(e.conn));
        s.closed_event = true;
        s.done = true;
        break;
    }
  }

  void close_side(Side& s, Port& port, bool abort) {
    collect(port.connection(s.conn));
    if (abort) {
      port.abort(s.conn);
    } else {
      port.close(s.conn);
    }
    s.app_closed = true;
    s.done = true;
  }

  void app_step(Side& s, Port& port) {
    if (s.conn == env::kNoConn || s.app_closed || s.closed_event || !s.connected) return;
    const Nanos now = clock_.t;
    // Read pauses (zero-window backpressure).
    if (s.paused && now >= s.pause_end) {
      s.paused = false;
      s.pause_end = kNoDeadline;
      port.pause_reading(s.conn, false);
    } else if (!s.paused && p_.pause_ppm != 0 && rng_.chance(p_.pause_ppm, 1'000'000)) {
      s.paused = true;
      s.pause_end = now + 1 + static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(p_.max_pause)));
      port.pause_reading(s.conn, true);
    }
    // Writes.
    const std::uint64_t limit = s.aborter ? std::min(s.to_send, p_.abort_at) : s.to_send;
    for (int k = 0; k < 64 && s.sent < limit; ++k) {
      const std::uint64_t want = std::min<std::uint64_t>(limit - s.sent, 1 + rng_.below(p_.max_write));
      for (std::uint64_t i = 0; i < want; ++i) wbuf_[i] = stream_byte(s.out_seed, s.sent + i);
      const std::size_t n = port.write(s.conn, std::span<const std::byte>(wbuf_.data(), want));
      s.sent += n;
      if (n < want) break;
    }
    if (s.aborter) {
      if (s.sent >= limit) close_side(s, port, true);
      return;
    }
    if (p_.abort_mode) {
      // Non-aborter: close after sending everything and an idle delay, so a lost RST is
      // still discovered (the FIN draws a fresh RST).
      if (s.sent == s.to_send) {
        if (s.close_at == kNoDeadline) s.close_at = now + p_.idle_before_close;
        if (now >= s.close_at) close_side(s, port, false);
      }
      return;
    }
    if (s.sent == s.to_send && s.received == s.expect) close_side(s, port, false);
  }

  bool finished() const {
    // A server that never saw the connection (client aborted during the handshake).
    const bool server_never = p_.abort_mode && s_.conn == env::kNoConn && c_.done && link_.idle();
    if (!c_.done || !(s_.done || server_never)) return false;
    if (client_.slots_in_use() != 0 || server_.slots_in_use() != 0) return false;
    if (!p_.abort_mode) {
      return c_.received == c_.expect && s_.received == s_.expect && c_.sent == c_.to_send && s_.sent == s_.to_send;
    }
    return true;
  }

  SessionParams p_;
  SimClock clock_;
  SimLink link_;
  MemFramePort cport_;
  MemFramePort sport_;
  Port client_;
  Port server_;
  Prng rng_;
  Side c_;
  Side s_;
  std::vector<std::byte> wbuf_;
  std::string error_;
  std::uint64_t retx_ = 0, rto_ = 0, fast_ = 0, zwp_ = 0, ooo_ = 0;
};

}  // namespace lle::net::utcp::test
