// utcp world (09 §2 `utcp`; 07 §2.4): the production user-space TCP
// (src/net/utcp) on every node, as UtcpStreamPort<DatagramFramePort<
// sim::DatagramPort>, sim::Clock> with the raw-IP link: each TCP segment is a
// simulated datagram, so the simulator's loss, duplication, reordering, delay,
// partitions, pauses and process crashes apply to utcp segments and stacks.
//
// The workload follows tests/integration/utcp/session_driver.h. Each client
// runs sessions one after another against the server: it connects, sends a
// 16-byte header naming (client, session), then both sides stream seeded
// pseudo-random bytes at each other in random write sizes, with random read
// pauses (zero-window backpressure), and close gracefully; one session in
// eight is an abort session instead. Sizes and modes derive from
// (seed, client, session), so the server checks a stream knowing only its
// header. Applications abort connections that make no progress for an idle
// timeout, as a real protocol's heartbeats would, so half-open connections left
// by a peer's crash are reclaimed.
//
// Oracles:
//   O-UTCP-STREAM  every byte delivered on a connection is the next byte the
//                  peer sent on it (exact, in order, never beyond its total);
//                  no data after Closed or after the application closed
//   O-UTCP-CLOSE   an orderly close (FIN) reaches a side only after all of the
//                  peer's data; Closed is raised at most once per connection
//   O-LIVE         after healing, every client completes its target number of
//                  sessions with both streams exact on both sides
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "common/hash.h"
#include "common/prng.h"
#include "env/buggify.h"
#include "env/concepts.h"
#include "net/utcp/datagram_frame_port.h"
#include "net/utcp/stream_port.h"
#include "sim/dist.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

namespace {

namespace ut = lle::net::utcp;
using FramePort = ut::DatagramFramePort<DatagramPort>;
using Stack = ut::UtcpStreamPort<FramePort, Clock>;

constexpr std::uint16_t kLinkPort = 6000;
constexpr std::uint16_t kServicePort = 8080;
constexpr std::size_t kHeaderLen = 16;  // magic (4) | client (4) | session (8)
constexpr std::uint32_t kMagic = 0x55544350;  // "UTCP"
constexpr std::size_t kMaxWrite = 6000;

// Per-session parameters, a pure function of (seed, client, session).
struct SessionSpec {
  std::uint64_t c2s = 0;  // client -> server bytes after the header
  std::uint64_t s2c = 0;
  std::uint32_t max_write = 1;
  bool abort_mode = false;
  bool client_aborts = false;
  std::uint64_t abort_at = 0;  // bytes the aborter sends before aborting
  std::uint32_t pause_ppm = 0;
  Nanos max_pause = 0;
  Nanos idle_before_close = 0;  // abort mode: the other side's delay before closing
  std::uint64_t c2s_seed = 0;
  std::uint64_t s2c_seed = 0;
};

SessionSpec session_spec(std::uint64_t seed, std::uint32_t client, std::uint64_t session) {
  Prng r(mix64(seed ^ (std::uint64_t{client} << 40) ^ (session * 0x9E3779B97F4A7C15ull)));
  SessionSpec s;
  auto size = [&r]() -> std::uint64_t {
    const std::uint64_t k = r.below(20);
    if (k < 2) return 0;
    if (k < 10) return r.below(2'000);
    if (k < 18) return r.below(20'000);
    return r.below(120'000);
  };
  s.c2s = size();
  s.s2c = size();
  s.max_write = static_cast<std::uint32_t>(r.range(1, static_cast<std::int64_t>(kMaxWrite)));
  s.abort_mode = r.chance(1, 8);
  s.client_aborts = r.chance(1, 2);
  s.abort_at = r.below((s.client_aborts ? s.c2s : s.s2c) + 1);
  s.pause_ppm = r.chance(1, 3) ? static_cast<std::uint32_t>(r.range(1'000, 50'000)) : 0;
  s.max_pause = static_cast<Nanos>(r.range(kMs, 100 * kMs));
  s.idle_before_close = static_cast<Nanos>(r.range(0, 50 * kMs));
  s.c2s_seed = r.next_u64();
  s.s2c_seed = r.next_u64();
  return s;
}

std::byte stream_byte(std::uint64_t seed, std::uint64_t i) noexcept {
  return std::byte{static_cast<unsigned char>(mix64(seed ^ (i >> 3) * 0x9E3779B97F4A7C15ull) >> (8 * (i & 7)))};
}

struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_stream = 0, o_close = 0;
  std::uint64_t seed = 0;
  bool verbose = false;
  std::uint64_t target = 0;  // complete sessions per client
  struct SessionState {
    bool client_done = false;  // sent everything, received everything, closed
    bool server_done = false;
  };
  std::map<std::pair<std::uint32_t, std::uint64_t>, SessionState> sessions;
  std::vector<std::uint64_t> next_session;  // per client, across crashes
  std::vector<std::uint64_t> complete;      // per client
  std::uint64_t started = 0;
  std::uint64_t aborted_idle = 0;
  std::uint64_t closed_unexpectedly = 0;
  std::uint64_t retransmits = 0, rto_expiries = 0, fast_retransmits = 0, zero_window_probes = 0;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  void side_done(std::uint32_t client, std::uint64_t session, bool server) {
    SessionState& s = sessions[{client, session}];
    (server ? s.server_done : s.client_done) = true;
    if (s.client_done && s.server_done) {
      ++complete[client];
      sessions.erase({client, session});
    }
  }

  [[nodiscard]] bool done() const {
    for (const std::uint64_t c : complete) {
      if (c < target) return false;
    }
    return true;
  }
};

ut::StackConfig stack_config(Node& n, const ut::ConnConfig& conn, bool server) {
  ut::StackConfig s;
  s.local_mac = ut::MacAddr{{0x02, 0, 0, 0, 0, static_cast<std::uint8_t>(n.id() + 1)}};
  s.local_ip = n.ip();
  s.link = ut::LinkType::RawIp;
  s.static_next_hop = ut::MacAddr{{0x02, 0, 0, 0, 0, 0xFE}};  // raw IP: no neighbour resolution
  s.conn = conn;
  s.max_connections = server ? 32 : 8;
  s.isn_secret = mix64(n.rng(0x7C).next_u64());  // a new secret per incarnation
  return s;
}

// One end of one connection: what it must send and what it must receive.
struct Side {
  env::ConnId conn = env::kNoConn;
  std::uint32_t client = 0;
  std::uint64_t session = 0;
  bool known = false;  // server: header received
  SessionSpec spec;
  bool is_server = false;
  std::array<std::byte, kHeaderLen> header{};
  std::size_t header_have = 0;  // server: header bytes received; client: header bytes sent
  std::uint64_t sent = 0;
  std::uint64_t received = 0;
  bool connected = false;
  bool closed_event = false;
  bool app_closed = false;
  bool paused = false;
  Nanos pause_end = 0;
  Nanos close_at = -1;
  Nanos last_progress = 0;
  bool reported = false;

  [[nodiscard]] std::uint64_t to_send() const { return is_server ? spec.s2c : spec.c2s; }
  [[nodiscard]] std::uint64_t expect() const { return is_server ? spec.c2s : spec.s2c; }
  [[nodiscard]] std::uint64_t out_seed() const { return is_server ? spec.s2c_seed : spec.c2s_seed; }
  [[nodiscard]] std::uint64_t in_seed() const { return is_server ? spec.c2s_seed : spec.s2c_seed; }
  [[nodiscard]] bool aborter() const { return spec.abort_mode && (spec.client_aborts != is_server); }
  [[nodiscard]] bool finished() const { return closed_event || app_closed; }
};

// Shared application logic of both ends.
class AppEnd {
 public:
  AppEnd(Node& n, Harness& h, const ut::ConnConfig& conn, bool server, Nanos app_idle)
      : node_(n), h_(h), dg_(n, kLinkPort), fp_(dg_, kLinkPort),
        stack_(fp_, n.clock(), stack_config(n, conn, server)), rng_(n.rng(server ? 0x7A : 0x7B)), app_idle_(app_idle),
        wbuf_(kMaxWrite) {}
  virtual ~AppEnd() = default;
  AppEnd(const AppEnd&) = delete;
  AppEnd& operator=(const AppEnd&) = delete;

 protected:
  void collect(env::ConnId c) {
    if (const ut::Connection* k = stack_.connection(c)) {
      h_.retransmits += k->stats().retransmit_segs;
      h_.rto_expiries += k->stats().rto_expiries;
      h_.fast_retransmits += k->stats().fast_retransmits;
      h_.zero_window_probes += k->stats().zero_window_probes;
    }
  }

  void on_data(Side& s, std::span<const std::byte> data, Nanos now) {
    if (s.closed_event || s.app_closed) {
      h_.o->fail(h_.o_stream, std::string(s.is_server ? "server" : "client") + " got data after " +
                                  (s.closed_event ? "Closed" : "its own close"));
      return;
    }
    s.last_progress = now;
    std::size_t i = 0;
    if (s.is_server && !s.known) {
      while (i < data.size() && s.header_have < kHeaderLen) s.header[s.header_have++] = data[i++];
      if (s.header_have < kHeaderLen) return;
      if (load_be32(s.header.data()) != kMagic) {
        h_.o->fail(h_.o_stream, "server: bad session header");
        return;
      }
      s.client = load_be32(s.header.data() + 4);
      s.session = load_be64(s.header.data() + 8);
      s.spec = session_spec(h_.seed, s.client, s.session);
      s.known = true;
    }
    for (; i < data.size(); ++i) {
      if (s.received >= s.expect() || data[i] != stream_byte(s.in_seed(), s.received)) {
        h_.o->fail(h_.o_stream, std::string(s.is_server ? "server" : "client") + " session " +
                                    std::to_string(s.client) + "/" + std::to_string(s.session) +
                                    ": stream mismatch at offset " + std::to_string(s.received));
        return;
      }
      ++s.received;
    }
    h_.o->pass(h_.o_stream);
  }

  void on_closed(Side& s, Nanos now) {
    if (s.closed_event) h_.o->fail(h_.o_close, "duplicate Closed");
    s.closed_event = true;
    const ut::Connection* k = stack_.connection(s.conn);
    // An orderly end of stream: the peer's FIN arrived, everything before it was read,
    // and the connection is still open (close_reason() is only final once the slot is
    // reclaimed). A RST after the FIN, with data still unread, closes it instead.
    const bool normal = k != nullptr && k->peer_fin_received() && k->readable_bytes() == 0 &&
                        k->state() != ut::State::Closed;
    collect(s.conn);
    if (normal && s.known && !s.spec.abort_mode) {
      // The peer closes only after sending everything, so its FIN comes last.
      if (s.received != s.expect()) {
        h_.o->fail(h_.o_close, std::string(s.is_server ? "server" : "client") + " session " +
                                   std::to_string(s.client) + "/" + std::to_string(s.session) +
                                   ": orderly close after " + std::to_string(s.received) + " of " +
                                   std::to_string(s.expect()) + " bytes");
      } else {
        h_.o->pass(h_.o_close);
      }
    }
    if (!normal) ++h_.closed_unexpectedly;
    h_.log("%s %u/%llu Closed (%s): sent %llu/%llu received %llu/%llu abort_mode=%d", s.is_server ? "server" : "client",
           s.client, static_cast<unsigned long long>(s.session), normal ? "fin" : (k != nullptr ? ut::to_string(k->close_reason()) : "?"),
           static_cast<unsigned long long>(s.sent), static_cast<unsigned long long>(s.to_send()),
           static_cast<unsigned long long>(s.received), static_cast<unsigned long long>(s.expect()),
           s.spec.abort_mode ? 1 : 0);
    if (s.known && s.spec.abort_mode && (s.aborter() || s.sent == s.to_send())) report(s);
    else if (normal && s.known && s.sent == s.to_send() && s.received == s.expect()) report(s);
    (void)now;
  }

  void close_side(Side& s, bool abort) {
    h_.log("%s %u/%llu %s: sent %llu/%llu received %llu/%llu", s.is_server ? "server" : "client", s.client,
           static_cast<unsigned long long>(s.session), abort ? "aborts" : "closes",
           static_cast<unsigned long long>(s.sent), static_cast<unsigned long long>(s.to_send()),
           static_cast<unsigned long long>(s.received), static_cast<unsigned long long>(s.expect()));
    collect(s.conn);
    if (abort) stack_.abort(s.conn);
    else stack_.close(s.conn);
    s.app_closed = true;
  }

  void report(Side& s) {
    if (s.reported) return;
    s.reported = true;
    h_.side_done(s.client, s.session, s.is_server);
  }

  // Reads pauses, writes, closes; aborts a connection that stopped progressing.
  void app_step(Side& s, Nanos now) {
    if (!s.connected || s.finished() || (s.is_server && !s.known)) {
      if (s.connected && !s.finished() && now - s.last_progress > app_idle_) {
        ++h_.aborted_idle;
        close_side(s, true);
      }
      return;
    }
    if (s.paused && now >= s.pause_end) {
      s.paused = false;
      stack_.pause_reading(s.conn, false);
    } else if (!s.paused && s.spec.pause_ppm != 0 && rng_.chance(s.spec.pause_ppm, 1'000'000)) {
      s.paused = true;
      s.pause_end = now + 1 + static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(s.spec.max_pause)));
      stack_.pause_reading(s.conn, true);
    }
    if (!s.is_server && s.header_have < kHeaderLen) {
      const std::size_t n = stack_.write(s.conn, std::span<const std::byte>(s.header.data() + s.header_have,
                                                                            kHeaderLen - s.header_have));
      s.header_have += n;
      if (n > 0) s.last_progress = now;
      if (s.header_have < kHeaderLen) return;
    }
    const std::uint64_t limit = s.aborter() ? std::min(s.to_send(), s.spec.abort_at) : s.to_send();
    for (int k = 0; k < 16 && s.sent < limit; ++k) {
      const std::uint64_t want = std::min<std::uint64_t>(limit - s.sent, 1 + rng_.below(s.spec.max_write));
      for (std::uint64_t i = 0; i < want; ++i) wbuf_[i] = stream_byte(s.out_seed(), s.sent + i);
      const std::size_t n = stack_.write(s.conn, std::span<const std::byte>(wbuf_.data(), want));
      s.sent += n;
      if (n > 0) s.last_progress = now;
      if (n < want) break;
    }
    if (s.aborter()) {
      if (s.sent >= limit) {
        close_side(s, true);
        report(s);
      }
      return;
    }
    if (s.spec.abort_mode) {
      if (s.sent == s.to_send()) {
        if (s.close_at < 0) s.close_at = now + s.spec.idle_before_close;
        if (now >= s.close_at) {
          close_side(s, false);
          report(s);
        }
      }
    } else if (s.sent == s.to_send() && s.received == s.expect()) {
      close_side(s, false);
      report(s);
      return;
    }
    if (!s.finished() && now - s.last_progress > app_idle_) {
      ++h_.aborted_idle;
      close_side(s, true);
    }
  }

  Node& node_;
  Harness& h_;
  DatagramPort dg_;
  FramePort fp_;
  Stack stack_;
  Rng rng_;
  Nanos app_idle_;
  std::vector<std::byte> wbuf_;
};

class ServerProc : public Process, AppEnd {
 public:
  ServerProc(Node& n, Harness& h, const ut::ConnConfig& conn, Nanos app_idle) : AppEnd(n, h, conn, true, app_idle) {
    LLE_ASSERT(stack_.listen(env::Endpoint{0, kServicePort}).has_value(), "utcp server: listen failed");
    n.add_stage(stage_, "utcp-srv");
  }

  bool poll() {
    const Nanos now = node_.clock().now_mono();
    bool did = stack_.poll([&](const env::StreamEvent& e) { on_event(e, now); }) > 0;
    for (auto& s : sides_) app_step(*s, now);
    std::erase_if(sides_, [](const auto& s) { return s->finished(); });
    return did;
  }

 private:
  struct Stage {
    ServerProc* p;
    bool poll() { return p->poll(); }
  };

  Side* find(env::ConnId c) {
    for (auto& s : sides_) {
      if (s->conn == c) return s.get();
    }
    return nullptr;
  }

  void on_event(const env::StreamEvent& e, Nanos now) {
    switch (e.kind) {
      case env::StreamEventKind::Accepted: {
        auto s = std::make_unique<Side>();
        s->conn = e.conn;
        s->is_server = true;
        s->connected = true;
        s->last_progress = now;
        sides_.push_back(std::move(s));
        break;
      }
      case env::StreamEventKind::Data:
        if (Side* s = find(e.conn)) on_data(*s, e.data, now);
        break;
      case env::StreamEventKind::Closed:
        if (Side* s = find(e.conn)) on_closed(*s, now);
        break;
      case env::StreamEventKind::Connected:
        break;
    }
  }

  std::vector<std::unique_ptr<Side>> sides_;
  Stage stage_{this};
};

class ClientProc : public Process, AppEnd {
 public:
  ClientProc(Node& n, Harness& h, std::uint32_t client, const ut::ConnConfig& conn, Nanos app_idle,
             env::Endpoint server)
      : AppEnd(n, h, conn, false, app_idle), client_(client), server_(server) {
    n.add_stage(stage_, "utcp-client");
  }

  bool poll() {
    const Nanos now = node_.clock().now_mono();
    bool did = stack_.poll([&](const env::StreamEvent& e) { on_event(e, now); }) > 0;
    if (side_) {
      app_step(*side_, now);
      if (side_->finished()) {
        side_.reset();
        next_start_ = now + static_cast<Nanos>(rng_.below(5 * kMs));
      }
    } else if (h_.complete[client_] < h_.target && now >= next_start_) {
      start(now);
      did = true;
    }
    return did;
  }

 private:
  struct Stage {
    ClientProc* p;
    bool poll() { return p->poll(); }
  };

  void start(Nanos now) {
    const auto c = stack_.connect(server_);
    if (!c) {
      next_start_ = now + kMs;  // no free slot or port yet
      return;
    }
    side_ = std::make_unique<Side>();
    Side& s = *side_;
    s.conn = *c;
    s.client = client_;
    s.session = h_.next_session[client_]++;
    s.spec = session_spec(h_.seed, s.client, s.session);
    s.known = true;
    s.last_progress = now;
    store_be32(s.header.data(), kMagic);
    store_be32(s.header.data() + 4, s.client);
    store_be64(s.header.data() + 8, s.session);
    ++h_.started;
    h_.log("client %u starts session %llu: c2s %llu s2c %llu max_write %u abort %d pause_ppm %u max_pause %lld", client_,
           static_cast<unsigned long long>(s.session), static_cast<unsigned long long>(s.spec.c2s),
           static_cast<unsigned long long>(s.spec.s2c), s.spec.max_write, s.spec.abort_mode ? 1 : 0, s.spec.pause_ppm,
           static_cast<long long>(s.spec.max_pause));
    // A client may abort before the handshake completes.
    if (s.aborter() && s.spec.abort_at == 0 && rng_.chance(1, 2)) {
      close_side(s, true);
      report(s);
    }
  }

  void on_event(const env::StreamEvent& e, Nanos now) {
    if (!side_ || e.conn != side_->conn) return;
    switch (e.kind) {
      case env::StreamEventKind::Connected:
        side_->connected = true;
        side_->last_progress = now;
        break;
      case env::StreamEventKind::Data:
        on_data(*side_, e.data, now);
        break;
      case env::StreamEventKind::Closed:
        on_closed(*side_, now);
        break;
      case env::StreamEventKind::Accepted:
        break;
    }
  }

  std::uint32_t client_;
  env::Endpoint server_;
  std::unique_ptr<Side> side_;
  Nanos next_start_ = 0;
  Stage stage_{this};
};

}  // namespace

Report run_utcp(const Options& o) {
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  // utcp targets a direct cable (07 §2.4; DEVIATIONS.md: out-of-order segments are
  // dropped), so links keep send order; reordering remains a fault class.
  w.net().set_fifo_datagrams(true);
  Rng wl = w.stream(Stream::Workload, 0x7C9);
  h->w = &w;
  h->o = &w.oracles();
  h->seed = o.seed;
  h->verbose = o.verbose;
  h->o_stream = w.oracles().activate("O-UTCP-STREAM", "bytes delivered on a connection are exactly the peer's, in order");
  h->o_close = w.oracles().activate("O-UTCP-CLOSE", "an orderly close arrives only after all of the peer's data");

  const std::uint32_t clients = 1 + static_cast<std::uint32_t>(wl.below(3));
  h->target = 3 + wl.below(6);
  h->next_session.assign(clients, 0);
  h->complete.assign(clients, 0);

  // Connection parameters for the simulated LAN (ranges of session_driver.h,
  // with RTOs in milliseconds so recovery fits the convergence bound).
  ut::ConnConfig conn;
  conn.mss = static_cast<std::uint16_t>(wl.chance(1, 3) ? wl.range(64, 600) : wl.range(600, 1460));
  conn.rx_buffer = static_cast<std::uint32_t>(wl.chance(1, 4) ? wl.range(256, 4096) : wl.range(4096, 65535));
  conn.tx_buffer = static_cast<std::uint32_t>(wl.range(1024, 131072));
  conn.max_inflight = static_cast<std::uint32_t>(wl.chance(1, 4) ? wl.range(conn.mss, 16384) : 65535);
  conn.min_rto = static_cast<Nanos>(wl.range(kMs, 50 * kMs));
  conn.initial_rto = static_cast<Nanos>(wl.range(conn.min_rto, 300 * kMs));
  conn.max_rto = 2 * kNsPerSec;
  conn.time_wait = static_cast<Nanos>(wl.range(5 * kMs, 100 * kMs));
  conn.fin_wait2_timeout = 3 * kNsPerSec;
  conn.dupack_threshold = static_cast<std::uint8_t>(wl.chance(1, 5) ? 0 : 3);
  conn.max_retransmits = 30;
  conn.max_syn_retransmits = 30;
  // Longer than the largest RTO, so live connections are never reclaimed.
  const Nanos app_idle = 3 * kNsPerSec + static_cast<Nanos>(wl.below(2 * kNsPerSec));

  Harness* hp = h.get();
  Node& srv = w.add_node("srv", NodeOptions{true, true});
  srv.set_boot([hp, conn, app_idle](Node& nd, BootReason) { nd.emplace_process<ServerProc>(nd, *hp, conn, app_idle); });
  const env::Endpoint server{srv.ip(), kServicePort};
  for (std::uint32_t c = 0; c < clients; ++c) {
    Node& n = w.add_node("c" + std::to_string(c), NodeOptions{true, true});
    n.set_boot([hp, c, conn, app_idle, server](Node& nd, BootReason) {
      nd.emplace_process<ClientProc>(nd, *hp, c, conn, app_idle, server);
    });
  }
  for (std::size_t i = 0; i < w.node_count(); ++i) w.node(static_cast<NodeId>(i)).boot();

  return finish(
      w, WorldKind::Utcp, o, [hp] { return hp->done(); },
      [hp, clients] {
        std::uint64_t complete = 0;
        for (const std::uint64_t c : hp->complete) complete += c;
        return "clients=" + std::to_string(clients) + " complete=" + std::to_string(complete) +
               " started=" + std::to_string(hp->started) + " idle_aborts=" + std::to_string(hp->aborted_idle) +
               " resets=" + std::to_string(hp->closed_unexpectedly) + " retx=" + std::to_string(hp->retransmits) +
               " rto=" + std::to_string(hp->rto_expiries) + " fast=" + std::to_string(hp->fast_retransmits) +
               " zwp=" + std::to_string(hp->zero_window_probes);
      });
}

}  // namespace lle::sim::worlds::detail
