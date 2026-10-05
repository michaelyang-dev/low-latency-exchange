#pragma once
// The gateway stage gwN (07 §3, WP N-17; 01 §4 step 1, §7).
//
// One pinned thread per gateway owns a SoupBinTCP listening port and the sessions the
// session table assigns to it:
//   - login: the username picks the session; the password is checked against its
//     salted hash (credentials.h); a second login of a session on the same port gets
//     Login Rejected 'S' and leaves the live connection alone (03 §5 decisions). On a
//     node that is not the primary the login is a mirror-attach: a second instance of
//     the session (10 §3).
//   - inbound: framing-only checks (ADR-027, inbound.h); raw OUCH bytes with
//     {session, instance, account, rx_tsc} go into the sequencer's SCQ queue. When the
//     queue is full the connection's remaining input is staged and, once staging runs
//     low, the port is not read at all, so the kernel's receive buffers fill and TCP
//     flow control pushes back. Nothing is dropped.
//   - session events (login / mirror-attach, logout, disconnect) go into the same SCQ as
//     the OUCH messages, tagged (seq::session_event_inbound), in the order the
//     connection produced them: the engine runs cancel-on-disconnect from the journaled
//     events (05 §4 step 8), so a Disconnect must follow every order its connection sent
//     before it, and a reconnect's Login precede that connection's orders (DST-004). An
//     event the full queue refused waits in a backlog, and this gateway's later OUCH
//     waits behind it. (The SessionQueue constructor argument is not used.)
//   - egress: OUCH outputs are taken from the egress ring (md/egress.h) only once their
//     journal index is <= the release watermark (Output Rule, ADR-005). A released
//     message is appended to the session's ReplayStore and sent if the session is
//     logged in on this port; otherwise the next login replays it from the store (ring,
//     then output log). SoupBinTCP sequence numbers are therefore identical on the
//     primary and on mirror sessions: both are positions in the same released stream.
//   - end of day: after the DayEnd marker every session delivers what is left, then
//     End of Session 'Z' (06 §10).
//   - close: a connection whose session ended keeps flushing its last bytes ('Z',
//     Login Rejected) before the port is closed, bounded by close_linger
//     (md/stream_linger.h). Input staged by flow control when the session closes is
//     discarded: the client got no response for it, and the Logout / Disconnect event
//     is already queued.
//
// The stage owns its network stack (Env::Net, e.g. net::Stack<K>), so the backend is
// selectable at run time (07 §1). No allocation on the per-message path: connection
// slots, staging buffers and stores are allocated at start(); a ServerSession is
// constructed in its slot when a connection is accepted (connection setup, cold).
// No locks; single-threaded except for the queues and watermarks.
#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "common/types.h"
#include "env/concepts.h"
#include "gateway/inbound.h"
#include "gateway/replay_store.h"
#include "gateway/session_table.h"
#include "journal/record.h"
#include "log/nlog.h"
#include "md/egress.h"
#include "md/stream_linger.h"
#include "md/work_meter.h"
#include "net/common/conn_table.h"
#include "net/common/fixed_queue.h"
#include "net/common/port.h"
#include "outlog/day.h"
#include "proto/soupbin/server_session.h"
#include "sequencer/sequencer.h"

namespace lle::gw {

struct GatewayConfig {
  std::uint8_t index = 0;      // gw0 / gw1: egress cursor md::kGw0 + index
  std::uint16_t instance = 0;  // session instance of this node (its node id, 10 §3)
  soup::ServerConfig soup{};   // current SoupBinTCP session, timers, packet limit, tx buffer
  net::TcpConfig tcp{};        // connection table and buffers
  env::Endpoint listen{};      // port 0: ephemeral (listen_endpoint())
  std::size_t replay_ring_messages = std::size_t{1} << 16;
  std::size_t replay_ring_bytes = std::size_t{8} << 20;
  std::size_t rx_backlog_bytes = std::size_t{256} << 10;  // per connection, while the SCQ is full
  std::size_t egress_batch = 256;                         // released entries per poll
  std::size_t session_event_backlog = 1024;
  Nanos close_linger = md::kDefaultCloseLinger;  // bound on flushing a closing connection
  std::string outlog_root;  // output-log root (outlog/<day>/soup-<id>.bin); empty: no fallback
  std::uint32_t day = 0;
};

// Node state the gateway reads (written by other stages).
struct GatewayShared {
  md::EgressRing* egress = nullptr;
  md::EgressState* state = nullptr;
  const std::atomic<bool>* mirror = nullptr;  // true while this node is not the primary
};

struct GatewayStats {
  std::uint64_t accepted = 0;
  std::uint64_t closed = 0;
  std::uint64_t logins = 0;
  std::uint64_t mirror_attaches = 0;
  std::uint64_t login_rejects = 0;
  std::uint64_t logouts = 0;
  std::uint64_t disconnects = 0;
  std::uint64_t cod_triggers = 0;     // disconnects of cancel-on-disconnect sessions
  std::uint64_t replays = 0;          // logins that requested an earlier sequence number
  std::uint64_t violations = 0;       // SoupBinTCP protocol violations (framing errors)
  std::uint64_t msgs_in = 0;          // OUCH messages pushed to the sequencer
  std::uint64_t truncated_in = 0;     // over-long payloads forwarded with the malformed flag
  std::uint64_t msgs_out = 0;         // released OUCH messages for this gateway's sessions
  std::uint64_t bytes_in = 0;
  std::uint64_t bytes_out = 0;
  std::uint64_t mpsc_full = 0;        // pushes refused by a full SCQ (each retried later)
  std::uint64_t mpsc_full_episodes = 0;
  std::uint64_t paused_polls = 0;     // polls that did not read the port (flow control)
  std::uint64_t events_dropped = 0;   // session events lost to a full backlog (must stay 0)
  std::uint64_t linger_timeouts = 0;  // closing connections that could not flush in time
  std::uint64_t sessions_live = 0;    // gauge
};

template <class E>
concept GatewayEnvLike = requires {
  typename E::Net;
  typename E::OuchQueue;
  typename E::SessionQueue;
  typename E::Clock;
} && env::StreamEndpointLike<typename E::Net::StreamPort> && env::ClockLike<typename E::Clock>;

template <GatewayEnvLike Env>
class Gateway {
 public:
  using Net = typename Env::Net;
  using Port = typename Net::StreamPort;
  using OuchQueue = typename Env::OuchQueue;
  using SessionQueue = typename Env::SessionQueue;
  using Clock = typename Env::Clock;
  using Store = ReplayStore<outlog::env_reader_t<Env>>;  // Env::OutlogReader, else POSIX

  // `next_seq`: (session id, next SoupBinTCP sequence) after recovery, sorted by
  // session id; sessions not listed start at 1.
  Gateway(const GatewayConfig& cfg, const SessionTable& table,
          std::span<const std::pair<std::uint32_t, SeqNo>> next_seq, OuchQueue& ouch, SessionQueue& /*events*/,
          Clock& clock, GatewayShared shared)
      : cfg_(cfg), table_(&table), ouch_q_(&ouch), clock_(&clock), sh_(shared), work_(&clock) {
    LLE_ASSERT(sh_.egress != nullptr && sh_.state != nullptr, "gateway: egress not wired");
    LLE_ASSERT(cfg_.index < md::kGateways, "gateway index");
    for (const SessionSpec& s : table.all()) {
      if (s.gateway != cfg_.index) continue;
      SeqNo first = 1;
      const auto it = std::lower_bound(next_seq.begin(), next_seq.end(), s.session_id,
                                       [](const auto& p, std::uint32_t id) { return p.first < id; });
      if (it != next_seq.end() && it->first == s.session_id) first = it->second;
      std::string path;
      if (!cfg_.outlog_root.empty()) path = outlog::OutlogDay::soup_path(cfg_.outlog_root, cfg_.day, s.session_id);
      sessions_.push_back(SessionState{&s, std::make_unique<Store>(cfg_.replay_ring_messages, cfg_.replay_ring_bytes,
                                                                   first, std::move(path)),
                                       -1});
    }
    const std::uint32_t n = cfg_.tcp.max_conns;
    // Flow control (below): reading continues while a blocked connection could still
    // take one more poll's worth of reads; the staging buffer holds at least two.
    cfg_.rx_backlog_bytes =
        std::max(cfg_.rx_backlog_bytes, 2 * std::size_t{cfg_.tcp.rx_buf_bytes} * cfg_.tcp.max_reads_per_poll);
    conns_ = std::make_unique<Conn[]>(n);
    for (std::uint32_t i = 0; i < n; ++i) {
      conns_[i].policy = Policy{this, i};
      conns_[i].backlog = std::make_unique<std::byte[]>(cfg_.rx_backlog_bytes);
    }
    events_.init(cfg_.session_event_backlog);
    // Stop reading the port while a blocked connection could not take one more poll's
    // worth of reads.
    pause_below_ = std::size_t{cfg_.tcp.rx_buf_bytes} * cfg_.tcp.max_reads_per_poll;
    LLE_ASSERT(cfg_.rx_backlog_bytes >= 2 * pause_below_,
               "gateway: rx_backlog_bytes must hold two polls of reads (tcp.rx_buf_bytes x tcp.max_reads_per_poll)");
  }
  Gateway(const Gateway&) = delete;
  Gateway& operator=(const Gateway&) = delete;

  // Opens the stack and the listening port.
  std::expected<void, std::string> start() {
    auto r = open_net();
    if (!r) {
      error_ = r.error();
      state_.store(-1, std::memory_order_release);
      return r;
    }
    state_.store(1, std::memory_order_release);
    return {};
  }
  // Opens on the first poll instead, on the thread that will poll the port: an io_uring
  // reactor (SINGLE_ISSUER) must be created and used by one thread (net/uring/ring.h).
  void start_on_first_poll() noexcept { deferred_ = true; }
  // 0 pending, 1 started, -1 failed (error()); acquire, so listen_endpoint() is then set.
  [[nodiscard]] int start_state() const noexcept { return state_.load(std::memory_order_acquire); }
  [[nodiscard]] const std::string& error() const noexcept { return error_; }

  // The stage body (01 §5).
  bool poll() {
    if (deferred_) [[unlikely]] {
      deferred_ = false;
      (void)start();
    }
    if (state_.load(std::memory_order_relaxed) != 1) return false;
    const Nanos now = clock_->now_mono();
    bool did = false;
    (void)net_.wait(0);
    did |= retry_events();
    did |= retry_blocked(now);
    if (paused()) {
      ++stats_.paused_polls;
    } else {
      did |= port_.poll([&](const env::StreamEvent& ev) { on_event(ev, now); }) != 0;
    }
    did |= drain_egress(now);
    did |= run_timers(now);
    work_.finish();
    return did;
  }

  [[nodiscard]] env::Endpoint listen_endpoint() const noexcept { return listen_; }
  [[nodiscard]] const GatewayStats& stats() const noexcept { return stats_; }
  // Work time (md/work_meter.h). Items: port events, released messages delivered,
  // staged messages and session events pushed, and session timer actions.
  [[nodiscard]] const md::WorkStats& work() const noexcept { return work_.stats(); }

 private:
  std::expected<void, std::string> open_net() {
    if (auto r = net_.open(); !r) return std::unexpected("gateway: reactor: " + net::to_string(r.error()));
    if (auto r = net_.open(port_, cfg_.tcp); !r) return std::unexpected("gateway: port: " + net::to_string(r.error()));
    auto ep = port_.listen(cfg_.listen);
    if (!ep) return std::unexpected("gateway: listen: " + net::to_string(ep.error()));
    listen_ = *ep;
    return {};
  }

 public:
  [[nodiscard]] std::size_t sessions() const noexcept { return sessions_.size(); }
  [[nodiscard]] bool ended() const noexcept { return ended_; }
  // The store of a session served by this gateway (tests, recovery checks).
  [[nodiscard]] const Store* store(std::uint32_t session_id) const noexcept {
    const SessionState* s = find_session(session_id);
    return s == nullptr ? nullptr : s->store.get();
  }
  [[nodiscard]] Net& net() noexcept { return net_; }
  [[nodiscard]] Port& port() noexcept { return port_; }

 private:
  // The connection's view of its session's store, bound at login.
  struct ProxyStore {
    Store* target = nullptr;
    [[nodiscard]] SeqNo next_seq() const noexcept { return target != nullptr ? target->next_seq() : 1; }
    bool append(std::span<const std::byte> msg) noexcept { return target != nullptr && target->append(msg); }
    [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo s) const noexcept {
      return target != nullptr ? target->get(s) : std::nullopt;
    }
  };
  struct Policy {
    Gateway* gw = nullptr;
    std::uint32_t slot = 0;
    soup::LoginDecision authorize(const soup::LoginRequest& r) { return gw->authorize(slot, r); }
  };
  using Session = soup::ServerSession<ProxyStore, Policy>;

  struct SessionState {
    const SessionSpec* spec = nullptr;
    std::unique_ptr<Store> store;
    int conn = -1;  // slot of the connection bound to this session on this port
  };

  struct Conn {
    env::ConnId id = env::kNoConn;
    ProxyStore proxy;
    Policy policy;
    std::optional<Session> sess;
    int session = -1;  // index into sessions_ once authorized
    bool logged_in = false;
    bool end_pending = false;  // end the session once the current call's actions are handled
    bool pump = false;         // replay waits for transmit room: call on_timer again
    bool tx_pending = false;   // bytes the port did not accept yet
    soup::CloseReason close_reason = soup::CloseReason::None;
    bool close_now = false;
    bool closing = false;  // closed at the session level; flushing before port close
    Nanos linger_until = 0;
    Nanos deadline = soup::kNever;
    // Back-pressure staging (the SCQ was full).
    bool blocked = false;
    std::array<seq::InboundMsg, soup::kMaxDelivered> pending{};
    std::size_t pending_head = 0;
    std::size_t pending_n = 0;
    std::unique_ptr<std::byte[]> backlog;
    std::size_t bl_head = 0;
    std::size_t bl_tail = 0;
  };

  // ---- login (called from inside ServerSession::on_bytes) ---------------------------

  soup::LoginDecision authorize(std::uint32_t slot, const soup::LoginRequest& r) {
    Conn& c = conns_[slot];
    const SessionSpec* spec = table_->find_user(r.username.view());
    if (spec == nullptr || spec->gateway != cfg_.index || !spec->credential.verify(r.password.view())) {
      NLOG_WARN("gw{} login refused: bad credentials (slot {})", cfg_.index, slot);
      return soup::LoginDecision::NotAuthorized;
    }
    SessionState* s = find_session(spec->session_id);
    if (s == nullptr) return soup::LoginDecision::NotAuthorized;
    if (s->conn >= 0) {
      NLOG_WARN("gw{} login refused: session {} already logged in on this port", cfg_.index, spec->session_id);
      return soup::LoginDecision::SessionUnavailable;
    }
    s->conn = static_cast<int>(slot);
    c.session = static_cast<int>(s - sessions_.data());
    c.proxy.target = s->store.get();
    return soup::LoginDecision::Accept;
  }

  // ---- port events -----------------------------------------------------------------------

  void on_event(const env::StreamEvent& ev, Nanos now) {
    work_.start();
    work_.add();
    const std::uint32_t slot = net::conn_slot(ev.conn);
    switch (ev.kind) {
      case env::StreamEventKind::Accepted: {
        if (slot >= cfg_.tcp.max_conns) {
          port_.close(ev.conn);
          return;
        }
        Conn& c = conns_[slot];
        reset(c);
        c.id = ev.conn;
        c.sess.emplace(cfg_.soup, c.proxy, c.policy, now);
        ++stats_.accepted;
        handle(c, c.sess->on_timer(now), now);  // arms the login timeout
        return;
      }
      case env::StreamEventKind::Data: {
        Conn* c = conn_of(ev.conn);
        if (c == nullptr || !c->sess || c->closing) return;  // a closing connection's input is ignored
        stats_.bytes_in += ev.data.size();
        if (c->blocked) {
          stage_input(*c, ev.data, now);
          return;
        }
        const std::size_t used = feed(*c, ev.data, now);
        if (c->sess && !c->closing && used < ev.data.size()) stage_input(*c, ev.data.subspan(used), now);
        return;
      }
      case env::StreamEventKind::Closed: {
        Conn* c = conn_of(ev.conn);
        if (c == nullptr || !c->sess) return;
        c->id = env::kNoConn;  // the port already released it
        close_conn(*c, soup::CloseReason::None, now);
        return;
      }
      case env::StreamEventKind::Connected: return;
    }
  }

  // Feeds input to the session until it is consumed or the SCQ blocks; returns the
  // bytes consumed.
  std::size_t feed(Conn& c, std::span<const std::byte> data, Nanos now) {
    std::size_t off = 0;
    while (off < data.size() && c.sess && !c.blocked && !c.closing) {
      const soup::Actions& a = c.sess->on_bytes(data.subspan(off), now);
      const std::size_t used = a.consumed;
      handle(c, a, now);
      off += used;
      if (used == 0) break;
    }
    return std::min(off, data.size());
  }

  void stage_input(Conn& c, std::span<const std::byte> data, Nanos now) {
    if (data.empty()) return;
    if (c.bl_head != 0 && cfg_.rx_backlog_bytes - c.bl_tail < data.size()) {
      std::memmove(c.backlog.get(), c.backlog.get() + c.bl_head, c.bl_tail - c.bl_head);
      c.bl_tail -= c.bl_head;
      c.bl_head = 0;
    }
    if (cfg_.rx_backlog_bytes - c.bl_tail < data.size()) {
      // Cannot happen while the pause threshold holds (pause_below_); never drop input.
      NLOG_ERROR("gw{} rx backlog overflow on slot {}: closing", cfg_.index, net::conn_slot(c.id));
      c.close_now = true;
      close_conn(c, soup::CloseReason::ProtocolViolation, now);
      return;
    }
    std::memcpy(c.backlog.get() + c.bl_tail, data.data(), data.size());
    c.bl_tail += data.size();
  }

  // Everything one session call produced, in order: events (login before the data that
  // follows it), delivered messages, bytes to write, the deadline, close.
  void handle(Conn& c, const soup::Actions& a, Nanos now) {
    for (const soup::Event& ev : a.events) on_soup_event(c, ev);
    for (const soup::Delivered& d : a.delivered) deliver_inbound(c, d.data);
    c.deadline = a.deadline;
    flush_tx(c);
    if (a.close || c.close_now) {
      close_conn(c, c.close_reason, now);
      return;
    }
    if (c.end_pending && c.sess) {
      c.end_pending = false;
      handle(c, c.sess->end_session(now), now);
    }
  }

  void on_soup_event(Conn& c, const soup::Event& ev) {
    switch (ev.kind) {
      case soup::EventKind::LoggedIn: {
        if (c.session < 0) return;
        SessionState& s = sessions_[static_cast<std::size_t>(c.session)];
        c.logged_in = true;
        const bool mirror = sh_.mirror != nullptr && sh_.mirror->load(std::memory_order_acquire);
        if (!ended_) {
          push_event(seq::SessionEventMsg{s.spec->session_id, cfg_.instance,
                                          mirror ? journal::SessionEventKind::MirrorAttach
                                                 : journal::SessionEventKind::Login,
                                          ev.seq});
        }
        ++(mirror ? stats_.mirror_attaches : stats_.logins);
        ++stats_.sessions_live;
        const SeqNo next = s.store->next_seq();
        if (ev.seq < next) {
          ++stats_.replays;
          NLOG_INFO("gw{} session {} sequence recovery: replay {} .. {}", cfg_.index, s.spec->session_id, ev.seq,
                    next - 1);
        }
        NLOG_INFO("gw{} login session {} instance {} mirror {} next {}", cfg_.index, s.spec->session_id,
                  cfg_.instance, mirror, ev.seq);
        if (ended_) c.end_pending = true;
        return;
      }
      case soup::EventKind::LoginRejected:
        ++stats_.login_rejects;
        NLOG_WARN("gw{} login rejected '{}'", cfg_.index, ev.code);
        if (!c.logged_in) unbind(c);
        return;
      case soup::EventKind::Closed:
        c.close_reason = ev.reason;
        if (ev.reason == soup::CloseReason::ProtocolViolation) ++stats_.violations;
        return;
      case soup::EventKind::EndOfSession:
        if (c.session >= 0) {
          NLOG_INFO("gw{} end of session {} at {}", cfg_.index, sessions_[static_cast<std::size_t>(c.session)].spec->session_id,
                    ev.seq);
        }
        return;
      case soup::EventKind::SequenceAhead:
        NLOG_WARN("gw{} login asked for sequence {} ahead of next {}", cfg_.index, ev.seq, ev.aux);
        return;
      case soup::EventKind::StoreFull:
        NLOG_ERROR("gw{} sequenced store refused an append at {}", cfg_.index, ev.seq);
        return;
    }
  }

  void deliver_inbound(Conn& c, std::span<const std::byte> payload) {
    if (c.session < 0) return;  // ServerSession delivers data only after login
    const SessionSpec& spec = *sessions_[static_cast<std::size_t>(c.session)].spec;
    // Behind a session event still waiting for the queue, as behind a blocked push:
    // the queue holds this gateway's input in its order (DST-004).
    if (c.blocked || c.pending_n != 0 || !events_.empty()) {
      stage_msg(c, spec, payload);
      return;
    }
    seq::InboundMsg m;
    make_inbound(m, spec.session_id, spec.account, cfg_.instance, payload, clock_->tsc());
    if (ouch_q_->try_push(m)) {
      count_in(m);
      return;
    }
    ++stats_.mpsc_full;
    ++stats_.mpsc_full_episodes;
    NLOG_WARN("gw{} sequencer queue full: session {} staged (flow control)", cfg_.index, spec.session_id);
    c.blocked = true;
    stage_built(c, m);
  }

  void stage_msg(Conn& c, const SessionSpec& spec, std::span<const std::byte> payload) {
    seq::InboundMsg m;
    make_inbound(m, spec.session_id, spec.account, cfg_.instance, payload, clock_->tsc());
    c.blocked = true;
    stage_built(c, m);
  }
  void stage_built(Conn& c, const seq::InboundMsg& m) {
    // At most one on_bytes() call's deliveries are staged: feed() stops at blocked.
    LLE_ASSERT(c.pending_n < c.pending.size(), "gateway: staged messages exceed one delivery batch");
    c.pending[(c.pending_head + c.pending_n) % c.pending.size()] = m;
    ++c.pending_n;
  }
  void count_in(const seq::InboundMsg& m) noexcept {
    ++stats_.msgs_in;
    if ((m.flags & journal::kFlagMalformedInput) != 0) ++stats_.truncated_in;
  }

  void flush_tx(Conn& c) {
    if (!c.sess || c.id == env::kNoConn) return;
    const std::span<const std::byte> w = c.sess->actions().write;
    if (w.empty()) {
      c.tx_pending = false;
      return;
    }
    const std::size_t n = port_.write(c.id, w);
    stats_.bytes_out += n;
    if (n != 0) c.pump = c.sess->consume_tx(n);
    c.tx_pending = n < w.size();
  }

  // Closes the session now and the port once its last bytes are out (linger).
  void close_conn(Conn& c, soup::CloseReason reason, Nanos now) {
    if (c.closing) {  // already closed at the session level
      if (c.id == env::kNoConn) reset(c);  // the peer went away while lingering
      return;
    }
    if (c.logged_in && c.session >= 0) {
      const SessionState& s = sessions_[static_cast<std::size_t>(c.session)];
      const bool logout = reason == soup::CloseReason::LogoutRequested;
      if (stats_.sessions_live > 0) --stats_.sessions_live;
      NLOG_INFO("gw{} session {} {} (reason {})", cfg_.index, s.spec->session_id, logout ? 'O' : 'D',
                static_cast<std::uint8_t>(reason));
      // After DayEnd nothing more is journaled (06 §10): sessions just end.
      if (!ended_) {
        push_event(seq::SessionEventMsg{s.spec->session_id, cfg_.instance,
                                        logout ? journal::SessionEventKind::Logout
                                               : journal::SessionEventKind::Disconnect,
                                        0});
        ++(logout ? stats_.logouts : stats_.disconnects);
        if (!logout && s.spec->cancel_on_disconnect) {
          ++stats_.cod_triggers;
          NLOG_INFO("gw{} cancel-on-disconnect trigger: session {} instance {}", cfg_.index, s.spec->session_id,
                    cfg_.instance);
        }
      }
    }
    unbind(c);
    ++stats_.closed;
    c.end_pending = false;
    c.pump = false;
    c.blocked = false;
    c.pending_head = c.pending_n = 0;
    c.bl_head = c.bl_tail = 0;
    if (c.id != env::kNoConn && !tx_drained(c)) {
      c.closing = true;
      c.linger_until = now + cfg_.close_linger;
      c.deadline = soup::kNever;
      return;
    }
    finish_close(c);
  }

  [[nodiscard]] bool tx_drained(const Conn& c) const noexcept {
    return (!c.sess || c.sess->actions().write.empty()) && md::port_tx_pending(port_, c.id) == 0;
  }

  void finish_close(Conn& c) {
    if (c.id != env::kNoConn) port_.close(c.id);
    reset(c);
  }

  // A closing connection: write what is left, close the port once it is out.
  void linger(Conn& c, Nanos now) {
    flush_tx(c);
    if (tx_drained(c)) {
      finish_close(c);
    } else if (now >= c.linger_until) {
      ++stats_.linger_timeouts;
      NLOG_WARN("gw{} slot {}: closing with {} bytes unsent (peer not reading)", cfg_.index, net::conn_slot(c.id),
                c.sess->actions().write.size() + md::port_tx_pending(port_, c.id));
      finish_close(c);
    }
  }

  void unbind(Conn& c) noexcept {
    if (c.session >= 0) {
      SessionState& s = sessions_[static_cast<std::size_t>(c.session)];
      if (s.conn >= 0 && &conns_[static_cast<std::size_t>(s.conn)] == &c) s.conn = -1;
    }
    c.proxy.target = nullptr;
    c.session = -1;
    c.logged_in = false;
  }

  void reset(Conn& c) {
    c.sess.reset();
    c.id = env::kNoConn;
    c.proxy.target = nullptr;
    c.session = -1;
    c.logged_in = false;
    c.end_pending = false;
    c.pump = false;
    c.tx_pending = false;
    c.close_reason = soup::CloseReason::None;
    c.close_now = false;
    c.closing = false;
    c.linger_until = 0;
    c.deadline = soup::kNever;
    c.blocked = false;
    c.pending_head = c.pending_n = 0;
    c.bl_head = c.bl_tail = 0;
  }

  Conn* conn_of(env::ConnId id) noexcept {
    const std::uint32_t slot = net::conn_slot(id);
    if (slot >= cfg_.tcp.max_conns || conns_[slot].id != id) return nullptr;
    return &conns_[slot];
  }

  // ---- back-pressure -----------------------------------------------------------------

  [[nodiscard]] bool paused() const noexcept {
    for (std::uint32_t i = 0; i < cfg_.tcp.max_conns; ++i) {
      const Conn& c = conns_[i];
      if (c.blocked && cfg_.rx_backlog_bytes - (c.bl_tail - c.bl_head) < pause_below_) return true;
    }
    return false;
  }

  bool retry_blocked(Nanos now) {
    if (!events_.empty()) return false;  // the session events go first (DST-004)
    bool did = false;
    for (std::uint32_t i = 0; i < cfg_.tcp.max_conns; ++i) {
      Conn& c = conns_[i];
      if (!c.blocked || !c.sess) continue;
      while (c.pending_n != 0) {
        const seq::InboundMsg& m = c.pending[c.pending_head];
        if (!ouch_q_->try_push(m)) {
          ++stats_.mpsc_full;
          break;
        }
        work_.start();
        work_.add();
        count_in(m);
        c.pending_head = (c.pending_head + 1) % c.pending.size();
        --c.pending_n;
        did = true;
      }
      if (c.pending_n != 0) continue;
      c.blocked = false;
      c.pending_head = 0;
      work_.start();
      work_.add();
      // Resume the staged input in place; whatever blocks again stays staged.
      const std::size_t used =
          feed(c, std::span<const std::byte>(c.backlog.get() + c.bl_head, c.bl_tail - c.bl_head), now);
      if (!c.sess || c.closing) continue;  // closed while feeding
      c.bl_head += used;
      if (c.bl_head == c.bl_tail) c.bl_head = c.bl_tail = 0;
      did = true;
    }
    return did;
  }

  // Session events travel in the OUCH queue, behind every OUCH this gateway pushed
  // before them (seq::session_event_inbound, DST-004).
  void push_event(const seq::SessionEventMsg& ev) {
    if (events_.empty() && ouch_q_->try_push(seq::session_event_inbound(ev))) return;
    if (!events_.push(ev)) {
      ++stats_.events_dropped;
      NLOG_ERROR("gw{} session event backlog full: event for session {} lost", cfg_.index, ev.session_id);
    }
  }
  bool retry_events() {
    bool did = false;
    while (!events_.empty() && ouch_q_->try_push(seq::session_event_inbound(events_.front()))) {
      work_.start();
      work_.add();
      events_.pop();
      did = true;
    }
    return did;
  }

  // ---- egress (Output Rule) -------------------------------------------------------------

  bool drain_egress(Nanos now) {
    const std::size_t n = md::drain_released(*sh_.egress, *sh_.state, md::kGw0 + cfg_.index, cfg_.egress_batch,
                                             [&](const md::OutEntry& e) {
                                               work_.start();
                                               work_.add();
                                               if (e.kind == md::OutKind::Ouch) {
                                                 if (SessionState* s = find_session(e.session)) deliver(*s, e.msg, now);
                                               } else if (e.kind == md::OutKind::DayEnd) {
                                                 end_day(now);
                                               }
                                               return true;
                                             });
    return n != 0;
  }

  void deliver(SessionState& s, std::span<const std::byte> msg, Nanos now) {
    ++stats_.msgs_out;
    if (s.conn >= 0) {
      Conn& c = conns_[static_cast<std::size_t>(s.conn)];
      if (c.logged_in && c.sess) {
        handle(c, c.sess->send_sequenced(msg, now), now);
        return;
      }
    }
    (void)s.store->append(msg);
  }

  void end_day(Nanos now) {
    if (ended_) return;
    ended_ = true;
    NLOG_INFO("gw{} end of day: ending {} sessions", cfg_.index, sessions_.size());
    for (SessionState& s : sessions_) {
      if (s.conn < 0) continue;
      Conn& c = conns_[static_cast<std::size_t>(s.conn)];
      if (c.logged_in && c.sess) handle(c, c.sess->end_session(now), now);
    }
  }

  bool run_timers(Nanos now) {
    bool did = false;
    for (std::uint32_t i = 0; i < cfg_.tcp.max_conns; ++i) {
      Conn& c = conns_[i];
      if (!c.sess) continue;
      if (c.closing) {
        work_.start();
        work_.add();
        linger(c, now);
        did = true;
      } else if (now >= c.deadline || c.pump) {
        work_.start();
        work_.add();
        c.pump = false;
        handle(c, c.sess->on_timer(now), now);
        did = true;
      } else if (c.tx_pending) {
        work_.start();
        work_.add();
        flush_tx(c);
        did = true;
      }
    }
    return did;
  }

  SessionState* find_session(std::uint32_t id) noexcept {
    const auto it = std::lower_bound(sessions_.begin(), sessions_.end(), id,
                                     [](const SessionState& s, std::uint32_t v) { return s.spec->session_id < v; });
    return it != sessions_.end() && it->spec->session_id == id ? &*it : nullptr;
  }
  const SessionState* find_session(std::uint32_t id) const noexcept {
    return const_cast<Gateway*>(this)->find_session(id);
  }

  GatewayConfig cfg_;
  const SessionTable* table_;
  OuchQueue* ouch_q_;
  Clock* clock_;
  GatewayShared sh_;
  Net net_;
  Port port_;
  env::Endpoint listen_{};
  bool deferred_ = false;
  std::atomic<int> state_{0};
  std::string error_;
  std::vector<SessionState> sessions_;  // sorted by session id (the table is)
  std::unique_ptr<Conn[]> conns_;
  net::FixedQueue<seq::SessionEventMsg> events_;
  std::size_t pause_below_ = 0;
  bool ended_ = false;
  GatewayStats stats_{};
  md::WorkMeter<Clock> work_;
};

}  // namespace lle::gw
