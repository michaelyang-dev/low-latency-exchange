// Model-based randomized tests of the SoupBinTCP sessions (03-protocols s5, s9:
// "Session state machines"). No RapidCheck: a seeded generator drives random
// command sequences against a reference model of one logical session (the
// server's sequenced stream plus the client's persisted position) while real
// ServerSession/ClientSession objects talk over a lossless byte pipe with
// random segmentation, coalescing and latency, on a simulated clock.
//
// Checked on every step:
//  - every sequenced message the client receives has the model's content for
//    its sequence number, and numbering is contiguous from Login Accepted;
//  - a normal re-login (requested = next expected) resumes with no gap or
//    duplicate; requested 0 starts at max(1, highest); ahead -> 'S' + alarm;
//  - unsequenced messages reach the server in order (a prefix if the
//    connection drops mid-flight; all of them otherwise);
//  - heartbeats: with both sides live, neither side ever sees more than
//    heartbeat_interval + max latency of silence, and no idle timeout fires;
//  - a frozen client is dropped exactly 15 s after its last byte arrived;
//    a connection that never logs in is dropped exactly at 30 s;
//  - bad credentials -> 'A', unknown session -> 'S', second login on the port
//    -> 'S' while the live connection keeps working.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/prng.h"
#include "proto/soupbin/soupbin.h"
#include "soup_test_util.h"

namespace lle::soup {
namespace {

using test::Bytes;
using test::str;

constexpr Nanos kMs = 1'000'000;
constexpr Nanos kSec = kNsPerSec;

struct ModelPolicy {
  bool live = false;
  LoginDecision authorize(const LoginRequest& r) {
    if (!credential_equals(std::as_bytes(std::span(r.username.c)), "USER") ||
        !credential_equals(std::as_bytes(std::span(r.password.c)), "secret"))
      return LoginDecision::NotAuthorized;
    return live ? LoginDecision::SessionUnavailable : LoginDecision::Accept;
  }
};

using Server = ServerSession<MemorySequencedStore, ModelPolicy>;

// One direction of a TCP connection: in order, lossless, random segmentation.
struct Pipe {
  struct Chunk {
    Nanos t;
    Bytes data;
  };
  std::deque<Chunk> q;
  Nanos last = 0;

  void push(Nanos now, std::span<const std::byte> b, Prng& r, Nanos lat_base, Nanos lat_jitter) {
    std::size_t pos = 0;
    while (pos < b.size()) {
      std::size_t len = b.size() - pos;
      if (r.chance(1, 2)) len = 1 + static_cast<std::size_t>(r.below(std::min<std::size_t>(len, 40)));
      const Nanos t = std::max(last, now + lat_base + static_cast<Nanos>(r.below(static_cast<std::uint64_t>(lat_jitter) + 1)));
      last = t;
      q.push_back({t, Bytes(b.begin() + static_cast<std::ptrdiff_t>(pos),
                            b.begin() + static_cast<std::ptrdiff_t>(pos + len))});
      pos += len;
    }
  }
  [[nodiscard]] Nanos next_time() const { return q.empty() ? kNever : q.front().t; }
  // Pops a random number of due chunks, coalesced.
  Bytes pop_due(Nanos now, Prng& r) {
    Bytes out;
    std::uint64_t take = 1 + r.below(4);
    while (!q.empty() && q.front().t <= now && take-- > 0) {
      out.insert(out.end(), q.front().data.begin(), q.front().data.end());
      q.pop_front();
    }
    return out;
  }
};

enum class LoginKind { Normal, Zero, One, Ahead, BadPassword, UnknownSession, Silent };

// Scenario coverage across all sequences (asserted at the end of the test).
struct Stats {
  std::uint64_t logins = 0, zero_logins = 0, replays = 0, rejects_a = 0, rejects_s = 0, ahead_alarms = 0;
  std::uint64_t idle_timeouts = 0, login_timeouts = 0, second_logins = 0, end_of_sessions = 0;
  std::uint64_t sequenced_delivered = 0, unsequenced_delivered = 0, s2c_bytes = 0, client_heartbeats = 0;
};
Stats& stats() {
  static Stats s;
  return s;
}

struct Conn {
  std::optional<Server> server;
  std::optional<ClientSession> client;
  Pipe c2s, s2c;
  Nanos lat_base = 0, lat_jitter = 0;
  Nanos connected_at = 0;
  LoginKind kind = LoginKind::Normal;
  SeqNo requested = 1;
  bool client_frozen = false;
  bool server_closed = false, client_closed = false;  // closed by that side; peer sees EOF after the pipe drains
  bool logged_in = false;
  bool expect_resume = false;  // requested == client's persisted next
  SeqNo client_expect = 0;     // next sequence the client must receive
  std::vector<std::string> client_sent, server_got;
  Nanos last_s2c = 0, last_c2s = 0;  // last arrival at the client / server
  Nanos frozen_at_rx = -1;           // server's last receive time when the client froze
};

class World {
 public:
  explicit World(std::uint64_t seed) : r_(seed), store_(1024, 1 << 16) {
    scfg_.session = SessionId::from("SESS" + std::to_string(seed % 1000));
    static constexpr std::size_t kTx[] = {128, 512, 65536};
    scfg_.tx_capacity = kTx[r_.below(3)];
    scfg_.max_replay_per_call = 1 + r_.below(64);
    ccfg_.username = Alpha<6>("user");  // case-insensitive match
    ccfg_.password = Alpha<10>("SECRET");
    ccfg_.tx_capacity = kTx[r_.below(3)];
    ccfg_.max_packet_length = 4096;
  }

  std::string failure;

  void run(int steps) {
    for (int i = 0; i < steps && failure.empty() && !ended_; ++i) step();
    if (failure.empty()) finish();
  }

 private:
  void fail(const std::string& why) {
    if (failure.empty()) failure = why + " (t=" + std::to_string(now_) + ")";
  }

  // ---------------------------------------------------------------- commands
  void step() {
    const std::uint64_t k = r_.below(1000);
    if (k < 280) {
      app_send_sequenced();
    } else if (k < 470) {
      client_send();
    } else if (k < 720) {
      advance(now_ + static_cast<Nanos>(r_.below(50)) * kMs);
    } else if (k < 820) {
      advance(now_ + 500 * kMs + static_cast<Nanos>(r_.below(2500)) * kMs);
    } else if (k < 835) {
      advance(now_ + 10 * kSec + static_cast<Nanos>(r_.below(30)) * kSec);
    } else if (k < 885) {
      drop();
    } else if (k < 955) {
      if (!conn_) connect();
    } else if (k < 970) {
      logout();
    } else if (k < 980) {
      freeze_client();
    } else if (k < 990) {
      second_login();
    } else if (k < 993) {
      end_session();
    } else {
      advance(now_ + 1);
    }
  }

  void app_send_sequenced() {
    std::string m(static_cast<std::size_t>(r_.below(80)), ' ');
    for (char& c : m) c = static_cast<char>(r_.below(256));
    stream_.push_back(m);
    const auto b = std::as_bytes(std::span(m.data(), m.size()));
    if (conn_ && conn_->server && !conn_->server_closed) {
      const Actions& a = conn_->server->send_sequenced(b, now_);
      if (!a.accepted) return fail("send_sequenced refused");
      handle_server(a);
    } else if (!store_.append(b)) {
      fail("store append failed");
    }
  }

  void client_send() {
    if (!conn_ || !conn_->client || conn_->client_closed || conn_->client_frozen) return;
    if (conn_->client->state() != ClientSession::State::Active) {
      if (conn_->client->send_unsequenced({}, now_).accepted) fail("client sent before Login Accepted");
      return;
    }
    std::string m(static_cast<std::size_t>(r_.below(60)), ' ');
    for (char& c : m) c = static_cast<char>(r_.below(256));
    const Actions& a = conn_->client->send_unsequenced(std::as_bytes(std::span(m.data(), m.size())), now_);
    if (!a.accepted) return fail("client send refused while active");
    conn_->client_sent.push_back(m);
    handle_client(a);
  }

  void connect() {
    conn_.emplace();
    Conn& c = *conn_;
    c.connected_at = c.last_s2c = c.last_c2s = now_;
    c.lat_base = static_cast<Nanos>(r_.below(5)) * kMs;
    c.lat_jitter = static_cast<Nanos>(r_.below(200)) * kMs;
    c.c2s.last = c.s2c.last = now_;
    c.server.emplace(scfg_, store_, policy_, now_);
    const std::uint64_t k = r_.below(100);
    c.kind = k < 70 ? LoginKind::Normal
           : k < 78 ? LoginKind::Zero
           : k < 83 ? LoginKind::One
           : k < 88 ? LoginKind::Ahead
           : k < 92 ? LoginKind::BadPassword
           : k < 96 ? LoginKind::UnknownSession
                    : LoginKind::Silent;
    if (c.kind == LoginKind::Silent) {
      // A connection that never logs in: only the server side exists.
      handle_server(c.server->on_timer(now_));
      return;
    }
    ClientConfig cfg = ccfg_;
    cfg.session = r_.chance(1, 2) ? learned_ : SessionId();
    cfg.sequence = client_next_;
    switch (c.kind) {
      case LoginKind::Zero: cfg.sequence = 0; break;
      case LoginKind::One: cfg.sequence = 1; break;
      case LoginKind::Ahead: cfg.sequence = store_.next_seq() + 1 + r_.below(3); break;
      case LoginKind::BadPassword: cfg.password = Alpha<10>("wrong"); break;
      case LoginKind::UnknownSession: cfg.session = SessionId::from("NOSUCH"); break;
      default: break;
    }
    c.requested = cfg.sequence;
    c.expect_resume = c.kind == LoginKind::Normal;
    c.client.emplace(cfg);
    handle_client(c.client->connect(now_));
  }

  void drop() {
    if (!conn_) return;
    end_conn();
  }

  void logout() {
    if (!conn_ || !conn_->client || conn_->client_closed || conn_->client_frozen) return;
    handle_client(conn_->client->logout(now_));
  }

  void freeze_client() {
    if (!conn_ || !conn_->client || conn_->client_closed || !conn_->server || conn_->server_closed) return;
    if (conn_->server->state() != Server::State::Active || !conn_->c2s.q.empty()) return;
    conn_->client_frozen = true;
    conn_->frozen_at_rx = conn_->last_c2s;
    advance(now_ + 16 * kSec);
    if (conn_ && conn_->server && !conn_->server_closed) fail("frozen client not dropped after 15 s");
  }

  // Another login for the same username on this port while one is live.
  void second_login() {
    if (!conn_ || !conn_->logged_in || !policy_.live || conn_->server_closed) return;
    Server other(scfg_, store_, policy_, now_);
    const Bytes l = test::packet(
        'L', test::login_payload("USER", "secret", std::string(10, ' '), test::pad_left("1", 20)));
    const Actions& a = other.on_bytes(std::span<const std::byte>(l.data(), l.size()), now_);
    const auto out = test::parse_all(a.write);
    if (!a.close || out.size() != 1 || out[0].type != 'J' || out[0].payload != "S")
      fail("second login on the port not rejected with 'S'");
    ++stats().second_logins;
    if (!policy_.live) fail("second login disturbed the live flag");
  }

  void end_session() {
    if (!conn_ || !conn_->server || conn_->server_closed || !conn_->logged_in) return;
    handle_server(conn_->server->end_session(now_));
    ending_ = true;
  }

  // ---------------------------------------------------------------- event loop
  void advance(Nanos target) {
    int guard = 0;
    while (failure.empty()) {
      if (++guard > 1'000'000) return fail("event loop does not converge");
      Nanos t = target;
      if (conn_) {
        Conn& c = *conn_;
        t = std::min({t, c.c2s.next_time(), c.s2c.next_time()});
        if (c.server && !c.server_closed) t = std::min(t, c.server->actions().deadline);
        if (c.client && !c.client_closed && !c.client_frozen) t = std::min(t, c.client->actions().deadline);
      }
      if (t > target) break;
      now_ = std::max(now_, t);
      if (!conn_) break;
      Conn& c = *conn_;
      bool progressed = false;
      if (c.c2s.next_time() <= now_) {
        progressed = true;
        deliver_to_server(c.c2s.pop_due(now_, r_));
      }
      if (conn_ && conn_->s2c.next_time() <= now_) {
        progressed = true;
        deliver_to_client(conn_->s2c.pop_due(now_, r_));
      }
      if (conn_ && conn_->server && !conn_->server_closed && conn_->server->actions().deadline <= now_) {
        progressed = true;
        handle_server(conn_->server->on_timer(now_));
      }
      if (conn_ && conn_->client && !conn_->client_closed && !conn_->client_frozen &&
          conn_->client->actions().deadline <= now_) {
        progressed = true;
        handle_client(conn_->client->on_timer(now_));
      }
      if (conn_) check_teardown();
      if (conn_) check_liveness();
      if (!progressed && t == target) break;
    }
    now_ = std::max(now_, target);
  }

  void deliver_to_server(const Bytes& b) {
    Conn& c = *conn_;
    if (!c.server || c.server_closed) return;
    if (c.last_c2s != 0 && !c.client_frozen && c.logged_in && c.client && !c.client_closed &&
        now_ - c.last_c2s > ccfg_.heartbeat_interval + c.lat_base + c.lat_jitter + 1)
      fail("server heard nothing for more than heartbeat + latency");
    c.last_c2s = now_;
    std::size_t pos = 0;
    while (pos < b.size() && conn_ && conn_->server && !conn_->server_closed) {
      const Actions& a = c.server->on_bytes(std::span<const std::byte>(b.data() + pos, b.size() - pos), now_);
      pos += a.consumed;
      handle_server(a);
      if (a.consumed == 0) break;
    }
  }

  void deliver_to_client(const Bytes& b) {
    Conn& c = *conn_;
    if (!c.client || c.client_closed) return;
    if (c.client_frozen) return;  // a frozen client reads nothing
    if (c.logged_in && c.server && !c.server_closed &&
        now_ - c.last_s2c > scfg_.heartbeat_interval + c.lat_base + c.lat_jitter + 1)
      fail("client heard nothing for more than heartbeat + latency");
    c.last_s2c = now_;
    stats().s2c_bytes += b.size();
    std::size_t pos = 0;
    while (pos < b.size() && conn_ && conn_->client && !conn_->client_closed) {
      const Actions& a = c.client->on_bytes(std::span<const std::byte>(b.data() + pos, b.size() - pos), now_);
      pos += a.consumed;
      handle_client(a);
      if (a.consumed == 0) break;
    }
  }

  // ---------------------------------------------------------------- action handling
  void handle_server(const Actions& a) {
    Conn& c = *conn_;
    if (!a.write.empty()) {
      c.s2c.push(now_, a.write, r_, c.lat_base, c.lat_jitter);
      c.server->consume_tx(a.write.size());
    }
    for (const Delivered& d : a.delivered) {
      if (d.seq != 0) fail("server delivered a sequenced message");
      c.server_got.push_back(str(d.data));
      ++stats().unsequenced_delivered;
      if (c.server_got.size() > c.client_sent.size() ||
          c.server_got.back() != c.client_sent[c.server_got.size() - 1])
        fail("server received unsequenced data out of order or corrupted");
    }
    for (const Event& e : a.events) on_server_event(e);
    if (a.close && !c.server_closed) {
      c.server_closed = true;
      policy_.live = false;
    }
  }

  void on_server_event(const Event& e) {
    Conn& c = *conn_;
    const SeqNo next = store_.next_seq();
    switch (e.kind) {
      case EventKind::LoggedIn: {
        // "Ahead" is judged against the store when the Login is processed: more
        // messages may have been appended while it was in flight.
        if (c.kind == LoginKind::BadPassword || c.kind == LoginKind::UnknownSession)
          return fail("login accepted that must be rejected");
        if (c.requested > next) return fail("accepted a sequence above next");
        ++stats().logins;
        if (c.requested == 0) ++stats().zero_logins;
        if (c.requested < next) ++stats().replays;
        const SeqNo want = c.requested == 0 ? std::max<SeqNo>(1, next - 1) : c.requested;
        if (e.seq != want) return fail("Login Accepted sequence differs from the decision table");
        if (policy_.live) return fail("two live logins");
        policy_.live = true;
        c.logged_in = true;
        break;
      }
      case EventKind::LoginRejected: {
        const char want = c.kind == LoginKind::BadPassword ? 'A' : 'S';
        const bool expected = c.kind == LoginKind::BadPassword || c.kind == LoginKind::UnknownSession ||
                              (c.kind == LoginKind::Ahead && c.requested > next) || ending_;
        if (!expected || e.code != want) return fail(std::string("unexpected login reject ") + e.code);
        ++(e.code == 'A' ? stats().rejects_a : stats().rejects_s);
        break;
      }
      case EventKind::SequenceAhead:
        if (c.kind != LoginKind::Ahead || e.seq != c.requested || e.aux != next) fail("bad SequenceAhead alarm");
        ++stats().ahead_alarms;
        break;
      case EventKind::Closed:
        switch (e.reason) {
          case CloseReason::IdleTimeout:
            if (!c.client_frozen && !c.client_closed) return fail("server idle timeout on a live client");
            if (c.client_frozen && now_ - c.frozen_at_rx != scfg_.idle_timeout)
              return fail("idle timeout not at exactly 15 s");
            ++stats().idle_timeouts;
            break;
          case CloseReason::LoginTimeout:
            if (c.kind != LoginKind::Silent || now_ - c.connected_at != scfg_.login_timeout)
              return fail("unexpected login timeout");
            ++stats().login_timeouts;
            break;
          case CloseReason::ProtocolViolation:
          case CloseReason::StoreUnavailable: return fail("server protocol violation in a clean run");
          default: break;
        }
        break;
      case EventKind::StoreFull: return fail("store full");
      case EventKind::EndOfSession: break;
    }
  }

  void handle_client(const Actions& a) {
    Conn& c = *conn_;
    if (!a.write.empty()) {
      c.c2s.push(now_, a.write, r_, c.lat_base, c.lat_jitter);
      c.client->consume_tx(a.write.size());
    }
    for (const Event& e : a.events) on_client_event(e);
    for (const Delivered& d : a.delivered) {
      if (d.seq == 0) {
        fail("client received unsequenced data in 3.00 mode");
        continue;
      }
      if (d.seq != c.client_expect) {
        fail("client sequence numbering not contiguous");
        continue;
      }
      if (d.seq > stream_.size() || str(d.data) != stream_[d.seq - 1]) {
        fail("client received the wrong content for its sequence number");
        continue;
      }
      ++c.client_expect;
      ++stats().sequenced_delivered;
    }
    if (a.close && !c.client_closed) c.client_closed = true;
  }

  void on_client_event(const Event& e) {
    Conn& c = *conn_;
    switch (e.kind) {
      case EventKind::LoggedIn:
        if (c.expect_resume && e.seq != c.requested) fail("re-login did not resume at the requested sequence");
        c.client_expect = e.seq;
        break;
      case EventKind::LoginRejected: break;  // checked on the server side
      case EventKind::EndOfSession:
        if (!ending_) fail("unexpected end of session");
        ++stats().end_of_sessions;
        break;
      case EventKind::Closed:
        if (e.reason == CloseReason::IdleTimeout) fail("client idle timeout on a live server");
        if (e.reason == CloseReason::ProtocolViolation) fail("client protocol violation");
        if (e.reason == CloseReason::LoginTimeout) fail("client login timeout");
        break;
      default: break;
    }
  }

  void check_liveness() {
    Conn& c = *conn_;
    if (!c.logged_in || c.client_frozen || c.server_closed || c.client_closed || !c.client) return;
    if (c.client->state() != ClientSession::State::Active) return;
    // Silence bounds also hold between arrivals (nothing in flight).
    if (c.s2c.q.empty() && now_ - c.last_s2c > scfg_.heartbeat_interval + c.lat_base + c.lat_jitter + 1)
      fail("client starved of heartbeats");
  }

  // A side that closed has flushed its bytes; once they are delivered the peer sees EOF.
  void check_teardown() {
    Conn& c = *conn_;
    const bool server_done = !c.server || (c.server_closed && c.s2c.q.empty());
    const bool client_done = !c.client || (c.client_closed && c.c2s.q.empty());
    if (c.server_closed && c.s2c.q.empty() && c.client && !c.client_closed) {
      if (c.client) remember_client();
      c.client_closed = true;
    }
    if (c.client_closed && c.c2s.q.empty() && c.server && !c.server_closed) {
      c.server_closed = true;
      policy_.live = false;
    }
    if ((server_done || c.server_closed) && (client_done || c.client_closed) && c.s2c.q.empty() && c.c2s.q.empty())
      end_conn();
  }

  void remember_client() {
    Conn& c = *conn_;
    if (c.client && c.logged_in && c.client->state() != ClientSession::State::AwaitingLoginResponse) {
      // Only a resume-style login advances the persisted position monotonically.
      if (c.client->next_expected() >= client_next_ || c.kind == LoginKind::Normal) {
        client_next_ = std::max(client_next_, c.client->next_expected());
      }
      learned_ = c.client->session();
    }
  }

  void end_conn() {
    Conn& c = *conn_;
    if (c.server_got.size() > c.client_sent.size()) fail("server got more than the client sent");
    remember_client();
    if (c.server && !c.server_closed) policy_.live = false;
    if (c.logged_in) policy_.live = false;
    conn_.reset();
  }

  void finish() {
    if (ended_) return;
    if (conn_ && conn_->logged_in && !conn_->client_frozen && !ending_) {
      advance(now_ + 3 * kSec);  // drain replay, data and heartbeats
      if (conn_ && conn_->client && !conn_->client_closed && !conn_->server_closed &&
          conn_->client->state() == ClientSession::State::Active) {
        if (conn_->client_expect != store_.next_seq()) fail("client did not catch up with the stream");
        if (conn_->server_got != conn_->client_sent) fail("server did not receive every unsequenced message");
      }
    }
    if (stream_.size() + 1 != store_.next_seq()) fail("store and model diverged");
  }

  Prng r_;
  Nanos now_ = 1;
  ServerConfig scfg_;
  ClientConfig ccfg_;
  MemorySequencedStore store_;
  ModelPolicy policy_;
  std::vector<std::string> stream_;
  SeqNo client_next_ = 1;
  SessionId learned_;
  std::optional<Conn> conn_;
  bool ending_ = false;
  bool ended_ = false;
};

TEST(SoupModel, RandomCommandSequences) {
  constexpr int kSequences = 100'000;
  constexpr int kSteps = 40;
  stats() = Stats{};
  int failures = 0;
  for (int s = 0; s < kSequences; ++s) {
    World w(std::uint64_t{0x50AB'0000} + static_cast<std::uint64_t>(s));
    w.run(kSteps);
    if (!w.failure.empty()) {
      ADD_FAILURE() << "seed " << (std::uint64_t{0x50AB'0000} + static_cast<std::uint64_t>(s)) << ": " << w.failure;
      if (++failures >= 5) break;
    }
  }
  const Stats& st = stats();
  std::printf(
      "sequences=%d logins=%llu (seq0=%llu replays=%llu) rejects A=%llu S=%llu ahead_alarms=%llu "
      "idle_timeouts=%llu login_timeouts=%llu second_logins=%llu end_of_session=%llu "
      "sequenced=%llu unsequenced=%llu s2c_bytes=%llu\n",
      kSequences, static_cast<unsigned long long>(st.logins), static_cast<unsigned long long>(st.zero_logins),
      static_cast<unsigned long long>(st.replays), static_cast<unsigned long long>(st.rejects_a),
      static_cast<unsigned long long>(st.rejects_s), static_cast<unsigned long long>(st.ahead_alarms),
      static_cast<unsigned long long>(st.idle_timeouts), static_cast<unsigned long long>(st.login_timeouts),
      static_cast<unsigned long long>(st.second_logins), static_cast<unsigned long long>(st.end_of_sessions),
      static_cast<unsigned long long>(st.sequenced_delivered), static_cast<unsigned long long>(st.unsequenced_delivered),
      static_cast<unsigned long long>(st.s2c_bytes));
  // Every scenario must actually occur.
  EXPECT_GT(st.logins, 10'000u);
  EXPECT_GT(st.zero_logins, 100u);
  EXPECT_GT(st.replays, 1'000u);
  EXPECT_GT(st.rejects_a, 100u);
  EXPECT_GT(st.rejects_s, 100u);
  EXPECT_GT(st.ahead_alarms, 100u);
  EXPECT_GT(st.idle_timeouts, 100u);
  EXPECT_GT(st.login_timeouts, 100u);
  EXPECT_GT(st.second_logins, 100u);
  EXPECT_GT(st.end_of_sessions, 100u);
  EXPECT_GT(st.sequenced_delivered, 100'000u);
  EXPECT_GT(st.unsequenced_delivered, 100'000u);
}

}  // namespace
}  // namespace lle::soup
