// soupbin world (09 §2; 03-protocols §5): the production SoupBinTCP server and
// client sessions (src/proto/soupbin) over simulated TCP-like streams, with
// segmentation and coalescing, stalls, partitions (resets after the timeout),
// pauses and process crashes of the server and the clients.
//
// The server node runs one listening port per account (10 §3: each account has
// its own SoupBinTCP port), a ServerSession per connection, the account's
// sequenced stream (a MemorySequencedStore standing in for the output-log
// backed store, so it survives a server crash) and a producer that appends
// messages through send_sequenced or straight into the store. At a seeded time
// the server ends every session (end of day): remaining messages, then 'Z'.
// A login after that gets the rest of the stream and 'Z' again.
//
// Each client node runs one account's ClientSession. It records every
// delivered message durably before acting on it (the harness keeps that
// record across client crashes) and re-logs in with the next expected
// sequence number after any disconnect, rejection or timeout. Clients also
// send tagged Unsequenced Data. Half the seeds run SoupBinTCP 4.10, where the
// client's Login Heartbeat Timeout replaces the server's idle timeout and the
// server also sends tagged best-effort Unsequenced Data. An optional intruder logs in with a wrong
// password, or with valid credentials and an unknown session.
//
// Oracles:
//   O-SOUP-SEQ      each client's sequenced stream, across re-logins, is gap-
//                   and duplicate-free with the published bytes; a login
//                   starts exactly at the requested sequence number
//   O-EXACTLY-ONCE  (final) every published message reached its client once
//   O-SOUP-EOS      End of Session only after the server ended the session,
//                   and only once every message was delivered
//   O-SOUP-UNSEQ    each side receives the other's Unsequenced Data on a
//                   connection as an in-order prefix of what was sent on it
//                   (server-to-client only in SoupBinTCP 4.10 mode, where it is
//                   best effort and never advances sequence numbers)
//   O-SOUP-AUTH     valid credentials are never refused with 'A'; a wrong
//                   password always is; the intruder never logs in
//   O-LIVE          after healing: everything delivered (and 'Z' if ended)
//
// --canary: the client drops message 100 of each account without recording it.
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/alpha.h"
#include "common/assert.h"
#include "common/hash.h"
#include "env/buggify.h"
#include "env/concepts.h"
#include "proto/soupbin/soupbin.h"
#include "sim/dist.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

namespace {

namespace sb = lle::soup;

constexpr std::uint16_t kBasePort = 7600;
constexpr std::size_t kMaxMessageBytes = 3000;
constexpr std::size_t kUnseqHeader = 13;  // account (1) + connection number (4) + index (8)
constexpr SeqNo kCanarySeq = 100;
const sb::SessionId kSessionId = sb::SessionId::from("SIMDAY0001");

// Deterministic content of message `seq` of account `u`: mostly short, some
// longer than an MTU so packets straddle reads.
std::size_t message_len(std::uint64_t seed, std::size_t u, SeqNo seq) noexcept {
  const std::uint64_t h = mix64(seed ^ (static_cast<std::uint64_t>(u) << 56) ^ (seq * 0x9E3779B97F4A7C15ull));
  return (h & 15) == 0 ? 200 + (h >> 8) % (kMaxMessageBytes - 199) : 1 + (h >> 8) % 64;
}
void fill_message(std::uint64_t seed, std::size_t u, SeqNo seq, std::span<std::byte> out) noexcept {
  std::uint64_t h = mix64(seed ^ (static_cast<std::uint64_t>(u) << 48) ^ seq);
  for (std::size_t i = 0; i < out.size(); ++i) {
    if (i % 8 == 0) h = mix64(h + i);
    out[i] = static_cast<std::byte>(h >> (8 * (i % 8)));
  }
}

std::string username(std::size_t u) { return "U" + std::to_string(u); }
std::string password(std::size_t u) { return "PW" + std::to_string(u) + "x"; }

struct ServerTiming {
  Nanos heartbeat = 20 * kMs;
  Nanos idle = 200 * kMs;
  Nanos login = 300 * kMs;
};
struct ClientTiming {
  Nanos heartbeat = 20 * kMs;
  Nanos idle = 200 * kMs;
  Nanos login = 300 * kMs;
  Nanos backoff_max = 30 * kMs;
  Nanos peer_idle = 200 * kMs;  // 4.10: Login Heartbeat Timeout requested from the server
};

// What survives crashes: the account's stream (output-log backed in
// production), the server's end-of-day decision, and each client's durable
// record of what it processed.
struct Account {
  std::unique_ptr<sb::MemorySequencedStore> store;
  SeqNo target = 0;
  bool ended = false;
  // client side
  SeqNo next_expected = 1;
  sb::SessionId session;  // learned from Login Accepted
  bool got_eos = false;
  std::uint32_t conn_no = 0;  // connections made, across client crashes
  // server-side check of client Unsequenced Data, per client connection
  std::vector<std::uint64_t> unseq_next;
  std::uint64_t logins = 0;
  std::uint64_t refused_s = 0;
  std::uint64_t unseq_received = 0;

  [[nodiscard]] SeqNo published() const { return store->next_seq() - 1; }
};

struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_seq = 0, o_once = 0, o_eos = 0, o_unseq = 0, o_auth = 0;
  std::uint64_t seed = 0;
  bool canary = false;
  bool verbose = false;
  bool direct_append = false;  // producer appends to the store, then on_timer delivers
  sb::Version version = sb::Version::V300;
  std::uint64_t server_unseq_received = 0;
  Nanos end_at = -1;           // end of day (-1: sessions never end)
  std::vector<Account> acct;
  std::uint64_t intruder_attempts = 0;
  std::uint64_t intruder_refused = 0;
  std::uint64_t server_starts = 0;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  [[nodiscard]] bool done() const {
    for (const Account& a : acct) {
      if (a.published() < a.target || a.next_expected != a.store->next_seq()) return false;
      if (end_at >= 0 && !a.got_eos) return false;
    }
    return true;
  }
};

// ---- server ---------------------------------------------------------------
struct AccountPort;

// Port-level login policy (credentials, one live login per port).
struct Policy {
  AccountPort* ap = nullptr;
  sb::LoginDecision authorize(const sb::LoginRequest& r);
};

using Session = sb::ServerSession<sb::MemorySequencedStore, Policy>;

struct ServerConn {
  env::ConnId id = env::kNoConn;
  std::unique_ptr<Session> s;
  Nanos deadline = 0;
  bool closing = false;
  bool end_pending = false;
  bool dead = false;
  std::uint32_t serial = 0;       // server-side connection number (4.10 Unsequenced Data tag)
  std::uint64_t unseq_sent = 0;
  Nanos next_unseq = 0;
};

struct AccountPort {
  std::size_t u = 0;
  std::unique_ptr<StreamPort> port;
  Policy policy;
  std::vector<std::unique_ptr<ServerConn>> conns;
  Nanos next_gen = 0;
};

sb::LoginDecision Policy::authorize(const sb::LoginRequest& r) {
  if (!sb::credential_equals(std::as_bytes(std::span(r.username.c)), username(ap->u)) ||
      !sb::credential_equals(std::as_bytes(std::span(r.password.c)), password(ap->u))) {
    return sb::LoginDecision::NotAuthorized;
  }
  for (const auto& c : ap->conns) {
    if (!c->dead && c->s->state() == Session::State::Active) {
      SIM_PROBE("soupbin_world.second_login_refused");
      return sb::LoginDecision::SessionUnavailable;
    }
  }
  return sb::LoginDecision::Accept;
}

class ServerProc : public Process {
 public:
  ServerProc(Node& n, Harness& h, const ServerTiming& t) : node_(n), h_(h), rng_(n.rng(0x50)) {
    ++h_.server_starts;
    cfg_.session = kSessionId;
    cfg_.version = h_.version;
    cfg_.heartbeat_interval = t.heartbeat;
    cfg_.idle_timeout = t.idle;
    cfg_.login_timeout = t.login;
    for (std::size_t u = 0; u < h_.acct.size(); ++u) {
      auto ap = std::make_unique<AccountPort>();
      ap->u = u;
      ap->port = std::make_unique<StreamPort>(n);
      ap->policy.ap = ap.get();
      const auto bound = ap->port->listen(env::Endpoint{0, static_cast<std::uint16_t>(kBasePort + u)});
      LLE_ASSERT(bound.has_value(), "soupbin server: listen failed");
      ports_.push_back(std::move(ap));
    }
    h_.log("server starts (%llu)", static_cast<unsigned long long>(h_.server_starts));
    n.add_stage(stage_, "soup-srv");
  }

  // Ports are torn down front to back explicitly: a StreamPort's destructor
  // resets its connections (scheduling events), and the order in which a
  // std::vector destroys its elements differs between standard libraries.
  ~ServerProc() override {
    for (auto& ap : ports_) ap.reset();
  }
  ServerProc(const ServerProc&) = delete;
  ServerProc& operator=(const ServerProc&) = delete;

  bool poll() {
    const Nanos now = node_.clock().now_mono();
    bool did = false;
    for (auto& ap : ports_) {
      ap->port->poll([&](const env::StreamEvent& ev) {
        did = true;
        on_event(*ap, ev, now);
      });
      did = produce(*ap, now) || did;
      did = end_of_day(*ap, now) || did;
      for (auto& c : ap->conns) {
        if (c->dead) continue;
        if (now >= c->deadline) {
          handle(*ap, *c, c->s->on_timer(now), now);
          did = true;
        }
        if (h_.version == sb::Version::V410 && !c->dead && now >= c->next_unseq) {
          send_unseq(*ap, *c, now);
          did = true;
        }
        did = flush(*ap, *c, now) || did;
      }
      std::erase_if(ap->conns, [](const auto& c) { return c->dead; });
    }
    return did;
  }

 private:
  struct Stage {
    ServerProc* p;
    bool poll() { return p->poll(); }
  };

  ServerConn* find(AccountPort& ap, env::ConnId id) {
    for (auto& c : ap.conns) {
      if (c->id == id && !c->dead) return c.get();
    }
    return nullptr;
  }

  void on_event(AccountPort& ap, const env::StreamEvent& ev, Nanos now) {
    switch (ev.kind) {
      case env::StreamEventKind::Accepted: {
        auto c = std::make_unique<ServerConn>();
        c->id = ev.conn;
        c->s = std::make_unique<Session>(cfg_, *h_.acct[ap.u].store, ap.policy, now);
        c->deadline = now + cfg_.login_timeout;
        c->serial = next_serial_++;
        ap.conns.push_back(std::move(c));
        break;
      }
      case env::StreamEventKind::Data: {
        ServerConn* c = find(ap, ev.conn);
        if (c == nullptr) break;
        std::span<const std::byte> rest = ev.data;
        while (!rest.empty() && !c->dead) {
          const sb::Actions& a = c->s->on_bytes(rest, now);
          const std::size_t used = a.consumed;
          handle(ap, *c, a, now);
          if (used == 0) break;
          rest = rest.subspan(used);
        }
        if (c->end_pending && !c->dead) {
          c->end_pending = false;
          handle(ap, *c, c->s->end_session(now), now);
        }
        flush(ap, *c, now);
        break;
      }
      case env::StreamEventKind::Closed:
        if (ServerConn* c = find(ap, ev.conn)) c->dead = true;
        break;
      case env::StreamEventKind::Connected:
        break;
    }
  }

  void handle(AccountPort& ap, ServerConn& c, const sb::Actions& a, Nanos now) {
    Account& acct = h_.acct[ap.u];
    for (const sb::Delivered& d : a.delivered) check_unseq(ap.u, d.data);
    for (const sb::Event& e : a.events) {
      switch (e.kind) {
        case sb::EventKind::LoggedIn:
          h_.log("server: account %zu logged in at seq %llu (published %llu)", ap.u,
                 static_cast<unsigned long long>(e.seq), static_cast<unsigned long long>(acct.published()));
          if (acct.ended) c.end_pending = true;  // a login after end of day gets the rest, then 'Z'
          break;
        case sb::EventKind::SequenceAhead:
          // Clients only ever ask for what they have not processed yet.
          h_.o->fail(h_.o_seq, "server: account " + std::to_string(ap.u) + " requested " + std::to_string(e.seq) +
                                   " ahead of next " + std::to_string(e.aux));
          break;
        case sb::EventKind::StoreFull:
          LLE_ASSERT(false, "soupbin world: store sized too small");
          break;
        case sb::EventKind::EndOfSession:
          h_.log("server: account %zu sent End of Session at %llu", ap.u, static_cast<unsigned long long>(e.seq));
          break;
        case sb::EventKind::LoginRejected:
        case sb::EventKind::Closed:
          break;
      }
    }
    c.deadline = a.deadline;
    if (a.close) c.closing = true;
    (void)now;
  }

  // Writes pending bytes; continues replay while the session asks for it.
  bool flush(AccountPort& ap, ServerConn& c, Nanos now) {
    if (c.dead) return false;
    bool did = false;
    for (int guard = 0; guard < 64; ++guard) {
      const std::span<const std::byte> out = c.s->actions().write;
      if (out.empty()) break;
      const std::size_t n = ap.port->write(c.id, out);
      if (n == 0) break;
      did = true;
      if (c.s->consume_tx(n)) handle(ap, c, c.s->on_timer(now), now);
      else c.deadline = c.s->actions().deadline;
    }
    if (c.closing && c.s->actions().write.empty()) {
      ap.port->close(c.id);
      c.dead = true;
      did = true;
    }
    return did;
  }

  ServerConn* active(AccountPort& ap) {
    for (auto& c : ap.conns) {
      if (!c->dead && !c->closing && c->s->state() == Session::State::Active) return c.get();
    }
    return nullptr;
  }

  bool produce(AccountPort& ap, Nanos now) {
    Account& acct = h_.acct[ap.u];
    if (acct.ended || acct.published() >= acct.target || now < ap.next_gen) return false;
    const std::uint64_t burst = 1 + rng_.below(6);
    std::array<std::byte, kMaxMessageBytes> buf{};
    for (std::uint64_t k = 0; k < burst && acct.published() < acct.target; ++k) {
      const SeqNo seq = acct.store->next_seq();
      const std::span<std::byte> msg(buf.data(), message_len(h_.seed, ap.u, seq));
      fill_message(h_.seed, ap.u, seq, msg);
      ServerConn* c = active(ap);
      if (c != nullptr && !h_.direct_append) {
        const sb::Actions& a = c->s->send_sequenced(msg, now);
        LLE_ASSERT(a.accepted, "soupbin world: send_sequenced refused");
        handle(ap, *c, a, now);
      } else {
        LLE_ASSERT(acct.store->append(msg), "soupbin world: store full");
        if (c != nullptr) handle(ap, *c, c->s->on_timer(now), now);  // delivers what was appended
      }
    }
    ap.next_gen = now + static_cast<Nanos>(50 * kUs + rng_.below(400 * kUs));
    return true;
  }

  bool end_of_day(AccountPort& ap, Nanos now) {
    Account& acct = h_.acct[ap.u];
    if (acct.ended || h_.end_at < 0 || now < h_.end_at || acct.published() < acct.target) return false;
    acct.ended = true;
    h_.log("server: ends account %zu at %llu messages", ap.u, static_cast<unsigned long long>(acct.published()));
    for (auto& c : ap.conns) {
      if (!c->dead && c->s->state() == Session::State::Active) handle(ap, *c, c->s->end_session(now), now);
    }
    return true;
  }

  // 4.10 best-effort Unsequenced Data, tagged (account, connection, index).
  void send_unseq(AccountPort& ap, ServerConn& c, Nanos now) {
    std::array<std::byte, kUnseqHeader + 100> buf{};
    const std::size_t len = kUnseqHeader + rng_.below(101);
    buf[0] = static_cast<std::byte>(ap.u);
    std::memcpy(buf.data() + 1, &c.serial, sizeof c.serial);
    std::memcpy(buf.data() + 5, &c.unseq_sent, sizeof c.unseq_sent);
    const sb::Actions& a = c.s->send_unsequenced(std::span<const std::byte>(buf.data(), len), now);
    if (a.accepted) ++c.unseq_sent;
    handle(ap, c, a, now);
    c.next_unseq = now + static_cast<Nanos>(500 * kUs + rng_.below(5 * kMs));
  }

  void check_unseq(std::size_t u, std::span<const std::byte> d) {
    Account& acct = h_.acct[u];
    if (d.size() < kUnseqHeader || std::to_integer<std::size_t>(d[0]) != u) {
      h_.o->fail(h_.o_unseq, "server: malformed or misrouted Unsequenced Data on account " + std::to_string(u));
      return;
    }
    std::uint32_t conn = 0;
    std::uint64_t idx = 0;
    std::memcpy(&conn, d.data() + 1, sizeof conn);
    std::memcpy(&idx, d.data() + 5, sizeof idx);
    if (conn >= acct.unseq_next.size()) acct.unseq_next.resize(conn + 1, 0);
    if (idx != acct.unseq_next[conn]) {
      h_.o->fail(h_.o_unseq, "server: account " + std::to_string(u) + " connection " + std::to_string(conn) +
                                 " delivered message " + std::to_string(idx) + ", expected " +
                                 std::to_string(acct.unseq_next[conn]));
      return;
    }
    ++acct.unseq_next[conn];
    ++acct.unseq_received;
    h_.o->pass(h_.o_unseq);
  }

  Node& node_;
  Harness& h_;
  Rng rng_;
  sb::ServerConfig cfg_;
  std::vector<std::unique_ptr<AccountPort>> ports_;
  std::uint32_t next_serial_ = 0;
  Stage stage_{this};
};

// ---- clients --------------------------------------------------------------
class ClientProc : public Process {
 public:
  // intruder: 0 = honest client of account u; 1 = wrong password; 2 = valid
  // credentials, unknown session.
  ClientProc(Node& n, Harness& h, std::size_t u, const ClientTiming& t, env::Endpoint server, int intruder)
      : node_(n), h_(h), u_(u), t_(t), server_(server), intruder_(intruder), port_(n), rng_(n.rng(0x51)) {
    n.add_stage(stage_, intruder_ != 0 ? "soup-intruder" : "soup-client");
  }

  bool poll() {
    const Nanos now = node_.clock().now_mono();
    bool did = false;
    port_.poll([&](const env::StreamEvent& ev) {
      did = true;
      on_event(ev, now);
    });
    Account& acct = h_.acct[u_];
    if (!conn_ && (intruder_ != 0 || !acct.got_eos) && now >= next_try_) {
      conn_ = port_.connect(server_);
      did = true;
    }
    if (session_) {
      if (now >= deadline_) {
        handle(session_->on_timer(now), now);
        did = true;
      }
      if (intruder_ == 0 && session_ && session_->state() == sb::ClientSession::State::Active && now >= next_unseq_) {
        send_unseq(now);
        did = true;
      }
      did = flush(now) || did;
    }
    return did;
  }

 private:
  struct Stage {
    ClientProc* p;
    bool poll() { return p->poll(); }
  };

  void on_event(const env::StreamEvent& ev, Nanos now) {
    if (!conn_ || ev.conn != *conn_) return;
    switch (ev.kind) {
      case env::StreamEventKind::Connected: {
        Account& acct = h_.acct[u_];
        sb::ClientConfig cfg;
        cfg.username = Alpha<sb::kUsernameLen>(username(u_));
        cfg.password = Alpha<sb::kPasswordLen>(intruder_ == 1 ? std::string("WRONG") : password(u_));
        cfg.session = intruder_ == 2 ? sb::SessionId::from("NOSUCHDAY") : acct.session;
        cfg.sequence = intruder_ != 0 ? 1 : acct.next_expected;
        requested_ = cfg.sequence;
        cfg.version = h_.version;
        if (h_.version == sb::Version::V410) cfg.heartbeat_timeout_ms = static_cast<std::uint32_t>(t_.peer_idle / kMs);
        cfg.heartbeat_interval = t_.heartbeat;
        cfg.idle_timeout = t_.idle;
        cfg.login_timeout = t_.login;
        session_ = std::make_unique<sb::ClientSession>(cfg);
        if (intruder_ == 0) {
          conn_no_ = acct.conn_no++;
          unseq_idx_ = 0;
          srv_serial_.reset();
          srv_unseq_next_ = 0;
        } else {
          ++h_.intruder_attempts;
        }
        handle(session_->connect(now), now);
        flush(now);
        break;
      }
      case env::StreamEventKind::Data: {
        if (!session_) break;
        std::span<const std::byte> rest = ev.data;
        while (!rest.empty() && session_) {
          const sb::Actions& a = session_->on_bytes(rest, now);
          const std::size_t used = a.consumed;
          handle(a, now);
          if (used == 0) break;
          rest = rest.subspan(used);
        }
        flush(now);
        break;
      }
      case env::StreamEventKind::Closed:
        drop(now);
        break;
      case env::StreamEventKind::Accepted:
        break;
    }
  }

  void handle(const sb::Actions& a, Nanos now) {
    Account& acct = h_.acct[u_];
    for (const sb::Delivered& d : a.delivered) {
      if (intruder_ != 0) {
        h_.o->fail(h_.o_auth, "intruder received data on account " + std::to_string(u_));
        continue;
      }
      if (d.seq == 0) {
        check_server_unseq(d.data);
        continue;
      }
      if (h_.canary && d.seq == kCanarySeq && !canary_fired_) {
        canary_fired_ = true;  // planted bug: drop one message without recording it
        continue;
      }
      check_message(acct, d);
    }
    for (const sb::Event& e : a.events) {
      switch (e.kind) {
        case sb::EventKind::LoggedIn:
          if (intruder_ != 0) {
            h_.o->fail(h_.o_auth, "intruder logged in on account " + std::to_string(u_));
            break;
          }
          ++acct.logins;
          acct.session = session_->session();
          // (Messages delivered in the same call are already counted.)
          if (e.seq != requested_) {
            h_.o->fail(h_.o_seq, "account " + std::to_string(u_) + " logged in at " + std::to_string(e.seq) +
                                     " but requested " + std::to_string(requested_));
          }
          if (e.seq > 1) SIM_PROBE("soupbin_world.relogin_mid_stream");
          h_.log("client %zu logged in at %llu", u_, static_cast<unsigned long long>(e.seq));
          break;
        case sb::EventKind::LoginRejected:
          if (intruder_ == 1) {
            ++h_.intruder_refused;
            if (e.code != 'A') h_.o->fail(h_.o_auth, std::string("wrong password refused with '") + e.code + "', not 'A'");
            else h_.o->pass(h_.o_auth);
          } else if (intruder_ == 2) {
            ++h_.intruder_refused;
            if (e.code != 'S') h_.o->fail(h_.o_auth, std::string("unknown session refused with '") + e.code + "', not 'S'");
            else h_.o->pass(h_.o_auth);
          } else if (e.code == 'A') {
            h_.o->fail(h_.o_auth, "valid credentials of account " + std::to_string(u_) + " refused with 'A'");
          } else {
            ++acct.refused_s;
            SIM_PROBE("soupbin_world.login_refused_session_unavailable");
          }
          break;
        case sb::EventKind::EndOfSession:
          if (intruder_ != 0) break;
          if (!acct.ended) {
            h_.o->fail(h_.o_eos, "account " + std::to_string(u_) + " got End of Session but the server never ended it");
          } else if (acct.next_expected != acct.store->next_seq()) {
            h_.o->fail(h_.o_eos, "account " + std::to_string(u_) + " got End of Session at " +
                                     std::to_string(acct.next_expected) + " before message " +
                                     std::to_string(acct.store->next_seq() - 1));
          } else {
            h_.o->pass(h_.o_eos);
          }
          acct.got_eos = true;
          h_.log("client %zu got End of Session", u_);
          break;
        case sb::EventKind::Closed:
          closing_ = true;
          break;
        case sb::EventKind::SequenceAhead:
        case sb::EventKind::StoreFull:
          break;
      }
    }
    deadline_ = a.deadline;
    if (a.close) closing_ = true;
    (void)now;
  }

  void check_message(Account& acct, const sb::Delivered& d) {
    if (d.seq != acct.next_expected) {
      h_.o->fail(h_.o_seq, "account " + std::to_string(u_) + " delivered " + std::to_string(d.seq) + ", expected " +
                               std::to_string(acct.next_expected));
      return;
    }
    if (d.seq > acct.published()) {
      h_.o->fail(h_.o_seq, "account " + std::to_string(u_) + " delivered unpublished message " + std::to_string(d.seq));
      return;
    }
    const std::size_t len = message_len(h_.seed, u_, d.seq);
    std::array<std::byte, kMaxMessageBytes> want{};
    fill_message(h_.seed, u_, d.seq, std::span(want.data(), len));
    if (d.data.size() != len || std::memcmp(d.data.data(), want.data(), len) != 0) {
      h_.o->fail(h_.o_seq, "account " + std::to_string(u_) + " message " + std::to_string(d.seq) + " has the wrong bytes");
      return;
    }
    ++acct.next_expected;  // recorded durably before the client acts on it
    h_.o->pass(h_.o_seq);
  }

  void check_server_unseq(std::span<const std::byte> d) {
    if (h_.version != sb::Version::V410 || d.size() < kUnseqHeader || std::to_integer<std::size_t>(d[0]) != u_) {
      h_.o->fail(h_.o_unseq, "client " + std::to_string(u_) + " got unexpected Unsequenced Data");
      return;
    }
    std::uint32_t serial = 0;
    std::uint64_t idx = 0;
    std::memcpy(&serial, d.data() + 1, sizeof serial);
    std::memcpy(&idx, d.data() + 5, sizeof idx);
    if (!srv_serial_) srv_serial_ = serial;
    if (serial != *srv_serial_ || idx != srv_unseq_next_) {
      h_.o->fail(h_.o_unseq, "client " + std::to_string(u_) + " got server Unsequenced Data " + std::to_string(idx) +
                                 " of connection " + std::to_string(serial) + ", expected " +
                                 std::to_string(srv_unseq_next_));
      return;
    }
    ++srv_unseq_next_;
    ++h_.server_unseq_received;
    h_.o->pass(h_.o_unseq);
  }

  void send_unseq(Nanos now) {
    std::array<std::byte, kUnseqHeader + 200> buf{};
    const std::size_t len = kUnseqHeader + rng_.below(201);
    buf[0] = static_cast<std::byte>(u_);
    std::memcpy(buf.data() + 1, &conn_no_, sizeof conn_no_);
    std::memcpy(buf.data() + 5, &unseq_idx_, sizeof unseq_idx_);
    const sb::Actions& a = session_->send_unsequenced(std::span<const std::byte>(buf.data(), len), now);
    if (a.accepted) ++unseq_idx_;
    handle(a, now);
    next_unseq_ = now + static_cast<Nanos>(200 * kUs + rng_.below(3 * kMs));
  }

  bool flush(Nanos now) {
    if (!session_ || !conn_) return false;
    bool did = false;
    for (int guard = 0; guard < 64; ++guard) {
      const std::span<const std::byte> out = session_->actions().write;
      if (out.empty()) break;
      const std::size_t n = port_.write(*conn_, out);
      if (n == 0) break;
      session_->consume_tx(n);
      did = true;
    }
    if (closing_ && session_->actions().write.empty()) {
      port_.close(*conn_);
      drop(now);
      did = true;
    }
    return did;
  }

  void drop(Nanos now) {
    session_.reset();
    conn_.reset();
    closing_ = false;
    deadline_ = sb::kNever;
    const Nanos backoff = intruder_ != 0 ? 20 * kMs + static_cast<Nanos>(rng_.below(80 * kMs))
                                         : kMs + static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(t_.backoff_max)));
    next_try_ = now + backoff;
  }

  Node& node_;
  Harness& h_;
  std::size_t u_;
  ClientTiming t_;
  env::Endpoint server_;
  int intruder_;
  StreamPort port_;
  Rng rng_;
  std::optional<env::ConnId> conn_;
  std::unique_ptr<sb::ClientSession> session_;
  Nanos deadline_ = sb::kNever;
  Nanos next_try_ = 0;
  Nanos next_unseq_ = 0;
  bool closing_ = false;
  bool canary_fired_ = false;
  std::uint32_t conn_no_ = 0;
  std::uint64_t unseq_idx_ = 0;
  SeqNo requested_ = 0;
  std::optional<std::uint32_t> srv_serial_;
  std::uint64_t srv_unseq_next_ = 0;
  Stage stage_{this};
};

}  // namespace

Report run_soupbin(const Options& o) {
  // The harness outlives the world: process destructors run inside it.
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x50B);
  h->w = &w;
  h->o = &w.oracles();
  h->seed = o.seed;
  h->canary = o.canary;
  h->verbose = o.verbose;
  h->o_seq = w.oracles().activate("O-SOUP-SEQ", "each client's sequenced stream is gap- and duplicate-free across re-logins");
  h->o_once = w.oracles().activate(kOExactlyOnce, "every published message reached its client exactly once, in order");
  h->o_eos = w.oracles().activate("O-SOUP-EOS", "End of Session only after the server ended it and everything was delivered");
  h->o_unseq = w.oracles().activate("O-SOUP-UNSEQ", "client Unsequenced Data arrives as an in-order prefix per connection");
  h->o_auth = w.oracles().activate("O-SOUP-AUTH", "credentials decide logins: 'A' exactly for a wrong password");

  const std::size_t accounts = 1 + wl.below(3);
  h->direct_append = wl.below(2) == 0;
  h->version = wl.below(2) == 0 ? sb::Version::V300 : sb::Version::V410;
  h->end_at = wl.below(4) == 0 ? -1
                               : o.plan.safety_ns / 4 + static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(o.plan.safety_ns)));
  h->acct.resize(accounts);
  for (std::size_t u = 0; u < accounts; ++u) {
    Account& a = h->acct[u];
    a.target = 100 + wl.below(1401);
    std::size_t bytes = 0;
    for (SeqNo s = 1; s <= a.target; ++s) bytes += message_len(o.seed, u, s);
    a.store = std::make_unique<sb::MemorySequencedStore>(static_cast<std::size_t>(a.target), bytes);
  }

  ServerTiming st;
  st.heartbeat = 5 * kMs + static_cast<Nanos>(wl.below(45 * kMs));
  ClientTiming ct;
  ct.heartbeat = 5 * kMs + static_cast<Nanos>(wl.below(45 * kMs));
  // Idle timeouts outlast the peer's heartbeat interval with margin, so only
  // faults (stalls, partitions, pauses) trip them.
  st.idle = 3 * ct.heartbeat + 50 * kMs + static_cast<Nanos>(wl.below(300 * kMs));
  ct.idle = 3 * st.heartbeat + 50 * kMs + static_cast<Nanos>(wl.below(300 * kMs));
  st.login = 100 * kMs + static_cast<Nanos>(wl.below(400 * kMs));
  ct.login = 100 * kMs + static_cast<Nanos>(wl.below(400 * kMs));
  ct.backoff_max = kMs + static_cast<Nanos>(wl.below(50 * kMs));
  ct.peer_idle = 3 * ct.heartbeat + 50 * kMs + static_cast<Nanos>(wl.below(300 * kMs));

  Harness* hp = h.get();
  Node& srv = w.add_node("srv", NodeOptions{true, true});
  srv.set_boot([hp, st](Node& nd, BootReason) { nd.emplace_process<ServerProc>(nd, *hp, st); });
  const std::uint32_t srv_ip = srv.ip();
  for (std::size_t u = 0; u < accounts; ++u) {
    Node& c = w.add_node("c" + std::to_string(u), NodeOptions{true, true});
    const env::Endpoint ep{srv_ip, static_cast<std::uint16_t>(kBasePort + u)};
    c.set_boot([hp, u, ct, ep](Node& nd, BootReason) { nd.emplace_process<ClientProc>(nd, *hp, u, ct, ep, 0); });
  }
  if (wl.below(2) == 0) {
    Node& x = w.add_node("x", NodeOptions{true, true});
    const env::Endpoint ep{srv_ip, kBasePort};
    const int kind = 1 + static_cast<int>(wl.below(2));
    x.set_boot([hp, ct, ep, kind](Node& nd, BootReason) { nd.emplace_process<ClientProc>(nd, *hp, 0, ct, ep, kind); });
  }
  for (std::size_t i = 0; i < w.node_count(); ++i) w.node(static_cast<NodeId>(i)).boot();

  w.oracles().add_final_check(hp->o_once, [hp] {
    for (std::size_t u = 0; u < hp->acct.size(); ++u) {
      const Account& a = hp->acct[u];
      if (a.next_expected != a.target + 1 || a.published() != a.target) {
        hp->o->fail(hp->o_once, "account " + std::to_string(u) + " delivered " + std::to_string(a.next_expected - 1) +
                                    " of " + std::to_string(a.target));
        return;
      }
    }
    hp->o->pass(hp->o_once);
  });

  return finish(
      w, WorldKind::Soupbin, o, [hp] { return hp->done(); },
      [hp] {
        std::uint64_t msgs = 0, logins = 0, refused = 0, unseq = 0;
        for (const Account& a : hp->acct) {
          msgs += a.target;
          logins += a.logins;
          refused += a.refused_s;
          unseq += a.unseq_received;
        }
        return "accounts=" + std::to_string(hp->acct.size()) + " messages=" + std::to_string(msgs) +
               " logins=" + std::to_string(logins) + " refused_s=" + std::to_string(refused) +
               " unseq=" + std::to_string(unseq) + " srv_unseq=" + std::to_string(hp->server_unseq_received) +
               " v410=" + std::to_string(hp->version == sb::Version::V410 ? 1 : 0) + " ends=" + std::to_string(hp->end_at >= 0 ? 1 : 0) +
               " server_starts=" + std::to_string(hp->server_starts) +
               " intruder=" + std::to_string(hp->intruder_refused) + "/" + std::to_string(hp->intruder_attempts);
      });
}

}  // namespace lle::sim::worlds::detail
