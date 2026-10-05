#pragma once
// A loopback OUCH 5.0 server for loadgen and refclient tests and smokes
// (`loadgen serve`): SoupBinTCP 3.00 sessions (src/proto/soupbin) in front of
// the real sequencer and matching engine run in-process (EngineDriver). It is
// a test exchange, not exchanged: one thread, no journal on disk, no
// replication, no market-data output (ITCH is counted and dropped).
//
// Sessions: usernames U00001..U<N> (any password) map to engine session n and
// account n; a second live login on a username is refused ('J' 'S'). Each
// session's sequenced stream lives in a bounded ring (re-login replays what it
// still holds). The engine runs on a virtual trading-day clock that starts at
// `start_time` (default 10:00:00, the regular session) and advances with the
// monotonic clock, so order handling does not depend on the wall-clock hour.
#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "client/engine_driver.h"
#include "client/ring_store.h"
#include "common/time.h"
#include "env/prod_clock.h"
#include "net/common/stack.h"
#include "proto/moldudp64/message_store.h"
#include "proto/soupbin/server_session.h"

namespace lle::client {

struct OuchServerConfig {
  net::Endpoint listen{};
  std::uint32_t sessions = 64;
  std::vector<Symbol8> symbols;
  std::uint32_t date = 20261001;
  Nanos start_time = hms_ns(10, 0, 0);
  // Per session, allocated at its first login (a session never logged into keeps
  // nothing); re-login replays what the ring still holds.
  std::size_t store_messages = std::size_t{1} << 18;
  std::size_t store_bytes = std::size_t{16} << 20;
  bool cancel_on_disconnect = false;
  // The engine's 1 Hz clock (halt and LULD periods, GTT expiry, peg pulls) is not
  // needed by the order flow this server carries; without it the day's walk to
  // the start time is a few hundred timer records instead of tens of thousands.
  bool clock_1hz = false;
  std::size_t reserve_orders = std::size_t{1} << 20;
  Nanos max_runtime = 0;  // 0 = until stopped
  // Mirror-attach (10 §3): a second port whose logins are second instances of the
  // same sessions, reading the same streams; and a scripted death of the primary
  // port after this long (0: never), for the HA client tests.
  net::Endpoint mirror_listen{};
  Nanos fail_primary_after = 0;
  std::uint64_t fail_primary_after_inbound = 0;  // ... or once the primary port has taken this many messages
  Nanos stall_primary = 0;  // the primary stops reading this long before it dies (a hang, then the crash)
};

struct OuchServerStats {
  std::uint64_t accepted = 0, logins = 0, login_rejects = 0, closed = 0;
  std::uint64_t inbound = 0, ouch_out = 0, itch_out = 0, audits = 0, store_full = 0;
  std::uint64_t ouch_unattached = 0;  // OUCH for a session that never logged in (e.g. start-of-day events)
  std::uint64_t primary_failures = 0;
};

// "U00042" -> 42 (0 if the name is not of that form).
[[nodiscard]] inline std::uint32_t session_of_username(std::string_view u) noexcept {
  if (u.size() != 6 || u[0] != 'U') return 0;
  std::uint32_t n = 0;
  for (std::size_t i = 1; i < 6; ++i) {
    if (u[i] < '0' || u[i] > '9') return 0;
    n = n * 10 + static_cast<std::uint32_t>(u[i] - '0');
  }
  return n;
}

[[nodiscard]] inline EngineDayConfig ouch_server_day(const OuchServerConfig& c) {
  EngineDayConfig d;
  d.date = c.date;
  d.clock_1hz = c.clock_1hz;
  for (const Symbol8& s : c.symbols) {
    engine::SymbolEntry e;
    e.symbol = s;
    d.symbols.push_back(e);
  }
  for (std::uint32_t n = 1; n <= c.sessions; ++n) {
    engine::AccountEntry a;
    a.account_id = n;
    a.firms[0] = Mpid4("LLEC");
    d.accounts.push_back(a);
    engine::SessionEntry s;
    s.session_id = n;
    s.account_id = n;
    s.flags = static_cast<std::uint8_t>((c.cancel_on_disconnect ? engine::SessionEntry::kCancelOnDisconnect : 0) |
                                        engine::SessionEntry::kMarketOrders);
    d.sessions.push_back(s);
    engine::RiskEntry r;  // Limit Order Protection is on unless the account turns it off (matching-rules §5)
    r.account_id = n;
    r.kind = engine::RiskKind::Lop;
    r.value = 0;
    d.risk.push_back(r);
  }
  d.engine.book.reserve_orders = c.reserve_orders;
  d.engine.urn_capacity = c.reserve_orders;
  return d;
}

template <net::BackendKind K>
class OuchServer {
 public:
  using StackT = net::Stack<K>;
  static constexpr std::size_t kPorts = 2;  // 0: the primary node's port, 1: the mirror port

  explicit OuchServer(const OuchServerConfig& cfg) : cfg_(cfg), stack_(net::WaitPolicy::Spin), sink_{this} {
    stores_.resize(cfg.sessions + 1);  // created at each session's first login
    for (auto& l : live_) l.assign(cfg.sessions + 1, false);
    dirty_.assign(cfg.sessions + 1, false);
    driver_ = std::make_unique<EngineDriver<Sink>>(ouch_server_day(cfg), sink_);
  }

  net::Result<net::Endpoint> open() {
    if (auto r = stack_.open(); !r) return std::unexpected(r.error());
    net::TcpConfig tc;
    tc.max_conns = cfg_.sessions * 2 + 8;
    tc.rx_buf_bytes = 64 * 1024;
    net::Endpoint ep{};
    for (std::size_t p = 0; p < kPorts; ++p) {
      const net::Endpoint& want = p == 0 ? cfg_.listen : cfg_.mirror_listen;
      if (p == 1 && want.port == 0) break;
      if (auto r = stack_.open(tcp_[p], tc); !r) return std::unexpected(r.error());
      auto e = tcp_[p].listen(want);
      if (!e) return std::unexpected(e.error());
      if (p == 0) ep = *e;
      up_[p] = true;
    }
    // The day starts before the first schedule entry and walks every timer up to
    // the start time (system hours, the opening cross), as a real day would.
    if (!driver_->start(hms_ns(2, 59, 59))) return net::fail("engine day start", 0);
    driver_->advance(cfg_.start_time);
    return ep;
  }

  void run(const std::atomic<bool>* stop) {
    const Nanos t0 = clock_.now_mono();
    for (;;) {
      if (stop != nullptr && stop->load(std::memory_order_relaxed)) break;
      (void)stack_.wait(0);
      const Nanos now = clock_.now_mono();
      if (cfg_.max_runtime > 0 && now - t0 >= cfg_.max_runtime) break;
      // Scripted death of the primary port: a stall (no reads) of stall_primary,
      // then the connections close. Triggered by time or by traffic.
      if (up_[0] && stall_from_ == 0) {
        if (cfg_.fail_primary_after > 0 && now - t0 >= cfg_.fail_primary_after - cfg_.stall_primary) stall_from_ = now;
        if (cfg_.fail_primary_after_inbound > 0 && inbound_[0] >= cfg_.fail_primary_after_inbound) stall_from_ = now;
      }
      if (up_[0] && stall_from_ != 0 && now - stall_from_ >= cfg_.stall_primary) fail_primary();
      driver_->advance(cfg_.start_time + (now - t0));
      const bool stalled = up_[0] && stall_from_ != 0;
      for (std::size_t p = 0; p < kPorts; ++p)
        if (up_[p] && !(p == 0 && stalled)) tcp_[p].poll([&](const env::StreamEvent& ev) { on_event(p, ev, now); });
      for (std::size_t i = 0; i < conns_.size(); ++i)
        if (!(stalled && conns_[i].port == 0)) service(i, now);
      std::fill(dirty_.begin(), dirty_.end(), false);  // every live instance took its stream
      std::erase_if(conns_, [](const Conn& c) { return c.conn == env::kNoConn; });
    }
  }

  [[nodiscard]] const OuchServerStats& stats() const noexcept { return st_; }
  [[nodiscard]] const engine::Engine& engine() const noexcept { return driver_->engine(); }

 private:
  struct Sink {
    OuchServer* self;
    void itch(std::uint64_t, std::span<const std::byte>) { ++self->st_.itch_out; }
    void ouch(std::uint64_t, std::uint32_t session, std::span<const std::byte> b) {
      ++self->st_.ouch_out;
      if (session == 0 || session >= self->stores_.size()) return;
      if (!self->stores_[session]) {
        ++self->st_.ouch_unattached;
        return;
      }
      if (!self->stores_[session]->append(b)) ++self->st_.store_full;
      self->dirty_[session] = true;
    }
    void audit(std::uint64_t, const engine::AuditEvent&) { ++self->st_.audits; }
  };

  // The store of whichever session the connection logs into. Both instances of a
  // session (primary and mirror port) read the same store: byte-identical streams.
  struct StoreProxy {
    RingSequencedStore* s = nullptr;
    [[nodiscard]] SeqNo next_seq() const noexcept { return s != nullptr ? s->next_seq() : 1; }
    bool append(std::span<const std::byte> m) noexcept { return s != nullptr && s->append(m); }
    [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo q) const noexcept {
      return s != nullptr ? s->get(q) : std::nullopt;
    }
  };
  struct Policy {
    OuchServer* self;
    StoreProxy* store;
    std::uint32_t* session;
    std::size_t port;
    soup::LoginDecision authorize(const soup::LoginRequest& r) {
      const std::uint32_t n = session_of_username(r.username.view());
      if (n == 0 || n > self->cfg_.sessions) return soup::LoginDecision::NotAuthorized;
      // A second login on the same port is refused; one on the other port is the
      // session's mirror instance (03 §5 decision table, 10 §3).
      if (self->live_[port][n]) return soup::LoginDecision::SessionUnavailable;
      *session = n;
      auto& st = self->stores_[n];
      if (!st) st = std::make_unique<RingSequencedStore>(self->cfg_.store_messages, self->cfg_.store_bytes);
      store->s = st.get();
      return soup::LoginDecision::Accept;
    }
  };
  using Session = soup::ServerSession<StoreProxy, Policy>;
  struct Conn {
    std::size_t port = 0;
    env::ConnId conn = env::kNoConn;
    std::unique_ptr<StoreProxy> store;
    std::unique_ptr<std::uint32_t> session;
    std::unique_ptr<Policy> policy;
    std::unique_ptr<Session> s;
    bool logged_in = false;
  };

  void on_event(std::size_t port, const env::StreamEvent& ev, Nanos now) {
    if (ev.kind == env::StreamEventKind::Accepted) {
      ++st_.accepted;
      Conn c;
      c.port = port;
      c.conn = ev.conn;
      c.store = std::make_unique<StoreProxy>();
      c.session = std::make_unique<std::uint32_t>(0);
      c.policy = std::make_unique<Policy>(Policy{this, c.store.get(), c.session.get(), port});
      soup::ServerConfig sc;
      sc.session = soup::SessionId::from("LLETEST");
      sc.tx_capacity = 1 << 20;
      c.s = std::make_unique<Session>(sc, *c.store, *c.policy, now);
      conns_.push_back(std::move(c));
      return;
    }
    for (std::size_t i = 0; i < conns_.size(); ++i) {
      Conn& c = conns_[i];
      if (c.port != port || c.conn != ev.conn) continue;
      if (ev.kind == env::StreamEventKind::Data) {
        std::span<const std::byte> in = ev.data;
        while (!in.empty() && c.conn != env::kNoConn) {
          const soup::Actions& a = c.s->on_bytes(in, now);
          const std::size_t used = a.consumed;
          absorb(i, a, now);
          if (used == 0) break;
          in = in.subspan(used);
        }
      } else if (ev.kind == env::StreamEventKind::Closed) {
        drop(i, false);
      }
      return;
    }
  }

  void absorb(std::size_t i, const soup::Actions& a, Nanos) {
    Conn& c = conns_[i];
    for (const soup::Event& e : a.events) {
      if (e.kind == soup::EventKind::LoggedIn) {
        c.logged_in = true;
        live_[c.port][*c.session] = true;
        ++st_.logins;
        (void)driver_->submit_session(*c.session, journal::SessionEventKind::Login, static_cast<std::uint16_t>(c.port));
      } else if (e.kind == soup::EventKind::LoginRejected) {
        ++st_.login_rejects;
      }
    }
    for (const soup::Delivered& d : a.delivered) {
      ++st_.inbound;
      ++inbound_[c.port];
      (void)driver_->submit_ouch(*c.session, *c.session, d.data, static_cast<std::uint16_t>(c.port));
    }
  }

  void service(std::size_t i, Nanos now) {
    Conn& c = conns_[i];
    if (c.conn == env::kNoConn) return;
    if ((c.logged_in && dirty_[*c.session]) || c.s->actions().deadline <= now) absorb(i, c.s->on_timer(now), now);
    for (int k = 0; k < 8; ++k) {
      const auto w = c.s->actions().write;
      if (w.empty()) break;
      const std::size_t n = tcp_[c.port].write(c.conn, w);
      if (n == 0) break;
      if (c.s->consume_tx(n)) absorb(i, c.s->on_timer(now), now);
    }
    if (c.s->actions().close && c.s->actions().write.empty()) drop(i, true);
  }

  void drop(std::size_t i, bool close_socket) {
    Conn& c = conns_[i];
    if (c.conn == env::kNoConn) return;
    if (close_socket) tcp_[c.port].close(c.conn);
    ++st_.closed;
    if (c.logged_in) {
      live_[c.port][*c.session] = false;
      (void)driver_->submit_session(*c.session, journal::SessionEventKind::Disconnect,
                                    static_cast<std::uint16_t>(c.port));
    }
    c.conn = env::kNoConn;
  }

  // The primary node dies: its port's connections close without End of Session
  // (bytes it had not read are lost) and it stops listening. The mirror port
  // carries on with the same streams (10 §4 step 5: sessions with a live
  // instance on the survivor are unaffected).
  void fail_primary() {
    for (std::size_t i = 0; i < conns_.size(); ++i)
      if (conns_[i].port == 0) drop(i, true);
    tcp_[0].shutdown();
    up_[0] = false;
    ++st_.primary_failures;
  }

  OuchServerConfig cfg_;
  env::ProdClock clock_;
  StackT stack_;
  std::array<typename StackT::StreamPort, kPorts> tcp_;
  std::array<bool, kPorts> up_{};
  std::array<std::uint64_t, kPorts> inbound_{};
  Nanos stall_from_ = 0;
  Sink sink_;
  std::vector<std::unique_ptr<RingSequencedStore>> stores_;
  std::array<std::vector<bool>, kPorts> live_;
  std::vector<bool> dirty_;
  std::vector<Conn> conns_;
  std::unique_ptr<EngineDriver<Sink>> driver_;
  OuchServerStats st_;
};

}  // namespace lle::client
