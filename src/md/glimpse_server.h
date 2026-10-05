#pragma once
// The GLIMPSE-style snapshot service (03 §8; 07 §3 N-18 "GLIMPSE server placement").
//
// Placement: a housekeeping stage, off the 8-core pipeline (01 §7: the GLIMPSE server
// runs on CPUs 0-7). It never reads the egress ring, so it can never gate the engine:
// it tails the output log's itch.bin (the released ITCH stream, MoldUDP64 sequence =
// position, 06 §8) with an OutlogReader and applies it to a GlimpseState.
//
// Protocol: SoupBinTCP. A client logs in (credentials from the configuration) asking
// for sequence 1; at login the spin of the state at the current position P is built
// (glimpse::SnapshotServer: S, R, H, Y, h, A/F, then End of Snapshot G(P+1)) and
// delivered as the session's sequenced messages, followed by End of Session. The
// client then applies MoldUDP64 messages from P+1 (glimpse::SnapshotJoiner).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "common/types.h"
#include "env/concepts.h"
#include "gateway/credentials.h"
#include "log/nlog.h"
#include "md/glimpse_state.h"
#include "md/stream_linger.h"
#include "md/work_meter.h"
#include "net/common/conn_table.h"
#include "net/common/port.h"
#include "outlog/reader.h"
#include "proto/glimpse/snapshot_server.h"
#include "proto/soupbin/sequenced_store.h"
#include "proto/soupbin/server_session.h"

namespace lle::md {

struct GlimpseConfig {
  soup::ServerConfig soup{};
  net::TcpConfig tcp{};
  env::Endpoint listen{};
  std::string itch_log_path;  // outlog/<day>/itch.bin
  std::string user;           // the snapshot login (SoupBinTCP username)
  gw::Credential credential;
  Nanos refresh_interval = 1'000'000;  // how often the output log is tailed
  std::size_t locates = 0;             // symbols of the day (pre-sizes the state)
  Nanos close_linger = kDefaultCloseLinger;  // bound on flushing a closing connection
};

struct GlimpseStats {
  std::uint64_t spins = 0;
  std::uint64_t spin_messages = 0;
  std::uint64_t login_rejects = 0;
  std::uint64_t applied = 0;
  std::uint64_t linger_timeouts = 0;  // closing connections that could not flush in time
};

template <class Env>
class GlimpseServer {
 public:
  using Net = typename Env::Net;
  using Port = typename Net::StreamPort;
  using Clock = typename Env::Clock;

  GlimpseServer(const GlimpseConfig& cfg, Clock& clock)
      : cfg_(cfg), clock_(&clock), state_(cfg.locates), work_(&clock) {
    conns_ = std::make_unique<Conn[]>(cfg_.tcp.max_conns);
    for (std::uint32_t i = 0; i < cfg_.tcp.max_conns; ++i) conns_[i].policy = Policy{this, i};
  }
  GlimpseServer(const GlimpseServer&) = delete;
  GlimpseServer& operator=(const GlimpseServer&) = delete;

  std::expected<void, std::string> start() {
    auto r = open_net();
    if (!r) {
      error_ = r.error();
      open_state_.store(-1, std::memory_order_release);
      return r;
    }
    open_state_.store(1, std::memory_order_release);
    return {};
  }
  // Opens on the first poll, on the polling thread (io_uring SINGLE_ISSUER).
  void start_on_first_poll() noexcept { deferred_ = true; }
  [[nodiscard]] int start_state() const noexcept { return open_state_.load(std::memory_order_acquire); }
  [[nodiscard]] const std::string& error() const noexcept { return error_; }

  bool poll() {
    if (deferred_) [[unlikely]] {
      deferred_ = false;
      (void)start();
    }
    if (open_state_.load(std::memory_order_relaxed) != 1) return false;
    const Nanos now = clock_->now_mono();
    bool did = false;
    (void)net_.wait(0);
    if (now - last_tail_ >= cfg_.refresh_interval) {
      last_tail_ = now;
      did |= tail();
    }
    did |= port_.poll([&](const env::StreamEvent& ev) { on_event(ev, now); }) != 0;
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
      }
    }
    work_.finish();
    return did;
  }

  [[nodiscard]] env::Endpoint listen_endpoint() const noexcept { return listen_; }
  [[nodiscard]] const GlimpseState& state() const noexcept { return state_; }
  [[nodiscard]] const GlimpseStats& stats() const noexcept { return stats_; }
  // Work time (md/work_meter.h). Items: output-log messages applied to the state, port
  // events and session timer actions (a spin is built inside its login's port event).
  [[nodiscard]] const WorkStats& work() const noexcept { return work_.stats(); }
  [[nodiscard]] Port& port() noexcept { return port_; }  // tests

 private:
  std::expected<void, std::string> open_net() {
    if (auto r = net_.open(); !r) return std::unexpected("glimpse: reactor: " + net::to_string(r.error()));
    if (auto r = net_.open(port_, cfg_.tcp); !r) return std::unexpected("glimpse: port: " + net::to_string(r.error()));
    auto ep = port_.listen(cfg_.listen);
    if (!ep) return std::unexpected("glimpse: listen: " + net::to_string(ep.error()));
    listen_ = *ep;
    return {};
  }

  struct ProxyStore {
    soup::MemorySequencedStore* target = nullptr;
    [[nodiscard]] SeqNo next_seq() const noexcept { return target != nullptr ? target->next_seq() : 1; }
    bool append(std::span<const std::byte> m) noexcept { return target != nullptr && target->append(m); }
    [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo s) const noexcept {
      return target != nullptr ? target->get(s) : std::nullopt;
    }
  };
  struct Policy {
    GlimpseServer* g = nullptr;
    std::uint32_t slot = 0;
    soup::LoginDecision authorize(const soup::LoginRequest& r) { return g->authorize(slot, r); }
  };
  using Session = soup::ServerSession<ProxyStore, Policy>;
  struct Conn {
    env::ConnId id = env::kNoConn;
    ProxyStore proxy;
    Policy policy;
    std::optional<Session> sess;
    std::unique_ptr<soup::MemorySequencedStore> spin;
    Nanos deadline = soup::kNever;
    bool pump = false;
    bool end_pending = false;
    bool closing = false;  // the session ended; flushing before the port is closed
    Nanos linger_until = 0;
  };

  bool tail() {
    if (!opened_) {
      if (!reader_.open(cfg_.itch_log_path)) return false;  // created by the io stage at start
      opened_ = true;
    }
    if (!reader_.refresh()) return false;
    const std::size_t n = reader_.for_each(state_.applied() + 1, 65'536, [&](SeqNo, std::span<const std::byte> m) {
      work_.start();
      work_.add();
      state_.apply(m);
    });
    stats_.applied = state_.applied();
    return n != 0;
  }

  // Login: credentials, then the spin of the state at this moment.
  soup::LoginDecision authorize(std::uint32_t slot, const soup::LoginRequest& r) {
    if (gw::normalize_credential(r.username.view()) != gw::normalize_credential(cfg_.user) ||
        !cfg_.credential.verify(r.password.view())) {
      ++stats_.login_rejects;
      return soup::LoginDecision::NotAuthorized;
    }
    Conn& c = conns_[slot];
    const std::size_t n = state_.spin_messages();
    c.spin = std::make_unique<soup::MemorySequencedStore>(n, n * itch50::kMaxMsgLen + 64);
    const glimpse::SpinStats st =
        glimpse::SnapshotServer{}.emit(state_, [&](std::span<const std::byte> m) { (void)c.spin->append(m); });
    c.proxy.target = c.spin.get();
    ++stats_.spins;
    stats_.spin_messages += st.messages;
    NLOG_INFO("glimpse: snapshot at {} ({} messages, {} resting orders)", st.next_seq - 1, st.messages,
              state_.resting_orders());
    return soup::LoginDecision::Accept;
  }

  void on_event(const env::StreamEvent& ev, Nanos now) {
    work_.start();
    work_.add();
    const std::uint32_t slot = net::conn_slot(ev.conn);
    if (slot >= cfg_.tcp.max_conns) {
      if (ev.kind == env::StreamEventKind::Accepted) port_.close(ev.conn);
      return;
    }
    Conn& c = conns_[slot];
    switch (ev.kind) {
      case env::StreamEventKind::Accepted:
        reset(c);
        c.id = ev.conn;
        c.sess.emplace(cfg_.soup, c.proxy, c.policy, now);
        handle(c, c.sess->on_timer(now), now);
        return;
      case env::StreamEventKind::Data:
        if (c.id != ev.conn || !c.sess || c.closing) return;
        for (std::size_t off = 0; off < ev.data.size() && c.sess && !c.closing;) {
          const soup::Actions& a = c.sess->on_bytes(ev.data.subspan(off), now);
          const std::size_t used = a.consumed;
          handle(c, a, now);
          off += used;
          if (used == 0) break;
        }
        return;
      case env::StreamEventKind::Closed:
        if (c.id == ev.conn) reset(c);
        return;
      case env::StreamEventKind::Connected: return;
    }
  }

  void handle(Conn& c, const soup::Actions& a, Nanos now) {
    for (const soup::Event& e : a.events) {
      if (e.kind == soup::EventKind::LoggedIn) c.end_pending = true;  // deliver the spin, then 'Z'
    }
    c.deadline = a.deadline;
    flush(c);
    if (a.close) {
      close(c, now);
      return;
    }
    if (c.end_pending) {
      c.end_pending = false;
      handle(c, c.sess->end_session(now), now);
    }
  }

  void flush(Conn& c) {
    const std::span<const std::byte> w = c.sess->actions().write;
    if (w.empty()) return;
    const std::size_t n = port_.write(c.id, w);
    if (n != 0) c.pump = c.sess->consume_tx(n);
    if (n < w.size()) c.pump = true;  // continue from on_timer() once the port has room
  }
  [[nodiscard]] bool tx_drained(const Conn& c) const noexcept {
    return c.sess->actions().write.empty() && port_tx_pending(port_, c.id) == 0;
  }
  // The session ended: close the port once its last bytes ('Z') are out (stream_linger.h).
  void close(Conn& c, Nanos now) {
    if (!tx_drained(c)) {
      c.closing = true;
      c.linger_until = now + cfg_.close_linger;
      c.deadline = soup::kNever;
      c.pump = false;
      c.end_pending = false;
      return;
    }
    port_.close(c.id);
    reset(c);
  }
  void linger(Conn& c, Nanos now) {
    flush(c);
    if (!tx_drained(c) && now < c.linger_until) return;
    if (!tx_drained(c)) {
      ++stats_.linger_timeouts;
      NLOG_WARN("glimpse: slot {} closing with bytes unsent (peer not reading)", net::conn_slot(c.id));
    }
    port_.close(c.id);
    reset(c);
  }

  void reset(Conn& c) {
    c.sess.reset();
    c.spin.reset();
    c.proxy.target = nullptr;
    c.id = env::kNoConn;
    c.deadline = soup::kNever;
    c.pump = false;
    c.end_pending = false;
    c.closing = false;
    c.linger_until = 0;
  }

  GlimpseConfig cfg_;
  Clock* clock_;
  Net net_;
  Port port_;
  env::Endpoint listen_{};
  GlimpseState state_;
  outlog::env_reader_t<Env> reader_;  // Env::OutlogReader, else POSIX
  bool opened_ = false;
  Nanos last_tail_ = 0;
  std::unique_ptr<Conn[]> conns_;
  GlimpseStats stats_{};
  bool deferred_ = false;
  std::atomic<int> open_state_{0};
  std::string error_;
  WorkMeter<Clock> work_;
};

}  // namespace lle::md
