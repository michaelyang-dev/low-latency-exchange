#pragma once
// loadgen v2's generator thread (07 §3 "loadgen v2", METHODOLOGY §15; WP N-16): one
// thread owns a subset of the sessions, its precomputed schedule (lg::build_schedule
// with thread_index), one I/O instance of the run's variant (client_io.h) and its own
// accounting. Threads share nothing but the start time and the stop flag.
//
// Loop, open loop on the precomputed schedule:
//   1. every message whose scheduled time has come is appended to its session (in
//      schedule order per session; a full transmit buffer delays it, and its latency
//      keeps counting from the scheduled time);
//   2. one write per session (batched TX: everything appended this iteration);
//   3. responses -> accounting (latency = response processed - scheduled send);
//   4. session timers; TX stamps of the NIC-to-NIC probes.
// Generator lateness = time the message was appended - scheduled time (a load point
// fails if its p99.9 exceeds 1 us). Per-second interval histograms of the latency, by
// scheduled time, are preallocated for the .hdr log.
//
// NIC-to-NIC probes (07 §4 "Exchange wire-to-wire", W2W_ack): every Nth message is
// written alone (its session is flushed before and after it), so the TX timestamp of
// its frame is its own; its ack's RX stamp counts when the ack is the last message of
// its read (the read's stamp is the newest frame's). W2W_ack = RX_hw(ack) - TX_hw(order),
// one PHC; other pairs are counted, not computed.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "client/client_io.h"
#include "client/histogram.h"
#include "client/loadgen.h"
#include "client/tx_stamps.h"
#include "common/alpha.h"
#include "env/prod_clock.h"
#include "net/hwts/clock_domain.h"
#include "proto/soupbin/client_session.h"

namespace lle::client::lg {

struct RunnerConfig {
  net::Endpoint server{};
  std::uint32_t user_base = 1;
  std::string password = "password";
  Nanos drain = 2 * kNsPerSec;
  Nanos warmup = 0;               // messages scheduled before this are not in the latency statistics
  std::uint64_t nic_sample = 0;   // every Nth message is a NIC-to-NIC probe (0: none)
  int phc = -1;                   // PHC of the port (for the probe intervals)
  std::size_t tx_capacity = 4 << 20;
};

struct RunnerResult {
  bool logged_in = false;
  std::uint64_t sent = 0, tx_blocked = 0, login_rejects = 0, disconnects = 0;
  Nanos last_send = 0;
  net::hwts::IntervalAccounting probe_acc;
  Histogram w2w;
  std::vector<std::unique_ptr<Histogram>> intervals;  // per second from t0
};

template <class Io>
class LoadRunner {
 public:
  LoadRunner(const Schedule& s, const RunnerConfig& rc, const VariantConfig& v)
      : s_(s), rc_(rc), io_(v), acc_(s) {
    const std::uint32_t k = s.cfg.sessions;
    for (std::uint32_t x = 0; x < k; ++x)
      if (session_of_thread(x, s.cfg.thread_index, s.cfg.threads)) mine_.push_back(x);
    per_.resize(k);
    for (std::size_t i = 0; i < s.items.size(); ++i) per_[s.items[i].session].push_back(static_cast<std::uint32_t>(i));
    next_.assign(k, 0);
    sess_.resize(k);
    conn_.assign(k, env::kNoConn);
    logged_.assign(k, false);
    txm_.resize(k);
    for (auto& m : txm_) m.init(1 << 12);
    if (rc.nic_sample != 0) probes_.resize(s.items.size() / rc.nic_sample + 1);
    const auto secs = static_cast<std::size_t>((s.items.empty() ? 0 : s.items.back().t) / kNsPerSec) +
                      static_cast<std::size_t>(rc.drain / kNsPerSec) + 3;
    res_.intervals.reserve(secs);
    for (std::size_t i = 0; i < secs; ++i) res_.intervals.push_back(std::make_unique<Histogram>());
  }
  LoadRunner(const LoadRunner&) = delete;
  LoadRunner& operator=(const LoadRunner&) = delete;

  std::expected<void, std::string> open() {
    IoSpec spec;
    spec.stream.enabled = true;
    spec.stream.max_conns = static_cast<std::uint32_t>(mine_.size()) + 4;
    spec.stream.rx_buf_bytes = 256 * 1024;
    spec.stream.max_reads_per_poll = 16;
    spec.stream.tx_staging_bytes = 1 << 20;
    spec.stream.sndbuf = 8 << 20;
    spec.stream.rcvbuf = 8 << 20;
    spec.stream.peers[0] = rc_.server;
    return io_.open(spec);
  }

  // Connects and logs in every owned session; false on rejection, error or timeout.
  bool login(Nanos timeout, const std::atomic<bool>& stop) {
    for (const std::uint32_t x : mine_) {
      soup::ClientConfig c;
      char u[8];
      std::snprintf(u, sizeof u, "U%05u", rc_.user_base + x);
      c.username = Alpha<6>(u);
      c.password = Alpha<10>(rc_.password);
      c.sequence = 1;
      c.tx_capacity = rc_.tx_capacity;
      sess_[x].emplace(c);
      const auto id = io_.connect(rc_.server);
      if (!id) return false;
      conn_[x] = *id;
    }
    const Nanos deadline = clock_.now_mono() + timeout;
    for (;;) {
      (void)io_.wait(0);
      const Nanos now = clock_.now_mono();
      poll(now);
      flush_all();
      std::size_t up = 0;
      for (const std::uint32_t x : mine_) up += logged_[x] ? 1u : 0u;
      if (up == mine_.size()) return res_.logged_in = true;
      if (now > deadline || res_.login_rejects > 0 || stop.load(std::memory_order_relaxed)) return false;
    }
  }

  // Runs the schedule from t0 (absolute, CLOCK_MONOTONIC_RAW) until it is sent and
  // answered, the drain time passes, or `stop`.
  void run(Nanos t0, const std::atomic<bool>& stop) {
    t0_ = t0;
    std::vector<Histogram*> iv;
    for (auto& h : res_.intervals) iv.push_back(h.get());
    acc_.set_intervals(std::move(iv), t0);
    const Nanos last_sched = t0 + (s_.items.empty() ? 0 : s_.items.back().t);
    while (clock_.now_mono() < t0) {
      const Nanos now = clock_.now_mono();
      poll(now);
      timers(now);
      flush_all();
    }
    Nanos now = clock_.now_mono();
    while (!stop.load(std::memory_order_relaxed)) {
      (void)io_.wait(0);
      now = clock_.now_mono();
      for (const std::uint32_t x : mine_) send_due(x, now);
      flush_all();
      poll(now);
      timers(now);
      if (rc_.nic_sample != 0 && probes_outstanding()) drain_stamps();
      if (res_.sent == s_.items.size() && (acc_.complete() || now > last_sched + rc_.drain)) break;
      if (res_.sent != s_.items.size() && now > last_sched + rc_.drain) break;  // could not send (blocked)
    }
    end_ = now;
    if (rc_.nic_sample != 0) drain_stamps();
    acc_.finish();
    for (const std::uint32_t x : mine_)
      if (conn_[x] != env::kNoConn && sess_[x]) (void)sess_[x]->logout(now);
    flush_all();
  }

  [[nodiscard]] const Accounting& accounting() const noexcept { return acc_; }
  [[nodiscard]] RunnerResult& result() noexcept { return res_; }
  [[nodiscard]] Io& io() noexcept { return io_; }
  [[nodiscard]] Nanos end() const noexcept { return end_; }
  [[nodiscard]] std::size_t sessions() const noexcept { return mine_.size(); }

 private:
  struct Probe {
    net::RxTimestamps tx{}, rx{};
    bool sent = false;
  };

  void send_due(std::uint32_t x, Nanos now) {
    auto& n = next_[x];
    const auto& list = per_[x];
    if (conn_[x] == env::kNoConn || !sess_[x]) return;
    std::array<std::byte, 256> buf{};
    while (n < list.size()) {
      const std::uint32_t i = list[n];
      const Item& it = s_.items[i];
      if (t0_ + it.t > now) break;
      const bool probe = rc_.nic_sample != 0 && i % rc_.nic_sample == 0;
      if (probe) flush(x);  // alone in its write
      const std::size_t len = encode_item(it, buf);
      const soup::Actions& a = sess_[x]->send_unsequenced(std::span<const std::byte>(buf.data(), len), now);
      if (!a.accepted) {
        ++res_.tx_blocked;
        break;
      }
      acc_.on_sent(i, t0_, now);
      ++res_.sent;
      res_.last_send = now;
      ++n;
      if (probe) {
        const std::size_t pi = i / rc_.nic_sample;
        probes_[pi].sent = true;
        const std::span<const std::byte> tx = sess_[x]->actions().write;
        if (!tx.empty()) txm_[x].expect(pi, txm_[x].written() + static_cast<std::uint32_t>(tx.size()) - 1);
        flush(x);
      }
    }
  }

  void flush(std::uint32_t x) {
    if (conn_[x] == env::kNoConn || !sess_[x]) return;
    for (int r = 0; r < 4; ++r) {
      const auto w = sess_[x]->actions().write;
      if (w.empty()) break;
      const std::size_t n = io_.write(conn_[x], w);
      if (n == 0) break;
      txm_[x].on_written(n);
      sess_[x]->consume_tx(n);
    }
  }
  void flush_all() {
    for (const std::uint32_t x : mine_) flush(x);
  }

  std::uint32_t session_of(env::ConnId c) const noexcept {
    for (const std::uint32_t x : mine_)
      if (conn_[x] == c) return x;
    return ~0u;
  }

  void handle(std::uint32_t x, const soup::Actions& a, Nanos now) {
    for (const soup::Delivered& d : a.delivered) {
      if (d.seq == 0) continue;
      acc_.reset_last_acked();
      acc_.on_response(static_cast<std::uint16_t>(x), d.data, now);
      // A probe's ack counts only if it is the last message of the read (see above).
      const std::int64_t it = acc_.last_acked_item();
      read_probe_ = rc_.nic_sample != 0 && it >= 0 && static_cast<std::uint64_t>(it) % rc_.nic_sample == 0 ? it : -1;
    }
    for (const soup::Event& e : a.events) {
      if (e.kind == soup::EventKind::LoggedIn) logged_[x] = true;
      if (e.kind == soup::EventKind::LoginRejected) ++res_.login_rejects;
    }
  }

  void poll(Nanos now) {
    io_.poll_streams([&](const env::StreamEvent& ev) {
      const std::uint32_t x = session_of(ev.conn);
      if (x == ~0u) return;
      if (ev.kind == env::StreamEventKind::Connected) {
        txm_[x].reset();
        handle(x, sess_[x]->connect(now), now);
      } else if (ev.kind == env::StreamEventKind::Data) {
        read_probe_ = -1;
        std::span<const std::byte> in = ev.data;
        while (!in.empty()) {
          const soup::Actions& a = sess_[x]->on_bytes(in, now);
          const std::size_t used = a.consumed;
          handle(x, a, now);
          if (used == 0) break;
          in = in.subspan(used);
        }
        if (read_probe_ >= 0) probes_[static_cast<std::size_t>(read_probe_) / rc_.nic_sample].rx.hw_ns = ev.hw_rx_ns;
      } else if (ev.kind == env::StreamEventKind::Closed) {
        conn_[x] = env::kNoConn;
        txm_[x].reset();
        ++res_.disconnects;
      }
    });
  }

  void timers(Nanos now) {
    for (const std::uint32_t x : mine_)
      if (sess_[x] && now >= sess_[x]->actions().deadline) handle(x, sess_[x]->on_timer(now), now);
  }

  [[nodiscard]] bool probes_outstanding() const noexcept {
    for (const std::uint32_t x : mine_)
      if (txm_[x].outstanding() != 0) return true;
    return false;
  }

  void drain_stamps() {
    (void)io_.drain_tx_stamps([&](env::ConnId c, const StreamTxStamp& st) {
      const std::uint32_t x = session_of(c);
      if (x == ~0u) return;
      txm_[x].on_stamp(st, [&](std::uint64_t pi, const net::RxTimestamps& ts) { probes_[pi].tx = ts; });
    });
  }

 public:
  // After run(): the probes' NIC-to-NIC intervals.
  void finish_probes() {
    for (const Probe& p : probes_) {
      if (!p.sent) continue;
      const net::hwts::PhcStamp tx = p.tx.hw_ns != 0 ? net::hwts::PhcStamp{rc_.phc, p.tx.hw_ns}
                                                     : net::hwts::PhcStamp{-1, p.tx.sw_ns};
      const net::hwts::PhcStamp rx = p.rx.hw_ns != 0 ? net::hwts::PhcStamp{rc_.phc, p.rx.hw_ns}
                                                     : net::hwts::PhcStamp{-1, p.rx.sw_ns};
      if (const auto d = res_.probe_acc.record(rx, tx)) res_.w2w.record(*d);
    }
  }

 private:
  const Schedule& s_;
  RunnerConfig rc_;
  Io io_;
  Accounting acc_;
  env::ProdClock clock_;
  std::vector<std::uint32_t> mine_;
  std::vector<std::vector<std::uint32_t>> per_;
  std::vector<std::size_t> next_;
  std::vector<std::optional<soup::ClientSession>> sess_;
  std::vector<env::ConnId> conn_;
  std::vector<bool> logged_;
  std::vector<StreamTxMatcher> txm_;
  std::vector<Probe> probes_;
  RunnerResult res_;
  Nanos t0_ = 0, end_ = 0;
  std::int64_t read_probe_ = -1;
};

}  // namespace lle::client::lg
