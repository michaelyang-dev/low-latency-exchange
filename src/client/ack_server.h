#pragma once
// The minimal ack server of loadgen v2's capacity self-test (07 §3 "loadgen v2": it
// must sustain >= 6M msgs/s with lateness p99.9 <= 1 us before any T20 campaign):
// SoupBinTCP sessions that answer every inbound OUCH message at once with its expected
// response type and no matching engine, so the generator, not the server, is what is
// measured:
//   Enter (Day)  -> Accepted (Live)
//   Enter (IOC)  -> Accepted (Live), then Executed for the whole quantity
//   Cancel       -> Canceled
//   Replace      -> Replaced (Live)
// Any username logs in; one thread; kernel sockets of any socket variant.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "client/ring_store.h"
#include "common/endian.h"
#include "env/prod_clock.h"
#include "net/common/stack.h"
#include "proto/ouch50/ouch50.h"
#include "proto/soupbin/server_session.h"

namespace lle::client {

struct AckServerStats {
  std::uint64_t accepted = 0, logins = 0, closed = 0, inbound = 0, responses = 0, unknown = 0;
};

template <net::BackendKind K>
class AckServer {
 public:
  using StackT = net::Stack<K>;
  explicit AckServer(net::Endpoint listen, net::WaitPolicy w = net::WaitPolicy::Spin) : listen_(listen), stack_(w) {}

  net::Result<net::Endpoint> open() {
    if (auto r = stack_.open(); !r) return std::unexpected(r.error());
    net::TcpConfig tc;
    tc.max_conns = 256;
    tc.rx_buf_bytes = 256 * 1024;
    tc.rcvbuf = 8 << 20;
    tc.sndbuf = 8 << 20;
    if (auto r = stack_.open(tcp_, tc); !r) return std::unexpected(r.error());
    return tcp_.listen(listen_);
  }

  void run(const std::atomic<bool>& stop, Nanos max_runtime = 0) {
    env::ProdClock clock;
    const Nanos start = clock.now_mono();
    while (!stop.load(std::memory_order_relaxed)) {
      (void)stack_.wait(0);
      const Nanos now = clock.now_mono();
      tcp_.poll([&](const env::StreamEvent& ev) { on_event(ev, now); });
      for (Conn& c : conns_) {
        if (!c.s) continue;
        if (now >= c.s->actions().deadline) absorb(c, c.s->on_timer(now), now);
        flush(c);
      }
      if (max_runtime > 0 && now - start >= max_runtime) break;
    }
  }

  [[nodiscard]] const AckServerStats& stats() const noexcept { return st_; }

 private:
  struct Policy {
    soup::LoginDecision authorize(const soup::LoginRequest&) { return soup::LoginDecision::Accept; }
  };
  using Session = soup::ServerSession<RingSequencedStore, Policy>;
  struct Conn {
    env::ConnId id = env::kNoConn;
    std::unique_ptr<RingSequencedStore> store;
    std::unique_ptr<Policy> policy;
    std::unique_ptr<Session> s;
  };

  void on_event(const env::StreamEvent& ev, Nanos now) {
    if (ev.kind == env::StreamEventKind::Accepted) {
      ++st_.accepted;
      Conn c;
      c.id = ev.conn;
      c.store = std::make_unique<RingSequencedStore>(std::size_t{1} << 20, std::size_t{64} << 20);
      c.policy = std::make_unique<Policy>();
      soup::ServerConfig sc;
      sc.session = soup::SessionId::from("LLEACK");
      sc.tx_capacity = 8 << 20;
      c.s = std::make_unique<Session>(sc, *c.store, *c.policy, now);
      conns_.push_back(std::move(c));
      return;
    }
    Conn* c = nullptr;
    for (Conn& x : conns_)
      if (x.id == ev.conn) c = &x;
    if (c == nullptr || !c->s) return;
    if (ev.kind == env::StreamEventKind::Closed) {
      ++st_.closed;
      c->s.reset();
      c->id = env::kNoConn;
      return;
    }
    if (ev.kind != env::StreamEventKind::Data) return;
    std::span<const std::byte> in = ev.data;
    while (!in.empty() && c->s) {
      const soup::Actions& a = c->s->on_bytes(in, now);
      const std::size_t used = a.consumed;
      absorb(*c, a, now);
      if (used == 0) break;
      in = in.subspan(used);
    }
    flush(*c);
  }

  void absorb(Conn& c, const soup::Actions& a, Nanos now) {
    for (const soup::Event& e : a.events)
      if (e.kind == soup::EventKind::LoggedIn) ++st_.logins;
    for (const soup::Delivered& d : a.delivered) respond(c, d.data, now);
    if (a.close) {
      flush(c);
      tcp_.close(c.id);
      c.s.reset();
      c.id = env::kNoConn;
    }
  }

  void out(Conn& c, std::span<const std::byte> m, Nanos now) {
    if (!c.s) return;
    ++st_.responses;
    const soup::Actions& a = c.s->send_sequenced(m, now);
    if (a.close) absorb(c, a, now);
  }

  void respond(Conn& c, std::span<const std::byte> m, Nanos now) {
    ++st_.inbound;
    if (m.empty()) return;
    std::byte buf[128];
    const auto ts = static_cast<std::uint64_t>(now);
    switch (static_cast<char>(m[0])) {
      case 'O': {
        if (m.size() < ouch50::in::EnterOrder::kMinLen) break;
        const ouch50::in::EnterOrder e = ouch50::in::EnterOrder::decode_base(m.data());
        ouch50::out::OrderAccepted a;
        a.timestamp = ts;
        a.user_ref_num = e.user_ref_num;
        a.side = e.side;
        a.quantity = e.quantity;
        a.symbol = e.symbol;
        a.price = e.price;
        a.time_in_force = e.time_in_force;
        a.display = e.display;
        a.order_reference_number = ++ref_;
        a.capacity = e.capacity;
        a.inter_market_sweep_eligibility = e.inter_market_sweep_eligibility;
        a.cross_type = e.cross_type;
        a.order_state = ouch50::OrderState::Live;
        a.cl_ord_id = e.cl_ord_id;
        if (const std::size_t n = ouch50::encode(std::span<std::byte>(buf), a)) out(c, {buf, n}, now);
        if (e.time_in_force == ouch50::TimeInForce::Ioc) {
          ouch50::out::OrderExecuted x;
          x.timestamp = ts;
          x.user_ref_num = e.user_ref_num;
          x.quantity = e.quantity;
          x.price = e.price;
          x.liquidity_flag = ouch50::LiquidityFlag::Removed;
          x.match_number = ++match_;
          if (const std::size_t n = ouch50::encode(std::span<std::byte>(buf), x)) out(c, {buf, n}, now);
        }
        return;
      }
      case 'X': {
        if (m.size() < ouch50::in::CancelOrder::kMinLen) break;
        ouch50::out::OrderCanceled x;
        x.timestamp = ts;
        x.user_ref_num = load_be32(m.data() + 1);
        x.quantity = 0;
        x.reason = ouch50::CancelReason::UserRequested;
        if (const std::size_t n = ouch50::encode(std::span<std::byte>(buf), x)) out(c, {buf, n}, now);
        return;
      }
      case 'U': {
        if (m.size() < ouch50::in::ReplaceOrder::kMinLen) break;
        const ouch50::in::ReplaceOrder r = ouch50::in::ReplaceOrder::decode_base(m.data());
        ouch50::out::OrderReplaced x;
        x.timestamp = ts;
        x.orig_user_ref_num = r.orig_user_ref_num;
        x.user_ref_num = r.user_ref_num;
        x.quantity = r.quantity;
        x.price = r.price;
        x.time_in_force = r.time_in_force;
        x.display = r.display;
        x.order_reference_number = ++ref_;
        x.order_state = ouch50::OrderState::Live;
        if (const std::size_t n = ouch50::encode(std::span<std::byte>(buf), x)) out(c, {buf, n}, now);
        return;
      }
      default: break;
    }
    ++st_.unknown;
  }

  void flush(Conn& c) {
    if (!c.s || c.id == env::kNoConn) return;
    for (int r = 0; r < 4; ++r) {
      const auto w = c.s->actions().write;
      if (w.empty()) return;
      const std::size_t n = tcp_.write(c.id, w);
      if (n == 0) return;
      c.s->consume_tx(n);
    }
  }

  net::Endpoint listen_;
  StackT stack_;
  typename StackT::StreamPort tcp_;
  std::vector<Conn> conns_;
  std::uint64_t ref_ = 0, match_ = 0;
  AckServerStats st_;
};

}  // namespace lle::client
