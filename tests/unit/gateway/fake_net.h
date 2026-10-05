#pragma once
// Deterministic in-memory stand-ins for a network stack (net::Stack<K>): a stream port
// whose events the test injects and whose writes it reads back, a datagram port that
// records what was sent and replays injected datagrams, and a manual clock. Used by
// the gateway and md unit tests, the allocation tests and the gateway fuzz harness.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <span>
#include <utility>
#include <vector>

#include "common/types.h"
#include "env/concepts.h"
#include "net/common/conn_table.h"
#include "net/common/port.h"

namespace lle::testnet {

using Bytes = std::vector<std::byte>;

class FakeStreamPort {
 public:
  // ---- the stage's side (env::StreamEndpointLike) -----------------------------------
  net::Result<env::Endpoint> listen(env::Endpoint ep) {
    listening = true;
    if (ep.port == 0) ep.port = 40000;
    bound = ep;
    return ep;
  }
  net::Result<env::ConnId> connect(env::Endpoint) { return net::fail("connect", 1); }
  std::size_t write(env::ConnId c, std::span<const std::byte> b) noexcept {
    const std::size_t n = std::min(b.size(), write_budget);
    if (discard) {  // allocation tests: count, keep nothing
      discarded += n;
      return n;
    }
    if (closed_by_stage.count(c) != 0 || peer_closed.count(c) != 0) return 0;
    Bytes& out = written[c];
    out.insert(out.end(), b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
    if (stage_tx && n != 0) staged[c] += n;
    return n;
  }
  void close(env::ConnId c) noexcept {
    if (discard) return;
    closed_by_stage[c] = true;
    if (const std::size_t p = tx_pending(c); p != 0) lost_at_close[c] += p;  // a cancelled SEND
  }
  // Bytes accepted but not yet completed (stage_tx: an io_uring-like port).
  [[nodiscard]] std::size_t tx_pending(env::ConnId c) const noexcept {
    const auto it = staged.find(c);
    return it == staged.end() ? 0 : it->second;
  }
  // Like the kernel port (net/sock/tcp_port.h: max_reads_per_poll reads of
  // rx_buf_bytes), one poll hands over at most `max_bytes_per_poll` data bytes per
  // connection; the rest stays queued ("in the kernel").
  template <class F>
  std::size_t poll(F&& cb) {
    ++polls;
    std::size_t n = 0;
    if (max_bytes_per_poll == 0) {  // no locals: allocation tests poll through here
      while (!events.empty()) {
        Event e = std::move(events.front());
        events.pop_front();
        env::StreamEvent ev{e.kind, e.conn, std::span<const std::byte>(e.data), 0};
        cb(ev);
        ++n;
      }
      return n;
    }
    std::map<env::ConnId, std::size_t> taken;
    std::deque<Event> later;
    while (!events.empty()) {
      Event e = std::move(events.front());
      events.pop_front();
      if (e.kind == env::StreamEventKind::Data && max_bytes_per_poll != 0) {
        std::size_t& t = taken[e.conn];
        if (t + e.data.size() > max_bytes_per_poll || !later.empty()) {
          later.push_back(std::move(e));
          continue;
        }
        t += e.data.size();
      } else if (!later.empty()) {
        later.push_back(std::move(e));  // keep each connection's events in order
        continue;
      }
      env::StreamEvent ev{e.kind, e.conn, std::span<const std::byte>(e.data), 0};
      cb(ev);
      ++n;
    }
    events.swap(later);
    return n;
  }

  // ---- the test's side -------------------------------------------------------------
  env::ConnId accept() {
    const env::ConnId c = net::make_conn_id(next_slot_++, 1);
    events.push_back(Event{env::StreamEventKind::Accepted, c, {}});
    return c;
  }
  void data(env::ConnId c, std::span<const std::byte> b) {
    events.push_back(Event{env::StreamEventKind::Data, c, Bytes(b.begin(), b.end())});
  }
  void peer_close(env::ConnId c) {
    peer_closed[c] = true;
    events.push_back(Event{env::StreamEventKind::Closed, c, {}});
  }
  // Every staged SEND completes.
  void complete_tx() { staged.clear(); }
  // Bytes written to `c` since the last call.
  Bytes take(env::ConnId c) {
    Bytes out;
    out.swap(written[c]);
    return out;
  }

  struct Event {
    env::StreamEventKind kind;
    env::ConnId conn;
    Bytes data;
  };
  std::deque<Event> events;
  std::map<env::ConnId, Bytes> written;
  std::map<env::ConnId, bool> closed_by_stage;
  std::map<env::ConnId, bool> peer_closed;
  std::size_t write_budget = ~std::size_t{0};  // bytes one write() takes
  std::size_t max_bytes_per_poll = 0;          // 0: no limit
  // Written bytes stay pending (tx_pending) until complete_tx(); a close() while bytes
  // are pending loses them (lost_at_close), as close() cancels an io_uring SEND.
  bool stage_tx = false;
  std::map<env::ConnId, std::size_t> staged;
  std::map<env::ConnId, std::size_t> lost_at_close;
  bool discard = false;
  std::uint64_t discarded = 0;
  bool listening = false;
  env::Endpoint bound{};
  std::uint64_t polls = 0;

 private:
  std::uint32_t next_slot_ = 0;
};

class FakeDatagramPort {
 public:
  bool send(env::Endpoint to, std::span<const std::byte> b) noexcept {
    if (discard) {  // allocation tests: count, keep nothing
      ++discarded;
      return true;
    }
    sent.emplace_back(to, Bytes(b.begin(), b.end()));
    return true;
  }
  template <class F>
  std::size_t poll_rx(F&& cb) {
    std::size_t n = 0;
    while (!inbox.empty()) {
      auto [from, bytes] = std::move(inbox.front());
      inbox.pop_front();
      cb(env::RxDatagram{std::span<const std::byte>(bytes), from, {}, 0});
      ++n;
    }
    return n;
  }
  [[nodiscard]] env::Endpoint local() const noexcept { return bound; }

  std::vector<std::pair<env::Endpoint, Bytes>> sent;
  std::deque<std::pair<env::Endpoint, Bytes>> inbox;
  env::Endpoint bound{0x7F000001u, 30003};
  bool discard = false;
  std::uint64_t discarded = 0;
};

// net::Stack<K> stand-in.
struct FakeNet {
  using StreamPort = FakeStreamPort;
  using DatagramPort = FakeDatagramPort;
  net::Result<void> open() { return {}; }
  net::Result<void> open(FakeStreamPort&, const net::TcpConfig&) { return {}; }
  net::Result<void> open(FakeDatagramPort& p, const net::UdpConfig& c) {
    if (c.bind.port != 0) p.bound = c.bind;
    return {};
  }
  int wait(Nanos) noexcept { return 0; }
};

// tsc() counts its reads (work meters: two per non-empty poll, none per empty one) and
// advances by tsc_step per read, so a metered batch has a non-zero duration.
struct FakeClock {
  Nanos mono = 1'000'000'000;
  Nanos real = 0;
  std::uint64_t tsc_step = 7;
  mutable std::uint64_t tsc_reads = 0;
  [[nodiscard]] Nanos now_mono() const noexcept { return mono; }
  [[nodiscard]] Nanos now_real() const noexcept { return real; }
  [[nodiscard]] std::uint64_t tsc() const noexcept {
    ++tsc_reads;
    return static_cast<std::uint64_t>(mono) + tsc_reads * tsc_step;
  }
};

}  // namespace lle::testnet
