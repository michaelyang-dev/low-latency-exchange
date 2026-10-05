// stream world: TCP-like echo under segmentation, coalescing, delay, stalls,
// partitions (resets after the timeout), server crashes and pauses.
//
// Each client connects, streams a seeded byte pattern and checks that the echo
// is a prefix of what it sent on that connection (O-PREFIX): no byte lost,
// duplicated, reordered or corrupted while connected. On reset it reconnects
// with backoff and starts a new session. Convergence: every client has had
// its target number of bytes echoed after healing.
#include <memory>
#include <vector>

#include "common/assert.h"
#include "common/hash.h"
#include "env/concepts.h"
#include "sim/worlds/worlds.h"
#include "sim/dist.h"
#include "sim/fault/buggify.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/oracles/prefix_checker.h"

namespace lle::sim::worlds::detail {

namespace {

constexpr std::uint16_t kEchoPort = 9000;
constexpr std::uint64_t kWindowBytes = 16 * 1024;

std::byte pattern(std::uint64_t seed, std::uint64_t client, std::uint64_t session, std::uint64_t i) noexcept {
  const std::uint64_t v = mix64(seed ^ (client << 48) ^ (session << 32) ^ (i >> 3));
  return static_cast<std::byte>(v >> ((i & 7) * 8));
}

struct Ledger {
  std::vector<std::uint64_t> echoed;  // per client, across sessions
  std::vector<std::uint64_t> sessions;
  std::vector<bool> settled;          // current session fully echoed
  std::uint64_t target = 0;
  OracleRegistry* oracles = nullptr;
  OracleId o_prefix = 0;

  [[nodiscard]] bool done() const {
    for (std::size_t i = 0; i < echoed.size(); ++i) {
      if (echoed[i] < target || !settled[i]) return false;
    }
    return true;
  }
};

template <env::StreamPortLike Port>
class EchoServer {
 public:
  EchoServer(Port& port, bool canary) : port_(port), canary_(canary) {}

  bool poll() {
    bool did = false;
    port_.poll([&](const env::StreamEvent& ev) {
      did = true;
      switch (ev.kind) {
        case env::StreamEventKind::Accepted:
          conns_.push_back(Conn{ev.conn, {}, 0});
          break;
        case env::StreamEventKind::Data: {
          Conn* c = find(ev.conn);
          if (c == nullptr) break;
          for (const std::byte b : ev.data) {
            // Planted canary bug: drop one byte at offset 1000 of each connection.
            if (!(canary_ && c->received == 1000)) c->pending.push_back(b);
            ++c->received;
          }
          flush(*c);
          break;
        }
        case env::StreamEventKind::Closed:
          std::erase_if(conns_, [&](const Conn& c) { return c.id == ev.conn; });
          break;
        case env::StreamEventKind::Connected:
          break;
      }
    });
    for (Conn& c : conns_) {
      if (!c.pending.empty()) did = flush(c) || did;
    }
    return did;
  }

 private:
  struct Conn {
    env::ConnId id;
    std::vector<std::byte> pending;
    std::uint64_t received;
  };
  Conn* find(env::ConnId id) {
    for (Conn& c : conns_) {
      if (c.id == id) return &c;
    }
    return nullptr;
  }
  bool flush(Conn& c) {
    if (c.pending.empty()) return false;
    std::size_t limit = c.pending.size();
    if (SIM_BUGGIFY("demo.stream.short_write") && limit > 1) limit /= 2;
    const std::size_t n = port_.write(c.id, std::span<const std::byte>(c.pending.data(), limit));
    c.pending.erase(c.pending.begin(), c.pending.begin() + static_cast<std::ptrdiff_t>(n));
    return n > 0;
  }

  Port& port_;
  bool canary_;
  std::vector<Conn> conns_;
};

template <env::StreamPortLike Port, env::ClockLike Clock>
class EchoClient {
 public:
  EchoClient(Port& port, Clock& clock, Ledger& ledger, env::Endpoint server, std::uint32_t id, std::uint64_t seed,
             Rng rng)
      : port_(port), clock_(clock), ledger_(ledger), server_(server), id_(id), seed_(seed), rng_(rng) {}

  bool poll() {
    bool did = false;
    port_.poll([&](const env::StreamEvent& ev) {
      did = true;
      if (ev.conn != conn_) return;
      switch (ev.kind) {
        case env::StreamEventKind::Connected:
          connected_ = true;
          ++session_;
          ++ledger_.sessions[id_];
          if (session_ > 1) SIM_PROBE("demo.stream.reconnected");
          sent_ = echoed_ = 0;
          checker_ = std::make_unique<PrefixChecker>();
          break;
        case env::StreamEventKind::Data:
          on_echo(ev.data);
          break;
        case env::StreamEventKind::Closed:
          if (connected_ && echoed_ < sent_) SIM_PROBE("demo.stream.reset_with_bytes_in_flight");
          conn_ = env::kNoConn;
          connected_ = false;
          ledger_.settled[id_] = true;  // nothing outstanding without a session
          retry_at_ = clock_.now_mono() + kMs + static_cast<Nanos>(rng_.below(50 * kMs));
          break;
        case env::StreamEventKind::Accepted:
          break;
      }
    });
    if (conn_ == env::kNoConn) {
      if (ledger_.echoed[id_] < ledger_.target && clock_.now_mono() >= retry_at_) {
        conn_ = port_.connect(server_).value_or(env::kNoConn);
        did = true;
      }
      return did;
    }
    if (!connected_) return did;
    // Keep at most kWindowBytes outstanding until the target is reached.
    while (sent_ - echoed_ < kWindowBytes && ledger_.echoed[id_] + (sent_ - echoed_) < ledger_.target) {
      std::byte chunk[512];
      const std::uint64_t room = std::min<std::uint64_t>(
          {sizeof chunk, kWindowBytes - (sent_ - echoed_), ledger_.target - ledger_.echoed[id_] - (sent_ - echoed_)});
      const auto n = static_cast<std::size_t>(1 + rng_.below(room));
      for (std::size_t i = 0; i < n; ++i) chunk[i] = pattern(seed_, id_, session_, sent_ + i);
      const std::size_t w = port_.write(conn_, std::span<const std::byte>(chunk, n));
      if (w == 0) break;
      checker_->append_canonical(std::span<const std::byte>(chunk, w));
      sent_ += w;
      did = true;
    }
    ledger_.settled[id_] = sent_ == echoed_;
    return did;
  }

 private:
  void on_echo(std::span<const std::byte> data) {
    if (!checker_->append_observed(data)) {
      ledger_.oracles->fail(ledger_.o_prefix, "client " + std::to_string(id_) + " session " +
                                                  std::to_string(session_) + " echo diverges at byte " +
                                                  std::to_string(checker_->divergence_offset()));
      return;
    }
    if (!checker_->is_prefix()) {
      ledger_.oracles->fail(ledger_.o_prefix, "client " + std::to_string(id_) + " echo longer than sent");
      return;
    }
    ledger_.oracles->pass(ledger_.o_prefix);
    echoed_ += data.size();
    ledger_.echoed[id_] += data.size();
    ledger_.settled[id_] = sent_ == echoed_;
  }

  Port& port_;
  Clock& clock_;
  Ledger& ledger_;
  env::Endpoint server_;
  std::uint32_t id_;
  std::uint64_t seed_;
  Rng rng_;
  env::ConnId conn_ = env::kNoConn;
  bool connected_ = false;
  std::uint64_t session_ = 0;
  std::uint64_t sent_ = 0;
  std::uint64_t echoed_ = 0;
  Nanos retry_at_ = 0;
  std::unique_ptr<PrefixChecker> checker_;
};

struct ServerProcess : Process {
  ServerProcess(Node& n, bool canary) : port(n), core(port, canary) {
    LLE_ASSERT(port.listen(env::Endpoint{0, kEchoPort}).has_value());
    n.add_stage(core, "echo");
  }
  StreamPort port;
  EchoServer<StreamPort> core;
};

struct ClientProcess : Process {
  ClientProcess(Node& n, Ledger& l, env::Endpoint server, std::uint32_t id, std::uint64_t seed)
      : port(n), core(port, n.clock(), l, server, id, seed, n.rng(1)) {
    n.add_stage(core, "client");
  }
  StreamPort port;
  EchoClient<StreamPort, Clock> core;
};

}  // namespace

Report run_stream(const Options& o) {
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x57E);
  const auto clients = static_cast<std::uint32_t>(1 + wl.below(3));
  auto ledger = std::make_unique<Ledger>();
  ledger->target = 20'000 + wl.below(180'001);
  ledger->echoed.assign(clients, 0);
  ledger->sessions.assign(clients, 0);
  ledger->settled.assign(clients, false);
  ledger->oracles = &w.oracles();
  ledger->o_prefix = w.oracles().activate(kOPrefix);
  declare_demo_probe(w, "demo.stream.reconnected");
  declare_demo_probe(w, "demo.stream.reset_with_bytes_in_flight");
  w.probes().declare("net.stream_reset_on_partition", false);

  Node& server = w.add_node("server", NodeOptions{true, true});
  const env::Endpoint server_ep{server.ip(), kEchoPort};
  const bool canary = o.canary;
  // The canary bug only exists in server incarnations after a crash, so only
  // seeds with a server crash catch it.
  server.set_boot([canary](Node& n, BootReason why) {
    n.emplace_process<ServerProcess>(n, canary && why == BootReason::Restart);
  });
  Ledger* lp = ledger.get();
  for (std::uint32_t c = 0; c < clients; ++c) {
    Node& n = w.add_node("client" + std::to_string(c), NodeOptions{false, true});
    const std::uint64_t seed = o.seed;
    n.set_boot([=](Node& nd, BootReason) { nd.emplace_process<ClientProcess>(nd, *lp, server_ep, c, seed); });
  }
  for (NodeId i = 0; i < w.node_count(); ++i) w.node(i).boot();

  return finish(
      w, WorldKind::Stream, o, [lp] { return lp->done(); },
      [lp] {
        std::uint64_t echoed = 0;
        std::uint64_t sessions = 0;
        for (std::size_t i = 0; i < lp->echoed.size(); ++i) {
          echoed += lp->echoed[i];
          sessions += lp->sessions[i];
        }
        return "clients=" + std::to_string(lp->echoed.size()) + " echoed=" + std::to_string(echoed) + "/" +
               std::to_string(lp->target * lp->echoed.size()) + " sessions=" + std::to_string(sessions);
      });
}

}  // namespace lle::sim::worlds::detail
