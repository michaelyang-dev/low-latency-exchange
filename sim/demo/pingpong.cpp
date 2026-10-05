// pingpong world: datagram request/response under loss, duplication,
// reordering, partitions, server crashes, pauses and buggified replies.
//
// Clients send numbered pings inside a window and retransmit after an RTO; the
// stateless server echoes each ping and multicasts a heartbeat every 1 ms.
// Clients deliver pongs to their application strictly in order, once each.
// O-EXACTLY-ONCE checks every delivery against a harness-held ledger.
#include <cstring>
#include <memory>
#include <vector>

#include "common/endian.h"
#include "common/hash.h"
#include "env/concepts.h"
#include "sim/worlds/worlds.h"
#include "sim/dist.h"
#include "sim/fault/buggify.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/oracles/seq_checker.h"

namespace lle::sim::worlds::detail {

namespace {

constexpr std::uint16_t kEchoPort = 7000;
constexpr std::uint16_t kClientPort = 7001;
constexpr env::Endpoint kHeartbeatGroup{0xEF01'0101u, 7100};  // 239.1.1.1:7100
constexpr std::uint8_t kPing = 1;
constexpr std::uint8_t kPong = 2;
constexpr std::uint8_t kHeartbeat = 3;
constexpr std::uint64_t kPongMagic = 0x9E3779B97F4A7C15ull;
constexpr std::size_t kMsgBytes = 24;

std::uint64_t ping_digest(std::uint64_t seed, std::uint64_t client, std::uint64_t seq) noexcept {
  return mix64(seed ^ (client << 40) ^ seq);
}

// Harness-side ledger: outside process memory, survives every fault.
struct Ledger {
  std::vector<SeqContiguityChecker> delivered;
  std::vector<std::uint64_t> totals;
  OracleRegistry* oracles = nullptr;
  OracleId o_once = 0;
  std::uint64_t seed = 0;

  void deliver(std::uint8_t client, std::uint64_t seq, std::uint64_t digest) {
    SeqContiguityChecker& c = delivered[client];
    const std::uint64_t expect = c.next();
    const SeqVerdict v = c.observe(seq);
    if (v != SeqVerdict::Ok) {
      oracles->fail(o_once, "client " + std::to_string(client) + " delivered seq " + std::to_string(seq) +
                                (v == SeqVerdict::Duplicate ? " twice" : " out of order") + " (expected " +
                                std::to_string(expect) + ")");
      return;
    }
    if (digest == (ping_digest(seed, client, seq) ^ kPongMagic)) {
      oracles->pass(o_once);  // no message built on the hot path
    } else {
      oracles->fail(o_once, "client " + std::to_string(client) + " pong content mismatch at seq " + std::to_string(seq));
    }
  }
  [[nodiscard]] bool done() const {
    for (std::size_t i = 0; i < totals.size(); ++i) {
      if (delivered[i].next() < totals[i]) return false;
    }
    return true;
  }
};

void put_msg(std::byte* b, std::uint8_t type, std::uint8_t client, std::uint64_t x, std::uint64_t y) {
  std::memset(b, 0, kMsgBytes);
  b[0] = static_cast<std::byte>(type);
  b[1] = static_cast<std::byte>(client);
  store_le64(b + 8, x);
  store_le64(b + 16, y);
}

// Stateless echo server + heartbeat publisher, generic over the env concepts.
template <env::DatagramPortLike Port, env::ClockLike Clock>
class EchoServer {
 public:
  EchoServer(Port& port, Clock& clock, std::uint32_t incarnation) : port_(port), clock_(clock), inc_(incarnation) {}

  bool poll() {
    bool did = false;
    port_.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      if (d.data.size() != kMsgBytes || d.data[0] != static_cast<std::byte>(kPing)) return;
      std::byte out[kMsgBytes];
      std::memcpy(out, d.data.data(), kMsgBytes);
      out[0] = static_cast<std::byte>(kPong);
      store_le64(out + 16, load_le64(d.data.data() + 16) ^ kPongMagic);
      if (SIM_BUGGIFY("demo.pingpong.drop_reply")) return;
      port_.send(d.src, std::span<const std::byte>(out, kMsgBytes));
      if (SIM_BUGGIFY("demo.pingpong.dup_reply")) port_.send(d.src, std::span<const std::byte>(out, kMsgBytes));
    });
    if (clock_.now_mono() >= next_hb_) {
      std::byte hb[kMsgBytes];
      put_msg(hb, kHeartbeat, 0, inc_, ++hb_seq_);
      port_.send(kHeartbeatGroup, std::span<const std::byte>(hb, kMsgBytes));
      next_hb_ = clock_.now_mono() + kMs;
      did = true;
    }
    return did;
  }

 private:
  Port& port_;
  Clock& clock_;
  std::uint64_t inc_;
  std::uint64_t hb_seq_ = 0;
  Nanos next_hb_ = 0;
};

template <env::DatagramPortLike Port, env::ClockLike Clock>
class PingClient {
 public:
  PingClient(Port& port, Clock& clock, Ledger& ledger, env::Endpoint server, std::uint8_t id, std::uint64_t total,
             std::uint64_t window, Nanos rto, std::uint64_t seed, bool canary)
      : port_(port),
        clock_(clock),
        ledger_(ledger),
        server_(server),
        id_(id),
        total_(total),
        window_(window),
        rto_(rto),
        seed_(seed),
        canary_(canary),
        acked_(total, 0),
        last_sent_(total, -1),
        digests_(total, 0) {}

  bool poll() {
    bool did = false;
    port_.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      if (d.data.size() != kMsgBytes) return;
      const auto type = static_cast<std::uint8_t>(d.data[0]);
      if (type == kHeartbeat) {
        on_heartbeat(load_le64(d.data.data() + 8), load_le64(d.data.data() + 16));
      } else if (type == kPong && static_cast<std::uint8_t>(d.data[1]) == id_) {
        on_pong(load_le64(d.data.data() + 8), load_le64(d.data.data() + 16));
      }
    });
    const Nanos now = clock_.now_mono();
    for (std::uint64_t s = base_; s < total_ && s < base_ + window_; ++s) {
      if (acked_[s] != 0) continue;
      if (last_sent_[s] >= 0 && now - last_sent_[s] < rto_) continue;
      if (last_sent_[s] >= 0) SIM_PROBE("demo.pingpong.resend");
      std::byte msg[kMsgBytes];
      put_msg(msg, kPing, id_, s, ping_digest(seed_, id_, s));
      port_.send(server_, std::span<const std::byte>(msg, kMsgBytes));
      last_sent_[s] = now;
      did = true;
    }
    return did;
  }

 private:
  void on_pong(std::uint64_t seq, std::uint64_t digest) {
    if (seq >= total_) return;
    if (seq < base_ || acked_[seq] != 0) {
      SIM_PROBE("demo.pingpong.duplicate_pong_ignored");
      // Planted canary bug: duplicates are delivered again.
      if (canary_) ledger_.deliver(id_, seq, digest);
      return;
    }
    acked_[seq] = 1;
    digests_[seq] = digest;
    while (base_ < total_ && acked_[base_] != 0) {
      ledger_.deliver(id_, base_, digests_[base_]);
      ++base_;
    }
  }

  void on_heartbeat(std::uint64_t incarnation, std::uint64_t hb_seq) {
    if (incarnation != hb_inc_) {
      if (hb_inc_ != ~std::uint64_t{0}) SIM_PROBE("demo.pingpong.server_restart_seen");
      hb_inc_ = incarnation;
      hb_last_ = hb_seq;
      return;
    }
    if (hb_seq <= hb_last_) {
      SIM_PROBE("demo.pingpong.heartbeat_reordered");
      return;
    }
    hb_last_ = hb_seq;
  }

  Port& port_;
  Clock& clock_;
  Ledger& ledger_;
  env::Endpoint server_;
  std::uint8_t id_;
  std::uint64_t total_;
  std::uint64_t window_;
  Nanos rto_;
  std::uint64_t seed_;
  bool canary_;
  std::uint64_t base_ = 0;
  std::vector<std::uint8_t> acked_;
  std::vector<Nanos> last_sent_;
  std::vector<std::uint64_t> digests_;
  std::uint64_t hb_inc_ = ~std::uint64_t{0};
  std::uint64_t hb_last_ = 0;
};

struct ServerProcess : Process {
  explicit ServerProcess(Node& n) : port(n, kEchoPort), core(port, n.clock(), n.incarnation()) {
    n.add_stage(core, "echo");
  }
  DatagramPort port;
  EchoServer<DatagramPort, Clock> core;
};

struct ClientProcess : Process {
  ClientProcess(Node& n, Ledger& l, env::Endpoint server, std::uint8_t id, std::uint64_t total, std::uint64_t window,
                Nanos rto, std::uint64_t seed, bool canary)
      : port(n, kClientPort), core(port, n.clock(), l, server, id, total, window, rto, seed, canary) {
    port.join(kHeartbeatGroup);
    n.add_stage(core, "ping");
  }
  DatagramPort port;
  PingClient<DatagramPort, Clock> core;
};

}  // namespace

Report run_pingpong(const Options& o) {
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x9196);
  const auto clients = static_cast<std::uint8_t>(2 + wl.below(3));

  auto ledger = std::make_unique<Ledger>();
  ledger->oracles = &w.oracles();
  ledger->o_once = w.oracles().activate(kOExactlyOnce);
  ledger->seed = o.seed;
  ledger->delivered.assign(clients, SeqContiguityChecker(0));
  declare_demo_probe(w, "demo.pingpong.resend");
  declare_demo_probe(w, "demo.pingpong.duplicate_pong_ignored");
  declare_demo_probe(w, "demo.pingpong.server_restart_seen");
  declare_demo_probe(w, "demo.pingpong.heartbeat_reordered");

  Node& server = w.add_node("server", NodeOptions{true, true});
  const env::Endpoint server_ep{server.ip(), kEchoPort};
  server.set_boot([](Node& n, BootReason) { n.emplace_process<ServerProcess>(n); });
  for (std::uint8_t c = 0; c < clients; ++c) {
    const std::uint64_t total = 50 + wl.below(251);
    const std::uint64_t window = 1 + wl.below(8);
    const Nanos rto = 2 * kMs + static_cast<Nanos>(wl.below(28 * kMs));
    ledger->totals.push_back(total);
    Node& n = w.add_node("client" + std::to_string(c), NodeOptions{false, true});
    Ledger* lp = ledger.get();
    const bool canary = o.canary;
    const std::uint64_t seed = o.seed;
    n.set_boot([=](Node& nd, BootReason) {
      nd.emplace_process<ClientProcess>(nd, *lp, server_ep, c, total, window, rto, seed, canary);
    });
  }
  for (NodeId i = 0; i < w.node_count(); ++i) w.node(i).boot();

  Ledger* lp = ledger.get();
  return finish(
      w, WorldKind::PingPong, o, [lp] { return lp->done(); },
      [lp] {
        std::uint64_t got = 0;
        std::uint64_t want = 0;
        for (std::size_t i = 0; i < lp->totals.size(); ++i) {
          got += lp->delivered[i].next();
          want += lp->totals[i];
        }
        return "clients=" + std::to_string(lp->totals.size()) + " delivered=" + std::to_string(got) + "/" +
               std::to_string(want);
      });
}

}  // namespace lle::sim::worlds::detail
