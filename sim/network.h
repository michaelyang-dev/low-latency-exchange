#pragma once
// Simulated network (09 §3).
//
// Datagrams: per directed link, a seeded latency (min + exponential mean, rare
// 100 ms spikes, occasional extra reorder delay), loss and duplication;
// multicast fans out to subscribed ports at send time. Unicast destinations
// are resolved at arrival, so a datagram reaches whichever socket is bound to
// the address when it lands (a restarted process included).
//
// Streams (TCP-like): in-order and reliable while connected; the sender's
// bytes leave in seeded segments of 1..MTU bytes and arrival times never
// decrease, receivers see whatever has accumulated (coalescing); stalls delay
// a direction. A connection resets when a partition between its endpoints
// lasts longer than the reset timeout, or when a peer process dies. Bytes live
// in one ring per direction (sender's unsent + in flight + receiver's unread),
// so data is copied once on write and handed out by span on read.
//
// Partitions are reference-counted blocks on directed links (symmetric,
// asymmetric, flapping). Iteration is always in index order; nothing is keyed
// by pointer.
#include <algorithm>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "env/concepts.h"
#include "sim/event.h"
#include "sim/ring_queue.h"

namespace lle::sim {

class World;
class Node;
class DatagramPort;
class StreamPort;

inline constexpr std::size_t kMaxDatagram = 65'507;
inline constexpr std::size_t kStreamMtu = 1'460;
inline constexpr std::size_t kStreamRingBytes = 64 * 1024;  // per direction (socket buffers)
inline constexpr std::size_t kRxQueueDatagrams = 4'096;     // per port (SO_RCVBUF)
inline constexpr Nanos kConnectTimeoutNs = 1'000'000'000;

[[nodiscard]] constexpr bool is_multicast(env::Endpoint e) noexcept { return (e.ipv4 >> 28) == 0xE; }
[[nodiscard]] constexpr std::uint64_t endpoint_key(env::Endpoint e) noexcept {
  return (static_cast<std::uint64_t>(e.ipv4) << 16) | e.port;
}

struct LinkParams {
  Nanos delay_min = 0;
  Nanos delay_mean = 0;
  std::uint32_t loss_ppm = 0;
  std::uint32_t dup_ppm = 0;
  std::uint32_t reorder_ppm = 0;
  std::uint32_t spike_ppm = 0;
  Nanos spike_ns = 0;
};

class Network {
 public:
  explicit Network(World& w);
  ~Network();
  Network(const Network&) = delete;
  Network& operator=(const Network&) = delete;

  void ensure_nodes(std::size_t n);

  // --- partitions ---
  // Blocks every link from a node in `a` to a node in `b` (and back if
  // symmetric) for `dur`. Masks are node bitmasks (node id < 64).
  void partition(std::uint64_t a, std::uint64_t b, bool symmetric, Nanos dur);
  void block(NodeId src, NodeId dst);
  void unblock(NodeId src, NodeId dst);
  [[nodiscard]] bool blocked(NodeId src, NodeId dst) const;
  void heal_all();

  // FIFO datagram links (off by default): datagrams on a directed link arrive in
  // send order unless the reorder fault fires, as on a direct cable or a switched
  // LAN path. Same random draws either way, so other worlds' traces are unchanged.
  void set_fifo_datagrams(bool on) noexcept { fifo_dg_ = on; }

  // --- link parameters (drawn lazily per directed link from its own stream) ---
  LinkParams& link_params(NodeId src, NodeId dst);
  [[nodiscard]] std::uint64_t link_reorders(NodeId src, NodeId dst) const;

  // --- datagram plumbing (used by DatagramPort) ---
  std::uint32_t dg_bind(DatagramPort* owner, NodeId node, env::Endpoint local);
  void dg_unbind(std::uint32_t port);
  void dg_join(std::uint32_t port, env::Endpoint group);
  void dg_leave(std::uint32_t port, env::Endpoint group);
  bool dg_send(std::uint32_t port, env::Endpoint dst, std::span<const std::byte> data);
  [[nodiscard]] std::size_t dg_pending(std::uint32_t port) const { return dg_ports_[port].rx.size(); }
  template <class F>
  std::size_t dg_poll(std::uint32_t port, F&& cb);

  // --- stream plumbing (used by StreamPort) ---
  std::uint32_t st_open(StreamPort* owner, NodeId node);
  void st_abort(std::uint32_t port);  // process died: resets every connection
  // Binds a listener on the port's node; ipv4 0 means "this node", port 0
  // picks an ephemeral port. nullopt if the address is foreign or taken.
  std::optional<env::Endpoint> st_listen(std::uint32_t port, env::Endpoint local);
  std::optional<env::ConnId> st_connect(std::uint32_t port, env::Endpoint remote);
  std::size_t st_write(std::uint32_t port, env::ConnId c, std::span<const std::byte> b);
  void st_close(std::uint32_t port, env::ConnId c);
  template <class F>
  std::size_t st_poll(std::uint32_t port, F&& cb);
  [[nodiscard]] std::size_t st_connections() const;  // live connection slots

  static Dispatch on_event(void* ctx, const Event& ev);

 private:
  struct Link {
    Prng rng{0};
    LinkParams p;
    bool init = false;
    std::uint32_t blocked = 0;
    std::uint64_t block_epoch = 0;
    std::uint64_t sent_seq = 0;
    std::uint64_t max_delivered = 0;
    std::uint64_t reorders = 0;
    Nanos fifo_last = 0;  // FIFO datagram mode: latest scheduled arrival
  };
  struct Packet {
    std::vector<std::byte> data;
    std::size_t len = 0;
    env::Endpoint src;
    env::Endpoint dst;
    NodeId src_node = kNoNode;
    std::uint64_t link_seq = 0;
  };
  struct DgPort {
    DatagramPort* owner = nullptr;
    NodeId node = kNoNode;
    env::Endpoint local;
    std::uint32_t gen = 0;
    bool used = false;
    RingQueue<std::uint32_t> rx;
    std::vector<env::Endpoint> groups;
  };

  struct Notif {
    env::StreamEventKind kind;
    env::ConnId conn;
  };
  struct StPort {
    StreamPort* owner = nullptr;
    NodeId node = kNoNode;
    std::uint32_t gen = 0;
    bool used = false;
    RingQueue<Notif> notifs;
    std::vector<std::uint16_t> listening;
  };
  enum class ConnState : std::uint8_t { Free, SynSent, Established, Reset };
  struct Dir {
    std::vector<std::byte> ring;
    std::uint64_t written = 0;
    std::uint64_t sent = 0;
    std::uint64_t delivered = 0;
    std::uint64_t read = 0;
    Nanos last_arrival = 0;
    Nanos stall_until = 0;
    bool tx_pending = false;
    bool fin = false;
    bool fin_sent = false;
  };
  struct Conn {
    ConnState state = ConnState::Free;
    std::uint32_t gen = 0;
    std::uint32_t epoch = 0;
    NodeId node[2] = {kNoNode, kNoNode};
    std::uint32_t port[2] = {0, 0};
    std::uint32_t port_gen[2] = {0, 0};
    env::Endpoint ep[2];
    bool released[2] = {true, true};
    bool data_notified[2] = {false, false};
    bool client_connected = false;
    Nanos syn_deadline = 0;
    Dir dir[2];
  };

  // Datagram internals
  Link& link(NodeId src, NodeId dst);
  void init_link(Link& l, NodeId src, NodeId dst);
  Nanos draw_delay(Link& l, bool allow_faults, bool* spiked, bool* reordered = nullptr);
  std::uint32_t alloc_packet(std::span<const std::byte> data);
  void free_packet(std::uint32_t idx);
  void dg_deliver_one(std::uint32_t src_port, NodeId dst_node, std::uint64_t target, bool multicast,
                      env::Endpoint dst, std::span<const std::byte> data);
  Dispatch on_dg_arrival(const Event& ev, bool multicast);
  [[nodiscard]] NodeId node_of_ip(std::uint32_t ip) const;

  // Stream internals
  std::uint32_t alloc_conn();
  void try_free_conn(std::uint32_t slot);
  bool resolve(std::uint32_t port, env::ConnId c, std::uint32_t& slot, std::uint32_t& side) const;
  static env::ConnId conn_id(std::uint32_t slot, std::uint32_t side, std::uint32_t gen) noexcept {
    return ((gen & 0xFFFu) << 20) | (slot << 1) | side;
  }
  void notify(std::uint32_t slot, std::uint32_t side, env::StreamEventKind kind);
  void send_syn(std::uint32_t slot);
  void reset_conn(std::uint32_t slot, Nanos delay0, Nanos delay1);
  void schedule_tx(std::uint32_t slot, std::uint32_t side, Nanos at);
  Dispatch on_stream_event(const Event& ev);
  void on_link_blocked(NodeId src, NodeId dst, Link& l);
  void wake_peer(NodeId n);
  [[nodiscard]] static std::uint64_t pack(std::uint32_t slot, std::uint32_t side, std::uint32_t epoch) noexcept {
    return static_cast<std::uint64_t>(slot) | (static_cast<std::uint64_t>(side) << 31) |
           (static_cast<std::uint64_t>(epoch) << 32);
  }

  World& w_;
  HandlerId handler_;
  std::size_t nodes_ = 0;
  std::size_t cap_ = 0;
  std::vector<Link> links_;

  std::deque<Packet> packets_;
  std::vector<std::uint32_t> free_packets_;
  std::vector<DgPort> dg_ports_;
  std::vector<std::uint32_t> free_dg_ports_;
  std::map<std::uint64_t, std::uint32_t> dg_bind_;
  std::map<std::uint64_t, std::vector<std::uint32_t>> groups_;

  std::vector<StPort> st_ports_;
  std::vector<std::uint32_t> free_st_ports_;
  std::deque<Conn> conns_;  // deque: stable while callbacks open connections
  std::vector<std::uint32_t> free_conns_;
  std::map<std::uint64_t, std::uint32_t> listeners_;  // endpoint key -> stream port
  std::uint16_t next_ephemeral_ = 40000;
  std::uint32_t seg_ppm_ = 0;
  std::uint32_t stall_ppm_ = 0;
  Nanos stall_max_ns_ = 0;
  Nanos reset_timeout_ns_ = 1'000'000'000;
  bool fifo_dg_ = false;

  struct ActivePartition {
    std::uint64_t a = 0;
    std::uint64_t b = 0;
    bool symmetric = true;
    bool active = false;
  };
  std::vector<ActivePartition> partitions_;
};

// env::DatagramPortLike bound to node_ip:port. Lives in process memory.
class DatagramPort {
 public:
  DatagramPort(Node& node, std::uint16_t local_port);
  ~DatagramPort();
  DatagramPort(const DatagramPort&) = delete;
  DatagramPort& operator=(const DatagramPort&) = delete;

  bool send(env::Endpoint dst, std::span<const std::byte> b) { return net_->dg_send(id_, dst, b); }
  // Calls cb(const env::RxDatagram&) for every queued datagram.
  template <class F>
  std::size_t poll_rx(F&& cb) {
    return net_->dg_poll(id_, cb);
  }
  void join(env::Endpoint group) { net_->dg_join(id_, group); }
  void leave(env::Endpoint group) { net_->dg_leave(id_, group); }
  [[nodiscard]] env::Endpoint local() const noexcept { return local_; }

 private:
  Network* net_;
  std::uint32_t id_;
  env::Endpoint local_;
};

// env::StreamPortLike for one process. Lives in process memory; destroying it
// (crash) resets all of its connections.
class StreamPort {
 public:
  explicit StreamPort(Node& node);
  ~StreamPort();
  StreamPort(const StreamPort&) = delete;
  StreamPort& operator=(const StreamPort&) = delete;

  // env::StreamEndpointLike: optional-like results (false on failure).
  std::optional<env::Endpoint> listen(env::Endpoint local) { return net_->st_listen(id_, local); }
  // Always yields a connection id; refusal and timeouts arrive as Closed.
  std::optional<env::ConnId> connect(env::Endpoint remote) { return net_->st_connect(id_, remote); }
  std::size_t write(env::ConnId c, std::span<const std::byte> b) { return net_->st_write(id_, c, b); }
  void close(env::ConnId c) { net_->st_close(id_, c); }
  // Calls cb(const env::StreamEvent&) for Accepted / Connected / Data / Closed.
  template <class F>
  std::size_t poll(F&& cb) {
    return net_->st_poll(id_, cb);
  }

 private:
  Network* net_;
  std::uint32_t id_;
};

// ---------------------------------------------------------------------------
// Template implementations.

template <class F>
std::size_t Network::dg_poll(std::uint32_t port, F&& cb) {
  const std::size_t n = dg_ports_[port].rx.size();
  for (std::size_t i = 0; i < n; ++i) {
    DgPort& dp = dg_ports_[port];
    const std::uint32_t idx = dp.rx.front();
    dp.rx.pop();
    const Packet& p = packets_[idx];
    const env::RxDatagram rx{std::span<const std::byte>(p.data.data(), p.len), p.src, p.dst, 0};
    cb(rx);
    free_packet(idx);
  }
  return n;
}

template <class F>
std::size_t Network::st_poll(std::uint32_t port, F&& cb) {
  std::size_t delivered = 0;
  const std::size_t n = st_ports_[port].notifs.size();
  for (std::size_t i = 0; i < n; ++i) {
    StPort& sp = st_ports_[port];
    const Notif nf = sp.notifs.front();
    sp.notifs.pop();
    std::uint32_t slot = 0;
    std::uint32_t side = 0;
    if (!resolve(port, nf.conn, slot, side)) continue;
    switch (nf.kind) {
      case env::StreamEventKind::Accepted:
      case env::StreamEventKind::Connected: {
        cb(env::StreamEvent{nf.kind, nf.conn, {}, 0});
        ++delivered;
        break;
      }
      case env::StreamEventKind::Data: {
        conns_[slot].data_notified[side] = false;
        while (true) {
          Conn& c = conns_[slot];
          if (c.released[side]) break;
          Dir& d = c.dir[side ^ 1u];
          if (d.read >= d.delivered) break;
          const std::size_t cap = d.ring.size();
          const auto at = static_cast<std::size_t>(d.read % cap);
          const std::size_t len = std::min<std::size_t>(static_cast<std::size_t>(d.delivered - d.read), cap - at);
          const bool was_full = d.written - d.read == cap;
          cb(env::StreamEvent{env::StreamEventKind::Data, nf.conn, std::span<const std::byte>(d.ring.data() + at, len),
                              0});
          ++delivered;
          std::uint32_t s2 = 0;
          std::uint32_t side2 = 0;
          if (!resolve(port, nf.conn, s2, side2)) break;  // closed from inside the callback
          Conn& c2 = conns_[slot];
          c2.dir[side ^ 1u].read += len;
          if (was_full) wake_peer(c2.node[side ^ 1u]);
        }
        break;
      }
      case env::StreamEventKind::Closed: {
        Conn& c = conns_[slot];
        c.released[side] = true;
        c.data_notified[side] = false;
        cb(env::StreamEvent{env::StreamEventKind::Closed, nf.conn, {}, 0});
        ++delivered;
        try_free_conn(slot);
        break;
      }
    }
  }
  return delivered;
}

}  // namespace lle::sim
