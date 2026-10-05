#pragma once
// The production stages' network environment on the simulated network (09 §2):
// a net::Stack<K>-shaped SimNetStack whose StreamPort and DatagramPort adapt
// sim::StreamPort / sim::DatagramPort to the backends' interface (net/common/port.h,
// net/common/stack.h) that Gateway<Env>, MdStage<Env> and GlimpseServer<Env> use.
//
// Binding: the stages default-construct their stack and ports as members, so the
// adapters bind to the node whose process image is being built (NodeBinding, a
// scope the process constructor opens; the simulator is single-threaded).
//
// Connection ids follow the backends' table convention (net/common/conn_table.h):
// make_conn_id(slot, gen) with slot < TcpConfig::max_conns (slot 0 is the
// listener's, as in the backends' shared table), so the gateway's slot arithmetic
// sees what it sees in production. A connection beyond the table is refused at
// accept (the peer sees a reset), as the backends do when the table is full.
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "common/assert.h"
#include "env/concepts.h"
#include "net/common/conn_table.h"
#include "net/common/error.h"
#include "net/common/port.h"
#include "sim/network.h"
#include "sim/node.h"

namespace lle::sim::exch {

// Ephemeral datagram ports of one process image, in a fixed order (the image owns it).
class EphemeralPorts {
 public:
  [[nodiscard]] std::uint16_t next() noexcept { return next_++; }

 private:
  std::uint16_t next_ = 50000;
};

// The node whose process image is being constructed, and that image's ephemeral ports.
class NodeBinding {
 public:
  NodeBinding(Node& n, EphemeralPorts& e) noexcept : prev_(cur_), prev_eph_(eph_) {
    cur_ = &n;
    eph_ = &e;
  }
  ~NodeBinding() {
    cur_ = prev_;
    eph_ = prev_eph_;
  }
  NodeBinding(const NodeBinding&) = delete;
  NodeBinding& operator=(const NodeBinding&) = delete;
  [[nodiscard]] static Node& current() noexcept {
    LLE_ASSERT(cur_ != nullptr, "sim exchange: stage built outside a NodeBinding scope");
    return *cur_;
  }
  [[nodiscard]] static EphemeralPorts& ephemeral() noexcept {
    LLE_ASSERT(eph_ != nullptr, "sim exchange: stage built outside a NodeBinding scope");
    return *eph_;
  }

 private:
  Node* prev_;
  EphemeralPorts* prev_eph_;
  static inline Node* cur_ = nullptr;
  static inline EphemeralPorts* eph_ = nullptr;
};

class SimUdpPort {
 public:
  SimUdpPort() : node_(&NodeBinding::current()), eph_(&NodeBinding::ephemeral()) {}
  SimUdpPort(const SimUdpPort&) = delete;
  SimUdpPort& operator=(const SimUdpPort&) = delete;

  net::Result<void> open(const net::UdpConfig& cfg) {
    std::uint16_t p = cfg.bind.port;
    if (p == 0) p = eph_->next();
    port_.emplace(*node_, p);
    for (const std::uint32_t g : cfg.groups) port_->join(env::Endpoint{g, cfg.bind.port});
    return {};
  }
  bool send(env::Endpoint dst, std::span<const std::byte> b) { return port_.has_value() && port_->send(dst, b); }
  template <class F>
  std::size_t poll_rx(F&& cb) {
    return port_ ? port_->poll_rx(cb) : 0;
  }
  [[nodiscard]] env::Endpoint local() const noexcept { return port_ ? port_->local() : env::Endpoint{}; }

 private:
  Node* node_;
  EphemeralPorts* eph_;
  std::optional<DatagramPort> port_;
};

class SimTcpPort {
 public:
  SimTcpPort() : node_(&NodeBinding::current()) {}
  SimTcpPort(const SimTcpPort&) = delete;
  SimTcpPort& operator=(const SimTcpPort&) = delete;

  net::Result<void> open(const net::TcpConfig& cfg) {
    if (cfg.max_conns < 2) return net::fail("open", EINVAL);
    cfg_ = cfg;
    port_.emplace(*node_);
    slots_.assign(cfg.max_conns, Slot{});
    return {};
  }
  net::Result<env::Endpoint> listen(env::Endpoint local) {
    if (!port_) return net::fail("listen", EBADF);
    const auto r = port_->listen(local);
    if (!r) return net::fail("bind", EADDRINUSE);
    return *r;
  }
  // Outbound connections share the table (net::StreamEndpointLike); refusal and
  // timeouts arrive as Closed.
  net::Result<env::ConnId> connect(env::Endpoint remote) {
    if (!port_) return net::fail("connect", EBADF);
    const std::uint32_t slot = free_slot();
    if (slot == 0) return net::fail("connect", EMFILE);
    const auto c = port_->connect(remote);
    if (!c) return net::fail("connect", ECONNREFUSED);
    Slot& s = slots_[slot];
    s.used = true;
    s.sim = *c;
    ++s.gen;
    by_sim_[*c] = slot;
    return net::make_conn_id(slot, s.gen);
  }
  std::size_t write(env::ConnId c, std::span<const std::byte> b) {
    const Slot* s = find(c);
    return s == nullptr ? 0 : port_->write(s->sim, b);
  }
  void close(env::ConnId c) {
    Slot* s = find(c);
    if (s == nullptr) return;
    port_->close(s->sim);
    release(*s);
  }
  template <class F>
  std::size_t poll(F&& cb) {
    if (!port_) return 0;
    return port_->poll([&](const env::StreamEvent& ev) {
      switch (ev.kind) {
        case env::StreamEventKind::Accepted: {
          const std::uint32_t slot = free_slot();
          if (slot == 0) {  // the table is full: refused
            port_->close(ev.conn);
            ++refused_;
            return;
          }
          Slot& s = slots_[slot];
          s.used = true;
          s.sim = ev.conn;
          ++s.gen;
          by_sim_[ev.conn] = slot;
          cb(env::StreamEvent{ev.kind, net::make_conn_id(slot, s.gen), {}, ev.hw_rx_ns});
          return;
        }
        case env::StreamEventKind::Connected: {
          const auto it = by_sim_.find(ev.conn);
          if (it == by_sim_.end()) return;
          cb(env::StreamEvent{ev.kind, id_of(it->second), {}, ev.hw_rx_ns});
          return;
        }
        case env::StreamEventKind::Data: {
          const auto it = by_sim_.find(ev.conn);
          if (it == by_sim_.end()) return;
          cb(env::StreamEvent{ev.kind, id_of(it->second), ev.data, ev.hw_rx_ns});
          return;
        }
        case env::StreamEventKind::Closed: {
          const auto it = by_sim_.find(ev.conn);
          if (it == by_sim_.end()) return;
          const std::uint32_t slot = it->second;
          const env::ConnId id = id_of(slot);
          release(slots_[slot]);  // the port releases it, as the backends do before the callback
          cb(env::StreamEvent{ev.kind, id, {}, ev.hw_rx_ns});
          return;
        }
      }
    });
  }

  [[nodiscard]] std::uint64_t refused() const noexcept { return refused_; }
  [[nodiscard]] std::size_t open_connections() const noexcept { return by_sim_.size(); }

 private:
  struct Slot {
    bool used = false;
    std::uint16_t gen = 0;
    env::ConnId sim = env::kNoConn;
  };
  [[nodiscard]] env::ConnId id_of(std::uint32_t slot) const noexcept {
    return net::make_conn_id(slot, slots_[slot].gen);
  }
  [[nodiscard]] std::uint32_t free_slot() const noexcept {
    for (std::uint32_t i = 1; i < slots_.size(); ++i)
      if (!slots_[i].used) return i;
    return 0;
  }
  Slot* find(env::ConnId c) noexcept {
    const std::uint32_t slot = net::conn_slot(c);
    if (slot == 0 || slot >= slots_.size()) return nullptr;
    Slot& s = slots_[slot];
    return s.used && net::make_conn_id(slot, s.gen) == c ? &s : nullptr;
  }
  void release(Slot& s) {
    by_sim_.erase(s.sim);
    s.used = false;
    s.sim = env::kNoConn;
  }

  Node* node_;
  net::TcpConfig cfg_{};
  std::optional<StreamPort> port_;
  std::vector<Slot> slots_;
  std::map<env::ConnId, std::uint32_t> by_sim_;
  std::uint64_t refused_ = 0;
};

// net::Stack<K>'s interface (net/common/stack.h) on the simulated network.
class SimNetStack {
 public:
  using DatagramPort = SimUdpPort;
  using StreamPort = SimTcpPort;

  SimNetStack() noexcept = default;
  net::Result<void> open() { return {}; }
  net::Result<void> open(DatagramPort& p, net::UdpConfig cfg) { return p.open(cfg); }
  net::Result<void> open(StreamPort& p, net::TcpConfig cfg) { return p.open(cfg); }
  // The scheduler's polls are the waits (sim/scheduler.h): never blocks.
  int wait(Nanos) noexcept { return 0; }
};

static_assert(env::DatagramPortLike<SimUdpPort>);
static_assert(env::StreamEndpointLike<SimTcpPort>);

}  // namespace lle::sim::exch
