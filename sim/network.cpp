#include "sim/network.h"

#include <algorithm>
#include <bit>
#include <cstring>

#include "common/assert.h"
#include "common/hash.h"
#include "sim/dist.h"
#include "sim/node.h"
#include "sim/scheduler.h"
#include "sim/world.h"

namespace lle::sim {

namespace {

constexpr std::uint16_t kDgUnicast = 1;
constexpr std::uint16_t kDgMulticast = 2;
constexpr std::uint16_t kSyn = 3;
constexpr std::uint16_t kSynAck = 4;
constexpr std::uint16_t kSynRetry = 5;
constexpr std::uint16_t kStTx = 6;
constexpr std::uint16_t kStData = 7;
constexpr std::uint16_t kStFin = 8;
constexpr std::uint16_t kStReset = 9;
constexpr std::uint16_t kPartTimeout = 10;
constexpr std::uint16_t kPartEnd = 11;

constexpr Nanos kLoopbackNs = 1'000;
constexpr Nanos kSynRetryNs = 200'000'000;
constexpr Nanos kRetransmitNs = 10'000'000;

struct Unpacked {
  std::uint32_t slot;
  std::uint32_t side;
  std::uint32_t epoch;
};
Unpacked unpack(std::uint64_t a) noexcept {
  return {static_cast<std::uint32_t>(a & 0x7FFF'FFFFu), static_cast<std::uint32_t>((a >> 31) & 1u),
          static_cast<std::uint32_t>(a >> 32)};
}

std::uint32_t clamp_ppm(std::int64_t v) noexcept {
  if (v < 0) return 0;
  return v > 1'000'000 ? 1'000'000u : static_cast<std::uint32_t>(v);
}

}  // namespace

Network::Network(World& w) : w_(w) {
  handler_ = w.register_handler(this, &Network::on_event, "net");
  const FaultConfig& f = w.faults();
  seg_ppm_ = clamp_ppm(f[Param::NetStreamSegPpm]);
  stall_ppm_ = clamp_ppm(f[Param::NetStreamStallPpm]);
  stall_max_ns_ = f[Param::NetStreamStallMaxNs];
  reset_timeout_ns_ = std::max<Nanos>(f[Param::NetResetTimeoutNs], kMs);
}

Network::~Network() = default;

void Network::ensure_nodes(std::size_t n) {
  if (n > cap_) {
    const std::size_t ncap = std::max<std::size_t>(16, std::bit_ceil(n));
    std::vector<Link> nl(ncap * ncap);
    for (std::size_t s = 0; s < cap_; ++s) {
      for (std::size_t d = 0; d < cap_; ++d) nl[s * ncap + d] = links_[s * cap_ + d];
    }
    links_.swap(nl);
    cap_ = ncap;
  }
  nodes_ = std::max(nodes_, n);
}

NodeId Network::node_of_ip(std::uint32_t ip) const {
  if (ip < node_ip(0)) return kNoNode;
  const std::uint32_t id = ip - node_ip(0);
  return id < nodes_ ? id : kNoNode;
}

void Network::wake_peer(NodeId n) { w_.scheduler().wake(n); }

// ---------------------------------------------------------------------------
// Links and partitions

Network::Link& Network::link(NodeId src, NodeId dst) {
  LLE_ASSERT(src < nodes_ && dst < nodes_, "link endpoint out of range");
  Link& l = links_[static_cast<std::size_t>(src) * cap_ + dst];
  if (!l.init) init_link(l, src, dst);
  return l;
}

void Network::init_link(Link& l, NodeId src, NodeId dst) {
  // Each directed link has its own stream: traffic on one link never shifts
  // the draws of another.
  l.rng = w_.stream(Stream::Network, (static_cast<std::uint64_t>(src) << 20) | dst);
  const FaultConfig& f = w_.faults();
  const std::int64_t lat_pct = uniform(l.rng, 50, 150);
  const std::int64_t mean_pct = uniform(l.rng, 50, 150);
  const std::int64_t loss_pct = uniform(l.rng, 25, 175);
  const std::int64_t dup_pct = uniform(l.rng, 25, 175);
  const std::int64_t reo_pct = uniform(l.rng, 25, 175);
  l.p.delay_min = scale_pct(f[Param::NetDelayMinNs], lat_pct);
  l.p.delay_mean = scale_pct(f[Param::NetDelayMeanNs], mean_pct);
  l.p.loss_ppm = clamp_ppm(scale_pct(f[Param::NetLossPpm], loss_pct));
  l.p.dup_ppm = clamp_ppm(scale_pct(f[Param::NetDupPpm], dup_pct));
  l.p.reorder_ppm = clamp_ppm(scale_pct(f[Param::NetReorderPpm], reo_pct));
  l.p.spike_ppm = clamp_ppm(f[Param::NetSpikePpm]);
  l.p.spike_ns = f[Param::NetSpikeNs];
  l.init = true;
}

LinkParams& Network::link_params(NodeId src, NodeId dst) { return link(src, dst).p; }

std::uint64_t Network::link_reorders(NodeId src, NodeId dst) const {
  return links_[static_cast<std::size_t>(src) * cap_ + dst].reorders;
}

Nanos Network::draw_delay(Link& l, bool allow_faults, bool* spiked, bool* reordered) {
  Nanos d = l.p.delay_min + exp_ns(l.rng, l.p.delay_mean);
  const bool spike = chance_ppm(l.rng, l.p.spike_ppm);
  const bool reorder = chance_ppm(l.rng, l.p.reorder_ppm);
  const Nanos extra = exp_ns(l.rng, 4 * std::max<Nanos>(l.p.delay_mean, 10 * kUs));
  if (allow_faults) {
    if (spike) {
      d += l.p.spike_ns;
      ++w_.stats().net_spike;
      if (spiked != nullptr) *spiked = true;
    }
    if (reorder) {
      d += extra;
      if (reordered != nullptr) *reordered = true;
    }
  }
  return d < 1 ? 1 : d;
}

void Network::on_link_blocked(NodeId src, NodeId dst, Link& l) {
  ++l.block_epoch;
  w_.schedule(w_.now() + reset_timeout_ns_, handler_, kPartTimeout, src,
              (static_cast<std::uint64_t>(src) << 32) | dst, l.block_epoch);
}

void Network::block(NodeId src, NodeId dst) {
  Link& l = link(src, dst);
  if (l.blocked++ == 0) on_link_blocked(src, dst, l);
}

void Network::unblock(NodeId src, NodeId dst) {
  Link& l = link(src, dst);
  if (l.blocked > 0) --l.blocked;
}

bool Network::blocked(NodeId src, NodeId dst) const {
  return links_[static_cast<std::size_t>(src) * cap_ + dst].blocked > 0;
}

void Network::partition(std::uint64_t a, std::uint64_t b, bool symmetric, Nanos dur) {
  const auto idx = static_cast<std::uint64_t>(partitions_.size());
  partitions_.push_back(ActivePartition{a, b, symmetric, true});
  ++w_.stats().partitions;
  const std::size_t n = std::min<std::size_t>(nodes_, 64);
  for (NodeId s = 0; s < n; ++s) {
    if (((a >> s) & 1u) == 0) continue;
    for (NodeId d = 0; d < n; ++d) {
      if (((b >> d) & 1u) == 0 || s == d) continue;
      block(s, d);
      if (symmetric) block(d, s);
    }
  }
  w_.schedule(w_.now() + std::max<Nanos>(dur, 1), handler_, kPartEnd, kNoNode, idx, 0, (a * 31) ^ b);
}

void Network::heal_all() {
  for (ActivePartition& p : partitions_) p.active = false;
  for (Link& l : links_) l.blocked = 0;
}

// ---------------------------------------------------------------------------
// Datagrams

std::uint32_t Network::alloc_packet(std::span<const std::byte> data) {
  std::uint32_t idx;
  if (!free_packets_.empty()) {
    idx = free_packets_.back();
    free_packets_.pop_back();
  } else {
    idx = static_cast<std::uint32_t>(packets_.size());
    packets_.emplace_back();
  }
  Packet& p = packets_[idx];
  if (p.data.size() < data.size()) p.data.resize(data.size());
  if (!data.empty()) std::memcpy(p.data.data(), data.data(), data.size());
  p.len = data.size();
  return idx;
}

void Network::free_packet(std::uint32_t idx) { free_packets_.push_back(idx); }

std::uint32_t Network::dg_bind(DatagramPort* owner, NodeId node, env::Endpoint local) {
  const std::uint64_t key = endpoint_key(local);
  LLE_ASSERT(dg_bind_.find(key) == dg_bind_.end(), "datagram endpoint already bound");
  std::uint32_t id;
  if (!free_dg_ports_.empty()) {
    id = free_dg_ports_.back();
    free_dg_ports_.pop_back();
  } else {
    id = static_cast<std::uint32_t>(dg_ports_.size());
    dg_ports_.emplace_back();
  }
  DgPort& p = dg_ports_[id];
  p.owner = owner;
  p.node = node;
  p.local = local;
  ++p.gen;
  p.used = true;
  p.rx.clear();
  p.groups.clear();
  dg_bind_.emplace(key, id);
  return id;
}

void Network::dg_unbind(std::uint32_t id) {
  DgPort& p = dg_ports_[id];
  if (!p.used) return;
  const auto it = dg_bind_.find(endpoint_key(p.local));
  if (it != dg_bind_.end() && it->second == id) dg_bind_.erase(it);
  while (!p.groups.empty()) dg_leave(id, p.groups.back());
  while (!p.rx.empty()) {
    free_packet(p.rx.front());
    p.rx.pop();
  }
  p.used = false;
  p.owner = nullptr;
  ++p.gen;
  free_dg_ports_.push_back(id);
}

void Network::dg_join(std::uint32_t id, env::Endpoint group) {
  std::vector<std::uint32_t>& subs = groups_[endpoint_key(group)];
  const auto it = std::lower_bound(subs.begin(), subs.end(), id);
  if (it != subs.end() && *it == id) return;
  subs.insert(it, id);
  dg_ports_[id].groups.push_back(group);
}

void Network::dg_leave(std::uint32_t id, env::Endpoint group) {
  const auto git = groups_.find(endpoint_key(group));
  if (git != groups_.end()) {
    std::erase(git->second, id);
    if (git->second.empty()) groups_.erase(git);
  }
  std::erase(dg_ports_[id].groups, group);
}

bool Network::dg_send(std::uint32_t port, env::Endpoint dst, std::span<const std::byte> data) {
  if (data.size() > kMaxDatagram) return false;
  if (!dg_ports_[port].used) return false;
  ++w_.stats().net_sent;
  if (dg_tap_) dg_tap_(dg_ports_[port].node, dst, data);
  if (is_multicast(dst)) {
    const auto it = groups_.find(endpoint_key(dst));
    if (it == groups_.end()) return true;
    for (const std::uint32_t sub : it->second) {
      const DgPort& sp = dg_ports_[sub];
      dg_deliver_one(port, sp.node, static_cast<std::uint64_t>(sub) | (static_cast<std::uint64_t>(sp.gen) << 32),
                     /*multicast=*/true, dst, data);
    }
    return true;
  }
  const NodeId dn = node_of_ip(dst.ipv4);
  if (dn == kNoNode) return true;  // no route: silently dropped, as UDP
  dg_deliver_one(port, dn, endpoint_key(dst), /*multicast=*/false, dst, data);
  return true;
}

void Network::dg_deliver_one(std::uint32_t src_port, NodeId dst_node, std::uint64_t target, bool multicast,
                             env::Endpoint dst, std::span<const std::byte> data) {
  const NodeId sn = dg_ports_[src_port].node;
  const env::Endpoint src_ep = dg_ports_[src_port].local;
  const bool loopback = sn == dst_node;
  Link& l = link(sn, dst_node);
  const bool faults = w_.faults_active() && !loopback;
  // Drawn unconditionally so the link stream stays aligned.
  const bool lose = chance_ppm(l.rng, l.p.loss_ppm);
  const bool dup = chance_ppm(l.rng, l.p.dup_ppm);
  if (!loopback && l.blocked > 0) {
    ++w_.stats().net_partition_drop;
    return;
  }
  if (faults && lose) {
    ++w_.stats().net_loss;
    return;
  }
  const int copies = faults && dup ? 2 : 1;
  if (copies == 2) ++w_.stats().net_dup;
  const std::uint64_t seq = ++l.sent_seq;
  Fnv1a64 h;
  h.bytes(data);
  h.u(endpoint_key(src_ep));
  h.u(endpoint_key(dst));
  for (int c = 0; c < copies; ++c) {
    bool reordered = false;
    const Nanos d = loopback ? kLoopbackNs : draw_delay(l, faults, nullptr, &reordered);
    Nanos at = w_.now() + d;
    if (fifo_dg_ && !loopback && !reordered) {
      at = std::max(at, l.fifo_last);
      l.fifo_last = at;
    }
    const std::uint32_t idx = alloc_packet(data);
    Packet& p = packets_[idx];
    p.src = src_ep;
    p.dst = dst;
    p.src_node = sn;
    p.link_seq = seq;
    p.era = dg_era_;
    w_.schedule(at, handler_, multicast ? kDgMulticast : kDgUnicast, dst_node, idx, target, h.value());
  }
}

Dispatch Network::on_dg_arrival(const Event& ev, bool multicast) {
  const auto idx = static_cast<std::uint32_t>(ev.a);
  const Packet& p = packets_[idx];
  std::uint32_t port = 0;
  bool ok = false;
  if (multicast) {
    port = static_cast<std::uint32_t>(ev.b & 0xFFFF'FFFFu);
    const auto gen = static_cast<std::uint32_t>(ev.b >> 32);
    ok = port < dg_ports_.size() && dg_ports_[port].used && dg_ports_[port].gen == gen;
  } else {
    const auto it = dg_bind_.find(ev.b);
    if (it != dg_bind_.end()) {
      port = it->second;
      ok = true;
    }
  }
  if (ok && dg_ports_[port].node != ev.node) ok = false;
  if (ok && p.era != dg_era_) ok = false;  // sent before drop_datagrams_in_flight()
  if (ok && p.src_node != ev.node) {
    Link& l = link(p.src_node, ev.node);
    if (l.blocked > 0) {
      // Cut while in flight.
      ++w_.stats().net_partition_drop;
      ok = false;
    } else if (p.link_seq < l.max_delivered) {
      ++l.reorders;
      ++w_.stats().net_reorder;
    } else {
      l.max_delivered = p.link_seq;
    }
  }
  if (ok && dg_ports_[port].rx.size() >= kRxQueueDatagrams) {
    ++w_.stats().net_rx_overflow;
    ok = false;
  }
  if (!ok) {
    free_packet(idx);
    return {true, 0};
  }
  dg_ports_[port].rx.push(idx);
  ++w_.stats().net_delivered;
  w_.scheduler().wake(ev.node);
  return {true, 1};
}

// ---------------------------------------------------------------------------
// Streams

std::uint32_t Network::st_open(StreamPort* owner, NodeId node) {
  std::uint32_t id;
  if (!free_st_ports_.empty()) {
    id = free_st_ports_.back();
    free_st_ports_.pop_back();
  } else {
    id = static_cast<std::uint32_t>(st_ports_.size());
    st_ports_.emplace_back();
  }
  StPort& p = st_ports_[id];
  p.owner = owner;
  p.node = node;
  ++p.gen;
  p.used = true;
  p.notifs.clear();
  p.listening.clear();
  return id;
}

std::optional<env::Endpoint> Network::st_listen(std::uint32_t port, env::Endpoint local) {
  StPort& sp = st_ports_[port];
  const std::uint32_t ip = node_ip(sp.node);
  if (local.ipv4 != 0 && local.ipv4 != ip) return std::nullopt;
  std::uint16_t p = local.port;
  if (p == 0) {
    // Ephemeral: first free port from the ephemeral range, in a fixed order.
    for (std::uint32_t tries = 0; tries < 0x10000 && p == 0; ++tries) {
      const std::uint16_t cand = next_ephemeral_;
      next_ephemeral_ = next_ephemeral_ == 0xFFFF ? 40000 : static_cast<std::uint16_t>(next_ephemeral_ + 1);
      if (listeners_.find(endpoint_key(env::Endpoint{ip, cand})) == listeners_.end()) p = cand;
    }
    if (p == 0) return std::nullopt;
  }
  const env::Endpoint bound{ip, p};
  if (listeners_.find(endpoint_key(bound)) != listeners_.end()) return std::nullopt;
  listeners_.emplace(endpoint_key(bound), port);
  sp.listening.push_back(p);
  return bound;
}

std::uint32_t Network::alloc_conn() {
  std::uint32_t slot;
  if (!free_conns_.empty()) {
    slot = free_conns_.back();
    free_conns_.pop_back();
  } else {
    slot = static_cast<std::uint32_t>(conns_.size());
    LLE_ASSERT(slot < (1u << 19), "too many simulated connections");
    conns_.emplace_back();
  }
  Conn& c = conns_[slot];
  for (Dir& d : c.dir) {
    if (d.ring.size() != ring_bytes_) d.ring.assign(ring_bytes_, std::byte{0});
    d.written = d.sent = d.delivered = d.read = 0;
    d.last_arrival = 0;
    d.stall_until = 0;
    d.tx_pending = d.fin = d.fin_sent = false;
  }
  c.node[0] = c.node[1] = kNoNode;
  c.released[0] = c.released[1] = true;
  c.data_notified[0] = c.data_notified[1] = false;
  c.client_connected = false;
  return slot;
}

void Network::try_free_conn(std::uint32_t slot) {
  Conn& c = conns_[slot];
  if (c.state == ConnState::Free || !c.released[0] || !c.released[1]) return;
  c.state = ConnState::Free;
  ++c.gen;
  ++c.epoch;
  free_conns_.push_back(slot);
}

bool Network::resolve(std::uint32_t port, env::ConnId id, std::uint32_t& slot, std::uint32_t& side) const {
  if (id == env::kNoConn) return false;
  slot = (id >> 1) & 0x7FFFFu;
  side = id & 1u;
  const std::uint32_t gen = id >> 20;
  if (slot >= conns_.size()) return false;
  const Conn& c = conns_[slot];
  return c.state != ConnState::Free && (c.gen & 0xFFFu) == gen && c.port[side] == port && !c.released[side] &&
         c.port_gen[side] == st_ports_[port].gen;
}

void Network::notify(std::uint32_t slot, std::uint32_t side, env::StreamEventKind kind) {
  Conn& c = conns_[slot];
  StPort& sp = st_ports_[c.port[side]];
  if (!sp.used || sp.gen != c.port_gen[side]) return;
  sp.notifs.push(Notif{kind, conn_id(slot, side, c.gen)});
  w_.scheduler().wake(c.node[side]);
}

std::optional<env::ConnId> Network::st_connect(std::uint32_t port, env::Endpoint remote) {
  const StPort& sp = st_ports_[port];
  const std::uint32_t slot = alloc_conn();
  Conn& c = conns_[slot];
  c.state = ConnState::SynSent;
  ++c.epoch;
  c.node[0] = sp.node;
  c.port[0] = port;
  c.port_gen[0] = sp.gen;
  c.released[0] = false;
  c.ep[0] = env::Endpoint{node_ip(sp.node), next_ephemeral_};
  next_ephemeral_ = next_ephemeral_ == 0xFFFF ? 40000 : static_cast<std::uint16_t>(next_ephemeral_ + 1);
  c.ep[1] = remote;
  c.syn_deadline = w_.now() + kConnectTimeoutNs;
  send_syn(slot);
  return conn_id(slot, 0, c.gen);
}

void Network::send_syn(std::uint32_t slot) {
  Conn& c = conns_[slot];
  const NodeId dn = node_of_ip(c.ep[1].ipv4);
  if (dn == kNoNode) {
    ++w_.stats().stream_refused;
    reset_conn(slot, kLoopbackNs, 0);
    return;
  }
  Link& l = link(c.node[0], dn);
  const Link& r = link(dn, c.node[0]);
  const bool lose = chance_ppm(l.rng, l.p.loss_ppm);
  if (l.blocked > 0 || r.blocked > 0 || (lose && w_.faults_active() && c.node[0] != dn)) {
    // SYN or SYN-ACK lost: retransmit.
    w_.schedule(w_.now() + kSynRetryNs, handler_, kSynRetry, c.node[0], pack(slot, 0, c.epoch));
    return;
  }
  const Nanos d = c.node[0] == dn ? kLoopbackNs : draw_delay(l, w_.faults_active(), nullptr);
  w_.schedule(w_.now() + d, handler_, kSyn, dn, pack(slot, 0, c.epoch));
}

void Network::reset_conn(std::uint32_t slot, Nanos delay0, Nanos delay1) {
  Conn& c = conns_[slot];
  ++c.epoch;
  c.state = ConnState::Reset;
  c.dir[0].tx_pending = c.dir[1].tx_pending = false;
  const Nanos delays[2] = {delay0, delay1};
  for (std::uint32_t s = 0; s < 2; ++s) {
    if (c.released[s] || c.node[s] == kNoNode) continue;
    w_.schedule(w_.now() + std::max<Nanos>(delays[s], 0), handler_, kStReset, c.node[s], pack(slot, s, c.epoch));
  }
  try_free_conn(slot);
}

void Network::st_abort(std::uint32_t port) {
  StPort& sp = st_ports_[port];
  if (!sp.used) return;
  for (const std::uint16_t lp : sp.listening) {
    const auto it = listeners_.find(endpoint_key(env::Endpoint{node_ip(sp.node), lp}));
    if (it != listeners_.end() && it->second == port) listeners_.erase(it);
  }
  for (std::uint32_t slot = 0; slot < conns_.size(); ++slot) {
    Conn& c = conns_[slot];
    if (c.state == ConnState::Free) continue;
    for (std::uint32_t side = 0; side < 2; ++side) {
      if (c.released[side] || c.port[side] != port || c.port_gen[side] != sp.gen) continue;
      c.released[side] = true;
      c.data_notified[side] = false;
      const std::uint32_t peer = side ^ 1u;
      Nanos delay[2] = {0, 0};
      if (!c.released[peer] && c.node[peer] != kNoNode) {
        // The peer learns through an RST after one-way latency, or when its
        // own timeout fires if the path is cut.
        Link& l = link(c.node[side], c.node[peer]);
        delay[peer] = l.blocked > 0 ? reset_timeout_ns_ : draw_delay(l, false, nullptr);
      }
      if (c.state == ConnState::Reset) {
        try_free_conn(slot);
      } else {
        ++w_.stats().stream_resets;
        reset_conn(slot, delay[0], delay[1]);
      }
      break;
    }
  }
  sp.used = false;
  sp.owner = nullptr;
  ++sp.gen;
  sp.notifs.clear();
  sp.listening.clear();
  free_st_ports_.push_back(port);
}

std::size_t Network::st_write(std::uint32_t port, env::ConnId id, std::span<const std::byte> b) {
  std::uint32_t slot = 0;
  std::uint32_t side = 0;
  if (!resolve(port, id, slot, side)) return 0;
  Conn& c = conns_[slot];
  if (c.state != ConnState::Established || (side == 0 && !c.client_connected)) return 0;
  Dir& d = c.dir[side];
  if (d.fin) return 0;
  const std::size_t cap = d.ring.size();
  const auto used = static_cast<std::size_t>(d.written - d.read);
  const std::size_t n = std::min(cap - used, b.size());
  if (n == 0) return 0;
  const auto at = static_cast<std::size_t>(d.written % cap);
  const std::size_t first = std::min(n, cap - at);
  std::memcpy(d.ring.data() + at, b.data(), first);
  if (n > first) std::memcpy(d.ring.data(), b.data() + first, n - first);
  d.written += n;
  if (!d.tx_pending) {
    d.tx_pending = true;
    schedule_tx(slot, side, w_.now());
  }
  return n;
}

void Network::schedule_tx(std::uint32_t slot, std::uint32_t side, Nanos at) {
  const Conn& c = conns_[slot];
  w_.schedule(at, handler_, kStTx, c.node[side], pack(slot, side, c.epoch));
}

void Network::st_close(std::uint32_t port, env::ConnId id) {
  std::uint32_t slot = 0;
  std::uint32_t side = 0;
  if (!resolve(port, id, slot, side)) return;
  Conn& c = conns_[slot];
  c.released[side] = true;
  c.data_notified[side] = false;
  if (c.state == ConnState::Established) {
    Dir& d = c.dir[side];
    d.fin = true;  // FIN follows the remaining data
    if (!d.tx_pending) {
      d.tx_pending = true;
      schedule_tx(slot, side, w_.now());
    }
  } else if (c.state == ConnState::SynSent) {
    ++c.epoch;
    c.state = ConnState::Reset;
  }
  try_free_conn(slot);
}

std::size_t Network::st_connections() const {
  std::size_t n = 0;
  for (const Conn& c : conns_) n += c.state != ConnState::Free ? 1u : 0u;
  return n;
}

Dispatch Network::on_stream_event(const Event& ev) {
  const Unpacked u = unpack(ev.a);
  if (ev.kind == kPartTimeout) {
    const auto src = static_cast<NodeId>(ev.a >> 32);
    const auto dst = static_cast<NodeId>(ev.a & 0xFFFF'FFFFu);
    const Link& l = link(src, dst);
    if (l.blocked == 0 || l.block_epoch != ev.b) return {true, 0};
    std::uint64_t n = 0;
    for (std::uint32_t slot = 0; slot < conns_.size(); ++slot) {
      Conn& c = conns_[slot];
      if (c.state != ConnState::Established) continue;
      if ((c.node[0] == src && c.node[1] == dst) || (c.node[0] == dst && c.node[1] == src)) {
        ++w_.stats().stream_resets;
        reset_conn(slot, 0, 0);
        ++n;
      }
    }
    if (n > 0) w_.probes().hit("net.stream_reset_on_partition");
    return {true, n};
  }
  if (ev.kind == kPartEnd) {
    ActivePartition& p = partitions_[ev.a];
    if (!p.active) return {true, 0};
    p.active = false;
    const std::size_t n = std::min<std::size_t>(nodes_, 64);
    for (NodeId s = 0; s < n; ++s) {
      if (((p.a >> s) & 1u) == 0) continue;
      for (NodeId d = 0; d < n; ++d) {
        if (((p.b >> d) & 1u) == 0 || s == d) continue;
        unblock(s, d);
        if (p.symmetric) unblock(d, s);
      }
    }
    return {true, 1};
  }

  if (u.slot >= conns_.size()) return {false, 0};
  Conn& c = conns_[u.slot];
  if (c.epoch != u.epoch || c.state == ConnState::Free) return {false, 0};

  switch (ev.kind) {
    case kSynRetry: {
      if (c.state != ConnState::SynSent) return {false, 0};
      if (w_.now() >= c.syn_deadline) {
        reset_conn(u.slot, 0, 0);
        return {true, 0};
      }
      send_syn(u.slot);
      return {true, 1};
    }
    case kSyn: {
      if (c.state != ConnState::SynSent) return {false, 0};
      const auto it = listeners_.find(endpoint_key(c.ep[1]));
      if (it == listeners_.end()) {
        ++w_.stats().stream_refused;
        Link& r = link(ev.node, c.node[0]);
        reset_conn(u.slot, ev.node == c.node[0] ? kLoopbackNs : draw_delay(r, false, nullptr), 0);
        return {true, 0};
      }
      const std::uint32_t lport = it->second;
      c.state = ConnState::Established;
      c.node[1] = ev.node;
      c.port[1] = lport;
      c.port_gen[1] = st_ports_[lport].gen;
      c.released[1] = false;
      Link& r = link(ev.node, c.node[0]);
      const Nanos d = ev.node == c.node[0] ? kLoopbackNs : draw_delay(r, w_.faults_active(), nullptr);
      const Nanos synack_at = w_.now() + d;
      c.dir[1].last_arrival = synack_at;  // server data never overtakes the SYN-ACK
      notify(u.slot, 1, env::StreamEventKind::Accepted);
      w_.schedule(synack_at, handler_, kSynAck, c.node[0], pack(u.slot, 0, c.epoch));
      return {true, 1};
    }
    case kSynAck: {
      if (c.state != ConnState::Established) return {false, 0};
      c.client_connected = true;
      if (!c.released[0]) notify(u.slot, 0, env::StreamEventKind::Connected);
      return {true, 1};
    }
    case kStTx: {
      if (c.state != ConnState::Established) return {false, 0};
      Dir& d = c.dir[u.side];
      const NodeId sn = c.node[u.side];
      const NodeId dn = c.node[u.side ^ 1u];
      Link& l = link(sn, dn);
      const Link& r = link(dn, sn);
      if (l.blocked > 0 || r.blocked > 0) {
        schedule_tx(u.slot, u.side, w_.now() + kRetransmitNs);  // retransmission timer
        return {true, 2};
      }
      const bool faults = w_.faults_active() && sn != dn;
      const std::uint64_t pending = d.written - d.sent;
      if (pending == 0) {
        if (d.fin && !d.fin_sent) {
          const Nanos arrival = std::max(w_.now() + (sn == dn ? kLoopbackNs : draw_delay(l, faults, nullptr)),
                                         d.last_arrival);
          d.last_arrival = arrival;
          d.fin_sent = true;
          w_.schedule(arrival, handler_, kStFin, dn, pack(u.slot, u.side, c.epoch));
        }
        d.tx_pending = false;
        return {true, 0};
      }
      // Segmentation: drawn unconditionally (two draws).
      const bool short_seg = chance_ppm(l.rng, seg_ppm_);
      const std::uint64_t rnd = l.rng.next_u64();
      std::uint64_t seg = std::min<std::uint64_t>(pending, kStreamMtu);
      if (short_seg && faults) {
        seg = 1 + rnd % seg;
        ++w_.stats().stream_short_segments;
      }
      d.sent += seg;
      ++w_.stats().stream_segments;
      Nanos arrival = w_.now() + (sn == dn ? kLoopbackNs : draw_delay(l, faults, nullptr));
      const bool stall = chance_ppm(l.rng, stall_ppm_);
      const Nanos stall_ns = log_uniform(l.rng, kMs, std::max(kMs, stall_max_ns_));
      if (stall && faults) {
        d.stall_until = std::max(d.stall_until, w_.now() + stall_ns);
        ++w_.stats().stream_stalls;
      }
      arrival = std::max({arrival, d.last_arrival, d.stall_until});
      d.last_arrival = arrival;
      w_.schedule(arrival, handler_, kStData, dn, pack(u.slot, u.side, c.epoch), d.sent, d.sent);
      // ~10 Gb/s pacing between segments.
      schedule_tx(u.slot, u.side, w_.now() + 1 + static_cast<Nanos>(seg * 4 / 5));
      return {true, seg};
    }
    case kStData: {
      if (c.state != ConnState::Established) return {false, 0};
      Dir& d = c.dir[u.side];
      d.delivered = std::max(d.delivered, ev.b);
      const std::uint32_t rcv = u.side ^ 1u;
      if (!c.released[rcv] && !c.data_notified[rcv]) {
        c.data_notified[rcv] = true;
        notify(u.slot, rcv, env::StreamEventKind::Data);
      }
      return {true, ev.b};
    }
    case kStFin: {
      const std::uint32_t rcv = u.side ^ 1u;
      if (!c.released[rcv]) notify(u.slot, rcv, env::StreamEventKind::Closed);
      return {true, 1};
    }
    case kStReset: {
      if (!c.released[u.side]) notify(u.slot, u.side, env::StreamEventKind::Closed);
      return {true, 1};
    }
    default:
      return {false, 0};
  }
}

Dispatch Network::on_event(void* ctx, const Event& ev) {
  auto* self = static_cast<Network*>(ctx);
  switch (ev.kind) {
    case kDgUnicast:
      return self->on_dg_arrival(ev, false);
    case kDgMulticast:
      return self->on_dg_arrival(ev, true);
    default:
      return self->on_stream_event(ev);
  }
}

// ---------------------------------------------------------------------------
// Ports

DatagramPort::DatagramPort(Node& node, std::uint16_t local_port)
    : net_(&node.world().net()), local_{node.ip(), local_port} {
  id_ = net_->dg_bind(this, node.id(), local_);
}

DatagramPort::~DatagramPort() { net_->dg_unbind(id_); }

StreamPort::StreamPort(Node& node) : net_(&node.world().net()) { id_ = net_->st_open(this, node.id()); }

StreamPort::~StreamPort() { net_->st_abort(id_); }

}  // namespace lle::sim
