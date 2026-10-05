#pragma once
// UtcpStreamPort: env::StreamPortLike over any FramePort (07 §2.4).
//
// It owns a fixed pool of utcp::Connection slots (allocated at construction), demuxes
// frames by 4-tuple, runs listeners (passive open), answers ARP for our address, resolves
// next hops (static next hop, neighbour table filled from netlink or by in-band ARP),
// sends gratuitous ARP, answers stray segments with RST (RFC 9293 §3.10.7.1), drives
// timers from the injected clock, and turns connection events into env::StreamEvents.
//
// Stream semantics (matching kernel sockets as used by the gateway):
//   - Accepted: a passive connection reached ESTABLISHED; Connected: an active one did.
//   - Data: in-order bytes; the span is valid only during the callback.
//   - Closed: the peer closed (after all data was delivered; our side then closes
//     automatically) or the connection was reset / timed out / could not resolve its
//     next hop. Not raised after the application itself calls close() or abort().
//   - write() before Connected returns 0 while the next hop is being resolved.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include "common/hash.h"
#include "env/buggify.h"
#include "env/concepts.h"
#include "net/utcp/arp.h"
#include "net/utcp/connection.h"
#include "net/utcp/frame_port.h"
#include "net/utcp/wire.h"

namespace lle::net::utcp {

struct StackConfig {
  MacAddr local_mac;
  std::uint32_t local_ip = 0;              // host order
  std::uint32_t netmask = 0xFFFF'FF00u;
  std::uint32_t gateway = 0;               // 0: on-link destinations only
  std::optional<MacAddr> static_next_hop;  // every destination via this MAC (direct cable)
  LinkType link = LinkType::Ethernet;
  ConnConfig conn;
  std::uint16_t max_connections = 16;
  std::uint16_t max_listeners = 8;
  // Local ports for active opens; reserve them from the kernel with
  // net.ipv4.ip_local_reserved_ports (07 §2.3).
  std::uint16_t ephemeral_lo = 40000;
  std::uint16_t ephemeral_hi = 40999;
  bool arp_reply = true;                   // answer ARP requests for local_ip that reach us
  Nanos arp_retry = 200'000'000;
  std::uint8_t arp_attempts = 5;
  Nanos garp_interval = 0;                 // gratuitous-ARP refresh period; 0 disables
  std::uint64_t isn_secret = 0x5EED'1234'ABCD'0001ull;  // RFC 6528 F() key
};

struct StackStats {
  std::uint64_t frames_in = 0;
  std::uint64_t frames_out = 0;
  std::uint64_t frames_ignored = 0;  // not addressed to us / not TCP or ARP
  std::uint64_t parse_errors = 0;
  std::uint64_t rst_sent = 0;        // for segments matching no connection
  std::uint64_t syn_dropped = 0;     // no free slot
  std::uint64_t arp_in = 0;
  std::uint64_t arp_replies = 0;
  std::uint64_t arp_requests = 0;
  std::uint64_t garp_sent = 0;
  std::uint64_t tx_full = 0;         // frame not sent: TX path full (retried later)
  std::uint64_t tx_dropped = 0;      // send_frame() refused a built frame (acts as loss)
  std::uint64_t ctl_dropped = 0;     // control queue overflow
  std::uint64_t accepted = 0;
  std::uint64_t connected = 0;
  std::uint64_t neighbor_changes = 0;  // connections re-pointed to a new next-hop MAC
  // Connections reclaimed, by Connection::close_reason().
  std::uint64_t closed_normal = 0;
  std::uint64_t closed_reset = 0;
  std::uint64_t closed_refused = 0;
  std::uint64_t closed_timeout = 0;
  std::uint64_t closed_aborted = 0;
  std::uint64_t closed_unresolved = 0;  // next hop never resolved
};

template <FramePort Port, env::ClockLike Clock>
class UtcpStreamPort {
 public:
  UtcpStreamPort(Port& port, Clock& clock, const StackConfig& cfg)
      : port_(port), clock_(clock), cfg_(cfg), listen_ports_(cfg.max_listeners, 0) {
    slots_.reserve(cfg.max_connections);
    for (std::uint16_t i = 0; i < cfg.max_connections; ++i) slots_.emplace_back(cfg.conn, cfg.link);
    scratch_.resize(tcp_headers_len(cfg.link, true) + cfg.conn.mss);
    next_ephemeral_ = cfg.ephemeral_lo;
    if (cfg.garp_interval > 0) garp_next_ = clock_.now_mono();
  }
  UtcpStreamPort(const UtcpStreamPort&) = delete;
  UtcpStreamPort& operator=(const UtcpStreamPort&) = delete;

  // ---- env::StreamPortLike ------------------------------------------------

  std::size_t write(env::ConnId c, std::span<const std::byte> b) {
    Slot* s = lookup(c);
    if (s == nullptr || s->app_closed) return 0;
    const Nanos now = clock_.now_mono();
    const Actions a = s->conn.send(b, now);
    absorb(*s, a);
    flush_tx(now);
    return a.accepted;
  }

  template <class Cb>
  std::size_t poll(Cb&& cb) {
    const Nanos now = clock_.now_mono();
    port_.poll_frames([this, now](std::span<const std::byte> f, Nanos hw) { on_frame(f, hw, now); });
    run_timers(now);
    const std::size_t n = deliver(cb, now);
    flush_tx(now);
    reap();
    return n;
  }

  void close(env::ConnId c) {
    Slot* s = lookup(c);
    if (s == nullptr || s->app_closed) return;
    const Nanos now = clock_.now_mono();
    s->app_closed = true;
    s->closed_reported = true;
    if (s->awaiting_arp || s->failed) {
      free_slot(*s);
      return;
    }
    absorb(*s, s->conn.close(now));
    if (s->conn.readable_bytes() != 0) absorb(*s, s->conn.consume(s->conn.readable_bytes(), now));
    flush_tx(now);
  }

  // ---- control ----------------------------------------------------------------

  // Passive open on `local` (ipv4 0 or our address; port 0 picks a free ephemeral
  // port). Returns the bound endpoint, or nullopt when the address is not ours or the
  // listener table is full.
  std::optional<env::Endpoint> listen(env::Endpoint local) {
    if (local.ipv4 != 0 && local.ipv4 != cfg_.local_ip) return std::nullopt;
    std::uint16_t port = local.port;
    if (port == 0) port = pick_ephemeral();
    if (port == 0) return std::nullopt;
    const env::Endpoint bound{cfg_.local_ip, port};
    for (auto& p : listen_ports_) {
      if (p == port) return bound;
    }
    for (auto& p : listen_ports_) {
      if (p == 0) {
        p = port;
        return bound;
      }
    }
    return std::nullopt;
  }

  void unlisten(std::uint16_t local_port) {
    for (auto& p : listen_ports_) {
      if (p == local_port) p = 0;
    }
  }

  // Active open from an ephemeral port in [ephemeral_lo, ephemeral_hi]; nullopt when no
  // slot or port is free.
  std::optional<env::ConnId> connect(env::Endpoint remote) { return connect_from(remote, 0); }

  // Active open from a given local port (0: ephemeral).
  std::optional<env::ConnId> connect_from(env::Endpoint remote, std::uint16_t local_port) {
    const Nanos now = clock_.now_mono();
    const int idx = alloc_slot();
    if (idx < 0) return std::nullopt;
    if (local_port == 0) local_port = pick_ephemeral();
    if (local_port == 0 || tuple_in_use(remote.ipv4, remote.port, local_port)) return std::nullopt;
    Slot& s = slots_[static_cast<std::size_t>(idx)];
    s.in_use = true;
    s.app_visible = true;
    s.pending_flow = FlowAddr{cfg_.local_mac, MacAddr{}, cfg_.local_ip, remote.ipv4, local_port, remote.port};
    s.nexthop_ip = next_hop_ip(remote.ipv4);
    const std::optional<MacAddr> mac = resolve(s.nexthop_ip);
    if (mac || cfg_.link == LinkType::RawIp) {
      start_connect(s, mac.value_or(MacAddr{}), now);
    } else {
      s.awaiting_arp = true;
      s.arp_tries = 1;
      s.arp_deadline = now + cfg_.arp_retry;
      min_deadline_ = std::min(min_deadline_, s.arp_deadline);
      queue_ctl(Ctl{CtlKind::ArpRequest, {}, s.nexthop_ip, 0, 0, 0, 0, 0, 0});
    }
    flush_tx(now);
    return make_id(static_cast<std::uint16_t>(idx), s.gen);
  }

  // Abortive close (RST).
  void abort(env::ConnId c) {
    Slot* s = lookup(c);
    if (s == nullptr) return;
    const Nanos now = clock_.now_mono();
    s->app_closed = true;
    s->closed_reported = true;
    if (s->awaiting_arp || s->failed) {
      free_slot(*s);
      return;
    }
    absorb(*s, s->conn.abort(now));
    flush_tx(now);
  }

  // Backpressure: while paused, received data stays in the connection's buffer and the
  // advertised window shrinks to zero.
  void pause_reading(env::ConnId c, bool paused) {
    Slot* s = lookup(c);
    if (s != nullptr) s->paused = paused;
  }

  NeighborTable& neighbors() noexcept { return neighbors_; }
  [[nodiscard]] const StackStats& stats() const noexcept { return stats_; }
  [[nodiscard]] const StackConfig& config() const noexcept { return cfg_; }

  [[nodiscard]] const Connection* connection(env::ConnId c) const noexcept {
    const std::size_t idx = c & 0xFFFFu;
    if (c == env::kNoConn || idx >= slots_.size()) return nullptr;
    const Slot& s = slots_[idx];
    if (!s.in_use || s.gen != static_cast<std::uint16_t>(c >> 16)) return nullptr;
    return &s.conn;
  }

  // Slots in use, including connections lingering in TIME-WAIT or LAST-ACK after the
  // application closed them.
  [[nodiscard]] std::size_t slots_in_use() const noexcept {
    std::size_t n = 0;
    for (const auto& s : slots_) n += s.in_use ? 1u : 0u;
    return n;
  }

  // Earliest time at which poll() has timer work (for event-driven drivers).
  [[nodiscard]] Nanos next_deadline() const noexcept {
    Nanos d = cfg_.garp_interval > 0 ? garp_next_ : kNoDeadline;
    for (const auto& s : slots_) {
      if (!s.in_use) continue;
      d = std::min(d, s.conn.deadline());
      if (s.awaiting_arp) d = std::min(d, s.arp_deadline);
    }
    return d;
  }

 private:
  enum class CtlKind : std::uint8_t { Rst, ArpRequest, ArpReply, Garp };
  struct Ctl {
    CtlKind kind = CtlKind::Rst;
    MacAddr mac;               // destination MAC
    std::uint32_t ip = 0;      // destination / target IP
    std::uint16_t lport = 0;   // our port (RST source)
    std::uint16_t rport = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t flags = 0;
    std::uint8_t pad = 0;
  };

  struct Slot {
    Slot(const ConnConfig& c, LinkType l) : conn(c, l) {}
    Connection conn;
    FlowAddr pending_flow{};
    std::uint32_t nexthop_ip = 0;
    Nanos arp_deadline = kNoDeadline;
    Nanos last_hw_rx = 0;
    std::uint64_t rto_seen = 0;  // conn RTO count when the next hop was last re-validated
    std::uint64_t rx_frames = 0;       // frames received for this connection
    std::uint64_t rx_frames_at_rto = 0;
    std::uint16_t gen = 0;
    std::uint8_t arp_tries = 0;
    bool in_use = false;
    bool app_visible = false;  // the application knows this ConnId
    bool app_closed = false;   // close()/abort() called, or EOF reported
    bool closed_reported = false;
    bool pending_connected = false;
    bool paused = false;
    bool awaiting_arp = false;
    bool failed = false;       // next hop unresolved
    bool tx_dirty = false;
  };

  static constexpr env::ConnId make_id(std::uint16_t slot, std::uint16_t gen) noexcept {
    return (env::ConnId{gen} << 16) | slot;
  }

  Slot* lookup(env::ConnId c) noexcept {
    const std::size_t idx = c & 0xFFFFu;
    if (c == env::kNoConn || idx >= slots_.size()) return nullptr;
    Slot& s = slots_[idx];
    if (!s.in_use || s.gen != static_cast<std::uint16_t>(c >> 16)) return nullptr;
    return &s;
  }

  int alloc_slot() noexcept {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      if (!slots_[i].in_use) return static_cast<int>(i);
    }
    return -1;
  }

  void free_slot(Slot& s) noexcept {
    s.conn.reset();
    s.in_use = s.app_visible = s.app_closed = s.closed_reported = false;
    s.pending_connected = s.paused = s.awaiting_arp = s.failed = s.tx_dirty = false;
    s.arp_tries = 0;
    s.arp_deadline = kNoDeadline;
    s.last_hw_rx = 0;
    s.rto_seen = 0;
    s.rx_frames = s.rx_frames_at_rto = 0;
    ++s.gen;
  }

  bool tuple_in_use(std::uint32_t rip, std::uint16_t rport, std::uint16_t lport) const noexcept {
    for (const auto& s : slots_) {
      if (!s.in_use) continue;
      const FlowAddr& f = s.awaiting_arp ? s.pending_flow : s.conn.flow();
      if (f.remote_ip == rip && f.remote_port == rport && f.local_port == lport) return true;
    }
    return false;
  }

  std::uint16_t pick_ephemeral() noexcept {
    const std::uint32_t span = std::uint32_t{cfg_.ephemeral_hi} - cfg_.ephemeral_lo + 1;
    for (std::uint32_t k = 0; k < span; ++k) {
      const std::uint16_t p = next_ephemeral_;
      next_ephemeral_ = p >= cfg_.ephemeral_hi ? cfg_.ephemeral_lo : static_cast<std::uint16_t>(p + 1);
      bool used = is_listening(p);
      for (const auto& s : slots_) {
        if (s.in_use && (s.awaiting_arp ? s.pending_flow.local_port : s.conn.flow().local_port) == p) used = true;
      }
      if (!used) return p;
    }
    return 0;
  }

  [[nodiscard]] std::uint32_t next_hop_ip(std::uint32_t dst) const noexcept {
    if (cfg_.gateway != 0 && (dst & cfg_.netmask) != (cfg_.local_ip & cfg_.netmask)) return cfg_.gateway;
    return dst;
  }

  [[nodiscard]] std::optional<MacAddr> resolve(std::uint32_t nexthop) const noexcept {
    if (cfg_.static_next_hop) return cfg_.static_next_hop;
    return neighbors_.lookup(nexthop);
  }

  // RFC 6528: ISN = M + F(4-tuple, secret), M a 4-microsecond clock.
  [[nodiscard]] std::uint32_t isn(const FlowAddr& f, Nanos now) const noexcept {
    std::uint64_t h = mix64(cfg_.isn_secret ^ ((std::uint64_t{f.local_ip} << 32) | f.remote_ip));
    h = mix64(h ^ ((std::uint64_t{f.local_port} << 16) | f.remote_port));
    return static_cast<std::uint32_t>(now / 4000) + static_cast<std::uint32_t>(h);
  }

  void start_connect(Slot& s, const MacAddr& mac, Nanos now) {
    s.awaiting_arp = false;
    FlowAddr f = s.pending_flow;
    f.remote_mac = mac;
    absorb(s, s.conn.connect(f, isn(f, now), now));
  }

  void absorb(Slot& s, const Actions& a) noexcept {
    if (a.has(ev::kConnected)) s.pending_connected = true;
    if (a.tx_pending) s.tx_dirty = true;
    min_deadline_ = std::min(min_deadline_, a.deadline);
  }

  Slot* find(std::uint32_t rip, std::uint16_t rport, std::uint16_t lport) noexcept {
    for (auto& s : slots_) {
      if (!s.in_use || s.awaiting_arp || s.conn.state() == State::Closed) continue;
      const FlowAddr& f = s.conn.flow();
      if (f.remote_port == rport && f.local_port == lport && f.remote_ip == rip) return &s;
    }
    return nullptr;
  }

  [[nodiscard]] bool is_listening(std::uint16_t port) const noexcept {
    for (const auto p : listen_ports_) {
      if (p == port && p != 0) return true;
    }
    return false;
  }

  void queue_ctl(const Ctl& c) noexcept {
    if (ctl_count_ == ctl_.size()) {
      ++stats_.ctl_dropped;
      return;
    }
    ctl_[(ctl_head_ + ctl_count_) % ctl_.size()] = c;
    ++ctl_count_;
  }

  void on_frame(std::span<const std::byte> f, Nanos hw, Nanos now) {
    ++stats_.frames_in;
    if (cfg_.link == LinkType::Ethernet) {
      const std::uint16_t et = ether_type(f);
      if (et == kEtherTypeArp) {
        on_arp(f, now);
        return;
      }
      if (et != kEtherTypeIpv4 || std::memcmp(f.data(), cfg_.local_mac.b.data(), 6) != 0) {
        ++stats_.frames_ignored;
        return;
      }
    }
    auto seg = parse_tcp(f, cfg_.link, cfg_.conn.verify_rx_checksum);
    if (!seg) {
      if (seg.error() == ParseError::NotTcp || seg.error() == ParseError::NotIpv4) {
        ++stats_.frames_ignored;
      } else {
        ++stats_.parse_errors;
      }
      return;
    }
    if (seg->dst_ip != cfg_.local_ip) {
      ++stats_.frames_ignored;
      return;
    }
    if (Slot* s = find(seg->src_ip, seg->src_port, seg->dst_port)) {
      s->last_hw_rx = hw;
      ++s->rx_frames;
      absorb(*s, s->conn.on_parsed(*seg, now));
      return;
    }
    using namespace tcp_flag;
    if (seg->has(kSyn) && !seg->has(kAck) && !seg->has(kRst) && is_listening(seg->dst_port)) {
      if (ipv4_is_multicast(seg->src_ip) || seg->src_ip == 0xFFFF'FFFFu || seg->src_ip == 0) return;
      const int idx = alloc_slot();
      if (idx < 0) {
        ++stats_.syn_dropped;  // the peer retransmits its SYN
        SIM_PROBE("utcp.syn_dropped_no_slot");
        return;
      }
      Slot& s = slots_[static_cast<std::size_t>(idx)];
      s.in_use = true;
      s.last_hw_rx = hw;
      s.nexthop_ip = next_hop_ip(seg->src_ip);
      // Reply to the MAC the SYN came from: the next hop towards the peer.
      const FlowAddr fl{cfg_.local_mac, seg->src_mac, cfg_.local_ip, seg->src_ip, seg->dst_port, seg->src_port};
      absorb(s, s.conn.accept(fl, *seg, isn(fl, now), now));
      return;
    }
    // CLOSED: answer with RST unless the segment is itself a RST (RFC 9293 §3.10.7.1).
    if (seg->has(kRst)) return;
    Ctl c;
    c.kind = CtlKind::Rst;
    c.mac = seg->src_mac;
    c.ip = seg->src_ip;
    c.lport = seg->dst_port;
    c.rport = seg->src_port;
    if (seg->has(kAck)) {
      c.seq = seg->ack;
      c.flags = kRst;
    } else {
      c.seq = 0;
      c.ack = seg->seq + seg->seg_len();
      c.flags = kRst | kAck;
    }
    queue_ctl(c);
  }

  void on_arp(std::span<const std::byte> f, Nanos now) {
    const std::optional<ArpPacket> a = parse_arp(f);
    if (!a) {
      ++stats_.frames_ignored;
      return;
    }
    ++stats_.arp_in;
    // RFC 826 merge: update a known sender; add it when the packet targets us.
    const bool merged = neighbors_.update_if_present(a->sender_ip, a->sender_mac);
    if (a->target_ip == cfg_.local_ip && a->sender_ip != 0) {
      if (!merged) (void)neighbors_.set(a->sender_ip, a->sender_mac, false);
      if (a->op == ArpOp::Request && cfg_.arp_reply) {
        Ctl c;
        c.kind = CtlKind::ArpReply;
        c.mac = a->sender_mac;
        c.ip = a->sender_ip;
        queue_ctl(c);
      }
    }
    const std::optional<MacAddr> mac = cfg_.static_next_hop ? std::nullopt : neighbors_.lookup(a->sender_ip);
    if (!mac) return;
    for (auto& s : slots_) {
      if (!s.in_use || s.nexthop_ip != a->sender_ip) continue;
      if (s.awaiting_arp) {
        start_connect(s, *mac, now);
      } else if (s.conn.state() != State::Closed && s.conn.flow().remote_mac != *mac) {
        // The next hop's MAC changed (or our entry was wrong): re-point the connection.
        s.conn.set_remote_mac(*mac);
        ++stats_.neighbor_changes;
      }
    }
  }

  void run_timers(Nanos now) {
    if (cfg_.garp_interval > 0 && now >= garp_next_) {
      queue_ctl(Ctl{CtlKind::Garp, {}, cfg_.local_ip, 0, 0, 0, 0, 0, 0});
      garp_next_ = now + cfg_.garp_interval;
    }
    if (now < min_deadline_) return;
    Nanos next = kNoDeadline;
    for (auto& s : slots_) {
      if (!s.in_use) continue;
      if (s.awaiting_arp && now >= s.arp_deadline) {
        if (s.arp_tries >= cfg_.arp_attempts) {
          s.awaiting_arp = false;
          s.failed = true;
          s.arp_deadline = kNoDeadline;
        } else {
          ++s.arp_tries;
          s.arp_deadline = now + cfg_.arp_retry;
          queue_ctl(Ctl{CtlKind::ArpRequest, {}, s.nexthop_ip, 0, 0, 0, 0, 0, 0});
        }
      }
      if (s.conn.deadline() <= now) {
        absorb(s, s.conn.on_timer(now));
        // Neighbour re-validation (like Linux NUD probing when TCP stalls): an RTO with a
        // learned next hop and nothing heard from the peer since the previous RTO sends an
        // ARP request; a reply with a different MAC re-points the connection (on_arp).
        if (s.conn.stats().rto_expiries != s.rto_seen) {
          s.rto_seen = s.conn.stats().rto_expiries;
          const bool silent = s.rx_frames == s.rx_frames_at_rto;
          s.rx_frames_at_rto = s.rx_frames;
          if (silent && !cfg_.static_next_hop && cfg_.link == LinkType::Ethernet && s.conn.state() != State::Closed) {
            queue_ctl(Ctl{CtlKind::ArpRequest, {}, s.nexthop_ip, 0, 0, 0, 0, 0, 0});
          }
        }
      }
      next = std::min(next, s.conn.deadline());
      if (s.awaiting_arp) next = std::min(next, s.arp_deadline);
    }
    min_deadline_ = next;
  }

  template <class Cb>
  std::size_t deliver(Cb& cb, Nanos now) {
    std::size_t count = 0;
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      Slot& s = slots_[i];
      if (!s.in_use) continue;
      const env::ConnId id = make_id(static_cast<std::uint16_t>(i), s.gen);
      if (s.failed) {
        if (!s.closed_reported) {
          s.closed_reported = true;
          cb(env::StreamEvent{env::StreamEventKind::Closed, id, {}, 0});
          ++count;
        }
        continue;
      }
      if (s.awaiting_arp) continue;  // the connection has not started yet
      if (s.pending_connected) {
        s.pending_connected = false;
        if (!s.app_closed) {
          const bool passive = s.conn.passive();
          s.app_visible = true;
          if (passive) {
            ++stats_.accepted;
          } else {
            ++stats_.connected;
          }
          cb(env::StreamEvent{passive ? env::StreamEventKind::Accepted : env::StreamEventKind::Connected, id, {}, 0});
          ++count;
        }
      }
      if (!s.in_use || s.gen != static_cast<std::uint16_t>(id >> 16) || !s.app_visible) continue;
      if (s.app_closed) {
        if (s.conn.readable_bytes() != 0) absorb(s, s.conn.consume(s.conn.readable_bytes(), now));
        continue;
      }
      if (!s.paused && s.conn.readable_bytes() != 0) {
        const ByteRing::Spans sp = s.conn.readable();
        const std::size_t total = sp.size();
        cb(env::StreamEvent{env::StreamEventKind::Data, id, sp.first, s.last_hw_rx});
        ++count;
        if (!sp.second.empty() && s.in_use && s.gen == static_cast<std::uint16_t>(id >> 16)) {
          cb(env::StreamEvent{env::StreamEventKind::Data, id, sp.second, s.last_hw_rx});
          ++count;
        }
        if (s.in_use && s.gen == static_cast<std::uint16_t>(id >> 16)) absorb(s, s.conn.consume(total, now));
      }
      if (!s.in_use || s.gen != static_cast<std::uint16_t>(id >> 16) || s.closed_reported) continue;
      if (s.conn.peer_fin_received() && s.conn.readable_bytes() == 0 && !s.app_closed) {
        // End of stream: report it, then close our half (the API has no half-close).
        s.closed_reported = true;
        s.app_closed = true;
        cb(env::StreamEvent{env::StreamEventKind::Closed, id, {}, 0});
        ++count;
        absorb(s, s.conn.close(now));
      } else if (s.conn.state() == State::Closed) {
        s.closed_reported = true;
        cb(env::StreamEvent{env::StreamEventKind::Closed, id, {}, 0});
        ++count;
      }
    }
    return count;
  }

  std::span<std::byte> scratch() noexcept { return std::span<std::byte>(scratch_.data(), scratch_.size()); }

  std::size_t build_ctl(std::span<std::byte> out, const Ctl& c) noexcept {
    switch (c.kind) {
      case CtlKind::Rst: {
        TcpHeaderSpec h;
        h.src_mac = cfg_.local_mac;
        h.dst_mac = c.mac;
        h.src_ip = cfg_.local_ip;
        h.dst_ip = c.ip;
        h.src_port = c.lport;
        h.dst_port = c.rport;
        h.seq = c.seq;
        h.ack = c.ack;
        h.flags = c.flags;
        h.ttl = cfg_.conn.ttl;
        ++stats_.rst_sent;
        SIM_PROBE("utcp.rst_for_stray_segment");
        return build_tcp(out, cfg_.link, h, {}, {}, cfg_.conn.tx_checksum_offload);
      }
      case CtlKind::ArpRequest:
        ++stats_.arp_requests;
        return cfg_.link == LinkType::Ethernet ? build_arp_request(out, cfg_.local_mac, cfg_.local_ip, c.ip) : 0;
      case CtlKind::ArpReply: {
        ++stats_.arp_replies;
        ArpPacket req;
        req.sender_mac = c.mac;
        req.sender_ip = c.ip;
        return cfg_.link == LinkType::Ethernet ? build_arp_reply(out, cfg_.local_mac, cfg_.local_ip, req) : 0;
      }
      case CtlKind::Garp:
        ++stats_.garp_sent;
        return cfg_.link == LinkType::Ethernet ? build_gratuitous_arp(out, cfg_.local_mac, cfg_.local_ip) : 0;
    }
    return 0;
  }

  enum class TxResult : std::uint8_t { Sent, Nothing, Full };

  // Sends one frame produced by `build(span) -> size_t` (0: nothing to send).
  template <class Build>
  TxResult tx_one(Build&& build) {
    if constexpr (FramePortTxAcquire<Port>) {
      std::span<std::byte> buf = port_.tx_acquire();
      if (buf.empty()) {
        ++stats_.tx_full;
        return TxResult::Full;
      }
      const std::size_t n = build(buf);
      port_.tx_commit(n);
      if (n == 0) return TxResult::Nothing;
      ++stats_.frames_out;
      return TxResult::Sent;
    } else {
      const std::size_t n = build(scratch());
      if (n == 0) return TxResult::Nothing;
      ++stats_.frames_out;
      // Fault: the device drops a built frame (counted like a refused send; acts as loss).
      if (SIM_BUGGIFY("utcp.tx_frame_dropped") || !port_.send_frame(std::span<const std::byte>(scratch_.data(), n))) {
        ++stats_.tx_dropped;
      }
      return TxResult::Sent;
    }
  }

  void flush_tx(Nanos now) {
    while (ctl_count_ != 0) {
      const Ctl c = ctl_[ctl_head_];
      if (tx_one([&](std::span<std::byte> out) { return build_ctl(out, c); }) == TxResult::Full) break;
      ctl_head_ = (ctl_head_ + 1) % ctl_.size();
      --ctl_count_;
    }
    for (auto& s : slots_) {
      if (!s.in_use || !s.tx_dirty) continue;
      while (s.conn.tx_pending()) {
        if (tx_one([&](std::span<std::byte> out) { return s.conn.next_tx(out, now); }) != TxResult::Sent) break;
      }
      s.tx_dirty = s.conn.tx_pending();
      min_deadline_ = std::min(min_deadline_, s.conn.deadline());
    }
    if constexpr (FramePortFlush<Port>) port_.flush();
  }

  void reap() noexcept {
    for (auto& s : slots_) {
      if (!s.in_use) continue;
      if (s.failed) {
        if (s.closed_reported || s.app_closed) {
          ++stats_.closed_unresolved;
          free_slot(s);
        }
        continue;
      }
      if (s.awaiting_arp || s.conn.state() != State::Closed || s.conn.tx_pending()) continue;
      if (s.closed_reported || !s.app_visible) {
        switch (s.conn.close_reason()) {
          case CloseReason::Normal: ++stats_.closed_normal; break;
          case CloseReason::Reset: ++stats_.closed_reset; break;
          case CloseReason::Refused: ++stats_.closed_refused; break;
          case CloseReason::Timeout: ++stats_.closed_timeout; break;
          case CloseReason::Aborted: ++stats_.closed_aborted; break;
          case CloseReason::None: break;
        }
        free_slot(s);
      }
    }
  }

  Port& port_;
  Clock& clock_;
  StackConfig cfg_;
  std::vector<Slot> slots_;
  std::vector<std::uint16_t> listen_ports_;
  std::vector<std::byte> scratch_;
  NeighborTable neighbors_;
  std::array<Ctl, 32> ctl_{};
  std::size_t ctl_head_ = 0;
  std::size_t ctl_count_ = 0;
  Nanos min_deadline_ = kNoDeadline;
  Nanos garp_next_ = kNoDeadline;
  std::uint16_t next_ephemeral_ = 0;
  StackStats stats_{};
};

}  // namespace lle::net::utcp
