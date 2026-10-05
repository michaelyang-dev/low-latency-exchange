#pragma once
// utcp::Connection: a sans-I/O TCP endpoint (07 §2.4). It implements the RFC 9293
// subset needed to carry SoupBinTCP to and from Linux kernel TCP on a dedicated link:
//
//   - active and passive open, 3-way handshake (and simultaneous open), MSS option only;
//   - cumulative ACKs sent immediately (no delayed ACK), one duplicate ACK per dropped
//     out-of-order segment;
//   - a send buffer with go-back-N retransmission, RFC 6298 RTO (configurable lower
//     bound) with exponential backoff and Karn's rule, fast retransmit with NewReno-style
//     partial-ACK retransmission, a retransmission limit followed by a reset;
//   - the peer's receive window is respected (plus a fixed in-flight cap); our window is
//     the free receive-buffer space (no window scaling, so at most 65,535) with receiver
//     SWS avoidance, reaching zero for backpressure; zero-window probing;
//   - FIN/RST teardown including simultaneous close, RFC 5961 RST/SYN challenge ACKs,
//     a short TIME-WAIT.
//
// Deviations are listed in DEVIATIONS.md. Inputs are bytes and time; outputs are events
// (Actions) plus frames pulled with next_tx(), which builds directly into the caller's
// buffer (for AF_XDP: a UMEM chunk). Buffers are allocated once in the constructor.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

#include "common/types.h"
#include "net/utcp/byte_ring.h"
#include "net/utcp/seq.h"
#include "net/utcp/wire.h"

namespace lle::net::utcp {

inline constexpr Nanos kNoDeadline = std::numeric_limits<Nanos>::max();
inline constexpr std::uint32_t kMaxWindow = 65535;  // no window scaling (RFC 7323 not offered)

enum class State : std::uint8_t {
  Closed,
  SynSent,
  SynReceived,
  Established,
  FinWait1,
  FinWait2,
  CloseWait,
  Closing,
  LastAck,
  TimeWait,
};
[[nodiscard]] const char* to_string(State s) noexcept;

enum class CloseReason : std::uint8_t {
  None,
  Normal,   // orderly FIN exchange (or TIME-WAIT expiry)
  Reset,    // peer RST in a synchronized state
  Refused,  // RST answering our SYN
  Timeout,  // retransmission limit, or FIN-WAIT-2 timeout
  Aborted,  // local abort() / close before established
};
[[nodiscard]] const char* to_string(CloseReason r) noexcept;

namespace ev {
inline constexpr std::uint32_t kConnected = 1u << 0;  // reached ESTABLISHED
inline constexpr std::uint32_t kReadable = 1u << 1;   // in-order bytes added to the receive buffer
inline constexpr std::uint32_t kPeerFin = 1u << 2;    // the peer's FIN was consumed (end of stream)
inline constexpr std::uint32_t kClosed = 1u << 3;     // reached CLOSED; see close_reason()
inline constexpr std::uint32_t kWritable = 1u << 4;   // an ACK freed send-buffer space
inline constexpr std::uint32_t kTimeWait = 1u << 5;   // entered TIME-WAIT
}  // namespace ev

struct Actions {
  std::uint32_t events = 0;    // ev::* raised by this call
  std::uint32_t accepted = 0;  // bytes taken by send()
  bool tx_pending = false;     // next_tx() has a frame to build
  Nanos deadline = kNoDeadline;
  [[nodiscard]] constexpr bool has(std::uint32_t e) const noexcept { return (events & e) != 0; }
};

struct ConnConfig {
  std::uint16_t mss = 1460;               // advertised, and the cap on what we send
  std::uint32_t rx_buffer = 65535;        // receive buffer; window = min(free, 65535)
  std::uint32_t tx_buffer = 256 * 1024;   // send buffer
  std::uint32_t max_inflight = 65535;     // fixed in-flight cap (no RFC 5681 cwnd)
  Nanos initial_rto = 1'000'000'000;      // RFC 6298 §2.1
  Nanos min_rto = 200'000'000;            // RFC 6298 §2.4 says 1 s; lower for the LAN
  Nanos max_rto = 60'000'000'000;         // RFC 6298 §2.5
  Nanos clock_granularity = 1'000;        // G in RFC 6298 §2.3
  std::uint8_t max_retransmits = 15;      // consecutive RTO expiries before reset
  std::uint8_t max_syn_retransmits = 6;
  Nanos time_wait = 1'000'000'000;        // 2*MSL (shortened, see DEVIATIONS.md)
  Nanos fin_wait2_timeout = 60'000'000'000;
  std::uint8_t dupack_threshold = 3;      // fast retransmit; 0 disables
  std::uint8_t ttl = 64;
  bool verify_rx_checksum = true;         // false: trust the NIC / link
  bool tx_checksum_offload = false;       // true: leave the TCP checksum to the device
};

// Addresses of one connection (host byte order).
struct FlowAddr {
  MacAddr local_mac;
  MacAddr remote_mac;  // next hop
  std::uint32_t local_ip = 0;
  std::uint32_t remote_ip = 0;
  std::uint16_t local_port = 0;
  std::uint16_t remote_port = 0;
};

struct ConnStats {
  std::uint64_t segs_in = 0;
  std::uint64_t segs_out = 0;
  std::uint64_t bytes_in = 0;        // payload accepted in order
  std::uint64_t bytes_out = 0;       // payload sent, including retransmissions
  std::uint64_t retransmit_segs = 0;
  std::uint64_t rto_expiries = 0;
  std::uint64_t fast_retransmits = 0;
  std::uint64_t dupacks_in = 0;
  std::uint64_t dupacks_out = 0;
  std::uint64_t ooo_dropped = 0;     // out-of-order segments dropped (07 §2.4)
  std::uint64_t unacceptable_in = 0; // outside the receive window (old duplicates etc.)
  std::uint64_t challenge_acks = 0;  // RFC 5961
  std::uint64_t zero_window_probes = 0;
  std::uint64_t window_updates = 0;
  std::uint64_t rtt_samples = 0;
  std::uint64_t parse_errors = 0;
};

class Connection {
 public:
  Connection() = default;
  explicit Connection(const ConnConfig& cfg, LinkType link = LinkType::Ethernet);
  Connection(Connection&&) noexcept = default;
  Connection& operator=(Connection&&) noexcept = default;

  // Returns a CLOSED connection to its pristine state (buffers kept) for slot reuse.
  void reset() noexcept;

  // Active open: queues a SYN (state SYN-SENT).
  Actions connect(const FlowAddr& flow, std::uint32_t iss, Nanos now) noexcept;
  // Passive open from a listener: `syn` is the peer's SYN; queues a SYN-ACK (SYN-RECEIVED).
  Actions accept(const FlowAddr& flow, const TcpSegment& syn, std::uint32_t iss, Nanos now) noexcept;

  // A frame (link type from the constructor) for this connection.
  Actions on_segment(std::span<const std::byte> frame, Nanos now) noexcept;
  // A segment already parsed and demultiplexed by the stack.
  Actions on_parsed(const TcpSegment& seg, Nanos now) noexcept;
  // Queues bytes; Actions::accepted may be less than data.size() (buffer full) or zero
  // (state does not allow sending).
  Actions send(std::span<const std::byte> data, Nanos now) noexcept;
  Actions on_timer(Nanos now) noexcept;
  // Orderly close (FIN after queued data).
  Actions close(Nanos now) noexcept;
  // Abortive close: RST (if synchronized), then CLOSED.
  Actions abort(Nanos now) noexcept;

  // Re-points the connection at a new next-hop MAC (neighbour re-validation).
  void set_remote_mac(const MacAddr& mac) noexcept { flow_.remote_mac = mac; }

  // Receive buffer: in-order bytes not yet consumed by the application.
  [[nodiscard]] ByteRing::Spans readable() const noexcept { return rx_.peek(0, rx_.size()); }
  [[nodiscard]] std::size_t readable_bytes() const noexcept { return rx_.size(); }
  // Frees receive-buffer space; may schedule a window update.
  Actions consume(std::size_t n, Nanos now) noexcept;

  // Builds the next outbound frame into `out` (which must hold max_frame_len() bytes)
  // and returns its length, or 0 when there is nothing to send.
  std::size_t next_tx(std::span<std::byte> out, Nanos now) noexcept;
  [[nodiscard]] bool tx_pending() const noexcept;
  [[nodiscard]] Nanos deadline() const noexcept;
  [[nodiscard]] std::size_t max_frame_len() const noexcept {
    return tcp_headers_len(link_, true) + cfg_.mss;
  }

  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] CloseReason close_reason() const noexcept { return reason_; }
  [[nodiscard]] const FlowAddr& flow() const noexcept { return flow_; }
  [[nodiscard]] const ConnConfig& config() const noexcept { return cfg_; }
  [[nodiscard]] const ConnStats& stats() const noexcept { return stats_; }
  [[nodiscard]] bool passive() const noexcept { return passive_; }
  [[nodiscard]] bool peer_fin_received() const noexcept { return fin_received_; }
  [[nodiscard]] std::size_t send_buffer_free() const noexcept { return tx_.free(); }
  [[nodiscard]] std::size_t send_buffer_used() const noexcept { return tx_.size(); }
  [[nodiscard]] std::uint32_t snd_una() const noexcept { return snd_una_; }
  [[nodiscard]] std::uint32_t snd_nxt() const noexcept { return snd_nxt_; }
  [[nodiscard]] std::uint32_t snd_max() const noexcept { return snd_max_; }
  [[nodiscard]] std::uint32_t snd_wnd() const noexcept { return snd_wnd_; }
  [[nodiscard]] std::uint32_t rcv_nxt() const noexcept { return rcv_nxt_; }
  [[nodiscard]] std::uint32_t rcv_window() const noexcept { return rcv_adv_ - rcv_nxt_; }
  [[nodiscard]] std::uint32_t iss() const noexcept { return iss_; }
  [[nodiscard]] std::uint32_t irs() const noexcept { return irs_; }
  [[nodiscard]] std::uint16_t snd_mss() const noexcept { return snd_mss_; }
  [[nodiscard]] Nanos rto() const noexcept { return rto_; }
  [[nodiscard]] Nanos srtt() const noexcept { return srtt_; }
  [[nodiscard]] bool synchronized() const noexcept {
    return state_ != State::Closed && state_ != State::SynSent && state_ != State::SynReceived;
  }
  // Checks internal invariants (used by tests and the fuzzer); true when consistent.
  [[nodiscard]] bool invariants_ok() const noexcept;

 private:
  void on_syn_sent(const TcpSegment& seg, Nanos now) noexcept;
  void on_synchronized(const TcpSegment& seg, Nanos now) noexcept;
  // Step five of RFC 9293 §3.10.7.4; false when the rest of the segment must be dropped.
  bool process_ack(const TcpSegment& seg, Nanos now) noexcept;
  void ack_advance(std::uint32_t ack, Nanos now) noexcept;
  void on_rto(Nanos now) noexcept;
  void rtt_sample(Nanos r) noexcept;
  void enter_established() noexcept;
  void enter_time_wait(Nanos now) noexcept;
  void enter_closed(CloseReason r) noexcept;
  void queue_rst(std::uint32_t seq, std::uint32_t ack, bool with_ack) noexcept;
  void update_timer(Nanos now) noexcept;
  void arm_rto(Nanos now) noexcept {
    if (rto_deadline_ == kNoDeadline) rto_deadline_ = now + rto_;
  }
  [[nodiscard]] bool fin_acked() const noexcept { return fin_queued_ && seq_gt(snd_una_, fin_seq_); }
  [[nodiscard]] std::uint32_t data_end() const noexcept {
    return tx_base_ + static_cast<std::uint32_t>(tx_.size());
  }
  [[nodiscard]] bool has_unsent() const noexcept;
  // Sequence number for segments that carry no data (pure ACK, RST): SND.MAX, but never
  // beyond the peer's right window edge (Linux tcp_acceptable_seq()).
  [[nodiscard]] std::uint32_t acceptable_seq() const noexcept {
    const std::uint32_t edge = snd_una_ + snd_wnd_;
    return seq_le(snd_max_, edge) ? snd_max_ : seq_max(edge, snd_una_);
  }
  [[nodiscard]] bool can_send_data() const noexcept;
  [[nodiscard]] std::uint16_t advertise_window() noexcept;
  [[nodiscard]] std::uint32_t window_threshold() const noexcept;
  std::size_t build(std::span<std::byte> out, std::uint32_t seq, std::uint8_t flags, std::uint32_t data_len,
                    bool mss_option) noexcept;
  std::size_t emit_data(std::span<std::byte> out, std::uint32_t seq, std::uint32_t max_data,
                        std::uint32_t seq_budget, Nanos now) noexcept;
  [[nodiscard]] bool sendable_now() const noexcept { return sendable_len() != 0; }
  [[nodiscard]] std::uint32_t sendable_len() const noexcept;
  Actions finish(Nanos now) noexcept;

  ConnConfig cfg_{};
  LinkType link_ = LinkType::Ethernet;
  FlowAddr flow_{};
  State state_ = State::Closed;
  CloseReason reason_ = CloseReason::None;
  bool passive_ = false;

  // Send sequence space (RFC 9293 §3.3.1) plus snd_max_, the highest sequence number
  // ever sent: go-back-N pulls snd_nxt_ back to snd_una_ after an RTO.
  std::uint32_t iss_ = 0;
  std::uint32_t snd_una_ = 0;
  std::uint32_t snd_nxt_ = 0;
  std::uint32_t snd_max_ = 0;
  std::uint32_t snd_wnd_ = 0;
  std::uint32_t snd_wl1_ = 0;
  std::uint32_t snd_wl2_ = 0;
  std::uint32_t max_snd_wnd_ = 0;  // largest window the peer has offered (sender SWS rule)
  std::uint32_t tx_base_ = 0;  // sequence number of tx_[0]
  std::uint32_t fin_seq_ = 0;  // sequence number of our FIN once queued
  std::uint32_t cwnd_ = 0;     // in-flight cap: max_inflight, restarted at one MSS after an RTO
  std::uint16_t snd_mss_ = kDefaultMss;
  bool fin_queued_ = false;
  ByteRing tx_;

  // Receive sequence space. rcv_adv_ is the right edge we last advertised; it never
  // moves left (RFC 9293 §3.8.6.2.2).
  std::uint32_t irs_ = 0;
  std::uint32_t rcv_nxt_ = 0;
  std::uint32_t rcv_adv_ = 0;
  bool fin_received_ = false;
  ByteRing rx_;

  // RFC 6298 state.
  Nanos srtt_ = 0;
  Nanos rttvar_ = 0;
  Nanos rto_ = 0;
  bool have_rtt_ = false;
  bool rtt_timing_ = false;
  std::uint32_t rtt_seq_ = 0;  // sample when an ACK covers this sequence number
  Nanos rtt_start_ = 0;
  Nanos rto_deadline_ = kNoDeadline;
  std::uint8_t rtx_count_ = 0;

  // Fast retransmit / NewReno-style recovery (RFC 5681 §3.2, RFC 6582).
  std::uint8_t dupacks_ = 0;
  bool in_recovery_ = false;
  std::uint32_t recover_ = 0;

  // Pending output.
  bool ack_now_ = false;
  std::uint16_t dupacks_to_send_ = 0;
  bool rtx_one_ = false;  // retransmit one segment at snd_una_
  bool probe_ = false;    // zero-window probe: one byte (or FIN) past the window
  bool rst_pending_ = false;
  bool rst_with_ack_ = false;
  std::uint32_t rst_seq_ = 0;
  std::uint32_t rst_ack_ = 0;
  std::uint16_t ip_id_ = 0;

  Nanos time_wait_deadline_ = kNoDeadline;
  Nanos fin_wait2_deadline_ = kNoDeadline;
  std::uint32_t events_ = 0;
  ConnStats stats_{};
};

}  // namespace lle::net::utcp
