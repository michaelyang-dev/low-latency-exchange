#include "net/utcp/connection.h"

#include "env/buggify.h"
#include <algorithm>

#include "common/assert.h"

namespace lle::net::utcp {
namespace {

using namespace tcp_flag;

// Linux's tcp_min_snd_mss: a tiny peer MSS would make us emit a flood of tiny segments.
constexpr std::uint16_t kMinSndMss = 48;

std::uint16_t effective_mss(std::uint16_t ours, std::uint16_t peer_option) noexcept {
  const std::uint16_t peer = peer_option != 0 ? peer_option : kDefaultMss;
  return std::max(kMinSndMss, std::min(ours, peer));
}

}  // namespace

const char* to_string(State s) noexcept {
  switch (s) {
    case State::Closed: return "CLOSED";
    case State::SynSent: return "SYN-SENT";
    case State::SynReceived: return "SYN-RECEIVED";
    case State::Established: return "ESTABLISHED";
    case State::FinWait1: return "FIN-WAIT-1";
    case State::FinWait2: return "FIN-WAIT-2";
    case State::CloseWait: return "CLOSE-WAIT";
    case State::Closing: return "CLOSING";
    case State::LastAck: return "LAST-ACK";
    case State::TimeWait: return "TIME-WAIT";
  }
  return "?";
}

const char* to_string(CloseReason r) noexcept {
  switch (r) {
    case CloseReason::None: return "none";
    case CloseReason::Normal: return "normal";
    case CloseReason::Reset: return "reset";
    case CloseReason::Refused: return "refused";
    case CloseReason::Timeout: return "timeout";
    case CloseReason::Aborted: return "aborted";
  }
  return "?";
}

Connection::Connection(const ConnConfig& cfg, LinkType link)
    : cfg_(cfg), link_(link), tx_(cfg.tx_buffer), rx_(cfg.rx_buffer) {
  LLE_ASSERT(cfg.mss >= kMinSndMss, "utcp: MSS too small");
  LLE_ASSERT(cfg.rx_buffer >= 2 && cfg.tx_buffer >= 1, "utcp: buffers too small");
  LLE_ASSERT(cfg.min_rto > 0 && cfg.min_rto <= cfg.max_rto && cfg.initial_rto > 0, "utcp: bad RTO bounds");
  reset();
}

void Connection::reset() noexcept {
  flow_ = FlowAddr{};
  state_ = State::Closed;
  reason_ = CloseReason::None;
  passive_ = false;
  iss_ = snd_una_ = snd_nxt_ = snd_max_ = 0;
  snd_wnd_ = snd_wl1_ = snd_wl2_ = 0;
  max_snd_wnd_ = 0;
  tx_base_ = fin_seq_ = 0;
  cwnd_ = cfg_.max_inflight;
  snd_mss_ = kDefaultMss;
  fin_queued_ = false;
  tx_.clear();
  irs_ = rcv_nxt_ = rcv_adv_ = 0;
  fin_received_ = false;
  rx_.clear();
  srtt_ = rttvar_ = 0;
  rto_ = cfg_.initial_rto;
  have_rtt_ = rtt_timing_ = false;
  rtt_seq_ = 0;
  rtt_start_ = 0;
  rto_deadline_ = kNoDeadline;
  rtx_count_ = 0;
  dupacks_ = 0;
  in_recovery_ = false;
  recover_ = 0;
  ack_now_ = false;
  dupacks_to_send_ = 0;
  rtx_one_ = probe_ = false;
  rst_pending_ = rst_with_ack_ = false;
  rst_seq_ = rst_ack_ = 0;
  ip_id_ = 0;
  time_wait_deadline_ = fin_wait2_deadline_ = kNoDeadline;
  events_ = 0;
  stats_ = ConnStats{};
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

Actions Connection::connect(const FlowAddr& flow, std::uint32_t iss, Nanos now) noexcept {
  reset();
  flow_ = flow;
  passive_ = false;
  iss_ = snd_una_ = snd_nxt_ = snd_max_ = iss;
  tx_base_ = iss + 1;
  state_ = State::SynSent;
  return finish(now);
}

Actions Connection::accept(const FlowAddr& flow, const TcpSegment& syn, std::uint32_t iss, Nanos now) noexcept {
  reset();
  flow_ = flow;
  passive_ = true;
  iss_ = snd_una_ = snd_nxt_ = snd_max_ = iss;
  tx_base_ = iss + 1;
  irs_ = syn.seq;
  rcv_nxt_ = syn.seq + 1;
  rcv_adv_ = rcv_nxt_ + static_cast<std::uint32_t>(std::min<std::size_t>(rx_.free(), kMaxWindow));
  snd_wnd_ = syn.window;
  max_snd_wnd_ = snd_wnd_;
  snd_wl1_ = syn.seq;
  snd_wl2_ = iss;
  snd_mss_ = effective_mss(cfg_.mss, syn.mss);
  state_ = State::SynReceived;
  return finish(now);
}

// ---------------------------------------------------------------------------
// Segment arrival (RFC 9293 §3.10.7)
// ---------------------------------------------------------------------------

Actions Connection::on_segment(std::span<const std::byte> frame, Nanos now) noexcept {
  auto seg = parse_tcp(frame, link_, cfg_.verify_rx_checksum);
  if (!seg) {
    ++stats_.parse_errors;
    return finish(now);
  }
  if (seg->dst_port != flow_.local_port || seg->src_port != flow_.remote_port || seg->dst_ip != flow_.local_ip ||
      seg->src_ip != flow_.remote_ip) {
    return finish(now);  // not this connection's flow
  }
  return on_parsed(*seg, now);
}

Actions Connection::on_parsed(const TcpSegment& seg, Nanos now) noexcept {
  ++stats_.segs_in;
  if (state_ == State::SynSent) {
    on_syn_sent(seg, now);
  } else if (state_ != State::Closed) {
    on_synchronized(seg, now);
  }
  return finish(now);
}

void Connection::on_syn_sent(const TcpSegment& seg, Nanos now) noexcept {
  const bool has_ack = seg.has(kAck);
  // First: the ACK must acknowledge our SYN.
  if (has_ack && (seq_le(seg.ack, iss_) || seq_gt(seg.ack, snd_max_))) {
    if (!seg.has(kRst)) queue_rst(seg.ack, 0, false);
    return;
  }
  // Second: RST is accepted only with an acceptable ACK.
  if (seg.has(kRst)) {
    if (has_ack) enter_closed(CloseReason::Refused);
    return;
  }
  // Fourth: SYN. Data and FIN on a SYN are not accepted (not acknowledged, so the peer
  // retransmits them after the handshake).
  if (!seg.has(kSyn)) return;
  irs_ = seg.seq;
  rcv_nxt_ = seg.seq + 1;
  rcv_adv_ = rcv_nxt_ + static_cast<std::uint32_t>(std::min<std::size_t>(rx_.free(), kMaxWindow));
  snd_mss_ = effective_mss(cfg_.mss, seg.mss);
  snd_wnd_ = seg.window;
  max_snd_wnd_ = snd_wnd_;
  snd_wl1_ = seg.seq;
  if (has_ack) {
    snd_wl2_ = seg.ack;
    ack_advance(seg.ack, now);
    enter_established();
    ack_now_ = true;
  } else {
    // Simultaneous open (RFC 9293 §3.5, figure 7): answer with SYN,ACK from ISS.
    snd_wl2_ = iss_;
    state_ = State::SynReceived;
    snd_nxt_ = iss_;
  }
}

void Connection::on_synchronized(const TcpSegment& seg, Nanos now) noexcept {
  const std::uint32_t seg_len = seg.seg_len();
  const std::uint32_t wnd = rcv_window();

  // A retransmitted SYN in SYN-RECEIVED means our SYN,ACK was lost: resend it now
  // (its sequence number lies just left of the window, so it is checked first).
  if (state_ == State::SynReceived && seg.has(kSyn) && !seg.has(kAck) && !seg.has(kRst) && seg.seq == irs_) {
    rtx_one_ = true;
    return;
  }

  // Simultaneous open: the peer's SYN,ACK in SYN-RECEIVED lies one left of the window
  // but acknowledges our SYN; take its ACK (as Linux does in tcp_validate_incoming).
  if (state_ == State::SynReceived && !passive_ && seg.has(kSyn) && seg.has(kAck) && !seg.has(kRst) &&
      seg.seq + 1 == rcv_nxt_ && seg.ack == snd_max_) {
    if (process_ack(seg, now)) ack_now_ = true;
    return;
  }

  // First: sequence-number acceptability (RFC 9293 §3.10.7.4, the four-case table).
  bool acceptable;
  if (seg_len == 0) {
    acceptable = wnd == 0 ? seg.seq == rcv_nxt_ : seq_in_window(seg.seq, rcv_nxt_, wnd);
  } else {
    acceptable = wnd != 0 && (seq_in_window(seg.seq, rcv_nxt_, wnd) || seq_in_window(seg.seq + seg_len - 1, rcv_nxt_, wnd));
    // Like Linux, a bare FIN at RCV.NXT is taken even with a zero window, so a reader
    // that applies backpressure does not stall the peer's close.
    if (!acceptable && seg.payload.empty() && seg.has(kFin) && !seg.has(kSyn) && seg.seq == rcv_nxt_) acceptable = true;
  }
  if (!acceptable) {
    if (seg.has(kRst)) return;
    ++stats_.unacceptable_in;
    ack_now_ = true;
    if (state_ == State::TimeWait && seg.has(kFin)) time_wait_deadline_ = now + cfg_.time_wait;
    // With a zero window, valid ACKs are still processed (RFC 9293 §3.10.7.4).
    if (wnd == 0 && seg.seq == rcv_nxt_ && seg.has(kAck) && !seg.has(kSyn) && state_ != State::SynReceived) {
      (void)process_ack(seg, now);
    }
    return;
  }

  // Second: RST (RFC 5961 §3.2: exact match resets, in-window gets a challenge ACK).
  if (seg.has(kRst)) {
    if (seg.seq != rcv_nxt_) {
      ack_now_ = true;
      ++stats_.challenge_acks;
      SIM_PROBE("utcp.challenge_ack_for_rst");
      return;
    }
    switch (state_) {
      case State::SynReceived:
        // Passive: back to LISTEN (the stack frees the slot); active: refused.
        enter_closed(passive_ ? CloseReason::Reset : CloseReason::Refused);
        break;
      case State::Closing:
      case State::LastAck:
      case State::TimeWait: enter_closed(CloseReason::Normal); break;
      default: enter_closed(CloseReason::Reset); break;
    }
    return;
  }

  // Fourth: SYN in a synchronized state gets a challenge ACK (RFC 5961 §4, RFC 9293).
  if (seg.has(kSyn)) {
    ack_now_ = true;
    ++stats_.challenge_acks;
    SIM_PROBE("utcp.challenge_ack_for_syn");
    return;
  }

  // Fifth: ACK.
  if (!seg.has(kAck)) return;
  if (!process_ack(seg, now)) return;
  if (state_ == State::Closed) return;

  // Trim to the receive window for text processing.
  std::uint32_t seq = seg.seq;
  std::span<const std::byte> data = seg.payload;
  bool fin = seg.has(kFin);
  if (seq_lt(seq, rcv_nxt_)) {
    const std::uint32_t skip = rcv_nxt_ - seq;
    if (skip >= data.size()) {
      if (skip > data.size()) fin = false;  // the FIN is old too
      seq += static_cast<std::uint32_t>(data.size());
      data = {};
    } else {
      data = data.subspan(skip);
      seq = rcv_nxt_;
    }
  }
  if (!data.empty()) {
    const std::uint32_t room = seq_lt(seq, rcv_adv_) ? rcv_adv_ - seq : 0;
    if (data.size() > room) {
      data = data.first(room);
      fin = false;
    }
  }

  // Seventh: segment text.
  if (!data.empty() || fin) {
    if (state_ != State::Established && state_ != State::FinWait1 && state_ != State::FinWait2) {
      return;  // CLOSE-WAIT/CLOSING/LAST-ACK/TIME-WAIT: the peer already sent FIN
    }
    if (seq != rcv_nxt_) {
      // Out of order: dropped (legal; the peer retransmits). One duplicate ACK per
      // dropped segment drives the peer's fast retransmit (RFC 5681 §4.2).
      ++stats_.ooo_dropped;
      SIM_PROBE("utcp.ooo_segment_dropped");
      if (dupacks_to_send_ < 255) ++dupacks_to_send_;
      return;
    }
    if (!data.empty()) {
      const std::size_t n = rx_.write(data);
      rcv_nxt_ += static_cast<std::uint32_t>(n);
      stats_.bytes_in += n;
      events_ |= ev::kReadable;
      ack_now_ = true;
      if (n < data.size()) fin = false;
      if (state_ == State::FinWait2) fin_wait2_deadline_ = now + cfg_.fin_wait2_timeout;
    }
  }

  // Eighth: FIN.
  if (fin) {
    rcv_nxt_ += 1;
    if (seq_gt(rcv_nxt_, rcv_adv_)) rcv_adv_ = rcv_nxt_;
    fin_received_ = true;
    events_ |= ev::kPeerFin;
    ack_now_ = true;
    switch (state_) {
      case State::Established: state_ = State::CloseWait; break;
      case State::FinWait1:
        if (fin_acked()) {
          enter_time_wait(now);
        } else {
          state_ = State::Closing;  // simultaneous close
        }
        break;
      case State::FinWait2: enter_time_wait(now); break;
      default: break;
    }
  }
}

bool Connection::process_ack(const TcpSegment& seg, Nanos now) noexcept {
  if (state_ == State::SynReceived) {
    if (!(seq_lt(snd_una_, seg.ack) && seq_le(seg.ack, snd_max_))) {
      queue_rst(seg.ack, 0, false);
      return false;
    }
    snd_wnd_ = seg.window;
    max_snd_wnd_ = std::max(max_snd_wnd_, snd_wnd_);
    snd_wl1_ = seg.seq;
    snd_wl2_ = seg.ack;
    enter_established();
  }
  if (seq_gt(seg.ack, snd_max_)) {
    ack_now_ = true;  // acknowledges something not yet sent
    return false;
  }
  if (seq_ge(seg.ack, snd_una_)) {
    // Duplicate-ACK detection (RFC 5681 §2) before the window update.
    if (seg.ack == snd_una_ && seq_gt(snd_max_, snd_una_) && seg.payload.empty() && !seg.has(kSyn) &&
        !seg.has(kFin) && seg.window == snd_wnd_) {
      ++stats_.dupacks_in;
      if (cfg_.dupack_threshold != 0 && !in_recovery_ && ++dupacks_ >= cfg_.dupack_threshold) {
        in_recovery_ = true;
        recover_ = snd_max_;
        rtx_one_ = true;
        dupacks_ = 0;
        ++stats_.fast_retransmits;
        SIM_PROBE("utcp.fast_retransmit");
      }
    }
    // Send-window update (RFC 9293 §3.10.7.4, SND.WL1/SND.WL2 rule).
    if (seq_lt(snd_wl1_, seg.seq) || (snd_wl1_ == seg.seq && seq_le(snd_wl2_, seg.ack))) {
      snd_wnd_ = seg.window;
      max_snd_wnd_ = std::max(max_snd_wnd_, snd_wnd_);
      snd_wl1_ = seg.seq;
      snd_wl2_ = seg.ack;
    }
    if (seq_gt(seg.ack, snd_una_)) ack_advance(seg.ack, now);
  }
  // A live peer advertising a zero window: probing continues indefinitely
  // (RFC 9293 §3.8.6.1), so probes do not count toward the retransmission limit.
  if (snd_wnd_ == 0) rtx_count_ = 0;

  switch (state_) {
    case State::FinWait1:
      if (fin_acked()) {
        state_ = State::FinWait2;
        fin_wait2_deadline_ = now + cfg_.fin_wait2_timeout;
      }
      break;
    case State::Closing:
      if (fin_acked()) enter_time_wait(now);
      break;
    case State::LastAck:
      if (fin_acked()) {
        enter_closed(CloseReason::Normal);
        return false;
      }
      break;
    default: break;
  }
  return true;
}

void Connection::ack_advance(std::uint32_t ack, Nanos now) noexcept {
  const std::uint32_t acked = ack - snd_una_;
  if (seq_gt(ack, tx_base_)) {
    const auto n = static_cast<std::uint32_t>(std::min<std::size_t>(ack - tx_base_, tx_.size()));
    if (n != 0) {
      tx_.consume(n);
      tx_base_ += n;
      events_ |= ev::kWritable;
    }
  }
  snd_una_ = ack;
  if (seq_lt(snd_nxt_, snd_una_)) snd_nxt_ = snd_una_;
  // Karn's rule: only segments never retransmitted are timed.
  if (rtt_timing_ && seq_gt(ack, rtt_seq_)) {
    rtt_timing_ = false;
    rtt_sample(now - rtt_start_);
  }
  rtx_count_ = 0;
  dupacks_ = 0;
  // After an RTO the in-flight cap restarts at one MSS and grows per ACK (slow-start
  // shape) back to max_inflight.
  if (cwnd_ < cfg_.max_inflight) {
    cwnd_ = std::min(cfg_.max_inflight, cwnd_ + std::min<std::uint32_t>(acked, snd_mss_));
  }
  if (in_recovery_) {
    if (seq_ge(ack, recover_)) {
      in_recovery_ = false;
    } else {
      rtx_one_ = true;  // partial ACK: the next hole (RFC 6582 §3.2 step 3)
    }
  }
  // RFC 6298 §5.2/5.3: stop when all is acknowledged, otherwise restart.
  rto_deadline_ = snd_una_ == snd_max_ ? kNoDeadline : now + rto_;
}

void Connection::rtt_sample(Nanos r) noexcept {
  if (r < 0) r = 0;
  ++stats_.rtt_samples;
  if (!have_rtt_) {
    srtt_ = r;  // RFC 6298 §2.2
    rttvar_ = r / 2;
    have_rtt_ = true;
  } else {
    // RFC 6298 §2.3 with alpha = 1/8, beta = 1/4, in integer nanoseconds.
    const Nanos d = srtt_ > r ? srtt_ - r : r - srtt_;
    rttvar_ = rttvar_ - rttvar_ / 4 + d / 4;
    srtt_ = srtt_ - srtt_ / 8 + r / 8;
  }
  rto_ = std::clamp(srtt_ + std::max(cfg_.clock_granularity, 4 * rttvar_), cfg_.min_rto, cfg_.max_rto);
}

// ---------------------------------------------------------------------------
// Application calls
// ---------------------------------------------------------------------------

Actions Connection::send(std::span<const std::byte> data, Nanos now) noexcept {
  const bool open = !fin_queued_ && (state_ == State::SynSent || state_ == State::SynReceived ||
                                     state_ == State::Established || state_ == State::CloseWait);
  const std::size_t n = open ? tx_.write(data) : 0;
  Actions a = finish(now);
  a.accepted = static_cast<std::uint32_t>(n);
  return a;
}

Actions Connection::consume(std::size_t n, Nanos now) noexcept {
  rx_.consume(n);
  if (state_ == State::Established || state_ == State::FinWait1 || state_ == State::FinWait2) {
    // Window update when the window at least doubles and grows by the SWS threshold
    // (the rule Linux uses in tcp_cleanup_rbuf; RFC 9293 §3.8.6.2.2).
    const std::uint32_t cur = rcv_window();
    const auto avail = static_cast<std::uint32_t>(std::min<std::size_t>(rx_.free(), kMaxWindow));
    const auto clamp = static_cast<std::uint32_t>(std::min<std::size_t>(rx_.capacity(), kMaxWindow));
    if (avail > cur && avail - cur >= window_threshold() && 2 * cur <= clamp && avail >= 2 * cur) {
      ack_now_ = true;
      ++stats_.window_updates;
    }
  }
  return finish(now);
}

Actions Connection::close(Nanos now) noexcept {
  switch (state_) {
    case State::SynSent: enter_closed(CloseReason::Aborted); break;
    case State::SynReceived:
      // RFC 9293 §3.10.4: queue the FIN until ESTABLISHED.
      fin_queued_ = true;
      fin_seq_ = data_end();
      break;
    case State::Established:
      fin_queued_ = true;
      fin_seq_ = data_end();
      state_ = State::FinWait1;
      break;
    case State::CloseWait:
      fin_queued_ = true;
      fin_seq_ = data_end();
      state_ = State::LastAck;
      break;
    default: break;  // already closing or closed
  }
  return finish(now);
}

Actions Connection::abort(Nanos now) noexcept {
  switch (state_) {
    case State::SynReceived:
    case State::Established:
    case State::FinWait1:
    case State::FinWait2:
    case State::CloseWait: queue_rst(acceptable_seq(), 0, false); break;
    default: break;
  }
  if (state_ != State::Closed) enter_closed(CloseReason::Aborted);
  return finish(now);
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

Actions Connection::on_timer(Nanos now) noexcept {
  if (state_ == State::TimeWait && now >= time_wait_deadline_) {
    enter_closed(CloseReason::Normal);
  } else if (state_ == State::FinWait2 && now >= fin_wait2_deadline_) {
    queue_rst(acceptable_seq(), 0, false);
    enter_closed(CloseReason::Timeout);
  } else if (rto_deadline_ != kNoDeadline && now >= rto_deadline_) {
    on_rto(now);
  }
  return finish(now);
}

void Connection::on_rto(Nanos now) noexcept {
  rto_deadline_ = kNoDeadline;
  if (state_ == State::Closed || state_ == State::TimeWait || state_ == State::FinWait2) return;
  if (snd_una_ == snd_max_) {
    // Persist timer: nothing outstanding, peer window zero (RFC 9293 §3.8.6.1).
    if (can_send_data() && snd_wnd_ == 0 && has_unsent()) {
      probe_ = true;
      rto_ = std::min(rto_ * 2, cfg_.max_rto);
      rto_deadline_ = now + rto_;
    }
    return;
  }
  const bool syn_state = state_ == State::SynSent || state_ == State::SynReceived;
  const std::uint8_t limit = syn_state ? cfg_.max_syn_retransmits : cfg_.max_retransmits;
  if (rtx_count_ >= limit) {
    // The peer most likely never received what is outstanding, so its RCV.NXT is our
    // SND.UNA: an exact match for RFC 5961 (no challenge-ACK round trip).
    if (state_ != State::SynSent) queue_rst(snd_una_, 0, false);
    enter_closed(CloseReason::Timeout);
    return;
  }
  ++rtx_count_;
  ++stats_.rto_expiries;
  SIM_PROBE("utcp.rto_expiry");
  if (rto_ * 2 >= cfg_.max_rto) SIM_PROBE("utcp.rto_backed_off_to_max");
  // RFC 6298 §5.4–5.6: retransmit the earliest unacknowledged segment, back off, restart.
  rto_ = std::min(rto_ * 2, cfg_.max_rto);
  snd_nxt_ = snd_una_;  // go-back-N
  cwnd_ = snd_mss_;
  rtt_timing_ = false;
  in_recovery_ = false;
  dupacks_ = 0;
  if (!syn_state && snd_wnd_ == 0) probe_ = true;
  rto_deadline_ = now + rto_;
}

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

void Connection::enter_established() noexcept {
  state_ = State::Established;
  events_ |= ev::kConnected;
  if (fin_queued_) state_ = State::FinWait1;  // close() was called in SYN-RECEIVED
}

void Connection::enter_time_wait(Nanos now) noexcept {
  SIM_PROBE("utcp.time_wait");
  state_ = State::TimeWait;
  time_wait_deadline_ = now + cfg_.time_wait;
  rto_deadline_ = kNoDeadline;
  events_ |= ev::kTimeWait;
}

void Connection::enter_closed(CloseReason r) noexcept {
  state_ = State::Closed;
  reason_ = r;
  events_ |= ev::kClosed;
  rto_deadline_ = kNoDeadline;
  time_wait_deadline_ = fin_wait2_deadline_ = kNoDeadline;
  ack_now_ = false;
  dupacks_to_send_ = 0;
  rtx_one_ = probe_ = false;
}

void Connection::queue_rst(std::uint32_t seq, std::uint32_t ack, bool with_ack) noexcept {
  rst_pending_ = true;
  rst_seq_ = seq;
  rst_ack_ = ack;
  rst_with_ack_ = with_ack;
}

void Connection::update_timer(Nanos now) noexcept {
  if (state_ == State::Closed || state_ == State::TimeWait) {
    rto_deadline_ = kNoDeadline;
    return;
  }
  if (snd_max_ != snd_una_) return;  // armed when the data was sent
  if (can_send_data() && snd_wnd_ == 0 && has_unsent()) {
    arm_rto(now);  // persist timer
  } else if (!probe_) {
    rto_deadline_ = kNoDeadline;
  }
}

Actions Connection::finish(Nanos now) noexcept {
  update_timer(now);
  Actions a;
  a.events = events_;
  events_ = 0;
  a.tx_pending = tx_pending();
  a.deadline = deadline();
  return a;
}

Nanos Connection::deadline() const noexcept {
  Nanos d = rto_deadline_;
  if (state_ == State::TimeWait) d = std::min(d, time_wait_deadline_);
  if (state_ == State::FinWait2) d = std::min(d, fin_wait2_deadline_);
  return d;
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

bool Connection::has_unsent() const noexcept {
  return seq_lt(snd_nxt_, data_end()) || (fin_queued_ && seq_le(snd_nxt_, fin_seq_));
}

bool Connection::can_send_data() const noexcept {
  return state_ == State::Established || state_ == State::CloseWait || state_ == State::FinWait1 ||
         state_ == State::Closing || state_ == State::LastAck;
}

std::uint32_t Connection::sendable_len() const noexcept {
  if (!can_send_data() || !has_unsent()) return 0;
  const std::uint32_t limit = snd_una_ + std::min(snd_wnd_, cwnd_);
  if (!seq_gt(limit, snd_nxt_)) return 0;
  const std::uint32_t usable = limit - snd_nxt_;
  const std::uint32_t end = data_end();
  const std::uint32_t unsent = seq_lt(snd_nxt_, end) ? end - snd_nxt_ : 0;
  if (unsent == 0) return 1;  // FIN only
  const std::uint32_t want = std::min<std::uint32_t>(unsent, snd_mss_);
  if (usable >= want) return want;
  // Window-limited: sender SWS avoidance (RFC 9293 §3.8.6.2.1). Send a partial segment
  // only when nothing is in flight, when retransmitting after go-back-N (as BSD's
  // tcp_output does for SND.NXT < SND.MAX), or when it is at least half the largest
  // window offered; otherwise the next ACK opens more room. No Nagle: small writes go
  // out at once.
  if (snd_nxt_ == snd_una_ || seq_lt(snd_nxt_, snd_max_) || usable >= max_snd_wnd_ / 2) return usable;
  return 0;
}

bool Connection::tx_pending() const noexcept {
  if (rst_pending_) return true;
  switch (state_) {
    case State::Closed: return false;
    case State::SynSent: return snd_nxt_ == iss_ || rtx_one_;
    case State::SynReceived: return snd_nxt_ == iss_ || rtx_one_ || ack_now_ || dupacks_to_send_ != 0;
    default: return rtx_one_ || probe_ || ack_now_ || dupacks_to_send_ != 0 || sendable_now();
  }
}

std::uint32_t Connection::window_threshold() const noexcept {
  const auto half = static_cast<std::uint32_t>(std::min<std::size_t>(rx_.capacity(), kMaxWindow) / 2);
  return std::max<std::uint32_t>(1, std::min<std::uint32_t>(cfg_.mss, half));
}

std::uint16_t Connection::advertise_window() noexcept {
  const auto avail = static_cast<std::uint32_t>(std::min<std::size_t>(rx_.free(), kMaxWindow));
  if (state_ == State::SynSent || state_ == State::Closed) return static_cast<std::uint16_t>(avail);
  // Receiver SWS avoidance: move the right edge only by at least min(MSS, buffer/2),
  // or when the buffer is completely free. The edge never moves left.
  const std::uint32_t edge = rcv_nxt_ + avail;
  if (seq_gt(edge, rcv_adv_)) {
    const auto full = static_cast<std::uint32_t>(std::min<std::size_t>(rx_.capacity(), kMaxWindow));
    if (edge - rcv_adv_ >= window_threshold() || avail == full) rcv_adv_ = edge;
  }
  return static_cast<std::uint16_t>(std::min(rcv_adv_ - rcv_nxt_, kMaxWindow));
}

std::size_t Connection::build(std::span<std::byte> out, std::uint32_t seq, std::uint8_t flags, std::uint32_t data_len,
                              bool mss_option) noexcept {
  TcpHeaderSpec h;
  h.src_mac = flow_.local_mac;
  h.dst_mac = flow_.remote_mac;
  h.src_ip = flow_.local_ip;
  h.dst_ip = flow_.remote_ip;
  h.src_port = flow_.local_port;
  h.dst_port = flow_.remote_port;
  h.seq = seq;
  h.ack = (flags & kAck) != 0 ? rcv_nxt_ : 0;
  h.window = (flags & kRst) != 0 ? std::uint16_t{0} : advertise_window();
  h.mss_option = mss_option ? cfg_.mss : std::uint16_t{0};
  h.ip_id = ip_id_++;
  h.flags = flags;
  h.ttl = cfg_.ttl;
  ByteRing::Spans s;
  if (data_len != 0) s = tx_.peek(seq - tx_base_, data_len);
  const std::size_t n = build_tcp(out, link_, h, s.first, s.second, cfg_.tx_checksum_offload);
  if (n != 0) ++stats_.segs_out;
  return n;
}

std::size_t Connection::emit_data(std::span<std::byte> out, std::uint32_t seq, std::uint32_t max_data,
                                  std::uint32_t seq_budget, Nanos now) noexcept {
  const std::uint32_t end = data_end();
  const std::uint32_t avail = seq_lt(seq, end) ? end - seq : 0;
  const std::uint32_t len = std::min({avail, max_data, seq_budget});
  const bool fin = fin_queued_ && seq + len == fin_seq_ && len < seq_budget;
  if (len == 0 && !fin) return 0;
  const auto flags = static_cast<std::uint8_t>(kAck | (fin ? kFin : 0) | (len != 0 ? kPsh : 0));
  const std::size_t n = build(out, seq, flags, len, false);
  if (n == 0) return 0;
  const std::uint32_t seg_end = seq + len + (fin ? 1u : 0u);
  if (seq_lt(seq, snd_max_)) {
    ++stats_.retransmit_segs;
    if (rtt_timing_ && seq_le(seq, rtt_seq_) && seq_lt(rtt_seq_, seg_end)) rtt_timing_ = false;  // Karn
  } else if (!rtt_timing_) {
    rtt_timing_ = true;
    rtt_seq_ = seg_end - 1;
    rtt_start_ = now;
  }
  if (seq_gt(seg_end, snd_nxt_)) snd_nxt_ = seg_end;
  snd_max_ = seq_max(snd_max_, snd_nxt_);
  stats_.bytes_out += len;
  ack_now_ = false;  // piggybacked
  arm_rto(now);
  return n;
}

std::size_t Connection::next_tx(std::span<std::byte> out, Nanos now) noexcept {
  if (rst_pending_) {
    const auto flags = static_cast<std::uint8_t>(kRst | (rst_with_ack_ ? kAck : 0));
    const std::uint32_t saved = rcv_nxt_;
    rcv_nxt_ = rst_ack_;  // build() takes the ACK field from rcv_nxt_
    const std::size_t n = build(out, rst_seq_, flags, 0, false);
    rcv_nxt_ = saved;
    if (n != 0) rst_pending_ = false;
    return n;
  }
  switch (state_) {
    case State::Closed: return 0;
    case State::SynSent:
    case State::SynReceived: {
      if (snd_nxt_ == iss_ || rtx_one_) {
        const bool retransmission = snd_max_ != iss_;
        const auto flags = static_cast<std::uint8_t>(kSyn | (state_ == State::SynReceived ? kAck : 0));
        const std::size_t n = build(out, iss_, flags, 0, true);
        if (n == 0) return 0;
        rtx_one_ = false;
        snd_nxt_ = iss_ + 1;
        snd_max_ = seq_max(snd_max_, snd_nxt_);
        if (retransmission) {
          ++stats_.retransmit_segs;
          rtt_timing_ = false;
        } else if (!rtt_timing_) {
          rtt_timing_ = true;
          rtt_seq_ = iss_;
          rtt_start_ = now;
        }
        ack_now_ = false;
        arm_rto(now);
        return n;
      }
      if (state_ == State::SynReceived && (ack_now_ || dupacks_to_send_ != 0)) break;
      return 0;
    }
    default: {
      if (rtx_one_) {
        rtx_one_ = false;
        if (seq_lt(snd_una_, snd_max_)) {
          const std::size_t n = emit_data(out, snd_una_, snd_mss_, std::uint32_t{snd_mss_} + 1, now);
          if (n != 0) return n;
        }
      }
      if (probe_) {
        probe_ = false;
        if (can_send_data()) {
          const std::size_t n = emit_data(out, snd_nxt_, 1, 1, now);
          if (n != 0) {
            ++stats_.zero_window_probes;
            SIM_PROBE("utcp.zero_window_probe");
            return n;
          }
        }
      }
      if (const std::uint32_t len = sendable_len(); len != 0) {
        const std::uint32_t limit = snd_una_ + std::min(snd_wnd_, cwnd_);
        const std::size_t n = emit_data(out, snd_nxt_, len, limit - snd_nxt_, now);
        if (n != 0) return n;
      }
      break;
    }
  }
  if (ack_now_ || dupacks_to_send_ != 0) {
    // A pure ACK carries the highest sequence number sent, never the pulled-back SND.NXT
    // of go-back-N (that could lie left of the peer's window, making the peer discard the
    // ACK while it retransmits into our discarding side: mutual livelock), but never
    // beyond the peer's right window edge either: with a zero window the peer accepts
    // only SEG.SEQ = RCV.NXT, and Linux >= 6.x also drops a one-byte probe while its
    // receive queue is non-empty, so this ACK is the only one it will process.
    const std::size_t n = build(out, acceptable_seq(), kAck, 0, false);
    if (n == 0) return 0;
    if (ack_now_) {
      ack_now_ = false;
    } else {
      --dupacks_to_send_;
      ++stats_.dupacks_out;
    }
    return n;
  }
  return 0;
}

bool Connection::invariants_ok() const noexcept {
  if (rx_.size() > rx_.capacity() || tx_.size() > tx_.capacity()) return false;
  if (state_ == State::Closed) return true;
  if (!seq_le(snd_una_, snd_nxt_) || !seq_le(snd_nxt_, snd_max_)) return false;
  if (state_ == State::SynSent || state_ == State::SynReceived) {
    return seq_le(snd_max_, iss_ + 1) && tx_base_ == iss_ + 1;
  }
  // Synchronized: the SYN is acknowledged; snd_una_ is at the data base, or one past
  // it once our FIN is acknowledged.
  const std::uint32_t fin_extra = fin_queued_ ? 1u : 0u;
  if (!seq_le(snd_max_, data_end() + fin_extra)) return false;
  if (snd_una_ != tx_base_ && !(fin_queued_ && snd_una_ == tx_base_ + 1 && tx_.empty())) return false;
  if (!seq_le(rcv_nxt_, rcv_adv_) || rcv_adv_ - rcv_nxt_ > kMaxWindow) return false;
  if (fin_queued_ && fin_seq_ != data_end()) return false;
  return true;
}

}  // namespace lle::net::utcp
