#include "net/uring/udp_port.h"

#include <cerrno>
#include <cstring>

#include "net/hwts/cmsg.h"
#include "net/sock/socket_setup.h"

namespace lle::net::uring {

TxStamp tx_stamp_from_cqe(const Cqe& c) noexcept {
  TxStamp s{};
  s.id = static_cast<std::uint32_t>(c.res);
#if defined(IORING_TIMESTAMP_HW_SHIFT)
  s.type = c.flags >> IORING_TIMESTAMP_TYPE_SHIFT;
  const Nanos ns = static_cast<Nanos>(c.big[0]) * kNsPerSec + static_cast<Nanos>(c.big[1]);
  if ((c.flags & IORING_CQE_F_TSTAMP_HW) != 0) {
    s.ts.hw_ns = ns;
  } else {
    s.ts.sw_ns = ns;
  }
#endif
  return s;
}

Result<void> UdpPort::open(const UdpConfig& cfg, Ring* ring, const RingConfig& own) {
  if (is_open() || ring_ != nullptr) return fail("uring::UdpPort::open", EALREADY);
  if (cfg.batch == 0 || cfg.max_datagram == 0 || cfg.tx_slots == 0 || cfg.tx_slots > 0xFFFF || cfg.rx_buffers == 0 ||
      (cfg.rx_buffers & (cfg.rx_buffers - 1)) != 0)
    return fail("uring::UdpPort::open", EINVAL);
  cfg_ = cfg;
  if (ring == nullptr) {
    RingConfig rc = own;
    if (cfg.tx_ts != TsMode::Off) rc.cqe32 = true;
    if (rc.cq_entries < 2 * (cfg.rx_buffers + cfg.tx_slots)) rc.cq_entries = 2 * (cfg.rx_buffers + cfg.tx_slots);
    if (auto r = own_ring_.open(rc); !r) return r;
    ring_ = &own_ring_;
    owns_ = true;
  } else {
    if (!ring->is_open()) return fail("uring::UdpPort::open", EBADF);
    ring_ = ring;
  }
  auto fail_close = [this](Error e) {
    close();
    return std::unexpected(e);
  };
  auto so = sock::open_udp_socket(cfg);
  if (!so) return fail_close(so.error());
  local_ = so->local;
  ts_flags_ = so->ts_flags;
  fd_ = std::move(so->fd);
  auto fixed = ring_->register_file(fd_.get());
  if (!fixed) return fail_close(fixed.error());
  fixed_ = *fixed;
  fixed_ok_ = true;
  epoch_ = ring_->next_epoch();

  // Every outstanding operation can complete at most once before the port drains it.
  rx_q_.init(std::size_t{cfg.rx_buffers} + 8);
  tx_q_.init(std::size_t{cfg.tx_slots} + 8);
  ts_q_.init(4 * std::size_t{cfg.tx_slots} + 64);
  for (auto [q, id] : {std::pair{&rx_q_, &rx_sink_}, std::pair{&tx_q_, &tx_sink_}, std::pair{&ts_q_, &ts_sink_}}) {
    auto sid = ring_->add_sink(*q);
    if (!sid) return fail_close(sid.error());
    *id = *sid;
  }
  tmpl_ = msghdr{};
  tmpl_.msg_namelen = sizeof(sockaddr_in);
  tmpl_.msg_controllen = kControlBytes;
  const std::uint32_t buf = static_cast<std::uint32_t>(sizeof(io_uring_recvmsg_out) + sizeof(sockaddr_in)) +
                            kControlBytes + cfg.max_datagram;
  if (auto r = bufs_.init(*ring_, cfg.rx_buffers, buf); !r) return fail_close(r.error());
  if (auto r = tx_.init(cfg.tx_slots, cfg.max_datagram, 64); !r) return fail_close(r.error());
  tx_addr_ = std::make_unique<sockaddr_in[]>(cfg.tx_slots);
  want_ts_ = cfg.rx_ts != TsMode::Off;
  ts_uring_ = cfg.tx_ts != TsMode::Off && tx_timestamp_cmd_compiled() && ring_->cqe32();

  arm_recv();
  if (ts_uring_) arm_tx_ts();
  (void)ring_->submit();
  return {};
}

void UdpPort::close() noexcept {
  if (ring_ != nullptr && ring_->is_open()) {
    if (fixed_ok_) {
      if (io_uring_sqe* s = ring_->sqe(); s != nullptr) {
        io_uring_prep_cancel_fd(s, static_cast<int>(fixed_), IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_FD_FIXED);
        io_uring_sqe_set_data64(s, make_ud(0, 0, 0));
      }
      (void)ring_->poll(0);
      ring_->unregister_file(fixed_);
      fixed_ok_ = false;
    }
    bufs_.destroy();
    for (std::uint8_t* id : {&rx_sink_, &tx_sink_, &ts_sink_}) {
      ring_->remove_sink(*id);
      *id = 0;
    }
  }
  fd_.reset();
  rx_armed_ = ts_armed_ = false;
  if (owns_) {
    own_ring_.close();
    owns_ = false;
  }
  ring_ = nullptr;
}

bool UdpPort::send(Endpoint dst, std::span<const std::byte> data) noexcept {
  if (data.size() > tx_.buf_size()) {
    ++stats_.tx_errors;
    return false;
  }
  if (!tx_q_.empty()) reap_tx();
  std::uint32_t slot = 0;
  if (!tx_.acquire(slot)) {
    (void)ring_->poll(0);
    reap_tx();
    if (!tx_.acquire(slot)) {
      ++stats_.tx_dropped;
      return false;
    }
  }
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) {
    tx_.release(slot);
    ++stats_.tx_dropped;
    return false;
  }
  std::memcpy(tx_.data(slot), data.data(), data.size());
  tx_addr_[slot] = to_sockaddr(dst);
  io_uring_prep_sendto(s, static_cast<int>(fixed_), tx_.data(slot), data.size(), 0,
                       reinterpret_cast<const sockaddr*>(&tx_addr_[slot]), sizeof(sockaddr_in));
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, make_ud(tx_sink_, kOpSend, make_aux(epoch_, slot)));
  (void)ring_->submit();  // latency path: issue now (inline under DEFER_TASKRUN)
  return true;
}

void UdpPort::reap_tx() noexcept {
  while (!tx_q_.empty()) {
    const Cqe c = tx_q_.front();
    tx_q_.pop();
    if (aux_epoch(c.user_data) != epoch_) continue;
    tx_.release(aux_payload(c.user_data));
    if (c.res >= 0) {
      ++stats_.tx_packets;
      stats_.tx_bytes += static_cast<std::uint64_t>(c.res);
    } else if (c.res == -EAGAIN || c.res == -ENOBUFS) {
      ++stats_.tx_dropped;
    } else if (c.res != -ECANCELED) {
      ++stats_.tx_errors;
    }
  }
}

void UdpPort::arm_recv() noexcept {
  if (!fd_ || !fixed_ok_) return;
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) return;  // retried on the next poll
  io_uring_prep_recvmsg_multishot(s, static_cast<int>(fixed_), &tmpl_, 0);
  s->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
  s->buf_group = bufs_.group();
  io_uring_sqe_set_data64(s, make_ud(rx_sink_, kOpRecv, make_aux(epoch_, 0)));
  if (armed_once_) ++stats_.rearms;
  armed_once_ = true;
  rx_armed_ = true;
}

void UdpPort::arm_tx_ts() noexcept {
#if defined(IORING_TIMESTAMP_HW_SHIFT)
  if (!fd_ || !fixed_ok_) return;
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) return;
  io_uring_prep_cmd_sock(s, SOCKET_URING_OP_TX_TIMESTAMP, static_cast<int>(fixed_), 0, 0, nullptr, 0);
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, make_ud(ts_sink_, kOpTxTs, make_aux(epoch_, 0)));
  ts_armed_ = true;
#endif
}

void UdpPort::on_recv_error(const Cqe& c) noexcept {
  if (c.res == -ENOBUFS) {
    ++stats_.no_buffers;
  } else if (c.res != -ECANCELED && c.res < 0) {
    ++stats_.rx_errors;
  }
}

void UdpPort::on_ts_error(const Cqe& c) noexcept {
  if (c.res == -ECANCELED) return;
  if (!cqe_more(c) && (c.res == -EINVAL || c.res == -EOPNOTSUPP || c.res == -ENOTTY)) {
    ts_uring_ = false;  // kernel without SOCKET_URING_OP_TX_TIMESTAMP: read the error queue
    return;
  }
  ++stats_.tx_errors;
}

bool UdpPort::parse_recv(const Cqe& c, std::uint16_t bid, env::RxDatagram& d, RxTimestamps& ts) noexcept {
  ++stats_.rx_calls;
  if (c.res < 0) {
    on_recv_error(c);
    return false;
  }
  void* buf = bufs_.data(bid);
  io_uring_recvmsg_out* out = io_uring_recvmsg_validate(buf, c.res, &tmpl_);
  if (out == nullptr) {
    ++stats_.rx_errors;
    return false;
  }
  if ((out->flags & MSG_TRUNC) != 0) {
    ++stats_.rx_truncated;
    return false;
  }
  sockaddr_in sa{};
  if (out->namelen >= sizeof(sa)) std::memcpy(&sa, io_uring_recvmsg_name(out), sizeof(sa));
  hwts::ControlInfo ci{};
  if (out->controllen > 0) {
    const auto* ctrl = static_cast<const std::byte*>(io_uring_recvmsg_name(out)) + tmpl_.msg_namelen;
    hwts::parse_control(ctrl, out->controllen, ci);
  }
  const auto* payload = static_cast<const std::byte*>(io_uring_recvmsg_payload(out, &tmpl_));
  const unsigned len = io_uring_recvmsg_payload_length(out, c.res, &tmpl_);
  d.data = {payload, len};
  d.src = from_sockaddr(sa);
  d.dst = ci.has_dst ? Endpoint{ci.dst_ipv4, local_.port} : local_;
  d.hw_rx_ns = ci.ts.hw_ns;
  ts = ci.ts;
  if (want_ts_) stats_.rx_ts.record(classify(ci.ts));
  ++stats_.rx_packets;
  stats_.rx_bytes += len;
  return true;
}

}  // namespace lle::net::uring
