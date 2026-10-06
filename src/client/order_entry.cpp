#include "client/order_entry.h"

#include <algorithm>
#include <cstring>

#include "common/assert.h"
#include "common/endian.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client {

HaOrderEntry::HaOrderEntry(const OrderEntryConfig& cfg)
    : cfg_(cfg), ring_(std::make_unique<Entry[]>(cfg.pending_capacity)), cap_(cfg.pending_capacity) {
  LLE_ASSERT(cap_ >= 1);
  next_seq_ = cfg.session.sequence == 0 ? 1 : cfg.session.sequence;
}

void HaOrderEntry::on_connected(std::size_t i, Nanos now) {
  Instance& k = inst_[i];
  soup::ClientConfig c = cfg_.session;
  c.sequence = next_seq_;  // line the stream up with what was already processed
  k.session.emplace(c);
  k.state = InstState::LoggingIn;
  k.close = false;
  absorb(i, k.session->connect(now), now);
}

void HaOrderEntry::on_closed(std::size_t i, Nanos now) {
  Instance& k = inst_[i];
  k.session.reset();
  k.close = false;
  if (k.state != InstState::Down) fail(i, now);
}

void HaOrderEntry::on_timer(Nanos now) {
  for (std::size_t i = 0; i < kInstances; ++i) {
    Instance& k = inst_[i];
    if (!k.session) continue;
    const soup::Actions& a = k.session->on_timer(now);
    absorb(i, a, now);
  }
  pump(now);
}

void HaOrderEntry::absorb(std::size_t i, const soup::Actions& a, Nanos now) {
  Instance& k = inst_[i];
  for (const soup::Event& e : a.events) {
    switch (e.kind) {
      case soup::EventKind::LoggedIn:
        ++st_.logins;
        if (e.seq > next_seq_) ++st_.sequence_jumps;  // server started above what we asked for
        k.state = InstState::Active;
        maybe_activate(now);
        break;
      case soup::EventKind::LoginRejected: ++st_.login_rejects; break;
      case soup::EventKind::Closed:
      case soup::EventKind::EndOfSession:
        if (k.state != InstState::Down) fail(i, now);
        k.close = true;
        break;
      default: break;
    }
  }
}

void HaOrderEntry::become_active(std::size_t i, Nanos now) {
  active_ = static_cast<int>(i);
  unsent_ = head_;  // every pending message goes out again, in its original order
  pump(now);
}

void HaOrderEntry::maybe_activate(Nanos now) {
  if (active_ >= 0) return;
  if (inst_[0].state == InstState::Active) {
    become_active(0, now);
  } else if (inst_[1].state == InstState::Active && inst_[0].state == InstState::Down) {
    become_active(1, now);  // the primary is not coming: the backup carries the session
  }
}

void HaOrderEntry::fail(std::size_t i, Nanos now) {
  Instance& k = inst_[i];
  const bool was_active = active_ == static_cast<int>(i);
  k.state = InstState::Down;
  ++st_.instance_failures;
  if (!was_active) {
    maybe_activate(now);  // a primary that never logged in: the waiting backup goes ahead
    return;
  }
  active_ = -1;
  unsent_ = head_;  // pending messages go out again on whichever instance takes over
  const std::size_t other = 1 - i;
  if (inst_[other].state == InstState::Active) {
    ++st_.takeovers;
    become_active(other, now);
  }
}

bool HaOrderEntry::send(std::span<const std::byte> ouch, Nanos now) {
  if (ouch.empty() || ouch.size() > kMaxMsg) return false;
  if (tail_ - head_ >= cap_) {
    ++st_.pending_full;
    return false;
  }
  Entry& e = at(tail_);
  e.type = static_cast<char>(ouch[0]);
  e.len = static_cast<std::uint16_t>(ouch.size());
  std::memcpy(e.bytes.data(), ouch.data(), ouch.size());
  e.consumed = ouch50::peek_new_user_ref_num(ouch).value_or(0);
  e.acked = false;
  e.refers = 0;
  if ((e.type == 'X' || e.type == 'M') && ouch.size() >= 5) e.refers = load_be32(ouch.data() + 1);
  if (e.type == 'U' && ouch.size() >= 5) e.refers = load_be32(ouch.data() + 1);
  ++tail_;
  st_.pending_high_water = std::max<std::uint64_t>(st_.pending_high_water, tail_ - head_);
  pump(now);
  return true;
}

void HaOrderEntry::pump(Nanos now) {
  if (active_ < 0) return;
  Instance& k = inst_[static_cast<std::size_t>(active_)];
  if (!k.session || k.state != InstState::Active) return;
  while (unsent_ < tail_) {
    const Entry& e = at(unsent_);
    if (e.acked) {  // a Cancel or Modify already answered: not sent again
      ++unsent_;
      continue;
    }
    const soup::Actions& a = k.session->send_unsequenced(std::span<const std::byte>(e.bytes.data(), e.len), now);
    if (!a.accepted) {
      ++st_.tx_blocked;
      break;
    }
    if (unsent_ < sent_hw_) {
      ++st_.resent;
    } else {
      ++st_.sent;
      sent_hw_ = unsent_ + 1;
    }
    ++unsent_;
  }
}

void HaOrderEntry::on_response(std::span<const std::byte> m) noexcept {
  if (m.size() < 13) return;
  const char t = static_cast<char>(m[0]);
  // System Event names no message. Account Query Response carries NextUserRefNum at
  // offset 9, one above the last UserRefNum consumed, so it would match the next Enter
  // Order still pending and release it unprocessed; nor does it say which pending query
  // it answers (a query re-sent after a takeover is answered twice). It releases nothing:
  // a query goes with the messages before the next response that names one.
  if (t == 'S' || t == 'Q') return;
  // Every other outbound type carries a UserRefNum at offset 9; Replaced carries the
  // new one at 13 (and the original at 9).
  const UserRefNum u9 = load_be32(m.data() + 9);
  const UserRefNum u13 = (t == 'U' && m.size() >= 17) ? load_be32(m.data() + 13) : 0;
  // Only solicited answers to a Cancel or Modify: Order Canceled with reason User
  // Requested, Cancel Pending, Cancel Reject, Order Modified. Unsolicited cancels
  // (cancel on disconnect 'Z', IOC, close 'E', halt, self-match, AIQ Canceled 'D') say
  // nothing about the messages before a pending Cancel of the same order (DST-007).
  constexpr std::size_t kReason = ouch50::layout::out::OrderCanceled::kReasonOff;
  const bool user_cancel = t == 'C' && m.size() > kReason && static_cast<char>(m[kReason]) == 'U';
  const bool cancel_answer = user_cancel || t == 'I' || t == 'P' || t == 'M';
  for (std::uint64_t p = head_; p < tail_; ++p) {
    Entry& e = at(p);
    if (e.acked) continue;
    // A response naming the UserRefNum this message consumed proves it was processed,
    // and with it every earlier message (one session's messages apply in order).
    if (e.consumed != 0 && e.consumed == (t == 'U' ? u13 : u9)) {
      for (std::uint64_t q = head_; q <= p; ++q) st_.acked += at(q).acked ? 0u : 1u;
      head_ = p + 1;
      advance_head();
      return;
    }
    // A solicited cancel answer names an order, not a message: it answers this Cancel
    // or Modify only, never the messages before it (it may even complete an earlier
    // Cancel of the same order, answered by Cancel Pending before; this one is then
    // moot, the order being gone).
    bool answered = (e.type == 'X' || e.type == 'M') && cancel_answer && e.refers == u9;
    // A Replace whose original was cancelled because the request failed validation.
    if (!answered && e.type == 'U' && user_cancel && e.refers == u9) answered = true;
    if (answered) {
      e.acked = true;
      ++st_.acked;
      advance_head();
      return;
    }
  }
}

void HaOrderEntry::advance_head() noexcept {
  while (head_ < tail_ && at(head_).acked) ++head_;
  if (unsent_ < head_) unsent_ = head_;
}

std::span<const std::byte> HaOrderEntry::tx(std::size_t i) const noexcept {
  const Instance& k = inst_[i];
  if (!k.session) return {};
  return k.session->actions().write;
}

void HaOrderEntry::consume_tx(std::size_t i, std::size_t n) noexcept {
  Instance& k = inst_[i];
  if (k.session) k.session->consume_tx(n);
}

Nanos HaOrderEntry::next_deadline() const noexcept {
  Nanos d = soup::kNever;
  for (const Instance& k : inst_)
    if (k.session) d = std::min(d, k.session->actions().deadline);
  return d;
}

}  // namespace lle::client
