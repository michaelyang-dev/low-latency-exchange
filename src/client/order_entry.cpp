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
  if (m.size() < 13 || static_cast<char>(m[0]) == 'S') return;
  const char t = static_cast<char>(m[0]);
  // Every outbound type but S carries a UserRefNum at offset 9; Replaced carries
  // the new one at 13 (and the original at 9).
  const UserRefNum u9 = load_be32(m.data() + 9);
  const UserRefNum u13 = (t == 'U' && m.size() >= 17) ? load_be32(m.data() + 13) : 0;
  const bool cancel_like = t == 'C' || t == 'I' || t == 'P' || t == 'M' || t == 'D';
  for (std::uint64_t p = head_; p < tail_; ++p) {
    const Entry& e = at(p);
    bool match = false;
    if (e.consumed != 0) match = e.consumed == (t == 'U' ? u13 : u9);
    if (!match && (e.type == 'X' || e.type == 'M') && cancel_like) match = e.refers == u9;
    // A Replace whose original was cancelled because the request failed validation.
    if (!match && e.type == 'U' && t == 'C') match = e.refers == u9;
    if (match) {
      const std::uint64_t released = p + 1 - head_;
      st_.acked += released;
      head_ = p + 1;
      if (unsent_ < head_) unsent_ = head_;
      return;
    }
  }
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
