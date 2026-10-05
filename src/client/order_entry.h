#pragma once
// refclient's order entry with the HA client rule (10 §3 step 5, ADR-009).
//
// An account has a SoupBinTCP port on each data node; a login on the mirror port
// is a second instance of the same session. Both instances deliver the same
// sequenced stream (byte-identical outputs on both nodes). The client rule,
// enforced here:
//   - every message is sent on ONE instance only, the active one;
//   - a message stays pending until the response to it, or to a later message,
//     arrives (the engine applies a session's messages in order, so a response
//     to message k means messages before k were processed, including those it
//     ignored without a response);
//   - when the active instance fails (TCP closed, idle timeout, end of session,
//     protocol violation), the other instance takes over and every pending
//     message is re-sent on it in its original order. Splitting messages across
//     instances concurrently could reorder UserRefNums and silently drop the
//     lower one (R7 D4); re-sending is exactly once through the UserRefNum
//     filter (consuming messages) or idempotent (Cancel: intended size).
// Responses are deduplicated across instances by SoupBinTCP sequence number and
// handed to the sink once, in order.
//
// Sans-I/O: the caller owns the TCP connections, reports connected / bytes /
// closed per instance, writes tx(i) and calls consume_tx(i, n). A one-instance
// configuration (no backup) is the same code with instance 1 absent.
// Allocation: the pending ring at construction; a ClientSession (its transmit
// buffer) each time an instance connects, which is the reconnect path only.
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "common/types.h"
#include "proto/soupbin/client_session.h"

namespace lle::client {

struct OrderEntryConfig {
  soup::ClientConfig session{};       // credentials, timers; `sequence` = first requested sequence
  std::size_t pending_capacity = 1 << 14;
};

struct OrderEntryStats {
  std::uint64_t sent = 0;                // messages written on an instance (first send)
  std::uint64_t resent = 0;              // re-sent after a takeover or a reconnect
  std::uint64_t acked = 0;               // pending messages released by responses
  std::uint64_t responses = 0;           // sequenced messages delivered to the sink
  std::uint64_t duplicate_responses = 0; // the same sequence from the other instance
  std::uint64_t sequence_jumps = 0;      // a sequence above the next expected (should not happen)
  std::uint64_t takeovers = 0;
  std::uint64_t pending_full = 0;        // send() refused: the pending ring is full
  std::uint64_t tx_blocked = 0;          // a send waited for transmit-buffer room
  std::uint64_t logins = 0;
  std::uint64_t login_rejects = 0;
  std::uint64_t instance_failures = 0;
  std::uint64_t pending_high_water = 0;
};

class HaOrderEntry {
 public:
  static constexpr std::size_t kInstances = 2;
  static constexpr std::size_t kMaxMsg = 192;  // above the largest inbound OUCH message (140)
  enum class InstState : std::uint8_t { Down, Connecting, LoggingIn, Active };

  explicit HaOrderEntry(const OrderEntryConfig& cfg);

  // Strictly increasing UserRefNums (OUCH 5.0 §1.2). Re-sends keep their numbers.
  [[nodiscard]] UserRefNum next_urn() noexcept { return ++last_urn_; }
  void set_last_urn(UserRefNum u) noexcept { last_urn_ = u; }

  // The caller started a TCP connection for instance i. While the primary
  // (instance 0) is connecting or logging in, a logged-in backup waits for it:
  // orders go to the primary unless it is down (10 §3: line A and the primary
  // instance belong to the primary node).
  void on_connecting(std::size_t i) noexcept {
    if (inst_[i].state == InstState::Down) inst_[i].state = InstState::Connecting;
  }
  // Instance i's TCP connection is up: queues its Login Request. It requests the
  // next sequence not yet processed, so both instances' streams line up.
  void on_connected(std::size_t i, Nanos now);
  // Instance i's TCP connection is gone (or the caller closed it).
  void on_closed(std::size_t i, Nanos now);
  // Bytes from instance i. sink(SeqNo seq, std::span<const std::byte> ouch) gets each
  // sequenced message once.
  template <class Sink>
  void on_bytes(std::size_t i, std::span<const std::byte> in, Nanos now, Sink&& sink);
  void on_timer(Nanos now);

  // Queues one OUCH message and writes it on the active instance (if any).
  // False if the pending ring is full or the message is too long.
  bool send(std::span<const std::byte> ouch, Nanos now);

  [[nodiscard]] std::span<const std::byte> tx(std::size_t i) const noexcept;
  void consume_tx(std::size_t i, std::size_t n) noexcept;
  // The caller should close instance i's connection (after flushing tx).
  [[nodiscard]] bool wants_close(std::size_t i) const noexcept { return inst_[i].close; }

  [[nodiscard]] InstState state(std::size_t i) const noexcept { return inst_[i].state; }
  [[nodiscard]] int active() const noexcept { return active_; }
  [[nodiscard]] std::size_t pending() const noexcept { return static_cast<std::size_t>(tail_ - head_); }
  [[nodiscard]] SeqNo next_seq() const noexcept { return next_seq_; }
  [[nodiscard]] Nanos next_deadline() const noexcept;
  [[nodiscard]] const OrderEntryStats& stats() const noexcept { return st_; }

  // Releases pending messages for a response (exposed for tests).
  void on_response(std::span<const std::byte> ouch) noexcept;

 private:
  struct Entry {
    UserRefNum consumed = 0;  // the new UserRefNum it consumes (Enter, Replace, ...), 0 = none
    UserRefNum refers = 0;    // the order it references (Cancel, Modify, Replace's original)
    char type = 0;
    std::uint16_t len = 0;
    std::array<std::byte, kMaxMsg> bytes{};
  };
  struct Instance {
    std::optional<soup::ClientSession> session;
    InstState state = InstState::Down;
    bool close = false;
  };

  [[nodiscard]] Entry& at(std::uint64_t pos) noexcept { return ring_[pos % cap_]; }
  void absorb(std::size_t i, const soup::Actions& a, Nanos now);
  void become_active(std::size_t i, Nanos now);
  void maybe_activate(Nanos now);
  void fail(std::size_t i, Nanos now);
  void pump(Nanos now);  // writes unsent pending messages on the active instance

  OrderEntryConfig cfg_;
  std::array<Instance, kInstances> inst_{};
  std::unique_ptr<Entry[]> ring_;
  std::size_t cap_;
  std::uint64_t head_ = 0;    // oldest pending
  std::uint64_t unsent_ = 0;  // first pending not yet written on the active instance
  std::uint64_t tail_ = 0;
  std::uint64_t sent_hw_ = 0;  // one past the highest position ever written
  int active_ = -1;
  UserRefNum last_urn_ = 0;
  SeqNo next_seq_ = 1;        // next sequenced response to process
  OrderEntryStats st_;
};

template <class Sink>
void HaOrderEntry::on_bytes(std::size_t i, std::span<const std::byte> in, Nanos now, Sink&& sink) {
  Instance& k = inst_[i];
  if (!k.session) return;
  while (!in.empty()) {
    const soup::Actions& a = k.session->on_bytes(in, now);
    for (const soup::Delivered& d : a.delivered) {
      if (d.seq == 0) continue;  // unsequenced (4.10 mode only)
      if (d.seq < next_seq_) {
        ++st_.duplicate_responses;
        continue;
      }
      if (d.seq > next_seq_) ++st_.sequence_jumps;
      next_seq_ = d.seq + 1;
      ++st_.responses;
      on_response(d.data);
      sink(d.seq, d.data);
    }
    const std::size_t used = a.consumed;
    absorb(i, a, now);
    if (used == 0 || !k.session) break;
    in = in.subspan(used);
  }
  pump(now);
}

}  // namespace lle::client
