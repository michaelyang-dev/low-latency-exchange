#pragma once
// The witness W (10 §1–§2): the only authority that decrees epochs and
// membership, in the style of Vertical Paxos II. Sans-I/O: decoded control
// messages and the current time go in; slot writes and reply datagrams come out.
// witnessd drives it with a UDP socket and an O_DSYNC state file; the simulator
// drives the same core with injected disk and network faults.
//
// Safety (HotStandby.tla, WitnessGrant*):
//   - every grant increments the epoch, so there is at most one grant per epoch;
//   - PROMOTE: from_epoch == epoch, candidate in members, candidate != primary,
//     incarnation == inc[candidate];
//   - SOLO: from_epoch == epoch, sender == primary, incarnation == inc[primary];
//   - JOIN (relayed by the solo primary at zero lag): from_epoch == epoch,
//     sender == primary with its recorded incarnation, joiner not a member;
//     records the joiner's incarnation;
//   - RESUME: from_epoch == epoch, sender == primary, members == {sender},
//     incarnation newer than the recorded one; records it.
//   - No reply leaves before the state it reflects is durable ("persist before
//     reply"): replies wait for the generation they were created at.
//   - A retransmitted request is answered from last_grant only if it asks for
//     exactly what was granted. For JOIN that includes the joiner's
//     incarnation: a JOIN relayed again for a joiner that restarted in the
//     meantime is a new request (rejected as stale), never the old grant
//     (DST-001: the old grant left W recording a dead incarnation, so the
//     joiner could never be promoted).
//   - Requests from an incarnation older than one W has heard from the node
//     (by heartbeat) are refused: they come from a dead process.
//   - A JOIN grant also goes to the joiner itself (at its latest heartbeat
//     endpoint) with to_node = joiner and its recorded incarnation, so a joiner
//     learns of its admission even if the primary crashes before relaying it.
// Liveness (HotStandbyLive.tla): PROMOTE is granted only once W has not heard
// W.primary's *current incarnation* for tie_break_ns. Heartbeats from a
// restarted primary (a newer incarnation) do not count.
//
// Durable state lives in two 4 KiB CRC-protected slots. Each write goes to the
// slot that does NOT hold the newest durable image, so a torn write can never
// destroy the state that replies have already been based on.
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>

#include "common/types.h"
#include "env/concepts.h"
#include "witness/control.h"

namespace lle::witness {

struct LastGrant {
  MsgType request = MsgType::kPromote;  // kHeartbeat (0 on disk) = none
  NodeId node = 0;
  std::uint64_t from_epoch = 0;
  std::uint64_t incarnation = 0;
  bool valid = false;
  friend bool operator==(const LastGrant&, const LastGrant&) = default;
};

struct State {
  std::uint64_t epoch = 1;
  NodeId primary = 0;
  Members members = 0b11;
  std::array<std::uint64_t, kNodes> inc{};
  LastGrant last_grant{};  // answers a retransmitted request whose GRANT was lost
  friend bool operator==(const State&, const State&) = default;
};

[[nodiscard]] bool valid_state(const State& s) noexcept;

// ---- durable slots ---------------------------------------------------------
inline constexpr std::size_t kSlotBytes = 4096;
inline constexpr std::size_t kSlots = 2;
using SlotImage = std::array<std::byte, kSlotBytes>;

struct Durable {
  State state;
  std::uint64_t generation = 0;  // increases with every persisted change
  std::size_t slot = 0;          // where this image lives
};

[[nodiscard]] SlotImage encode_slot(const State& s, std::uint64_t generation) noexcept;
[[nodiscard]] std::optional<Durable> decode_slot(std::span<const std::byte> image, std::size_t slot) noexcept;
// The newest valid image of the two slots, or nothing (W must then refuse to start).
[[nodiscard]] std::optional<Durable> choose(std::span<const std::byte> slot0, std::span<const std::byte> slot1) noexcept;

// ---- the core --------------------------------------------------------------
struct Config {
  Nanos tie_break_ns = 5'000'000;  // 5 ms; T_w < T_d (10 §4)
};

struct SlotWrite {
  std::uint64_t generation = 0;
  std::size_t slot = 0;
  SlotImage image{};
};

struct Stats {
  std::uint64_t grants = 0;
  std::uint64_t rejects = 0;
  std::uint64_t duplicate_grants = 0;  // retransmitted requests answered from last_grant
  std::uint64_t heartbeats = 0;
};

class Witness {
 public:
  // `started_at`: W gives its primary the benefit of the doubt for one tie-break
  // window after (re)start, because it cannot yet judge silence.
  Witness(const Config& cfg, const Durable& durable, Nanos started_at);

  // One decoded inbound control message from `from` at monotonic time `now`.
  // GRANT/REJECT are ignored (W only sends them).
  void handle(const Message& m, const env::Endpoint& from, Nanos now);

  // Persistence. At most one write is outstanding; begin_write() returns the
  // newest unpersisted state, or nothing if all is durable or a write is in
  // flight. on_persisted() must name the generation that completed.
  [[nodiscard]] std::optional<SlotWrite> begin_write();
  void on_persisted(std::uint64_t generation);
  // A failed write: W stops replying and must be restarted (witnessd exits).
  void on_write_failed() noexcept { failed_ = true; }

  // Sends every reply whose state is durable: send(Endpoint, span<const byte>).
  template <class F>
  std::size_t drain(F&& send) {
    std::size_t n = 0;
    while (!failed_ && !outbox_.empty() && outbox_.front().generation <= durable_generation_) {
      const Out& o = outbox_.front();
      send(o.to, o.msg.span());
      outbox_.pop_front();
      ++n;
    }
    return n;
  }

  [[nodiscard]] const State& state() const noexcept { return state_; }
  [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }
  [[nodiscard]] std::uint64_t durable_generation() const noexcept { return durable_generation_; }
  [[nodiscard]] std::size_t pending_replies() const noexcept { return outbox_.size(); }
  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] const Stats& stats() const noexcept { return stats_; }
  // Tie-break view: W hears its primary's current incarnation at `now`.
  [[nodiscard]] bool hears_primary(Nanos now) const noexcept;
  // True if W has heard `node` in an incarnation newer than `inc`.
  [[nodiscard]] bool superseded(NodeId node, std::uint64_t inc) const noexcept;

 private:
  struct Heard {
    std::uint64_t incarnation = 0;
    Nanos at = 0;
    bool any = false;
    env::Endpoint from{};  // where the node's latest heartbeat came from
  };
  struct Out {
    std::uint64_t generation;
    env::Endpoint to;
    Encoded msg;
  };

  template <class Req>
  void on_request(const Req& r, MsgType type, NodeId node, std::uint64_t inc, const env::Endpoint& from, Nanos now);
  std::optional<RejectReason> check(const Promote& r, Nanos now) const noexcept;
  std::optional<RejectReason> check(const Solo& r, Nanos now) const noexcept;
  std::optional<RejectReason> check(const Join& r, Nanos now) const noexcept;
  std::optional<RejectReason> check(const Resume& r, Nanos now) const noexcept;
  void apply(const Promote& r) noexcept;
  void apply(const Solo& r) noexcept;
  void apply(const Join& r) noexcept;
  void apply(const Resume& r) noexcept;
  void reply_grant(MsgType type, NodeId node, std::uint64_t inc, std::uint64_t from_epoch, const env::Endpoint& to);
  void notify_joiner(const Join& j);
  void reply_reject(MsgType type, RejectReason why, NodeId node, std::uint64_t inc, std::uint64_t from_epoch,
                    const env::Endpoint& to);

  Config cfg_;
  Nanos started_at_ = 0;
  State state_;
  std::uint64_t generation_ = 0;          // of state_ (in memory)
  std::uint64_t durable_generation_ = 0;  // newest image on disk
  std::size_t durable_slot_ = 0;
  std::optional<std::uint64_t> inflight_;
  std::size_t inflight_slot_ = 0;
  bool failed_ = false;
  std::array<Heard, kNodes> heard_{};
  std::deque<Out> outbox_;
  Stats stats_;
};

}  // namespace lle::witness
