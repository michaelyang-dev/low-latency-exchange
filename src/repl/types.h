#pragma once
// Vocabulary of the replication core (10 §1–§5): roles, configuration, alarms, the
// trace events that name HotStandby.tla actions, and the Host concept through which
// the sans-I/O core reaches the node's log, applier, sequencer, gateway and links.
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

#include "common/types.h"
#include "journal/record.h"
#include "repl/wire.h"
#include "witness/control.h"

namespace lle::repl {

using NodeId = witness::NodeId;

// HotStandby.tla roles: P, SP, SC, B, C, R; kDeposed is "Down" after a deposed
// node's voluntary exit (10 §4: it closes without End of Session and exits).
enum class Role : std::uint8_t {
  kNone = 0,
  kPrimary = 1,        // P: paired primary, releases at commit_index
  kSoloPrimary = 2,    // SP: releases at durable_index
  kSoloCandidate = 3,  // SC: stopped releasing, flushed, SOLO sent
  kBackup = 4,         // B
  kCandidate = 5,      // C: frozen, never ACKs, PROMOTE after its L3 flush
  kRecovering = 6,     // R: restarted; RESUME or rejoin
  kDeposed = 7,        // exited
};
[[nodiscard]] const char* to_string(Role r) noexcept;
[[nodiscard]] constexpr bool is_primary(Role r) noexcept { return r == Role::kPrimary || r == Role::kSoloPrimary; }

// An alarm is an nlog ERROR plus a metrics flag (10 §3); the host raises both.
enum class Alarm : std::uint8_t {
  kBuildMismatch = 1,     // build-ID handshake failed (10 §3)
  kStateHashMismatch,     // state hashes differ at a checkpoint: the backup is unpromotable
  kBadRecord,             // a replicated record failed validation (seal, chain, epoch)
  kDiverged,              // rejoin: the epoch-based truncation point did not verify
  kSnapshotInvalid,       // a transferred snapshot failed validation
  kIncarnationRegressed,  // the witness has a newer incarnation for this node than ours
  kUnpromotableSuspect,   // an unpromotable backup suspects the primary: no takeover
};
[[nodiscard]] const char* to_string(Alarm a) noexcept;

struct Config {
  NodeId self = 0;
  std::uint64_t incarnation = 0;       // unique per process start, monotonic and durable
  std::uint64_t build_id = 0;          // identical artifact on both nodes (10 §3)
  std::uint64_t config_digest = 0;     // stamped into EpochStart records
  Nanos heartbeat_ns = 1'000'000;      // data-plane HEARTBEAT and HEARTBEAT_W (10 §3)
  Nanos t_d = 20'000'000;              // backup suspects the primary (10 §4)
  Nanos t_ack = 10'000'000;            // primary suspects the backup; T_ack < T_d
  Nanos rto_ns = 2'000'000;            // APPEND retransmission without ACK progress
  Nanos witness_retry_ns = 2'000'000;  // PROMOTE / SOLO / RESUME / JOIN retransmission
  Nanos forward_retry_ns = 2'000'000;  // FORWARD retransmission until sequenced
  Nanos rejoin_retry_ns = 5'000'000;   // EPOCH_END_QUERY / CATCHUP_REQ retransmission
  std::size_t window_bytes = 256 * 1024;  // unacknowledged records held for retransmission
  std::size_t window_records = 8192;
  std::size_t max_datagrams_per_poll = 64;
  std::uint64_t hash_interval = 65'536;   // state-hash checkpoint spacing (10 §3)
  std::uint64_t join_lag_records = 64;    // a joiner this close: pause and drain (10 §5)
  std::uint64_t snapshot_threshold = std::numeric_limits<std::uint64_t>::max();  // catch-up gap
  std::size_t snapshot_window_bytes = 32 * 1024;
  std::size_t forward_slots = 1024;       // pending FORWARDs on a backup
};

// The last record whose epoch is <= a queried epoch (EPOCH_END, 10 §5). index 0: none.
struct EpochEndInfo {
  std::uint64_t index = 0;
  std::uint32_t crc = 0;  // content crc of that record
  std::uint32_t epoch = 0;
};

// A snapshot the primary can send to a lagging joiner.
struct SnapshotOffer {
  std::uint64_t index = 0;  // state after records 1..index
  std::uint64_t bytes = 0;
};

// Protocol actions in HotStandby.tla vocabulary, reported to the host for logging and
// for trace validation (R-08, verify/tla/HotStandbyTrace.tla).
enum class TraceKind : std::uint8_t {
  kSendAppend = 1,      // a: index (paired stream only)
  kRecvAppend,          // a: index, b: content crc (backup in a paired epoch)
  kCatchupAppend,       // a: index, b: content crc (joiner, hidden by the atomic Rejoin)
  kRecvAck,             // a: l2_index
  kRelease,             // a: new release watermark of a primary role, b: mode (0 paired, 1 solo)
  kFreeze,              // a: frozen last_index
  kRequestPromote,      // a: from_epoch, b: last_index
  kRequestSolo,         // a: from_epoch
  kRequestResume,       // a: from_epoch
  kRequestJoin,         // a: from_epoch, b: last_index, c: joiner incarnation
  kGrantApplied,        // a: new epoch, b: witness::MsgType of the request, c: EpochStart index
  kRejoined,            // joiner became the backup: a: epoch
  kTruncate,            // a: truncation point
  kAdoptEpoch,          // a: epoch learned from the witness (restarted solo primary of record)
  kDeposed,             // a: epoch
  kSoloCancelled,       // a primary's backup came back before SOLO was sent
  kRejoinEpochStart,    // a joiner appended the EpochStart of its JOIN epoch: a: index, b: crc, c: epoch
  kEpochEndAnswer,      // a primary answered EPOCH_END_QUERY: a: the querier's incarnation
  kSendCatchup,         // a primary first sent record a to a joiner (catch-up stream)
  kJoinAbandoned,       // a solo primary gave up its pending JOIN on a REJECT: a: the JOIN's last_index
};
struct TraceEvent {
  TraceKind kind = TraceKind::kSendAppend;
  std::uint64_t a = 0;
  std::uint64_t b = 0;
  std::uint64_t c = 0;
};

// What the core needs from its node. Every call happens on the repl stage's thread.
//
// Log: the node's journal, L2 ring and L3 segments together. Records cross this
// interface in canonical form (seal == content crc, record.h); the host re-seals them
// for its own media. log_read must serve any index the node holds (the hot path reads
// sequentially just behind the tail; catch-up reads older records).
template <class H>
concept Host = requires(H& h, const H& ch, std::span<const std::byte> bytes, std::span<std::byte> out,
                        std::uint64_t idx, const wire::Forward& fwd, const TraceEvent& ev) {
  { ch.log_tail() } -> std::same_as<journal::ChainState>;
  { ch.durable_index() } -> std::same_as<std::uint64_t>;       // L3
  { ch.applied_index() } -> std::same_as<std::uint64_t>;       // applier position
  { h.log_append(bytes) } -> std::same_as<bool>;               // false: no room now, retry later
  { h.log_read(idx, out) } -> std::same_as<std::uint32_t>;     // record length, 0 if not held
  { h.log_epoch_end(idx) } -> std::same_as<EpochEndInfo>;      // argument: an epoch
  { h.log_epoch_start(idx) } -> std::same_as<EpochEndInfo>;    // first record of that epoch (index 0: none)
  { h.log_truncate(idx) } -> std::same_as<bool>;               // drop records > idx (L2 and L3)
  h.request_flush();                                           // submit the open L3 batch now
  h.reload_state(idx);                                         // applier := snapshot <= idx + replay to idx
  { h.inject_inbound(fwd) } -> std::same_as<bool>;             // primary: into the sequencer queue
  h.on_role(Role{}, std::uint64_t{});
  h.instance_down(NodeId{});                                   // journal instance-down for that node's instances
  h.deposed();                                                 // exit without End of Session
  h.alarm(Alarm{}, std::uint64_t{});
  h.send_peer(bytes);                                          // data link datagram
  h.send_witness(bytes);                                       // control datagram
  { ch.now_real() } -> std::same_as<Nanos>;                    // timestamps for EpochStart records
  h.trace(ev);
  // Snapshot transfer for catch-up (10 §5). Primary side:
  { h.snapshot_offer() } -> std::same_as<SnapshotOffer>;      // bytes 0: none available
  { h.snapshot_read(idx, out) } -> std::same_as<std::uint32_t>;  // copy from offset idx
  h.snapshot_release();
  // Joiner side:
  { h.snapshot_receive(idx, idx, idx, bytes) } -> std::same_as<bool>;  // (snap index, total, offset, bytes)
  { h.snapshot_install() } -> std::same_as<bool>;              // validate and load the received snapshot
};

}  // namespace lle::repl
