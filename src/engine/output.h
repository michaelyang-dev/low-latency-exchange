#pragma once
// Engine outputs (05-matching-engine §4 "Output sink", 01-architecture §4).
//
// The engine appends, in a defined order, three kinds of output, each tagged
// with the journal index of the record that caused it:
//   itch(index, bytes)               one ITCH 5.0 message, unsequenced
//                                    (MoldUDP64 numbering happens at egress);
//   ouch(index, session_id, bytes)   one OUCH 5.0 outbound message for a
//                                    SoupBinTCP session (sequenced at egress);
//   audit(index, event)              a dropped or ignored input, for nlog.
// The sink is a template parameter (no virtual dispatch on the hot path). In
// production it writes straight into per-destination SPSC rings; BufferSink
// keeps everything in pre-reserved vectors for tests and harnesses.
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lle::engine {

// Inputs the engine drops or ignores without a client-visible message.
enum class AuditCode : std::uint16_t {
  MalformedPayload = 1,  // record payload does not parse
  UnknownSession,        // OuchInbound/SessionEvent for a session not in the table
  AccountMismatch,       // OuchInbound account != the session's account
  NoUserRefNum,          // consuming message too short to carry its UserRefNum: dropped
  Resend,                // UserRefNum <= last consumed: benign resend, ignored (OUCH 5.0 §1.2)
  InvalidNoReject,       // X/M/Q failed validation: no new UserRefNum to reject, dropped
  UnknownOrder,          // X/M/U referencing no live order: ignored
  Superfluous,           // cancel/modify that changes nothing: ignored
  InvalidModify,         // Modify with a disallowed side transition: ignored
  ConfigRejected,        // Config record malformed or after trading began
  UnhandledRecord,       // record type or timer/admin kind the engine does not act on
};

struct AuditEvent {
  AuditCode code = AuditCode::MalformedPayload;
  std::uint32_t session_id = 0;
  std::uint64_t detail = 0;
};

template <class S>
concept OutputSink = requires(S& s, std::uint64_t idx, std::uint32_t session, std::span<const std::byte> b,
                              const AuditEvent& a) {
  s.itch(idx, b);
  s.ouch(idx, session, b);
  s.audit(idx, a);
};

enum class Dest : std::uint8_t { Itch = 1, Ouch = 2, Audit = 3 };

// Collects outputs in arrival order. Pre-size with reserve(); clear() between
// batches keeps capacity, so steady-state appends do not allocate.
class BufferSink {
 public:
  struct Entry {
    std::uint64_t index;
    Dest dest;
    std::uint32_t session;  // OUCH destination; audit: the session involved
    std::uint32_t off;      // into bytes()
    std::uint32_t len;
    AuditEvent audit;
  };

  void reserve(std::size_t entries, std::size_t bytes) {
    entries_.reserve(entries);
    bytes_.reserve(bytes);
  }
  void clear() noexcept {
    entries_.clear();
    bytes_.clear();
  }

  void itch(std::uint64_t idx, std::span<const std::byte> b) { push(idx, Dest::Itch, 0, b, AuditEvent{}); }
  void ouch(std::uint64_t idx, std::uint32_t session, std::span<const std::byte> b) {
    push(idx, Dest::Ouch, session, b, AuditEvent{});
  }
  void audit(std::uint64_t idx, const AuditEvent& a) { push(idx, Dest::Audit, a.session_id, {}, a); }

  [[nodiscard]] std::span<const Entry> entries() const noexcept { return entries_; }
  [[nodiscard]] std::span<const std::byte> bytes(const Entry& e) const noexcept {
    return std::span<const std::byte>(bytes_).subspan(e.off, e.len);
  }
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

 private:
  void push(std::uint64_t idx, Dest d, std::uint32_t session, std::span<const std::byte> b, const AuditEvent& a) {
    const auto off = static_cast<std::uint32_t>(bytes_.size());
    bytes_.insert(bytes_.end(), b.begin(), b.end());
    entries_.push_back(Entry{idx, d, session, off, static_cast<std::uint32_t>(b.size()), a});
  }

  std::vector<Entry> entries_;
  std::vector<std::byte> bytes_;
};
static_assert(OutputSink<BufferSink>);

// Discards everything but counts it (benchmarks).
struct CountingSink {
  std::uint64_t itch_msgs = 0, ouch_msgs = 0, audits = 0, bytes = 0;
  void itch(std::uint64_t, std::span<const std::byte> b) noexcept {
    ++itch_msgs;
    bytes += b.size();
  }
  void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte> b) noexcept {
    ++ouch_msgs;
    bytes += b.size();
  }
  void audit(std::uint64_t, const AuditEvent&) noexcept { ++audits; }
};
static_assert(OutputSink<CountingSink>);

}  // namespace lle::engine
