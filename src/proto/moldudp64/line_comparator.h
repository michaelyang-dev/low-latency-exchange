#pragma once
// LineComparator (03 §5 "HA line consistency", T10): checks that line A and line B carry
// the same bytes for every sequence number. In the HA configuration line A comes from the
// primary and line B from the backup, each packetized independently (10 §3), so packets
// are not comparable; messages are, by sequence number.
//
// A debugging and evidence tool, not a hot-path component. It holds a fixed window of
// `window` sequence numbers (allocated once, at construction). Each slot keeps the
// message's length and a 64-bit FNV-1a hash of its bytes, and which lines delivered it:
//   - the second line's copy is compared with the first (mismatch: different length or
//     hash), and the slot is kept so that later duplicates are checked too;
//   - a line repeating a sequence number (MoldUDP64 duplicates, re-request responses)
//     must repeat the same bytes;
//   - a message that leaves the window, or is still pending at finish(), before the other
//     line delivered it is counted as unmatched on that line (loss), not as a mismatch;
//   - a message older than the window (stale) is counted and cannot be checked.
// The session name of both lines must agree. Packets that do not parse are counted.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "common/hash.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::mold {

struct LineComparatorStats {
  std::uint64_t packets[2] = {0, 0};
  std::uint64_t messages[2] = {0, 0};   // messages received, duplicates included
  std::uint64_t compared = 0;           // sequence numbers seen on both lines
  std::uint64_t mismatches = 0;         // different bytes for one sequence number
  std::uint64_t duplicates[2] = {0, 0}; // a line repeated a sequence number (same bytes)
  std::uint64_t unmatched[2] = {0, 0};  // delivered by this line only (left the window or finish())
  std::uint64_t stale[2] = {0, 0};      // older than the window: not checked
  std::uint64_t session_mismatches = 0; // packets whose session differs from the other line's
  std::uint64_t malformed[2] = {0, 0};
  bool ended[2] = {false, false};       // end of session seen
  SeqNo end_seq[2] = {0, 0};            // its next expected sequence number
  SeqNo first_mismatch = 0;             // 0: none
};

class LineComparator {
 public:
  explicit LineComparator(std::size_t window = std::size_t{1} << 20)
      : window_(window == 0 ? 1 : window), slots_(std::make_unique<Slot[]>(window_)) {}

  // One downstream packet received on `line` (0 = A, 1 = B).
  void on_packet(int line, std::span<const std::byte> pkt) {
    const int l = line == 0 ? 0 : 1;
    ++st_.packets[l];
    const auto v = PacketView::parse(pkt);
    if (!v) {
      ++st_.malformed[l];
      return;
    }
    check_session(l, v->header().session);
    if (v->is_end_of_session()) {
      st_.ended[l] = true;
      st_.end_seq[l] = v->seq();
      if (st_.ended[1 - l] && st_.end_seq[1 - l] != st_.end_seq[l]) note_mismatch(std::min(st_.end_seq[0], st_.end_seq[1]));
      return;
    }
    v->for_each([&](SeqNo s, std::span<const std::byte> m) { on_message(l, s, m); });
  }

  // Counts every message still waiting for the other line as unmatched.
  void finish() {
    for (std::size_t i = 0; i < window_; ++i) {
      Slot& e = slots_[i];
      if (e.lines == 1 || e.lines == 2) ++st_.unmatched[e.lines - 1];
      e = Slot{};
    }
  }

  [[nodiscard]] const LineComparatorStats& stats() const noexcept { return st_; }
  // True when every sequence number seen on both lines carried the same bytes.
  [[nodiscard]] bool consistent() const noexcept { return st_.mismatches == 0 && st_.session_mismatches == 0; }

 private:
  struct Slot {
    SeqNo seq = 0;
    std::uint64_t hash = 0;
    std::uint32_t len = 0;
    std::uint8_t lines = 0;  // bit 0: line A, bit 1: line B; 0: empty
  };

  void on_message(int l, SeqNo s, std::span<const std::byte> m) {
    ++st_.messages[l];
    Fnv1a64 h;
    h.bytes(m.data(), m.size());
    const std::uint64_t hash = h.value();
    const auto len = static_cast<std::uint32_t>(m.size());
    const std::uint8_t bit = static_cast<std::uint8_t>(1u << l);
    if (s + window_ <= high_ && high_ >= window_) {  // older than the window
      ++st_.stale[l];
      return;
    }
    if (s > high_) high_ = s;
    Slot& e = slots_[static_cast<std::size_t>(s % window_)];
    if (e.lines != 0 && e.seq != s) {
      if (e.seq > s) {  // the slot already holds a newer sequence number
        ++st_.stale[l];
        return;
      }
      if (e.lines != 3) ++st_.unmatched[e.lines - 1];  // left the window unmatched
      e = Slot{};
    }
    if (e.lines == 0) {
      e = Slot{s, hash, len, bit};
      return;
    }
    if (e.hash != hash || e.len != len) note_mismatch(s);
    if ((e.lines & bit) != 0) {
      ++st_.duplicates[l];
    } else {
      e.lines = static_cast<std::uint8_t>(e.lines | bit);
      ++st_.compared;
    }
  }

  void check_session(int l, const Session& s) {
    if (!have_session_[l]) {
      session_[l] = s;
      have_session_[l] = true;
    } else if (!(session_[l] == s)) {
      session_[l] = s;  // a session change on one line: it must match the other
    }
    if (have_session_[1 - l] && !(session_[1 - l] == s)) ++st_.session_mismatches;
  }

  void note_mismatch(SeqNo s) {
    ++st_.mismatches;
    if (st_.first_mismatch == 0 || s < st_.first_mismatch) st_.first_mismatch = s;
  }

  std::size_t window_;
  std::unique_ptr<Slot[]> slots_;
  SeqNo high_ = 0;
  Session session_[2];
  bool have_session_[2] = {false, false};
  LineComparatorStats st_;
};

}  // namespace lle::mold
