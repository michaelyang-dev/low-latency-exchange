#pragma once
// Correlates TX timestamps with the sends that produced them (07 §2.5, R3a §3.3).
//
// SOF_TIMESTAMPING_OPT_ID tags every timestamp with a 32-bit key:
//   - Datagram sockets: the key counts sends, starting at 0 when the option is set.
//   - Stream sockets with OPT_ID_TCP: the key is the offset of the send's last byte
//     relative to write_seq at the time the option was set (N bytes sent → key N-1).
// The correlator records each send's expected key in a fixed-capacity FIFO. Keys are
// monotonic, so a timestamp for key K proves every older pending send will never get
// one of this type (e.g. TCP merged it into a later skb): those count as missing.
// Everything is preallocated at init(); on_send/on_stamp are allocation-free.
#include <cstddef>
#include <cstdint>

#include "net/common/fixed_queue.h"
#include "net/common/timestamps.h"
#include "net/hwts/abi.h"

namespace lle::net::hwts {

enum class KeyMode : std::uint8_t { Datagram, Stream };

struct PendingSend {
  std::uint64_t tag = 0;   // caller's correlation id (e.g. order token, trigger seq)
  std::uint32_t key = 0;   // expected OPT_ID
};

class TxCorrelator {
 public:
  // `capacity` bounds outstanding sends; `match_type` selects which report type is
  // correlated (SCM_TSTAMP_SND by default; others are ignored).
  void init(KeyMode mode, std::size_t capacity, std::uint32_t match_type = abi::kTstampSnd) {
    mode_ = mode;
    match_type_ = match_type;
    pending_.init(capacity);
  }

  // Records a successful send of `bytes` (ignored for datagrams). Returns its key. When
  // the FIFO is full the oldest send is dropped and counted missing.
  std::uint32_t on_send(std::uint64_t tag, std::size_t bytes) noexcept {
    std::uint32_t key;
    if (mode_ == KeyMode::Datagram) {
      key = next_;
      ++next_;
    } else {
      next_ += static_cast<std::uint32_t>(bytes);
      key = next_ - 1;
    }
    if (pending_.full()) {
      pending_.pop();
      ++validity_.missing;
    }
    (void)pending_.push(PendingSend{tag, key});
    return key;
  }

  // Matches a timestamp; on success calls cb(tag, stamp) and returns true.
  template <class F>
  bool on_stamp(const TxStamp& s, F&& cb) noexcept {
    if (s.type != match_type_) return false;
    while (!pending_.empty() && before(pending_.front().key, s.id)) {
      pending_.pop();
      ++validity_.missing;
    }
    if (pending_.empty() || pending_.front().key != s.id) {
      ++unmatched_;
      return false;
    }
    const PendingSend p = pending_.front();
    pending_.pop();
    validity_.record(s.kind());
    cb(p.tag, s);
    return true;
  }

  // Declares every outstanding send missing (end of run / connection closed).
  void expire_all() noexcept {
    validity_.missing += pending_.size();
    pending_.clear();
  }

  [[nodiscard]] const TsValidity& validity() const noexcept { return validity_; }
  [[nodiscard]] std::size_t outstanding() const noexcept { return pending_.size(); }
  [[nodiscard]] std::uint64_t unmatched() const noexcept { return unmatched_; }
  [[nodiscard]] std::uint32_t next_key() const noexcept { return mode_ == KeyMode::Datagram ? next_ : next_ - 1; }

 private:
  // Serial-number order on the 32-bit key space (RFC 1982 style).
  static bool before(std::uint32_t a, std::uint32_t b) noexcept { return static_cast<std::int32_t>(a - b) < 0; }

  FixedQueue<PendingSend> pending_;
  TsValidity validity_{};
  std::uint64_t unmatched_ = 0;
  std::uint32_t next_ = 0;  // datagram: next key; stream: bytes sent so far (mod 2^32)
  std::uint32_t match_type_ = abi::kTstampSnd;
  KeyMode mode_ = KeyMode::Datagram;
};

}  // namespace lle::net::hwts
