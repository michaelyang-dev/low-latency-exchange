#pragma once
// Outputs of the sans-I/O SoupBinTCP sessions (03-protocols s5). Every session
// call returns a reference to the session's Actions, valid until the next call
// on that session: bytes to write, delivered messages, events, the next timer
// deadline and whether to close. Fixed capacity; no allocation per call.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <string_view>

#include "common/types.h"

namespace lle::soup {

inline constexpr Nanos kNever = std::numeric_limits<Nanos>::max();
inline constexpr std::size_t kMaxDelivered = 64;
inline constexpr std::size_t kMaxEvents = 8;

template <class T, std::size_t N>
class FixedList {
 public:
  bool push_back(const T& v) noexcept {
    if (n_ == N) return false;
    items_[n_++] = v;
    return true;
  }
  void clear() noexcept { n_ = 0; }
  [[nodiscard]] std::size_t size() const noexcept { return n_; }
  [[nodiscard]] bool empty() const noexcept { return n_ == 0; }
  [[nodiscard]] bool full() const noexcept { return n_ == N; }
  [[nodiscard]] static constexpr std::size_t capacity() noexcept { return N; }
  [[nodiscard]] const T& operator[](std::size_t i) const noexcept { return items_[i]; }
  [[nodiscard]] const T* begin() const noexcept { return items_.data(); }
  [[nodiscard]] const T* end() const noexcept { return items_.data() + n_; }

 private:
  std::array<T, N> items_{};
  std::size_t n_ = 0;
};

enum class EventKind : std::uint8_t {
  LoggedIn,       // seq = first sequence number of the stream on this connection
  LoginRejected,  // code = 'A' (not authorized) or 'S' (session unavailable)
  EndOfSession,   // server: 'Z' sent; client: 'Z' received
  Closed,         // reason says why; close the connection after flushing `write`
  SequenceAhead,  // server alarm: seq = requested sequence, aux = server's next (03-protocols s5)
  StoreFull,      // server: the SequencedStore refused an append
};

enum class CloseReason : std::uint8_t {
  None,
  LogoutRequested,    // 'O' received (server) or sent (client)
  LoginTimeout,       // no Login Request (server) / no Login Accepted (client) in time
  IdleTimeout,        // nothing received for the idle timeout
  LoginRejected,      // 'J' sent (server) or received (client)
  ProtocolViolation,  // unknown type, data before login, oversize, malformed packet
  EndOfSession,       // 'Z'
  StoreUnavailable,   // server: a replay message is missing from the store
};

struct Event {
  EventKind kind = EventKind::Closed;
  CloseReason reason = CloseReason::None;
  char code = 0;
  SeqNo seq = 0;
  SeqNo aux = 0;
};

// A message handed to the application. Sequenced messages carry their implicit
// sequence number; unsequenced ones carry 0. `data` is valid until the next
// call on the session.
struct Delivered {
  std::span<const std::byte> data;
  SeqNo seq = 0;
};

struct Actions {
  std::span<const std::byte> write;  // all pending outbound bytes; call consume_tx(n) after writing n
  FixedList<Delivered, kMaxDelivered> delivered;
  FixedList<Event, kMaxEvents> events;
  std::size_t consumed = 0;  // on_bytes(): input consumed; when < input size, call again with the rest
  Nanos deadline = kNever;   // call on_timer() at or after this time
  bool close = false;        // close the connection once `write` is flushed
  bool accepted = true;      // send_*(): the message was queued (or stored)
};

// Linear transmit buffer with compaction. Preallocated; never grows.
class TxBuffer {
 public:
  explicit TxBuffer(std::size_t capacity) : buf_(std::make_unique_for_overwrite<std::byte[]>(capacity)), cap_(capacity) {}

  // Pointer to `n` writable bytes at the tail, compacting if needed; nullptr when they do not fit.
  std::byte* reserve(std::size_t n) noexcept {
    if (cap_ - tail_ < n) {
      if (cap_ - (tail_ - head_) < n) return nullptr;
      std::memmove(buf_.get(), buf_.get() + head_, tail_ - head_);
      tail_ -= head_;
      head_ = 0;
    }
    return buf_.get() + tail_;
  }
  void commit(std::size_t n) noexcept { tail_ += n; }
  [[nodiscard]] std::span<std::byte> tail_space() noexcept { return {buf_.get() + tail_, cap_ - tail_}; }
  [[nodiscard]] std::span<const std::byte> pending() const noexcept { return {buf_.get() + head_, tail_ - head_}; }
  [[nodiscard]] std::size_t room() const noexcept { return cap_ - (tail_ - head_); }
  [[nodiscard]] std::size_t capacity() const noexcept { return cap_; }
  void consume(std::size_t n) noexcept {
    head_ += std::min(n, tail_ - head_);
    if (head_ == tail_) head_ = tail_ = 0;
  }
  void clear() noexcept { head_ = tail_ = 0; }

 private:
  std::unique_ptr<std::byte[]> buf_;
  std::size_t cap_;
  std::size_t head_ = 0;
  std::size_t tail_ = 0;
};

// Small fixed-capacity text builder for debug packets (no allocation).
class DebugText {
 public:
  DebugText& str(std::string_view s) noexcept {
    for (char c : s)
      if (n_ < sizeof(buf_)) buf_[n_++] = c;
    return *this;
  }
  DebugText& num(std::uint64_t v) noexcept {
    char tmp[20];
    std::size_t k = 0;
    do {
      tmp[k++] = static_cast<char>('0' + v % 10);
      v /= 10;
    } while (v != 0);
    while (k > 0)
      if (n_ < sizeof(buf_)) buf_[n_++] = tmp[--k];
      else --k;
    return *this;
  }
  [[nodiscard]] std::string_view view() const noexcept { return {buf_, n_}; }

 private:
  char buf_[160];
  std::size_t n_ = 0;
};

}  // namespace lle::soup
