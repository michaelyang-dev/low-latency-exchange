#pragma once
// Released-message store for the MoldUDP64 re-request server (03-protocols §6):
// the MessageStoreLike concept, and MessageRing, a fixed-capacity in-memory
// ring (the "in-memory ring" in front of the output log). Sequence numbers are
// assigned in append order starting at a configured first sequence.
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>

#include "common/assert.h"
#include "common/types.h"

namespace lle::mold {

// get() returns the message bytes, or nullopt if `seq` is not held (zero-length
// messages are valid, so an empty span cannot mean "missing").
template <class S>
concept MessageStoreLike = requires(const S& s, SeqNo q) {
  { s.highest() } -> std::same_as<SeqNo>;  // highest stored sequence, 0 if none
  { s.lowest() } -> std::same_as<SeqNo>;   // lowest sequence still held (> highest if empty)
  { s.get(q) } -> std::same_as<std::optional<std::span<const std::byte>>>;
};

class MessageRing {
 public:
  // Holds at most `max_messages` messages and `max_bytes` payload bytes; the
  // oldest are evicted first. Memory is allocated here, never afterwards.
  MessageRing(std::size_t max_messages, std::size_t max_bytes, SeqNo first_seq = 1)
      : max_msgs_(max_messages),
        cap_(max_bytes),
        offs_(std::make_unique<std::uint32_t[]>(max_messages)),
        lens_(std::make_unique<std::uint32_t[]>(max_messages)),
        data_(std::make_unique_for_overwrite<std::byte[]>(max_bytes)),  // written before read
        next_(first_seq),
        oldest_(first_seq) {
    LLE_ASSERT(max_messages > 0 && max_bytes > 0 && max_bytes <= 0xFFFF'FFFFu && first_seq >= 1);
  }

  // Appends the next message (sequence highest()+1). False if it can never fit.
  //
  // Layout: messages occupy the byte arena in sequence order and wrap at most
  // once. Not wrapped: used = [tail, write), free = [write, cap) + [0, tail).
  // Wrapped: used = [tail, lap end) + [0, write), free = [write, tail).
  // Every message is contiguous, so get() returns a plain span.
  bool append(std::span<const std::byte> msg) noexcept {
    const std::size_t len = msg.size();
    if (len > cap_) return false;
    if (size() == max_msgs_) evict();
    for (;;) {
      if (size() == 0) {
        wrapped_ = false;
        write_ = 0;
        break;
      }
      if (!wrapped_) {
        if (write_ + len <= cap_) break;
        write_ = 0;  // start the next lap; [0, tail) must hold the message
        wrapped_ = true;
        continue;
      }
      if (write_ + len <= offs_[oldest_ % max_msgs_]) break;
      evict();
    }
    if (len != 0) std::memcpy(data_.get() + write_, msg.data(), len);
    const std::size_t i = next_ % max_msgs_;
    offs_[i] = static_cast<std::uint32_t>(write_);
    lens_[i] = static_cast<std::uint32_t>(len);
    write_ += len;
    ++next_;
    return true;
  }

  [[nodiscard]] SeqNo highest() const noexcept { return next_ - 1; }
  [[nodiscard]] SeqNo lowest() const noexcept { return oldest_; }
  [[nodiscard]] std::size_t size() const noexcept { return static_cast<std::size_t>(next_ - oldest_); }

  [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo seq) const noexcept {
    if (seq < oldest_ || seq >= next_) return std::nullopt;
    const std::size_t i = seq % max_msgs_;
    return std::span<const std::byte>(data_.get() + offs_[i], lens_[i]);
  }

 private:
  void evict() noexcept {
    LLE_DASSERT(next_ > oldest_);
    const std::uint32_t old_tail = offs_[oldest_ % max_msgs_];
    ++oldest_;
    // Crossing from the old lap into the current one: the arena is no longer wrapped.
    if (size() == 0 || (wrapped_ && offs_[oldest_ % max_msgs_] < old_tail)) wrapped_ = false;
  }

  std::size_t max_msgs_;
  std::size_t cap_;
  std::unique_ptr<std::uint32_t[]> offs_;
  std::unique_ptr<std::uint32_t[]> lens_;
  std::unique_ptr<std::byte[]> data_;
  SeqNo next_;
  SeqNo oldest_;
  std::size_t write_ = 0;
  bool wrapped_ = false;
};

static_assert(MessageStoreLike<MessageRing>);

}  // namespace lle::mold
