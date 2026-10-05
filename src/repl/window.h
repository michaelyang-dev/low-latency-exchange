#pragma once
// RecordWindow: the records a sender has read from its log but the receiver has not
// acknowledged, kept for retransmission (10 §3: NACK and go-back-N resend).
//
// A byte ring holding consecutive journal records [first(), last()] in canonical form.
// A record never wraps: if it does not fit before the end of the buffer, the gap to the
// end is skipped (and charged to that record until it is popped). Fixed capacity,
// allocated by init(); push/get/pop never allocate. Single-threaded.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

#include "common/assert.h"

namespace lle::repl {

class RecordWindow {
 public:
  void init(std::size_t bytes, std::size_t max_records) {
    LLE_ASSERT(bytes >= 64 * 1024 && max_records >= 16, "window too small");
    buf_ = std::make_unique<std::byte[]>(bytes);
    cap_ = bytes;
    ents_ = std::make_unique<Entry[]>(max_records);
    max_ = max_records;
    clear(1);
  }

  // Empties the window; the next push must be `next_index`.
  void clear(std::uint64_t next_index) noexcept {
    first_ = next_index;
    count_ = 0;
    head_ = 0;
    tail_ = 0;
    used_ = 0;
  }

  [[nodiscard]] bool empty() const noexcept { return count_ == 0; }
  [[nodiscard]] std::uint64_t first() const noexcept { return first_; }
  // Index of the newest record, or first() - 1 when empty.
  [[nodiscard]] std::uint64_t last() const noexcept { return first_ + count_ - 1; }
  [[nodiscard]] std::size_t bytes_used() const noexcept { return used_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return cap_; }

  [[nodiscard]] bool has_room(std::size_t len) const noexcept {
    if (count_ == max_ || len > cap_) return false;
    const std::size_t gap = tail_ + len > cap_ ? cap_ - tail_ : 0;
    return used_ + gap + len <= cap_;
  }

  // Appends record last() + 1. Returns false if there is no room.
  bool push(std::span<const std::byte> rec) noexcept {
    const std::size_t len = rec.size();
    if (len == 0 || !has_room(len)) return false;
    std::size_t gap = 0;
    if (tail_ + len > cap_) {
      gap = cap_ - tail_;
      tail_ = 0;
    }
    std::memcpy(buf_.get() + tail_, rec.data(), len);
    ents_[(head_ent() + count_) % max_] = Entry{tail_, static_cast<std::uint32_t>(len), static_cast<std::uint32_t>(gap)};
    tail_ += len;
    if (tail_ == cap_) tail_ = 0;
    used_ += gap + len;
    ++count_;
    return true;
  }

  // The record with this index, or an empty span.
  [[nodiscard]] std::span<const std::byte> get(std::uint64_t index) const noexcept {
    if (index < first_ || index >= first_ + count_) return {};
    const Entry& e = ents_[(head_ent() + static_cast<std::size_t>(index - first_)) % max_];
    return {buf_.get() + e.off, e.len};
  }

  // Drops every record with index <= `index`.
  void pop_through(std::uint64_t index) noexcept {
    while (count_ != 0 && first_ <= index) {
      const Entry& e = ents_[head_ent()];
      used_ -= e.gap + e.len;
      ++first_;
      --count_;
      ++ent_head_;
    }
    if (count_ == 0) {
      head_ = 0;
      tail_ = 0;
      used_ = 0;
    }
  }

 private:
  struct Entry {
    std::size_t off = 0;
    std::uint32_t len = 0;
    std::uint32_t gap = 0;  // bytes skipped at the end of the buffer before this record
  };
  [[nodiscard]] std::size_t head_ent() const noexcept { return ent_head_ % max_; }

  std::unique_ptr<std::byte[]> buf_;
  std::size_t cap_ = 0;
  std::unique_ptr<Entry[]> ents_;
  std::size_t max_ = 0;
  std::size_t ent_head_ = 0;
  std::uint64_t first_ = 1;
  std::size_t count_ = 0;
  std::size_t head_ = 0;
  std::size_t tail_ = 0;
  std::size_t used_ = 0;
};

}  // namespace lle::repl
