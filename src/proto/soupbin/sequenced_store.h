#pragma once
// SequencedStore: the released sequenced messages of one SoupBinTCP session,
// read for re-login replay (03-protocols s5 "Replay"). The production store is
// an in-memory ring backed by the output log (06-sequencer-journal-recovery,
// J-09); MemorySequencedStore is a bounded, preallocated implementation for
// tests, the simulator and small deployments.
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>

#include "common/types.h"

namespace lle::soup {

// Sequence numbers start at 1 (spec 1.2). next_seq() is the number the next
// appended message receives, i.e. highest + 1. get() returns nullopt for a
// sequence the store cannot serve (never appended or evicted); zero-length
// messages are legal and come back as an empty span.
template <class S>
concept SequencedStoreLike = requires(S& s, const S& cs, SeqNo seq, std::span<const std::byte> msg) {
  { cs.next_seq() } -> std::same_as<SeqNo>;
  { s.append(msg) } -> std::same_as<bool>;
  { cs.get(seq) } -> std::same_as<std::optional<std::span<const std::byte>>>;
};

class MemorySequencedStore {
 public:
  // Allocates everything up front; append() fails once either bound is hit.
  MemorySequencedStore(std::size_t max_messages, std::size_t max_bytes)
      : offsets_(std::make_unique_for_overwrite<std::size_t[]>(max_messages + 1)),
        bytes_(std::make_unique_for_overwrite<std::byte[]>(max_bytes)),
        max_messages_(max_messages),
        max_bytes_(max_bytes) {
    offsets_[0] = 0;
  }

  [[nodiscard]] SeqNo next_seq() const noexcept { return static_cast<SeqNo>(count_) + 1; }
  [[nodiscard]] std::size_t size() const noexcept { return count_; }

  bool append(std::span<const std::byte> msg) noexcept {
    if (count_ >= max_messages_ || max_bytes_ - used_ < msg.size()) return false;
    if (!msg.empty()) std::memcpy(bytes_.get() + used_, msg.data(), msg.size());
    used_ += msg.size();
    offsets_[++count_] = used_;
    return true;
  }

  [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo seq) const noexcept {
    if (seq == 0 || seq > count_) return std::nullopt;
    const std::size_t i = static_cast<std::size_t>(seq);
    return std::span<const std::byte>(bytes_.get() + offsets_[i - 1], offsets_[i] - offsets_[i - 1]);
  }

  void clear() noexcept {
    count_ = 0;
    used_ = 0;
  }

 private:
  std::unique_ptr<std::size_t[]> offsets_;  // offsets_[i] = end of message i; offsets_[0] = 0
  std::unique_ptr<std::byte[]> bytes_;
  std::size_t max_messages_;
  std::size_t max_bytes_;
  std::size_t count_ = 0;
  std::size_t used_ = 0;
};

static_assert(SequencedStoreLike<MemorySequencedStore>);

}  // namespace lle::soup
