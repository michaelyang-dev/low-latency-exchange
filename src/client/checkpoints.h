#pragma once
// Book checkpoints for the real-feed arbitration evidence (03-protocols §9, T10).
//
// The acceptance criterion compares the book a client reconstructs from lossy
// dual lines with a direct replay of the file. A full NASDAQ day ends with an
// empty book (01302019: 0 live orders at the end), so the final digest alone
// proves little. Both sides therefore record checkpoints at the same sequences:
//   - books_digest: the final-books digest of src/book/digest.h after applying
//     message `seq` (every resting order: locate, side, level, FIFO position,
//     reference and shares);
//   - stream_hash: a hash of every message delivered since the previous
//     checkpoint, (sequence, length, bytes), which shows the delivered stream is
//     the file's, exactly once and in order;
//   - bbo_digest: the running BBO-change digest, when the book records it.
// A snapshot join skips messages: checkpoints inside the skipped range are not
// observed, and the next checkpoint's stream hash and BBO digest are marked
// `tainted` (not comparable); its book digest still is. The client also records
// a checkpoint right after each splice (at S(P)) so the rebuilt book itself is
// compared; the direct replay takes those sequences as extra checkpoints.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "common/hash.h"
#include "common/types.h"

namespace lle::client {

struct Checkpoint {
  SeqNo seq = 0;  // book state after applying message `seq`
  std::uint64_t books_digest = 0;
  std::uint64_t live_orders = 0;
  std::uint64_t stream_hash = 0;
  std::uint64_t bbo_digest = 0;
  bool tainted = false;  // a snapshot splice lies between the previous checkpoint and this one
  bool splice = false;   // recorded right after a snapshot splice (not a planned sequence)
};

// Order-sensitive hash of a message stream: (seq, len, bytes in 8-byte words).
class StreamHasher {
 public:
  static constexpr std::uint64_t kSeed = 0x6C6C652D'73747231ull;  // "lle-str1"
  void add(SeqNo seq, std::span<const std::byte> msg) noexcept {
    std::uint64_t h = combine(h_, seq);
    h = combine(h, msg.size());
    std::size_t i = 0;
    for (; i + 8 <= msg.size(); i += 8) {
      std::uint64_t w;
      std::memcpy(&w, msg.data() + i, 8);
      h = combine(h, w);
    }
    if (i < msg.size()) {
      std::uint64_t w = 0;
      std::memcpy(&w, msg.data() + i, msg.size() - i);
      h = combine(h, w);
    }
    h_ = h;
  }
  [[nodiscard]] std::uint64_t value() const noexcept { return h_; }
  void reset() noexcept { h_ = kSeed; }

 private:
  std::uint64_t h_ = kSeed;
};

struct CheckpointConfig {
  std::uint64_t every = 0;          // a checkpoint at every multiple of this sequence; 0 = none
  std::vector<SeqNo> extra;         // more checkpoint sequences (any order)
  std::size_t max_checkpoints = 1 << 14;
};

class CheckpointRecorder {
 public:
  explicit CheckpointRecorder(const CheckpointConfig& cfg) : every_(cfg.every), extra_(cfg.extra), max_(cfg.max_checkpoints) {
    std::sort(extra_.begin(), extra_.end());
    extra_.erase(std::unique(extra_.begin(), extra_.end()), extra_.end());
    list_.reserve(max_);
    next_ = next_after(0);
  }

  [[nodiscard]] bool enabled() const noexcept { return every_ != 0 || !extra_.empty(); }

  // Called for every delivered message after the book applied it.
  template <class Book>
  void on_message(SeqNo seq, std::span<const std::byte> msg, const Book& book, std::uint64_t bbo) {
    hash_.add(seq, msg);
    if (seq == next_) {
      record(seq, book, bbo, false);
      next_ = next_after(seq);
    }
  }

  // A snapshot splice: messages [from, to) were not delivered; the book now
  // holds the state after message to - 1.
  template <class Book>
  void on_splice(SeqNo from, SeqNo to, const Book& book, std::uint64_t bbo) {
    tainted_ = true;
    while (next_ != 0 && next_ < to) {
      ++skipped_;
      next_ = next_after(next_);
    }
    (void)from;
    if (to > 1) record(to - 1, book, bbo, true);
  }

  // The final checkpoint (end of the stream).
  template <class Book>
  // `last` is the sequence the book reflects: the last message delivered, or
  // S(P) when the stream ended inside a snapshot splice.
  void finish(SeqNo last, const Book& book, std::uint64_t bbo) {
    if (last != 0 && (list_.empty() || list_.back().seq != last)) record(last, book, bbo, false);
  }

  [[nodiscard]] const std::vector<Checkpoint>& list() const noexcept { return list_; }
  [[nodiscard]] std::uint64_t skipped() const noexcept { return skipped_; }
  [[nodiscard]] std::uint64_t dropped() const noexcept { return dropped_; }

 private:
  [[nodiscard]] SeqNo next_after(SeqNo s) const noexcept {
    SeqNo n = 0;
    if (every_ != 0) n = (s / every_ + 1) * every_;
    const auto it = std::upper_bound(extra_.begin(), extra_.end(), s);
    if (it != extra_.end() && (n == 0 || *it < n)) n = *it;
    return n;
  }

  template <class Book>
  void record(SeqNo seq, const Book& book, std::uint64_t bbo, bool splice) {
    if (list_.size() >= max_) {
      ++dropped_;
      return;
    }
    list_.push_back(Checkpoint{seq, book.books_digest(), book.live_orders(), hash_.value(), bbo, tainted_, splice});
    hash_.reset();
    tainted_ = false;
  }

  std::uint64_t every_;
  std::vector<SeqNo> extra_;
  std::size_t max_;
  std::vector<Checkpoint> list_;
  StreamHasher hash_;
  SeqNo next_ = 0;
  bool tainted_ = false;
  std::uint64_t skipped_ = 0;
  std::uint64_t dropped_ = 0;
};

}  // namespace lle::client
