#pragma once
// Sequence-contiguity utilities for O-SEQ (09 §7): journal indices, MoldUDP64
// sequence numbers and per-session SoupBinTCP sequences must be contiguous.
#include <cstdint>
#include <map>

#include "common/types.h"

namespace lle::sim {

enum class SeqVerdict : std::uint8_t {
  Ok,         // exactly the next expected number
  Duplicate,  // already seen (below next)
  Gap,        // skipped ahead
};

// One stream. Strict: every observation must be `next()`. Callers that
// tolerate retransmitted duplicates (e.g. MoldUDP64 re-requests) treat
// Duplicate as benign and only fail on Gap.
class SeqContiguityChecker {
 public:
  explicit constexpr SeqContiguityChecker(SeqNo first = 1) noexcept : next_(first) {}

  constexpr SeqVerdict observe(SeqNo s) noexcept {
    if (s == next_) {
      ++next_;
      ++accepted_;
      return SeqVerdict::Ok;
    }
    if (s < next_) {
      ++duplicates_;
      return SeqVerdict::Duplicate;
    }
    ++gaps_;
    return SeqVerdict::Gap;
  }

  // A block [first, first + count), as in a MoldUDP64 packet header. Accepts a
  // block that overlaps already-seen numbers as long as it does not skip ahead.
  constexpr SeqVerdict observe_range(SeqNo first, std::uint64_t count) noexcept {
    if (count == 0) return first <= next_ ? SeqVerdict::Ok : SeqVerdict::Gap;
    const SeqNo end = first + count;
    if (first > next_) {
      ++gaps_;
      return SeqVerdict::Gap;
    }
    if (end <= next_) {
      ++duplicates_;
      return SeqVerdict::Duplicate;
    }
    accepted_ += end - next_;
    next_ = end;
    return SeqVerdict::Ok;
  }

  [[nodiscard]] constexpr SeqNo next() const noexcept { return next_; }
  [[nodiscard]] constexpr std::uint64_t accepted() const noexcept { return accepted_; }
  [[nodiscard]] constexpr std::uint64_t duplicates() const noexcept { return duplicates_; }
  [[nodiscard]] constexpr std::uint64_t gaps() const noexcept { return gaps_; }

 private:
  SeqNo next_;
  std::uint64_t accepted_ = 0;
  std::uint64_t duplicates_ = 0;
  std::uint64_t gaps_ = 0;
};

// Many streams keyed by an integer (session id, line, node). Ordered map, so
// any report iterates deterministically.
class KeyedSeqChecker {
 public:
  explicit KeyedSeqChecker(SeqNo first = 1) : first_(first) {}

  SeqVerdict observe(std::uint64_t key, SeqNo s) { return stream(key).observe(s); }
  SeqContiguityChecker& stream(std::uint64_t key) { return streams_.try_emplace(key, first_).first->second; }
  [[nodiscard]] std::size_t size() const noexcept { return streams_.size(); }
  template <class F>
  void for_each(F&& f) const {
    for (const auto& [k, s] : streams_) f(k, s);
  }

 private:
  SeqNo first_;
  std::map<std::uint64_t, SeqContiguityChecker> streams_;
};

}  // namespace lle::sim
