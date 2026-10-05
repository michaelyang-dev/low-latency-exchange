#pragma once
// Prefix checker for byte streams (O-PREFIX, 09 §7): an observed stream must
// always be a prefix of the canonical stream.
//
// Both sides are fed incrementally. Only the unmatched tail of whichever side
// is ahead is buffered, so memory stays proportional to the lag, not to the
// stream length. A divergence is sticky and records its byte offset.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lle::sim {

class PrefixChecker {
 public:
  // Returns false once the streams have diverged.
  bool append_canonical(std::span<const std::byte> b) { return feed(b, /*canonical=*/true); }
  bool append_observed(std::span<const std::byte> b) { return feed(b, /*canonical=*/false); }

  // Observed is a prefix of canonical: no divergence and no observed bytes
  // beyond the canonical end.
  [[nodiscard]] bool is_prefix() const noexcept { return !diverged_ && !(observed_ahead_ && pending() > 0); }
  [[nodiscard]] bool diverged() const noexcept { return diverged_; }
  [[nodiscard]] std::uint64_t divergence_offset() const noexcept { return divergence_offset_; }
  [[nodiscard]] std::uint64_t canonical_size() const noexcept { return canonical_size_; }
  [[nodiscard]] std::uint64_t observed_size() const noexcept { return observed_size_; }
  [[nodiscard]] std::uint64_t matched() const noexcept { return std::min(canonical_size_, observed_size_); }

 private:
  [[nodiscard]] std::size_t pending() const noexcept { return buf_.size() - head_; }

  bool feed(std::span<const std::byte> b, bool canonical) {
    if (diverged_) return false;
    std::uint64_t& my_size = canonical ? canonical_size_ : observed_size_;
    const bool i_am_ahead = canonical ? !observed_ahead_ : observed_ahead_;
    std::size_t i = 0;
    if (!i_am_ahead || pending() == 0) {
      // Compare against the other side's buffered tail.
      while (i < b.size() && pending() > 0) {
        if (buf_[head_] != b[i]) {
          diverged_ = true;
          divergence_offset_ = my_size + i;
          return false;
        }
        ++head_;
        ++i;
      }
      if (pending() == 0) {
        buf_.clear();
        head_ = 0;
        observed_ahead_ = !canonical;
      }
    }
    // Whatever is left puts this side ahead.
    buf_.insert(buf_.end(), b.begin() + static_cast<std::ptrdiff_t>(i), b.end());
    if (head_ > 4096 && head_ * 2 > buf_.size()) {
      buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(head_));
      head_ = 0;
    }
    my_size += b.size();
    return true;
  }

  std::vector<std::byte> buf_;
  std::size_t head_ = 0;
  bool observed_ahead_ = false;  // which side owns buf_ when pending() > 0
  bool diverged_ = false;
  std::uint64_t divergence_offset_ = 0;
  std::uint64_t canonical_size_ = 0;
  std::uint64_t observed_size_ = 0;
};

}  // namespace lle::sim
