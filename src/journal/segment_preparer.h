#pragma once
// SegmentPreparer (06 §6): initializes segments ahead of use, off the hot path.
//
//   1. invalidate the header block (zeros, dsync), so a half-prepared file is never
//      mistaken for a segment;
//   2. zero-fill the whole file and sync, so every later append is a pure overwrite
//      (FUA fast path on the device, and ENOSPC cannot occur on the hot path);
//   3. write a fresh header: new nonce, first_index 0 ("prepared, unassigned"), dsync;
//   4. fsync the directory (the file may be new or renamed).
//
// Recycled segments go through the same steps: they are always re-zeroed and
// re-nonced. The new nonce's seed differs from the old one, so even a record that
// survived an incomplete zero-fill can never validate in the new incarnation.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <span>

#include "env/concepts.h"
#include "journal/journal_device.h"
#include "journal/record.h"
#include "journal/segment.h"
#include "journal/segment_dir.h"

namespace lle::journal {

struct PreparedSegment {
  std::size_t handle = 0;  // index in the SegmentDirLike
  SegmentHeader header;    // prepared: first_index == 0
};

enum class PrepareError : std::uint8_t { CreateFailed, IoError, BadSize };

template <SegmentDirLike Dir, env::RngLike Rng>
class SegmentPreparer {
 public:
  static constexpr std::size_t kChunkBytes = std::size_t{1} << 20;

  // `rng` draws nonces: the simulator passes its seeded stream, production a generator
  // seeded from the OS at startup.
  SegmentPreparer(Dir& dir, Rng& rng, std::uint32_t day, std::uint64_t segment_bytes = kDefaultSegmentBytes)
      : dir_(&dir), rng_(&rng), day_(day), segment_bytes_(segment_bytes), zeros_(alloc_zeros()) {}

  [[nodiscard]] std::uint64_t segment_bytes() const noexcept { return segment_bytes_; }

  // Creates and prepares a new pool file ("prep-<n>.seg").
  std::expected<PreparedSegment, PrepareError> create() {
    if (!valid_size()) return std::unexpected(PrepareError::BadSize);
    std::optional<std::size_t> h;
    for (std::uint64_t n = dir_->count(); !h && n < dir_->count() + 1'000'000; ++n) {
      h = dir_->create(prepared_file_name(n), segment_bytes_);
    }
    if (!h) return std::unexpected(PrepareError::CreateFailed);
    return prepare(*h, 0);
  }

  // Re-zeroes and re-nonces an existing segment file (any content, any size: it is
  // resized to segment_bytes()).
  std::expected<PreparedSegment, PrepareError> recycle(std::size_t handle) {
    if (!valid_size()) return std::unexpected(PrepareError::BadSize);
    auto& dev = dir_->device(handle);
    std::uint64_t old_nonce = 0;
    const std::span<std::byte> block = header_block();
    if (read_exact(dev, 0, block)) {
      if (auto old = decode_segment_header(block)) old_nonce = old->nonce;
    }
    return prepare(handle, old_nonce);
  }

 private:
  struct FreeDeleter {
    void operator()(std::byte* p) const noexcept { std::free(p); }
  };
  using ZeroBuf = std::unique_ptr<std::byte, FreeDeleter>;

  // One 4 KiB-aligned allocation (O_DIRECT devices): a zero chunk followed by a
  // scratch block for headers.
  static ZeroBuf alloc_zeros() {
    auto* p = static_cast<std::byte*>(std::aligned_alloc(kBlockBytes, kChunkBytes + kSegmentHeaderBytes));
    if (p != nullptr) std::memset(p, 0, kChunkBytes + kSegmentHeaderBytes);
    return ZeroBuf(p);
  }
  [[nodiscard]] std::span<std::byte, kSegmentHeaderBytes> header_block() const noexcept {
    return std::span<std::byte, kSegmentHeaderBytes>(zeros_.get() + kChunkBytes, kSegmentHeaderBytes);
  }

  [[nodiscard]] bool valid_size() const noexcept {
    return zeros_ != nullptr && segment_bytes_ >= kMinSegmentBytes && segment_bytes_ % kBlockBytes == 0;
  }

  std::uint64_t fresh_nonce(std::uint64_t old_nonce) {
    const std::uint32_t old_seed = old_nonce == 0 ? 0 : nonce_seed(old_nonce);
    for (;;) {
      const std::uint64_t n = rng_->next_u64();
      if (usable_nonce(n) && n != old_nonce && nonce_seed(n) != old_seed) return n;
    }
  }

  std::expected<PreparedSegment, PrepareError> prepare(std::size_t handle, std::uint64_t old_nonce) {
    auto& dev = dir_->device(handle);
    if (dev.size() != segment_bytes_ && !dev.resize(segment_bytes_)) return std::unexpected(PrepareError::IoError);
    const std::span<const std::byte> zeros(zeros_.get(), kChunkBytes);
    // 1. Invalidate the header first.
    if (write_sync(dev, 0, zeros.first(kSegmentHeaderBytes), true) != static_cast<std::int32_t>(kSegmentHeaderBytes)) {
      return std::unexpected(PrepareError::IoError);
    }
    // 2. Zero-fill everything after it, then one sync.
    for (std::uint64_t off = kSegmentHeaderBytes; off < segment_bytes_;) {
      const std::uint64_t n = std::min<std::uint64_t>(kChunkBytes, segment_bytes_ - off);
      if (write_sync(dev, off, zeros.first(static_cast<std::size_t>(n)), false) != static_cast<std::int32_t>(n)) {
        return std::unexpected(PrepareError::IoError);
      }
      off += n;
    }
    if (sync_device(dev) != 0) return std::unexpected(PrepareError::IoError);
    // 3. Fresh header.
    SegmentHeader h;
    h.day = day_;
    h.nonce = fresh_nonce(old_nonce);
    h.segment_bytes = segment_bytes_;
    const auto block = header_block();
    encode_segment_header(block, h);
    if (write_sync(dev, 0, std::span<const std::byte>(block), true) != static_cast<std::int32_t>(kSegmentHeaderBytes)) {
      return std::unexpected(PrepareError::IoError);
    }
    // 4. Directory entry.
    if (!dir_->sync_dir()) return std::unexpected(PrepareError::IoError);
    return PreparedSegment{handle, h};
  }

  Dir* dir_;
  Rng* rng_;
  std::uint32_t day_;
  std::uint64_t segment_bytes_;
  ZeroBuf zeros_;
};

}  // namespace lle::journal
