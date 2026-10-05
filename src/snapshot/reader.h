#pragma once
// Validating snapshot loader (06 §7 step 4, §9). Snapshot files are untrusted
// input: a torn copy, a misdirected write or bit rot must be detected, never
// trusted, so Reader::open validates the whole image (header, layout arithmetic,
// trailer, session table, every chunk CRC and the cross-section CRC) before it
// exposes any data. It never asserts, overflows or reads out of bounds on
// arbitrary bytes; the fuzz harness fuzz/journal/snapshot_loader_fuzz.cpp checks
// this.
//
// Payload cursor error model (sticky, like the writer): a read that does not fit
// in the remaining payload consumes nothing, zero-fills its output (typed getters
// return 0), and turns ok() false for good; every later read also fails. This
// suits `static Engine restore(snap::Reader&)` (01 §8): decode straight through,
// then check ok() and remaining() == 0 once at the end. Reads that span chunk
// boundaries are transparent.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "common/endian.h"
#include "snapshot/format.h"
#include "snapshot/storage.h"

namespace lle::snap {

class Reader {
 public:
  // Validates `image` and returns a reader over it. The reader does not copy the
  // image: it must outlive the reader.
  [[nodiscard]] static std::expected<Reader, LoadError> open(std::span<const std::byte> image);

  [[nodiscard]] const SnapshotMeta& meta() const noexcept { return meta_; }
  [[nodiscard]] const SnapshotLayout& layout() const noexcept { return layout_; }
  [[nodiscard]] std::span<const SessionSeq> sessions() const noexcept { return sessions_; }
  [[nodiscard]] std::span<const std::byte> image() const noexcept { return image_; }

  // --- Payload cursor (little-endian) ---
  bool read(std::span<std::byte> out) noexcept;
  bool get_bytes(std::span<std::byte> out) noexcept { return read(out); }
  bool skip(std::uint64_t n) noexcept;
  [[nodiscard]] std::uint8_t get_u8() noexcept { return get_le<std::uint8_t>(); }
  [[nodiscard]] std::uint16_t get_u16() noexcept { return get_le<std::uint16_t>(); }
  [[nodiscard]] std::uint32_t get_u32() noexcept { return get_le<std::uint32_t>(); }
  [[nodiscard]] std::uint64_t get_u64() noexcept { return get_le<std::uint64_t>(); }
  [[nodiscard]] std::int32_t get_i32() noexcept { return get_le<std::int32_t>(); }
  [[nodiscard]] std::int64_t get_i64() noexcept { return get_le<std::int64_t>(); }

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] std::uint64_t position() const noexcept { return pos_; }
  [[nodiscard]] std::uint64_t remaining() const noexcept { return layout_.payload_bytes - pos_; }

 private:
  Reader() = default;

  [[nodiscard]] const std::byte* chunk_data(std::uint64_t chunk_index) const noexcept {
    return image_.data() + layout_.payload_offset + chunk_index * chunk_frame_bytes(layout_.chunk_bytes);
  }

  template <class T>
  [[nodiscard]] T get_le() noexcept {
    using U = std::make_unsigned_t<T>;
    // Fast path: the value lies inside the current chunk (the remaining() test
    // also covers the shorter last chunk).
    const std::uint64_t off = pos_ & chunk_mask_;
    if (ok_ && sizeof(T) <= remaining() && off + sizeof(T) <= layout_.chunk_bytes) {
      const std::byte* p = chunk_data(pos_ >> chunk_shift_) + off;
      pos_ += sizeof(T);
      return static_cast<T>(to_little(load_raw<U>(p)));
    }
    std::byte tmp[sizeof(T)];
    if (!read(tmp)) return T{};
    return static_cast<T>(to_little(load_raw<U>(tmp)));
  }

  std::span<const std::byte> image_;
  SnapshotMeta meta_;
  SnapshotLayout layout_;
  std::vector<SessionSeq> sessions_;
  std::uint64_t chunk_mask_ = 0;
  int chunk_shift_ = 0;
  std::uint64_t pos_ = 0;
  bool ok_ = true;
};

// A snapshot file mapped read-only and validated (cold path: recovery and
// tools). The mapping is private and read-only; snapshots are immutable once
// renamed into place (a rewrite replaces the inode), but truncating a mapped
// file from outside would raise SIGBUS, as with any mmap.
class MappedSnapshot {
 public:
  [[nodiscard]] static std::expected<MappedSnapshot, LoadError> open(const std::string& path);

  MappedSnapshot(MappedSnapshot&& other) noexcept;
  MappedSnapshot& operator=(MappedSnapshot&&) = delete;
  MappedSnapshot(const MappedSnapshot&) = delete;
  MappedSnapshot& operator=(const MappedSnapshot&) = delete;
  ~MappedSnapshot();

  [[nodiscard]] Reader& reader() noexcept { return reader_; }
  [[nodiscard]] const Reader& reader() const noexcept { return reader_; }
  [[nodiscard]] const SnapshotMeta& meta() const noexcept { return reader_.meta(); }

 private:
  MappedSnapshot(void* base, std::size_t len, Reader reader) noexcept;

  void* base_ = nullptr;
  std::size_t len_ = 0;
  Reader reader_;
};

// Fully validates the file at `path`.
[[nodiscard]] std::expected<SnapshotMeta, LoadError> validate_file(const std::string& path);

struct SnapshotInfo {
  std::string path;
  SnapshotMeta meta;
  SnapshotLayout layout;
};

// Recovery step 4 (06 §7): the newest snapshot in `day_dir` with index <=
// `max_index` that fully validates and whose header index matches its file name
// (so a misnamed file cannot make recovery replay from the wrong point). Ignores
// temporary files and other names; falls back to older snapshots when a newer
// one is corrupt. nullopt if there is none (or the directory does not exist).
// The caller still checks meta.day against the day it is recovering.
[[nodiscard]] std::optional<SnapshotInfo> find_latest(const std::string& day_dir, std::uint64_t max_index);

// A snapshot read whole through a Storage (snapshot/storage.h) and validated.
class LoadedSnapshot {
 public:
  [[nodiscard]] static std::expected<LoadedSnapshot, LoadError> open(Storage& storage, const std::string& path);
  [[nodiscard]] const SnapshotMeta& meta() const noexcept { return reader_->meta(); }
  [[nodiscard]] Reader& reader() noexcept { return *reader_; }
  [[nodiscard]] const Reader& reader() const noexcept { return *reader_; }

 private:
  LoadedSnapshot() = default;
  std::vector<std::byte> image_;  // the reader points into it (a move keeps the buffer)
  std::optional<Reader> reader_;
};

// find_latest() through a Storage.
[[nodiscard]] std::optional<SnapshotInfo> find_latest(Storage& storage, const std::string& day_dir,
                                                      std::uint64_t max_index);

}  // namespace lle::snap
