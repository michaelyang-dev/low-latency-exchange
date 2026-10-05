#pragma once
// Streaming snapshot writer (06 §9). The engine serializes itself through the
// payload API (`void Engine::snapshot(snap::Writer&) const`, 01 §8); the writer
// cuts the bytes into chunks, CRCs each chunk as it is flushed and, on commit,
// publishes the file atomically:
//
//   write <index:020>.snap.tmp -> fdatasync(tmp) -> rename(tmp, final) -> fsync(dir)
//
// so a crash leaves either no file or a complete one (plus possibly a stale
// .tmp, which find_latest ignores and the next writer at that index truncates).
//
// Error model: the payload calls return nothing, because the engine's snapshot()
// cannot propagate errors. The first failure is sticky: later payload calls are
// ignored, ok() turns false, and commit() returns the error and removes the
// temporary file. Nothing throws.
//
// Memory: one chunk buffer (chunk_bytes + 8), allocated by create(). Not
// thread-safe. This is a cold-path component (snapshotd runs on housekeeping
// cores, 06 §9): file mode calls POSIX directly, and storage mode publishes
// through a snap::Storage (snapshot/storage.h; the simulator's disk).
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "common/endian.h"
#include "snapshot/format.h"
#include "snapshot/storage.h"

namespace lle::snap {

struct WriterOptions {
  std::uint32_t chunk_bytes = kDefaultChunkBytes;  // power of two in [4 KiB, 1 GiB]
  // macOS fsync() does not flush the drive's write cache, so it does not give
  // power-loss durability; F_FULLFSYNC does, at a cost (4.5 ms measured, 06 §6).
  // As for the journal's PosixJournalDevice, it is opt-in (durability tests).
  // Ignored on Linux, where fdatasync/fsync already flush the device cache.
  bool full_fsync = false;
};

class Writer {
 public:
  // File-backed writer for `snap/<day>/<meta.index:020>.snap` in `day_dir`, which
  // must exist. Sessions must be strictly ascending by session_id. Truncates a
  // stale temporary file left by an earlier crash at the same index.
  [[nodiscard]] static std::expected<Writer, Error> create(const std::string& day_dir, const SnapshotMeta& meta,
                                                           std::span<const SessionSeq> sessions = {},
                                                           const WriterOptions& opts = {});

  // Like create(), on `storage` (which must outlive the writer) instead of POSIX.
  [[nodiscard]] static std::expected<Writer, Error> create(Storage& storage, const std::string& day_dir,
                                                           const SnapshotMeta& meta,
                                                           std::span<const SessionSeq> sessions = {},
                                                           const WriterOptions& opts = {});

  // Memory-backed writer producing the same bytes, finished with finish_image();
  // for tests, fuzz seeds and the simulator, which must not touch the disk.
  [[nodiscard]] static std::expected<Writer, Error> create_in_memory(const SnapshotMeta& meta,
                                                                     std::span<const SessionSeq> sessions = {},
                                                                     const WriterOptions& opts = {});

  Writer(Writer&& other) noexcept;
  Writer& operator=(Writer&&) = delete;
  Writer(const Writer&) = delete;
  Writer& operator=(const Writer&) = delete;
  ~Writer();  // removes the temporary file unless committed

  // --- Payload (little-endian) ---
  void write(std::span<const std::byte> bytes) noexcept;
  void put_bytes(std::span<const std::byte> bytes) noexcept { write(bytes); }
  void put_u8(std::uint8_t v) noexcept { put_le(v); }
  void put_u16(std::uint16_t v) noexcept { put_le(v); }
  void put_u32(std::uint32_t v) noexcept { put_le(v); }
  void put_u64(std::uint64_t v) noexcept { put_le(v); }
  void put_i32(std::int32_t v) noexcept { put_le(v); }
  void put_i64(std::int64_t v) noexcept { put_le(v); }

  [[nodiscard]] bool ok() const noexcept { return !error_.has_value(); }
  [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }
  [[nodiscard]] std::uint64_t payload_bytes() const noexcept { return payload_bytes_; }
  [[nodiscard]] const SnapshotMeta& meta() const noexcept { return meta_; }
  // Both "" in memory mode; temp_path() is also "" once the temporary file has
  // been renamed (commit) or removed (abort).
  [[nodiscard]] const std::string& final_path() const noexcept { return final_path_; }
  [[nodiscard]] const std::string& temp_path() const noexcept { return temp_path_; }

  // File mode: flushes the last chunk, writes trailer and header, then runs the
  // atomic sequence above and returns the final path. Any failure before the
  // rename removes the temporary file. A failure of fsync(dir) after the rename
  // is reported as an error although the final file is complete: its directory
  // entry may not be durable, so the caller must not count the snapshot as made.
  // fsync errors are never retried (06 §6: the kernel may have dropped the pages).
  [[nodiscard]] std::expected<std::string, Error> commit();

  // Memory mode: returns the complete image.
  [[nodiscard]] std::expected<std::vector<std::byte>, Error> finish_image();

  // Discards the snapshot: closes and removes the temporary file. Idempotent.
  void abort() noexcept;

 private:
  enum class Mode : std::uint8_t { File, Memory, Store };

  Writer(Mode mode, const SnapshotMeta& meta, const WriterOptions& opts) noexcept;
  [[nodiscard]] static std::expected<Writer, Error> make(Mode mode, Storage* storage, const std::string& day_dir,
                                                         const SnapshotMeta& meta,
                                                         std::span<const SessionSeq> sessions,
                                                         const WriterOptions& opts);

  template <class T>
  void put_le(T v) noexcept {
    // Fast path stays strictly below the chunk end so the buffer is only ever
    // filled to the brim, and flushed, by write(). fast_limit_ is 0 once the
    // writer has failed or closed, which routes every call to write().
    if (fill_ + sizeof(T) < fast_limit_) {
      store_raw(buf_.get() + fill_, to_little(static_cast<std::make_unsigned_t<T>>(v)));
      fill_ += sizeof(T);
      payload_bytes_ += sizeof(T);
      return;
    }
    std::byte tmp[sizeof(T)];
    store_raw(tmp, to_little(static_cast<std::make_unsigned_t<T>>(v)));
    write(tmp);
  }

  void fail(Error e) noexcept;
  void flush_chunk() noexcept;
  bool put_at(std::uint64_t offset, const std::byte* data, std::size_t n) noexcept;
  bool finish_sections() noexcept;
  void close_fd() noexcept;
  [[nodiscard]] std::expected<std::string, Error> commit_store();
  void remove_temp() noexcept;

  Mode mode_;
  bool open_ = false;  // accepting payload; the temporary file (file mode) exists
  int fd_ = -1;        // file mode: descriptor; storage mode: the storage's handle
  Storage* storage_ = nullptr;
  std::string day_dir_;
  std::string temp_path_;
  std::string final_path_;
  SnapshotMeta meta_;
  WriterOptions opts_;
  std::uint32_t session_count_ = 0;
  std::unique_ptr<std::byte[]> buf_;  // chunk_bytes + 8: room for the CRC and pad
  std::size_t chunk_bytes_ = 0;
  std::size_t fill_ = 0;
  std::size_t fast_limit_ = 0;
  std::uint64_t payload_bytes_ = 0;
  std::uint64_t offset_ = 0;          // where the next chunk goes
  std::uint64_t chunk_index_ = 0;
  std::uint32_t sections_crc_ = 0;    // running CRC over table_crc and chunk CRCs
  std::optional<Error> error_;
  std::vector<std::byte> mem_;        // memory mode only
};

// Encodes a complete image in memory (memory-mode Writer + write + finish_image).
[[nodiscard]] std::expected<std::vector<std::byte>, Error> encode_image(const SnapshotMeta& meta,
                                                                        std::span<const SessionSeq> sessions,
                                                                        std::span<const std::byte> payload,
                                                                        std::uint32_t chunk_bytes = kDefaultChunkBytes);

}  // namespace lle::snap
