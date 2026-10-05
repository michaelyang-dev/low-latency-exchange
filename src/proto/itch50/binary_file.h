#pragma once
// NASDAQ BinaryFILE 1.00 framing (03-protocols §3): records of
//   [u16 big-endian length][message bytes]
// repeated. A zero-length record marks the end of a session; a file that ends
// without one is "incomplete" per the spec, but NASDAQ's historical files end
// with System Event 'C' and no zero-length record (R1a Q4), so a clean EOF at
// a record boundary is reported as EndOfFile, not as an error.
//
//   BinaryFileView    zero-copy parser over an in-memory buffer (tests, fuzzing,
//                     mmapped files);
//   BinaryFileReader  streaming reader for plain files (buffered read(2)) and
//                     gzip files (zlib, multi-member aware), constant memory;
//   MappedFile        read-only mmap of a whole plain file.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>

#include "common/endian.h"

namespace lle::itch50 {

enum class RecordStatus : std::uint8_t {
  Message,       // `data` holds one message (length >= 1)
  EndOfSession,  // zero-length record; reading may continue
  EndOfFile,     // clean end at a record boundary
  Truncated,     // input ended inside a record; `data` holds the partial bytes
  IoError,       // read or decompression failure
};

struct Record {
  RecordStatus status = RecordStatus::EndOfFile;
  std::span<const std::byte> data;  // valid until the next call
};

// Zero-copy parser over a complete buffer.
class BinaryFileView {
 public:
  constexpr explicit BinaryFileView(std::span<const std::byte> buf) noexcept : buf_(buf) {}

  [[nodiscard]] Record next() noexcept {
    const std::size_t avail = buf_.size() - pos_;
    if (avail == 0) return {RecordStatus::EndOfFile, {}};
    if (avail < 2) {
      Record r{RecordStatus::Truncated, buf_.subspan(pos_)};
      pos_ = buf_.size();
      return r;
    }
    const std::size_t len = load_be16(buf_.data() + pos_);
    if (avail < 2 + len) {
      Record r{RecordStatus::Truncated, buf_.subspan(pos_)};
      pos_ = buf_.size();
      return r;
    }
    const std::span<const std::byte> msg = buf_.subspan(pos_ + 2, len);
    pos_ += 2 + len;
    return {len == 0 ? RecordStatus::EndOfSession : RecordStatus::Message, msg};
  }

  // Offset of the next record's length prefix.
  [[nodiscard]] std::size_t offset() const noexcept { return pos_; }

 private:
  std::span<const std::byte> buf_;
  std::size_t pos_ = 0;
};

// Streaming reader. Memory use is the fixed buffer chosen at open(), whatever
// the file size. Not thread-safe; not copyable.
class BinaryFileReader {
 public:
  static constexpr std::size_t kDefaultBufferBytes = std::size_t{4} << 20;
  static constexpr std::size_t kMinBufferBytes = std::size_t{1} << 17;  // > 2 + 65535

  BinaryFileReader() noexcept;
  ~BinaryFileReader();
  BinaryFileReader(const BinaryFileReader&) = delete;
  BinaryFileReader& operator=(const BinaryFileReader&) = delete;

  // Opens `path`; gzip input is detected by its magic bytes (1f 8b), not the
  // file name. "-" reads standard input (plain or gzip).
  std::expected<void, std::string> open(const std::string& path, std::size_t buffer_bytes = kDefaultBufferBytes);
  void close() noexcept;

  [[nodiscard]] Record next() noexcept {
    const std::size_t avail = end_ - pos_;
    if (avail >= 2) [[likely]] {
      const std::size_t len = load_be16(buf_.get() + pos_);
      if (avail >= 2 + len) [[likely]] {
        const std::span<const std::byte> msg(buf_.get() + pos_ + 2, len);
        pos_ += 2 + len;
        consumed_ += 2 + len;
        return {len == 0 ? RecordStatus::EndOfSession : RecordStatus::Message, msg};
      }
    }
    return next_slow();
  }

  [[nodiscard]] bool is_open() const noexcept { return kind_ != SourceKind::None; }
  [[nodiscard]] bool compressed() const noexcept { return kind_ == SourceKind::Gzip; }
  // Decompressed bytes consumed by returned records (length prefixes included).
  [[nodiscard]] std::uint64_t bytes_consumed() const noexcept { return consumed_; }
  [[nodiscard]] const std::string& error() const noexcept { return error_; }

 private:
  enum class SourceKind : std::uint8_t { None, Fd, Gzip };

  Record next_slow() noexcept;
  // Reads up to `n` bytes; returns bytes read, 0 at EOF, -1 on error.
  std::ptrdiff_t read_source(std::byte* dst, std::size_t n) noexcept;

  SourceKind kind_ = SourceKind::None;
  int fd_ = -1;
  bool owns_fd_ = false;
  void* gz_ = nullptr;  // gzFile
  bool eof_ = false;
  bool failed_ = false;
  std::unique_ptr<std::byte[]> buf_;
  std::size_t cap_ = 0;
  std::size_t pos_ = 0;
  std::size_t end_ = 0;
  std::uint64_t consumed_ = 0;
  std::string error_;
};

// Read-only mapping of a plain (uncompressed) file.
class MappedFile {
 public:
  MappedFile() noexcept = default;
  ~MappedFile();
  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;

  std::expected<void, std::string> open(const std::string& path);
  void close() noexcept;
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return {static_cast<const std::byte*>(p_), n_}; }

 private:
  void* p_ = nullptr;
  std::size_t n_ = 0;
};

}  // namespace lle::itch50
