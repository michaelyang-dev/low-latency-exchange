#pragma once
// OutlogWriter: appends released messages to one output-log data file and its
// sparse index (06 §8). Used by the `io` stage, one writer per file.
//
// Design rules:
//   - open() allocates every buffer and repairs an existing file; append(),
//     flush(), sync() and count() never allocate and never throw.
//   - Writes are asynchronous with respect to the Output Rule: the output log
//     is derived data, so nothing waits for fsync (06 §8). sync() exists for
//     tools and tests and is never required for correctness.
//   - A failed system call makes the writer fail permanently ("sticky"): the
//     data file may then end in a torn record, which the next open() repairs.
//     Nothing is retried (the journal's error policy, 06 §6).
//   - One writer per data file, enforced with an advisory flock.
//   - Generic over the storage (outlog/disk.h): OutlogWriter is the POSIX
//     binding; the simulator instantiates BasicOutlogWriter on its disk.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <utility>

#include "common/assert.h"
#include "common/endian.h"
#include "common/types.h"
#include "outlog/disk.h"
#include "outlog/file_io.h"
#include "outlog/format.h"
#include "outlog/posix_fs.h"

namespace lle::outlog {

template <OutlogFsLike Fs>
class BasicOutlogWriter {
 public:
  using File = typename Fs::File;
  static constexpr std::size_t kDefaultBufferBytes = std::size_t{1} << 20;
  static constexpr std::size_t kMinBufferBytes = kMaxRecordBytes;  // any record fits

  BasicOutlogWriter() requires std::default_initializable<Fs> = default;
  explicit BasicOutlogWriter(Fs fs) noexcept : fs_(std::move(fs)) {}
  ~BasicOutlogWriter();
  BasicOutlogWriter(const BasicOutlogWriter&) = delete;
  BasicOutlogWriter& operator=(const BasicOutlogWriter&) = delete;

  // Creates `path` and `path.idx`, or opens an existing log: it is repaired
  // first (torn tail truncated, index rebuilt if it does not match) and
  // appending continues after its last complete message. `buffer_bytes` is
  // raised to kMinBufferBytes if smaller.
  std::expected<void, std::string> open(const std::string& path, std::size_t buffer_bytes = kDefaultBufferBytes);

  // Appends one message and returns its sequence number. The message is
  // copied into the user-space buffer; write(2) happens only when the buffer
  // cannot take the next record.
  std::expected<SeqNo, Error> append(std::span<const std::byte> msg) noexcept {
    if (failed_) [[unlikely]] return std::unexpected(Error::Io);
    if (!file_.valid()) [[unlikely]] return std::unexpected(Error::NotOpen);
    const std::size_t n = msg.size();
    if (n == 0) [[unlikely]] return std::unexpected(Error::EmptyMessage);
    if (n > kMaxMessageBytes) [[unlikely]] return std::unexpected(Error::MessageTooLarge);
    if (cap_ - buf_len_ < kLengthPrefixBytes + n) [[unlikely]] {
      if (!write_out()) return std::unexpected(Error::Io);
    }
    if (count_ % kIndexInterval == 0) [[unlikely]] push_index_entry(file_bytes_ + buf_len_);
    std::byte* p = buf_.get() + buf_len_;
    store_be16(p, static_cast<std::uint16_t>(n));
    std::memcpy(p + kLengthPrefixBytes, msg.data(), n);
    buf_len_ += kLengthPrefixBytes + n;
    return ++count_;
  }

  // Writes buffered data, then the index entries that point into it.
  std::expected<void, Error> flush() noexcept;
  // flush() + fdatasync of data and index. Optional (derived data).
  std::expected<void, Error> sync() noexcept;
  // flush() and release the file (and its lock). The writer is closed even
  // when the final flush fails; the error is still reported.
  std::expected<void, Error> close() noexcept;

  [[nodiscard]] bool is_open() const noexcept { return file_.valid(); }
  // Messages appended so far, including those still buffered.
  [[nodiscard]] SeqNo count() const noexcept { return count_; }
  // Data bytes appended so far (length prefixes included), buffered or not.
  [[nodiscard]] std::uint64_t bytes() const noexcept { return file_bytes_ + buf_len_; }
  // Data bytes handed to write(2).
  [[nodiscard]] std::uint64_t written_bytes() const noexcept { return file_bytes_; }
  [[nodiscard]] bool failed() const noexcept { return failed_; }
  // Describes the failure (empty when not failed). Allocates; diagnostics only.
  [[nodiscard]] std::string error_message() const;
  [[nodiscard]] const std::string& path() const noexcept { return path_; }

 private:
  void push_index_entry(std::uint64_t off) noexcept {
    // Sized in open() so that every boundary crossed by the buffered messages fits.
    LLE_ASSERT(pending_len_ < pending_cap_, "outlog: index entry buffer overflow");
    store_le64(pending_.get() + pending_len_ * kIndexEntryBytes, off);
    ++pending_len_;
  }
  bool write_out() noexcept;
  bool fail(const char* op, int err) noexcept;

  Fs fs_{};
  File file_;
  File idx_file_;
  std::string path_;
  std::unique_ptr<std::byte[]> buf_;
  std::size_t cap_ = 0;
  std::size_t buf_len_ = 0;
  std::unique_ptr<std::byte[]> pending_;  // encoded u64 LE index entries not yet written
  std::size_t pending_cap_ = 0;           // in entries
  std::size_t pending_len_ = 0;           // in entries
  std::uint64_t file_bytes_ = 0;          // data bytes written to the file
  std::uint64_t idx_written_ = 0;         // index entries written to the file
  SeqNo count_ = 0;
  bool failed_ = false;
  const char* err_op_ = "";
  int err_no_ = 0;
};

// The production writer: POSIX files.
using OutlogWriter = BasicOutlogWriter<PosixFs>;
extern template class BasicOutlogWriter<PosixFs>;

}  // namespace lle::outlog
