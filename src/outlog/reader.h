#pragma once
// OutlogReader: random and streaming access to an output-log data file by
// sequence number, for the SoupBinTCP re-login replay and MoldUDP64
// re-request servers (06 §8).
//
// Seeking uses the sparse index (one entry per 4096 messages) and then scans
// forward at most 4095 messages. The index is derived data and is never
// trusted blindly:
//   - open() keeps only its structurally plausible prefix (valid header, entry
//     0 == 0, consecutive entries 4096 minimum-size to 4096 maximum-size
//     records apart, inside the data), checks the block before the last
//     entry, and scans the data after the last entry to count messages;
//   - every other block is checked the first time it is used: the scan from
//     entry k must reach entry k + 1 after exactly 4096 complete messages;
//   - a failed check rebuilds the in-memory index by scanning from the nearest
//     trusted entry. The reader never writes the index file (only the writer
//     and the repair tools do).
// Only complete records count, so a writer may append concurrently from
// another process; refresh() picks up what it has written since.
//
// Memory: open() and refresh() may allocate (the in-memory index grows with
// the file). read(), offset_of() and for_each() use the fixed buffer allocated
// by open() and allocate only when they find the index inconsistent and have
// to rebuild it.
//
// Generic over the storage (outlog/disk.h); OutlogReader reads POSIX files.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "common/types.h"
#include "outlog/disk.h"
#include "outlog/file_io.h"
#include "outlog/format.h"
#include "outlog/posix_fs.h"

namespace lle::outlog {

template <OutlogFsLike Fs>
class BasicOutlogReader {
 public:
  using File = typename Fs::File;
  static constexpr std::size_t kDefaultBufferBytes = std::size_t{1} << 18;
  static constexpr std::size_t kMinBufferBytes = kMaxRecordBytes;  // any record fits

  BasicOutlogReader() requires std::default_initializable<Fs> = default;
  explicit BasicOutlogReader(Fs fs) noexcept : fs_(std::move(fs)) {}
  BasicOutlogReader(const BasicOutlogReader&) = delete;
  BasicOutlogReader& operator=(const BasicOutlogReader&) = delete;

  std::expected<void, std::string> open(const std::string& path, std::size_t buffer_bytes = kDefaultBufferBytes);
  void close() noexcept;
  // Picks up complete messages appended since open() or the last refresh().
  // If the file shrank (repair or truncate_to ran), the reader starts over.
  std::expected<void, Error> refresh();

  [[nodiscard]] bool is_open() const noexcept { return file_.valid(); }
  [[nodiscard]] SeqNo count() const noexcept { return count_; }
  // End of the last complete message.
  [[nodiscard]] std::uint64_t bytes() const noexcept { return end_off_; }
  // True if the index file was missing or unusable, or found inconsistent
  // with the data, so (part of) it was rebuilt by scanning.
  [[nodiscard]] bool index_rebuilt() const noexcept { return index_rebuilt_; }
  // The in-memory index: entry k = offset of message k*4096 + 1.
  [[nodiscard]] std::span<const std::uint64_t> index_entries() const noexcept { return entries_; }

  // Byte offset of the length prefix of `seq`, for seq in [1, count() + 1]
  // (count() + 1 gives bytes()).
  std::expected<std::uint64_t, Error> offset_of(SeqNo seq);

  // Copies message `seq` into `scratch` and returns the copied bytes.
  std::expected<std::span<const std::byte>, Error> read(SeqNo seq, std::span<std::byte> scratch);

  // Calls f(SeqNo, std::span<const std::byte>) for messages from, from + 1, ...
  // up to max_count of them or the end of the log, and returns how many were
  // delivered. The span points into the reader's buffer and is valid only
  // during the call; f must not call back into this reader. If f returns bool,
  // returning false stops after that message.
  template <class F>
  std::size_t for_each(SeqNo from, std::size_t max_count, F&& f);

 private:
  struct Position {
    SeqNo seq = 0;           // 0: none
    std::uint64_t off = 0;   // offset of the length prefix of `seq`
  };

  std::expected<Position, Error> locate(SeqNo seq);
  std::expected<std::uint64_t, Error> find(SeqNo seq);
  std::expected<std::uint64_t, Error> seek_block(std::size_t k);
  bool verify_block(std::size_t k) noexcept;
  std::expected<void, Error> rescan_from(std::size_t k);
  std::expected<void, Error> scan_to_end();
  void note_boundary(SeqNo seq, std::uint64_t off) noexcept;
  [[nodiscard]] static Error status_error(detail::RecordStatus s) noexcept {
    return s == detail::RecordStatus::Io ? Error::Io : Error::Corrupt;
  }

  Fs fs_{};
  std::string path_;
  std::size_t buffer_bytes_ = 0;
  File file_;
  std::unique_ptr<std::byte[]> buf_;
  detail::WindowReader<File> window_;
  std::vector<std::uint64_t> entries_;
  std::vector<std::uint8_t> trusted_;  // entries_[k] verified against the data
  SeqNo count_ = 0;
  std::uint64_t end_off_ = 0;    // end of the last complete message
  std::uint64_t data_size_ = 0;  // file size at the last open() / refresh()
  Position hint_;                // where the last read or scan stopped
  bool index_rebuilt_ = false;
};

template <OutlogFsLike Fs>
template <class F>
std::size_t BasicOutlogReader<Fs>::for_each(SeqNo from, std::size_t max_count, F&& f) {
  if (max_count == 0) return 0;
  const std::expected<Position, Error> start = locate(from);
  if (!start) return 0;
  SeqNo seq = start->seq;
  std::uint64_t off = start->off;
  std::size_t delivered = 0;
  while (seq <= count_ && delivered < max_count) {
    const detail::RecordView rv = window_.record(off, end_off_);
    if (rv.status != detail::RecordStatus::Ok) break;  // truncated underneath us
    bool more = true;
    if (seq >= from) {
      ++delivered;
      if constexpr (std::is_same_v<std::invoke_result_t<F&, SeqNo, std::span<const std::byte>>, bool>) {
        more = std::invoke(f, seq, rv.msg);
      } else {
        std::invoke(f, seq, rv.msg);
      }
    }
    off += kLengthPrefixBytes + rv.msg.size();
    ++seq;
    if ((seq - 1) % kIndexInterval == 0) note_boundary(seq, off);
    if (!more) break;
  }
  hint_ = {seq, off};
  return delivered;
}

// The production reader: POSIX files.
using OutlogReader = BasicOutlogReader<PosixFs>;
extern template class BasicOutlogReader<PosixFs>;

// The reader a stage environment uses for its output-log fallbacks (gateway replay,
// md re-requests, GLIMPSE): Env::OutlogReader if the environment names one (the
// simulator: a reader on its disk), else the POSIX OutlogReader. Must be default
// constructible (the stores construct it before the first fallback read).
template <class Env>
struct EnvOutlogReader {
  using type = OutlogReader;
};
template <class Env>
  requires requires { typename Env::OutlogReader; }
struct EnvOutlogReader<Env> {
  using type = typename Env::OutlogReader;
};
template <class Env>
using env_reader_t = typename EnvOutlogReader<Env>::type;

}  // namespace lle::outlog
