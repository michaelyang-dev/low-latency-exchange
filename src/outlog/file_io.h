#pragma once
// File helpers shared by the output-log writer, reader and repair tools
// (06 §8), over the storage concepts of outlog/disk.h. Internal to
// lle::outlog; not a public interface.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <vector>

#include "common/endian.h"
#include "outlog/disk.h"
#include "outlog/format.h"

namespace lle::outlog::detail {

// "<what> '<path>': <strerror(err)>".
std::string errno_text(const char* what, const std::string& path, int err);

enum class RecordStatus : std::uint8_t {
  Ok,          // `msg` holds a complete message
  End,         // offset is exactly at the limit
  Torn,        // the limit (or end of file) falls inside the record
  ZeroLength,  // zero length prefix: never written by OutlogWriter, so the end of valid data
  Io,          // the read failed (error() says why)
};

struct RecordView {
  RecordStatus status = RecordStatus::End;
  std::span<const std::byte> msg;  // valid until the next call on the same WindowReader
};

// Record access through one caller-owned buffer. The buffer caches a window of
// the file; bytes of complete records never change once written, so the
// window stays valid until invalidate() (needed only when bytes past the last
// complete record may have been rewritten, e.g. after a repair).
template <OutlogFileLike F>
class WindowReader {
 public:
  // `buf` must hold at least kMaxRecordBytes so any record fits in one window.
  void reset(const F* file, std::byte* buf, std::size_t cap) noexcept {
    file_ = file;
    buf_ = buf;
    cap_ = cap;
    win_off_ = 0;
    win_len_ = 0;
  }
  void invalidate() noexcept { win_len_ = 0; }
  // errno of the last failed read.
  [[nodiscard]] int error() const noexcept { return err_; }

  // The record whose length prefix is at `off`, considering only file bytes
  // below `limit`.
  RecordView record(std::uint64_t off, std::uint64_t limit) noexcept {
    if (off >= limit) return {RecordStatus::End, {}};
    const std::uint64_t avail = limit - off;
    if (avail < kLengthPrefixBytes) return {RecordStatus::Torn, {}};
    Fill f = ensure(off, kLengthPrefixBytes, limit);
    if (f != Fill::Ok) return {f == Fill::Io ? RecordStatus::Io : RecordStatus::Torn, {}};
    const std::size_t len = load_be16(buf_ + (off - win_off_));
    if (len == 0) return {RecordStatus::ZeroLength, {}};
    if (avail < kLengthPrefixBytes + len) return {RecordStatus::Torn, {}};
    f = ensure(off, kLengthPrefixBytes + len, limit);
    if (f != Fill::Ok) return {f == Fill::Io ? RecordStatus::Io : RecordStatus::Torn, {}};
    return {RecordStatus::Ok, std::span<const std::byte>(buf_ + (off - win_off_) + kLengthPrefixBytes, len)};
  }

 private:
  enum class Fill : std::uint8_t { Ok, Short, Io };
  // Makes [off, off + n) resident; n <= limit - off and n <= cap_.
  Fill ensure(std::uint64_t off, std::size_t n, std::uint64_t limit) noexcept {
    if (off >= win_off_ && off + n <= win_off_ + win_len_) return Fill::Ok;
    if (file_ == nullptr || !file_->valid()) {
      win_len_ = 0;
      return Fill::Short;  // no file: reads as empty
    }
    // Reload a whole window starting at the record so a sequential scan issues
    // one read per buffer, not one per record.
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(cap_, limit - off));
    const std::ptrdiff_t got = file_->read_checked(off, std::span<std::byte>(buf_, want));
    if (got < 0) {
      err_ = static_cast<int>(-got);
      win_len_ = 0;
      return Fill::Io;
    }
    win_off_ = off;
    win_len_ = static_cast<std::size_t>(got);
    return win_len_ >= n ? Fill::Ok : Fill::Short;
  }

  const F* file_ = nullptr;
  std::byte* buf_ = nullptr;
  std::size_t cap_ = 0;
  std::uint64_t win_off_ = 0;
  std::size_t win_len_ = 0;
  int err_ = 0;
};

// Scan buffer for the maintenance paths (repair, first_difference).
inline constexpr std::size_t kScanBufferBytes = std::size_t{1} << 20;

struct LoadedIndex {
  bool header_ok = false;              // file present with a valid header
  std::uint64_t file_bytes = 0;        // size of the index file (0 if missing)
  std::vector<std::uint64_t> entries;  // whole entries, at most the requested maximum
};

// Loads at most `max_entries` entries, so a garbage index cannot make the
// caller read an arbitrarily large file into memory.
template <OutlogFsLike S>
LoadedIndex load_index(S& fs, const std::string& idx_path, std::uint64_t max_entries) {
  LoadedIndex out;
  auto f = fs.open(idx_path, OpenMode::ReadOnly);
  if (!f) return out;
  const auto size = f->size_checked();
  if (!size) return out;
  out.file_bytes = *size;
  std::array<std::byte, kIndexHeaderBytes> header{};
  if (f->read_checked(0, header) != static_cast<std::ptrdiff_t>(header.size())) return out;
  if (!index_header_valid(header)) return out;
  out.header_ok = true;
  const std::uint64_t n = std::min<std::uint64_t>((*size - kIndexHeaderBytes) / kIndexEntryBytes, max_entries);
  std::vector<std::byte> raw(static_cast<std::size_t>(n) * kIndexEntryBytes);
  const std::ptrdiff_t got = f->read_checked(kIndexHeaderBytes, raw);
  if (got < 0) return out;  // unreadable entries: treat as an empty (lagging) index
  const std::size_t whole = static_cast<std::size_t>(got) / kIndexEntryBytes;
  out.entries.resize(whole);
  for (std::size_t k = 0; k < whole; ++k) out.entries[k] = load_le64(raw.data() + k * kIndexEntryBytes);
  return out;
}

// Replaces the index file atomically (temporary file + rename), so a reader
// opening it concurrently sees either the old or the new index, never a mix.
template <OutlogFsLike S>
std::expected<void, std::string> write_index(S& fs, const std::string& idx_path, std::span<const std::uint64_t> entries) {
  const std::string tmp = idx_path + ".tmp";
  std::vector<std::byte> raw(kIndexHeaderBytes + entries.size() * kIndexEntryBytes);
  std::byte* const out = raw.data();
  if (out == nullptr) return std::unexpected(errno_text("cannot allocate", tmp, ENOMEM));  // never: raw is non-empty
  const auto header = encode_index_header();
  std::memcpy(out, header.data(), header.size());
  for (std::size_t k = 0; k < entries.size(); ++k) store_le64(out + kIndexHeaderBytes + k * kIndexEntryBytes, entries[k]);
  {
    auto f = fs.open(tmp, OpenMode::CreateTruncate);
    if (!f) return std::unexpected(errno_text("cannot create", tmp, f.error()));
    if (const int err = write_sync(*f, 0, raw); err != 0) {
      (void)fs.remove(tmp);
      return std::unexpected(errno_text("cannot write", tmp, err));
    }
  }
  // No fsync: the index is derived data and is validated by every reader (06 §8).
  if (const int err = fs.rename(tmp, idx_path); err != 0) {
    (void)fs.remove(tmp);
    return std::unexpected(errno_text("cannot rename to", idx_path, err));
  }
  return {};
}

// write_index() on POSIX files (tools and tests).
std::expected<void, std::string> write_index(const std::string& idx_path, std::span<const std::uint64_t> entries);

}  // namespace lle::outlog::detail
