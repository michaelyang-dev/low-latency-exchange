#pragma once
// Output-log repair and regeneration hooks (06 §8).
//
// The output log is derived data: after a crash its tail may be torn and its
// index stale, and recovery rebuilds or extends it from the journal. These
// functions are the file-level half of that: they make a log internally
// consistent (repair), cut it back to a known prefix (truncate_to), append a
// regenerated suffix (regenerate) and compare two logs (first_difference).
// None of them runs on the append path; they may allocate.
//
// Each comes in two forms: on an explicit storage (outlog/disk.h; the
// simulator runs them on its disk) and on POSIX paths.
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <cstring>
#include <vector>
#include <span>
#include <string>
#include <type_traits>

#include "common/types.h"
#include "outlog/format.h"
#include "outlog/disk.h"
#include "outlog/file_io.h"
#include "outlog/posix_fs.h"
#include "outlog/reader_impl.h"
#include "outlog/writer.h"

namespace lle::outlog {

struct RepairResult {
  SeqNo messages = 0;                 // complete messages kept
  std::uint64_t bytes = 0;            // data file size after repair
  std::uint64_t truncated_bytes = 0;  // torn-tail bytes removed
  bool index_rebuilt = false;         // the index file did not match the data and was rewritten
  std::string error;                  // empty on success

  [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

namespace detail {

// repair() on a data file the caller has opened read-write and locked
// (BasicOutlogWriter::open holds the lock while it repairs).
template <OutlogFsLike Fs>
RepairResult repair_locked(Fs& fs, typename Fs::File& file, const std::string& path) {
  RepairResult r;
  const auto size = file.size_checked();
  if (!size) {
    r.error = errno_text("cannot stat", path, size.error());
    return r;
  }
  const auto buf = std::make_unique<std::byte[]>(kScanBufferBytes);
  WindowReader<typename Fs::File> win;
  win.reset(&file, buf.get(), kScanBufferBytes);
  std::vector<std::uint64_t> entries;
  std::uint64_t off = 0;
  SeqNo count = 0;
  for (;;) {
    const RecordView rv = win.record(off, *size);
    if (rv.status == RecordStatus::Io) {
      r.error = errno_text("cannot read", path, win.error());
      return r;
    }
    // End, torn record, or a zero length prefix (never written, so a
    // zero-filled tail left by a crash): the valid data ends here.
    if (rv.status != RecordStatus::Ok) break;
    if (count % kIndexInterval == 0) entries.push_back(off);
    off += kLengthPrefixBytes + rv.msg.size();
    ++count;
  }
  if (off < *size) {
    if (!file.resize(off)) {
      r.error = errno_text("cannot truncate", path, EIO);
      return r;
    }
    r.truncated_bytes = *size - off;
  }

  const std::string idx = index_path(path);
  const LoadedIndex li = load_index(fs, idx, entries.size() + 1);
  const bool matches = li.header_ok && li.file_bytes == kIndexHeaderBytes + entries.size() * kIndexEntryBytes &&
                       li.entries == entries;
  if (!matches) {
    if (auto w = write_index(fs, idx, entries); !w) {
      r.error = w.error();
      return r;
    }
    r.index_rebuilt = true;
  }
  r.messages = count;
  r.bytes = off;
  return r;
}

}  // namespace detail

// Scans the whole data file (sequentially, so the result never depends on the
// index), truncates a torn final record (partial length prefix, partial
// message, or a zero-filled tail) and rewrites the index file if it does not
// match the data exactly. Fails if a writer holds the file.
template <OutlogFsLike Fs>
RepairResult repair(Fs& fs, const std::string& path) {
  RepairResult failed;
  auto file = fs.open(path, OpenMode::ReadWrite);
  if (!file) {
    failed.error = detail::errno_text("cannot open", path, file.error());
    return failed;
  }
  if (!fs.lock_writer(*file)) {
    failed.error = detail::errno_text("cannot lock (writer active?)", path, EWOULDBLOCK);
    return failed;
  }
  return detail::repair_locked(fs, *file, path);
}
RepairResult repair(const std::string& path);

// Keeps exactly the first `count` messages (and trims the index to match), so
// that the suffix can be regenerated from the journal. Fails with OutOfRange
// if the log holds fewer than `count` complete messages and with Locked if a
// writer holds the file.
template <OutlogFsLike Fs>
std::expected<void, Error> truncate_to(Fs& fs, const std::string& path, SeqNo count) {
  auto file = fs.open(path, OpenMode::ReadWrite);
  if (!file) return std::unexpected(Error::Io);
  if (!fs.lock_writer(*file)) return std::unexpected(Error::Locked);
  // The reader locates the cut through the index (checking the blocks it
  // uses) instead of scanning the whole file. The kept entries are its view
  // of the index; readers and repair() check them again before relying on
  // them.
  BasicOutlogReader<Fs> reader(fs);
  if (!reader.open(path)) return std::unexpected(Error::Io);
  if (count > reader.count()) return std::unexpected(Error::OutOfRange);
  const auto cut = reader.offset_of(count + 1);
  if (!cut) return std::unexpected(cut.error());
  // Index first: if we stop between the two steps, the index merely lags.
  const auto keep = static_cast<std::size_t>(index_entries_for(count));
  if (!detail::write_index(fs, index_path(path), reader.index_entries().first(keep))) {
    return std::unexpected(Error::Io);
  }
  if (!file->resize(*cut)) return std::unexpected(Error::Io);
  return {};
}
std::expected<void, Error> truncate_to(const std::string& path, SeqNo count);

// Appends the messages produced by `src`, starting at sequence w.count() + 1,
// until it returns an empty span, then flushes. `src(seq, scratch)` returns
// message `seq`, built in `scratch` (65,535 bytes, the largest message) or in
// storage of its own. Returns the number of messages appended. The journal
// replay that reproduces released output plugs in here (06 §8: the output log
// is regenerated byte for byte from the journal).
template <OutlogFsLike Fs, class Source>
  requires std::invocable<Source&, SeqNo, std::span<std::byte>> &&
           std::convertible_to<std::invoke_result_t<Source&, SeqNo, std::span<std::byte>>, std::span<const std::byte>>
std::expected<std::size_t, Error> regenerate(BasicOutlogWriter<Fs>& w, Source&& src) {
  if (!w.is_open()) return std::unexpected(Error::NotOpen);
  // Recovery path, not the append path: one scratch allocation per call.
  const auto scratch = std::make_unique<std::byte[]>(kMaxMessageBytes);
  std::size_t appended = 0;
  for (SeqNo seq = w.count() + 1;; ++seq) {
    const std::span<const std::byte> msg = src(seq, std::span<std::byte>(scratch.get(), kMaxMessageBytes));
    if (msg.empty()) break;
    if (const auto r = w.append(msg); !r) return std::unexpected(r.error());
    ++appended;
  }
  if (const auto r = w.flush(); !r) return std::unexpected(r.error());
  return appended;
}

// First sequence number at which the complete messages of two logs differ
// (content, length, or one log ending before the other); nullopt if they hold
// identical message sequences. Torn tails are ignored; a missing or
// unreadable file reads as an empty log.
template <OutlogFsLike Fs>
std::optional<SeqNo> first_difference(Fs& fs, const std::string& a, const std::string& b) {
  using File = typename Fs::File;
  struct Side {
    File file;
    std::uint64_t size = 0;
    std::unique_ptr<std::byte[]> buf = std::make_unique<std::byte[]>(detail::kScanBufferBytes);
    detail::WindowReader<File> win;
    std::uint64_t off = 0;

    Side(Fs& f, const std::string& path) {
      if (auto opened = f.open(path, OpenMode::ReadOnly)) {
        file = std::move(*opened);
        if (const auto s = file.size_checked()) size = *s;
      }
      win.reset(&file, buf.get(), detail::kScanBufferBytes);
    }
  };
  Side sa(fs, a);
  Side sb(fs, b);
  for (SeqNo seq = 1;; ++seq) {
    const detail::RecordView ra = sa.win.record(sa.off, sa.size);
    const detail::RecordView rb = sb.win.record(sb.off, sb.size);
    const bool has_a = ra.status == detail::RecordStatus::Ok;
    const bool has_b = rb.status == detail::RecordStatus::Ok;
    if (!has_a && !has_b) return std::nullopt;
    if (has_a != has_b || ra.msg.size() != rb.msg.size() ||
        std::memcmp(ra.msg.data(), rb.msg.data(), ra.msg.size()) != 0) {
      return seq;
    }
    sa.off += kLengthPrefixBytes + ra.msg.size();
    sb.off += kLengthPrefixBytes + rb.msg.size();
  }
}
std::optional<SeqNo> first_difference(const std::string& a, const std::string& b);

}  // namespace lle::outlog
