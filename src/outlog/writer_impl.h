#pragma once
// BasicOutlogWriter member definitions. Included by writer.cpp (explicit
// instantiation for POSIX files) and by other bindings (the simulator).
#include <algorithm>
#include <cerrno>
#include <utility>

#include "outlog/repair.h"
#include "outlog/writer.h"

namespace lle::outlog {

template <OutlogFsLike Fs>
BasicOutlogWriter<Fs>::~BasicOutlogWriter() {
  (void)close();
}

template <OutlogFsLike Fs>
std::expected<void, std::string> BasicOutlogWriter<Fs>::open(const std::string& path, std::size_t buffer_bytes) {
  (void)close();
  failed_ = false;
  err_op_ = "";
  err_no_ = 0;

  auto file = fs_.open(path, OpenMode::ReadWriteCreate);
  if (!file) return std::unexpected(detail::errno_text("cannot open", path, file.error()));
  if (!fs_.lock_writer(*file)) {
    return std::unexpected(detail::errno_text("cannot lock (another writer?)", path, EWOULDBLOCK));
  }
  // A crash may have left a torn final record or a stale index; continue
  // after the last complete message (06 §8).
  const RepairResult rr = detail::repair_locked(fs_, *file, path);
  if (!rr.ok()) return std::unexpected(rr.error);
  const std::string idx = index_path(path);
  auto idx_file = fs_.open(idx, OpenMode::ReadWrite);
  if (!idx_file) return std::unexpected(detail::errno_text("cannot open", idx, idx_file.error()));

  // All buffers are allocated (and zero-filled, so their pages are faulted in)
  // here; the append path only copies into them.
  cap_ = std::max(buffer_bytes, kMinBufferBytes);
  buf_ = std::make_unique<std::byte[]>(cap_);
  // Pending entries all point at buffered messages, which are 4096 messages
  // of at least kMinRecordBytes apart: at most cap_ / (3 * 4096) + 1 of them.
  pending_cap_ = cap_ / (kMinRecordBytes * kIndexInterval) + 2;
  pending_ = std::make_unique<std::byte[]>(pending_cap_ * kIndexEntryBytes);

  file_ = std::move(*file);
  idx_file_ = std::move(*idx_file);
  path_ = path;
  buf_len_ = 0;
  pending_len_ = 0;
  file_bytes_ = rr.bytes;
  count_ = rr.messages;
  idx_written_ = index_entries_for(count_);
  return {};
}

template <OutlogFsLike Fs>
bool BasicOutlogWriter<Fs>::fail(const char* op, int err) noexcept {
  failed_ = true;
  err_op_ = op;
  err_no_ = err;
  return false;
}

template <OutlogFsLike Fs>
bool BasicOutlogWriter<Fs>::write_out() noexcept {
  if (buf_len_ != 0) {
    if (const int err = write_sync(file_, file_bytes_, std::span<const std::byte>(buf_.get(), buf_len_)); err != 0) {
      return fail("cannot write", err);
    }
    file_bytes_ += buf_len_;
    buf_len_ = 0;
  }
  // Index entries go out only after the data they point to, so an entry
  // never refers to a message that is not in the data file (06 §8).
  if (pending_len_ != 0) {
    const std::uint64_t off = kIndexHeaderBytes + idx_written_ * kIndexEntryBytes;
    const std::span<const std::byte> entries(pending_.get(), pending_len_ * kIndexEntryBytes);
    if (const int err = write_sync(idx_file_, off, entries); err != 0) return fail("cannot write index of", err);
    idx_written_ += pending_len_;
    pending_len_ = 0;
  }
  return true;
}

template <OutlogFsLike Fs>
std::expected<void, Error> BasicOutlogWriter<Fs>::flush() noexcept {
  if (failed_) return std::unexpected(Error::Io);
  if (!file_.valid()) return std::unexpected(Error::NotOpen);
  if (!write_out()) return std::unexpected(Error::Io);
  return {};
}

template <OutlogFsLike Fs>
std::expected<void, Error> BasicOutlogWriter<Fs>::sync() noexcept {
  if (auto r = flush(); !r) return r;
  if (const int err = sync_file(file_); err != 0) {
    fail("cannot sync", err);
    return std::unexpected(Error::Io);
  }
  if (const int err = sync_file(idx_file_); err != 0) {
    fail("cannot sync index of", err);
    return std::unexpected(Error::Io);
  }
  return {};
}

template <OutlogFsLike Fs>
std::expected<void, Error> BasicOutlogWriter<Fs>::close() noexcept {
  if (!file_.valid()) return {};
  const std::expected<void, Error> r = flush();
  file_ = File{};
  idx_file_ = File{};
  buf_.reset();
  pending_.reset();
  cap_ = buf_len_ = pending_cap_ = pending_len_ = 0;
  file_bytes_ = idx_written_ = 0;
  count_ = 0;
  return r;
}

template <OutlogFsLike Fs>
std::string BasicOutlogWriter<Fs>::error_message() const {
  if (!failed_) return {};
  return detail::errno_text(err_op_, path_, err_no_);
}

}  // namespace lle::outlog
