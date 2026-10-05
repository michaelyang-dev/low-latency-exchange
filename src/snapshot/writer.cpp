#include "snapshot/writer.h"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

#include "common/assert.h"
#include "common/crc32c.h"

namespace lle::snap {

namespace {

// fdatasync is enough for the temporary file: it flushes the data and the size,
// and the rename that follows is made durable by fsync(dir). macOS lacks a usable
// fdatasync, so fsync there; F_FULLFSYNC on request (see WriterOptions).
int sync_fd(int fd, bool full_fsync, bool data_only) noexcept {
#if defined(__APPLE__)
  (void)data_only;
  if (full_fsync) {
    if (::fcntl(fd, F_FULLFSYNC) == 0) return 0;
    // Filesystems without F_FULLFSYNC support (e.g. some network mounts).
    if (errno != ENOTSUP && errno != ENOTTY && errno != EINVAL) return -1;
  }
  return ::fsync(fd);
#else
  (void)full_fsync;
  return data_only ? ::fdatasync(fd) : ::fsync(fd);
#endif
}

Error io_error(const char* op) noexcept { return Error{ErrorCode::Io, errno, op}; }

}  // namespace

Writer::Writer(Mode mode, const SnapshotMeta& meta, const WriterOptions& opts) noexcept
    : mode_(mode), meta_(meta), opts_(opts) {}

Writer::Writer(Writer&& o) noexcept
    : mode_(o.mode_),
      open_(std::exchange(o.open_, false)),
      fd_(std::exchange(o.fd_, -1)),
      storage_(o.storage_),
      day_dir_(std::exchange(o.day_dir_, {})),
      temp_path_(std::exchange(o.temp_path_, {})),
      final_path_(std::exchange(o.final_path_, {})),
      meta_(o.meta_),
      opts_(o.opts_),
      session_count_(o.session_count_),
      buf_(std::move(o.buf_)),
      chunk_bytes_(std::exchange(o.chunk_bytes_, 0)),
      fill_(std::exchange(o.fill_, 0)),
      fast_limit_(std::exchange(o.fast_limit_, 0)),
      payload_bytes_(o.payload_bytes_),
      offset_(o.offset_),
      chunk_index_(o.chunk_index_),
      sections_crc_(o.sections_crc_),
      error_(o.error_),
      mem_(std::exchange(o.mem_, {})) {
  // A moved-from writer rejects further use instead of touching the moved buffer.
  o.error_ = Error{ErrorCode::Closed, 0, "moved from"};
}

Writer::~Writer() { abort(); }

std::expected<Writer, Error> Writer::create(const std::string& day_dir, const SnapshotMeta& meta,
                                            std::span<const SessionSeq> sessions, const WriterOptions& opts) {
  return make(Mode::File, nullptr, day_dir, meta, sessions, opts);
}

std::expected<Writer, Error> Writer::create(Storage& storage, const std::string& day_dir, const SnapshotMeta& meta,
                                            std::span<const SessionSeq> sessions, const WriterOptions& opts) {
  return make(Mode::Store, &storage, day_dir, meta, sessions, opts);
}

std::expected<Writer, Error> Writer::create_in_memory(const SnapshotMeta& meta, std::span<const SessionSeq> sessions,
                                                      const WriterOptions& opts) {
  return make(Mode::Memory, nullptr, std::string{}, meta, sessions, opts);
}

std::expected<Writer, Error> Writer::make(Mode mode, Storage* storage, const std::string& day_dir,
                                          const SnapshotMeta& meta, std::span<const SessionSeq> sessions,
                                          const WriterOptions& opts) {
  if (!valid_chunk_bytes(opts.chunk_bytes)) {
    return std::unexpected(Error{ErrorCode::InvalidArgument, 0, "chunk_bytes"});
  }
  if (sessions.size() > std::numeric_limits<std::uint32_t>::max()) {
    return std::unexpected(Error{ErrorCode::TooLarge, 0, "session count"});
  }
  if (!sessions_canonical(sessions)) {
    return std::unexpected(Error{ErrorCode::UnsortedSessions, 0, "sessions"});
  }

  Writer w(mode, meta, opts);
  w.session_count_ = static_cast<std::uint32_t>(sessions.size());
  w.chunk_bytes_ = opts.chunk_bytes;
  w.buf_.reset(new (std::nothrow) std::byte[w.chunk_bytes_ + 8]);
  if (!w.buf_) return std::unexpected(Error{ErrorCode::OutOfMemory, 0, "chunk buffer"});

  if (mode == Mode::File || mode == Mode::Store) {
    w.storage_ = storage;
    w.day_dir_ = day_dir;
    w.temp_path_ = snapshot_temp_path(day_dir, meta.index);
    w.final_path_ = snapshot_path(day_dir, meta.index);
    if (mode == Mode::File) {
      w.fd_ = ::open(w.temp_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    } else {
      const int h = storage->create(w.temp_path_);
      if (h < 0) errno = -h;
      w.fd_ = h < 0 ? -1 : h;
    }
    if (w.fd_ < 0) {
      const Error e = io_error("open(temp)");
      w.temp_path_.clear();  // not ours: nothing to remove
      return std::unexpected(e);
    }
  }
  w.open_ = true;

  // The session table goes right after the (not yet written) header; the header
  // is written last, at commit, once the payload length is known.
  std::vector<std::byte> table(std::size_t{kSessionEntryBytes} * sessions.size() + kSessionTableTailBytes);
  for (std::size_t i = 0; i < sessions.size(); ++i) {
    std::byte* e = table.data() + i * kSessionEntryBytes;
    store_le32(e, sessions[i].session_id);
    store_le32(e + 4, 0);
    store_le64(e + 8, sessions[i].next_seq);
  }
  const std::size_t entries = table.size() - kSessionTableTailBytes;
  const std::uint32_t table_crc = crc32c(table.data(), entries);
  store_le32(table.data() + entries, table_crc);
  store_le32(table.data() + entries + 4, 0);
  if (!w.put_at(kHeaderBytes, table.data(), table.size())) {
    const Error e = *w.error_;
    w.abort();
    return std::unexpected(e);
  }
  std::byte crc_le[4];
  store_le32(crc_le, table_crc);
  w.sections_crc_ = crc32c(crc_le, sizeof(crc_le));
  w.offset_ = kHeaderBytes + table.size();
  w.fast_limit_ = w.chunk_bytes_;
  return w;
}

void Writer::fail(Error e) noexcept {
  if (!error_) error_ = e;
  fast_limit_ = 0;
}

void Writer::write(std::span<const std::byte> bytes) noexcept {
  if (!open_) {
    fail(Error{ErrorCode::Closed, 0, "write"});
    return;
  }
  if (error_) return;
  const std::byte* p = bytes.data();
  std::size_t n = bytes.size();
  while (n > 0) {
    const std::size_t take = std::min(chunk_bytes_ - fill_, n);
    std::memcpy(buf_.get() + fill_, p, take);
    fill_ += take;
    p += take;
    n -= take;
    payload_bytes_ += take;
    if (fill_ == chunk_bytes_) {
      flush_chunk();
      if (error_) return;
    }
  }
}

void Writer::flush_chunk() noexcept {
  // chunk_count is a u32 in the header.
  if (chunk_index_ >= std::numeric_limits<std::uint32_t>::max()) {
    fail(Error{ErrorCode::TooLarge, 0, "chunk count"});
    return;
  }
  const std::uint32_t crc = chunk_crc(chunk_index_, std::span<const std::byte>(buf_.get(), fill_));
  const auto frame = static_cast<std::size_t>(chunk_frame_bytes(fill_));
  store_le32(buf_.get() + fill_, crc);
  std::memset(buf_.get() + fill_ + 4, 0, frame - fill_ - 4);
  if (!put_at(offset_, buf_.get(), frame)) return;
  std::byte crc_le[4];
  store_le32(crc_le, crc);
  sections_crc_ = crc32c_extend(sections_crc_, crc_le, sizeof(crc_le));
  offset_ += frame;
  ++chunk_index_;
  fill_ = 0;
}

bool Writer::put_at(std::uint64_t offset, const std::byte* data, std::size_t n) noexcept {
  if (mode_ == Mode::Memory) {
    const std::uint64_t end = offset + n;
    if (end > mem_.max_size()) {
      fail(Error{ErrorCode::OutOfMemory, 0, "image"});
      return false;
    }
    if (mem_.size() < end) {
      try {
        mem_.resize(static_cast<std::size_t>(end));
      } catch (const std::bad_alloc&) {
        fail(Error{ErrorCode::OutOfMemory, 0, "image"});
        return false;
      }
    }
    std::memcpy(mem_.data() + offset, data, n);
    return true;
  }
  if (mode_ == Mode::Store) {
    if (const int err = storage_->write_at(fd_, offset, std::span<const std::byte>(data, n)); err != 0) {
      fail(Error{ErrorCode::Io, err, "pwrite"});
      return false;
    }
    return true;
  }
  while (n > 0) {
    const ssize_t r = ::pwrite(fd_, data, n, static_cast<off_t>(offset));
    if (r < 0) {
      if (errno == EINTR) continue;
      fail(io_error("pwrite"));
      return false;
    }
    if (r == 0) {  // no progress: treat like a full device rather than spin
      fail(Error{ErrorCode::Io, ENOSPC, "pwrite"});
      return false;
    }
    data += r;
    n -= static_cast<std::size_t>(r);
    offset += static_cast<std::uint64_t>(r);
  }
  return true;
}

bool Writer::finish_sections() noexcept {
  if (fill_ > 0) flush_chunk();
  if (error_) return false;
  const std::optional<SnapshotLayout> layout = compute_layout(chunk_bytes_, session_count_, payload_bytes_);
  // The writer produced exactly this layout chunk by chunk; disagreement is a bug.
  LLE_ASSERT(layout.has_value() && layout->chunk_count == chunk_index_ &&
             layout->file_bytes == offset_ + kTrailerBytes);
  const auto header = encode_header(meta_, *layout);
  const auto trailer = encode_trailer(layout->file_bytes, load_le32(header.data() + hdr::kHeaderCrc), sections_crc_);
  return put_at(offset_, trailer.data(), trailer.size()) && put_at(0, header.data(), header.size());
}

std::expected<std::string, Error> Writer::commit() {
  if (mode_ == Mode::Memory) return std::unexpected(Error{ErrorCode::InvalidArgument, 0, "commit on memory writer"});
  if (!open_) return std::unexpected(error_.value_or(Error{ErrorCode::Closed, 0, "commit"}));
  if (!finish_sections()) {
    const Error e = *error_;
    abort();
    return std::unexpected(e);
  }
  // Atomic publication (06 §9): data durable, then the name, then the name's
  // directory entry.
  if (mode_ == Mode::Store) return commit_store();
  if (sync_fd(fd_, opts_.full_fsync, /*data_only=*/true) != 0) {
    fail(io_error("fdatasync(temp)"));
  } else if (::close(std::exchange(fd_, -1)) != 0) {
    fail(io_error("close(temp)"));
  } else if (::rename(temp_path_.c_str(), final_path_.c_str()) != 0) {
    fail(io_error("rename"));
  }
  if (error_) {
    const Error e = *error_;
    abort();
    return std::unexpected(e);
  }
  temp_path_.clear();  // renamed: nothing left to remove
  open_ = false;
  fast_limit_ = 0;

  const std::string dir = day_dir_.empty() ? std::string(".") : day_dir_;
  const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd < 0) {
    fail(io_error("open(dir)"));
    return std::unexpected(*error_);
  }
  const int rc = sync_fd(dfd, opts_.full_fsync, /*data_only=*/false);
  const int sync_errno = errno;
  ::close(dfd);
  if (rc != 0) {
    errno = sync_errno;
    fail(io_error("fsync(dir)"));
    return std::unexpected(*error_);
  }
  return final_path_;
}

std::expected<std::vector<std::byte>, Error> Writer::finish_image() {
  if (mode_ != Mode::Memory) {
    return std::unexpected(Error{ErrorCode::InvalidArgument, 0, "finish_image on file writer"});
  }
  if (!open_) return std::unexpected(error_.value_or(Error{ErrorCode::Closed, 0, "finish_image"}));
  const bool finished = finish_sections();
  open_ = false;
  fast_limit_ = 0;
  if (!finished) {
    std::vector<std::byte>().swap(mem_);
    return std::unexpected(*error_);
  }
  return std::exchange(mem_, {});
}

std::expected<std::string, Error> Writer::commit_store() {
  // The same sequence as file mode, through the storage.
  if (const int err = storage_->sync(fd_, /*data_only=*/true); err != 0) {
    fail(Error{ErrorCode::Io, err, "fdatasync(temp)"});
  } else if (const int cerr = storage_->close(std::exchange(fd_, -1)); cerr != 0) {
    fail(Error{ErrorCode::Io, cerr, "close(temp)"});
  } else if (const int rerr = storage_->rename(temp_path_, final_path_); rerr != 0) {
    fail(Error{ErrorCode::Io, rerr, "rename"});
  }
  if (error_) {
    const Error e = *error_;
    abort();
    return std::unexpected(e);
  }
  temp_path_.clear();
  open_ = false;
  fast_limit_ = 0;
  if (const int err = storage_->sync_dir(day_dir_.empty() ? std::string(".") : day_dir_); err != 0) {
    fail(Error{ErrorCode::Io, err, "fsync(dir)"});
    return std::unexpected(*error_);
  }
  return final_path_;
}

void Writer::close_fd() noexcept {
  if (fd_ < 0) return;
  if (mode_ == Mode::Store) {
    (void)storage_->close(std::exchange(fd_, -1));
  } else {
    ::close(std::exchange(fd_, -1));
  }
}

void Writer::remove_temp() noexcept {
  if (!temp_path_.empty()) {
    if (mode_ == Mode::Store) {
      (void)storage_->remove(temp_path_);
    } else {
      ::unlink(temp_path_.c_str());
    }
    temp_path_.clear();
  }
}

void Writer::abort() noexcept {
  close_fd();
  remove_temp();
  if (open_) {
    open_ = false;
    fail(Error{ErrorCode::Closed, 0, "aborted"});
  }
  fast_limit_ = 0;
  std::vector<std::byte>().swap(mem_);
}

std::expected<std::vector<std::byte>, Error> encode_image(const SnapshotMeta& meta,
                                                          std::span<const SessionSeq> sessions,
                                                          std::span<const std::byte> payload,
                                                          std::uint32_t chunk_bytes) {
  WriterOptions opts;
  opts.chunk_bytes = chunk_bytes;
  auto w = Writer::create_in_memory(meta, sessions, opts);
  if (!w) return std::unexpected(w.error());
  w->write(payload);
  return w->finish_image();
}

}  // namespace lle::snap
