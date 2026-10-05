#pragma once
// BasicOutlogReader member definitions. Included by reader.cpp (explicit
// instantiation for POSIX files) and by other bindings (the simulator).
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <utility>

#include "common/assert.h"
#include "outlog/reader.h"

namespace lle::outlog {
namespace detail {

inline constexpr std::uint64_t kMinBlockBytes = std::uint64_t{kMinRecordBytes} * kIndexInterval;
inline constexpr std::uint64_t kMaxBlockBytes = std::uint64_t{kMaxRecordBytes} * kIndexInterval;

// Length of the prefix of `e` that could describe a data file of `size`
// bytes. Cheap arithmetic only; the data checks happen in verify_block().
inline std::size_t plausible_prefix(const std::vector<std::uint64_t>& e, std::uint64_t size) noexcept {
  if (e.empty() || e[0] != 0 || size < kMinRecordBytes) return 0;
  std::size_t n = 1;
  while (n < e.size()) {
    const std::uint64_t prev = e[n - 1];
    const std::uint64_t cur = e[n];
    if (cur <= prev || cur - prev < kMinBlockBytes || cur - prev > kMaxBlockBytes) break;
    if (cur > size - kMinRecordBytes) break;  // the record it points at cannot be complete
    ++n;
  }
  return n;
}

}  // namespace detail

template <OutlogFsLike Fs>
std::expected<void, std::string> BasicOutlogReader<Fs>::open(const std::string& path, std::size_t buffer_bytes) {
  close();
  auto file = fs_.open(path, OpenMode::ReadOnly);
  if (!file) return std::unexpected(detail::errno_text("cannot open", path, file.error()));
  const auto size = file->size_checked();
  if (!size) return std::unexpected(detail::errno_text("cannot stat", path, size.error()));

  buffer_bytes_ = std::max(buffer_bytes, kMinBufferBytes);
  buf_ = std::make_unique<std::byte[]>(buffer_bytes_);
  file_ = std::move(*file);
  path_ = path;
  window_.reset(&file_, buf_.get(), buffer_bytes_);
  data_size_ = *size;

  // Start from the index file, keeping only what could describe this data.
  const std::uint64_t max_entries = data_size_ / detail::kMinBlockBytes + 1;
  detail::LoadedIndex li = detail::load_index(fs_, index_path(path), max_entries);
  entries_ = std::move(li.entries);
  const std::size_t plausible = detail::plausible_prefix(entries_, data_size_);
  index_rebuilt_ = !li.header_ok || plausible != entries_.size();
  entries_.resize(plausible);
  trusted_.assign(plausible, 0);
  if (plausible > 0) trusted_[0] = 1;  // entry 0 is 0 by definition

  // The last entry anchors count(): accept it only if the block before it
  // checks out, otherwise rebuild everything from the start of the file.
  std::size_t start = 0;
  if (plausible >= 2) {
    if (verify_block(plausible - 2)) {
      start = plausible - 1;
    } else {
      index_rebuilt_ = true;
    }
  }
  if (auto r = rescan_from(start); !r) {
    const int err = window_.error();
    close();
    return std::unexpected(detail::errno_text("cannot read", path, err));
  }
  return {};
}

template <OutlogFsLike Fs>
void BasicOutlogReader<Fs>::close() noexcept {
  file_ = File{};
  buf_.reset();
  window_.reset(nullptr, nullptr, 0);
  entries_.clear();
  trusted_.clear();
  path_.clear();
  buffer_bytes_ = 0;
  count_ = 0;
  end_off_ = 0;
  data_size_ = 0;
  hint_ = {};
  index_rebuilt_ = false;
}

template <OutlogFsLike Fs>
std::expected<void, Error> BasicOutlogReader<Fs>::refresh() {
  if (!file_.valid()) return std::unexpected(Error::NotOpen);
  const auto size = file_.size_checked();
  if (!size) return std::unexpected(Error::Io);
  // Bytes past the last complete record (a torn tail) may have been
  // truncated and rewritten since they were cached.
  window_.invalidate();
  if (*size < end_off_) {
    std::string path = std::move(path_);
    if (!open(path, buffer_bytes_)) return std::unexpected(Error::Io);
    return {};
  }
  data_size_ = *size;
  return scan_to_end();
}

template <OutlogFsLike Fs>
bool BasicOutlogReader<Fs>::verify_block(std::size_t k) noexcept {
  LLE_DASSERT(k + 1 < entries_.size());
  const std::uint64_t next = entries_[k + 1];
  std::uint64_t off = entries_[k];
  for (std::uint32_t i = 0; i < kIndexInterval; ++i) {
    // `next` as the limit: no record of block k may extend past entry k + 1.
    const detail::RecordView rv = window_.record(off, next);
    if (rv.status != detail::RecordStatus::Ok) return false;
    off += kLengthPrefixBytes + rv.msg.size();
  }
  if (off != next) return false;
  trusted_[k] = 1;
  trusted_[k + 1] = 1;
  return true;
}

template <OutlogFsLike Fs>
std::expected<void, Error> BasicOutlogReader<Fs>::rescan_from(std::size_t k) {
  LLE_DASSERT(k == 0 || (k < entries_.size() && trusted_[k] != 0));
  const std::uint64_t off = k == 0 ? 0 : entries_[k];
  entries_.resize(k);
  trusted_.resize(k);
  count_ = SeqNo{k} * kIndexInterval;
  end_off_ = off;
  hint_ = {};
  return scan_to_end();
}

template <OutlogFsLike Fs>
std::expected<void, Error> BasicOutlogReader<Fs>::scan_to_end() {
  for (;;) {
    const detail::RecordView rv = window_.record(end_off_, data_size_);
    if (rv.status == detail::RecordStatus::Io) return std::unexpected(Error::Io);
    // End, torn record or zero-filled tail: only complete records count.
    if (rv.status != detail::RecordStatus::Ok) return {};
    if (count_ % kIndexInterval == 0) {
      entries_.push_back(end_off_);
      trusted_.push_back(1);
    }
    end_off_ += kLengthPrefixBytes + rv.msg.size();
    ++count_;
  }
}

template <OutlogFsLike Fs>
std::expected<std::uint64_t, Error> BasicOutlogReader<Fs>::seek_block(std::size_t k) {
  if (k >= entries_.size()) return std::unexpected(Error::OutOfRange);
  if (trusted_[k] != 0) return entries_[k];
  // The last entry is always trusted, so k + 1 exists here; checked anyway.
  if (k + 1 < entries_.size() && verify_block(k)) return entries_[k];
  // The index disagrees with the data: rebuild it from the nearest entry
  // known to be right (entry 0 at worst).
  std::size_t j = k;
  while (trusted_[j] == 0) --j;
  index_rebuilt_ = true;
  if (auto r = rescan_from(j); !r) return std::unexpected(r.error());
  if (k >= entries_.size()) return std::unexpected(Error::OutOfRange);
  return entries_[k];
}

template <OutlogFsLike Fs>
std::expected<typename BasicOutlogReader<Fs>::Position, Error> BasicOutlogReader<Fs>::locate(SeqNo seq) {
  if (!file_.valid()) return std::unexpected(Error::NotOpen);
  if (seq == 0 || seq > count_) return std::unexpected(Error::OutOfRange);
  const auto k = static_cast<std::size_t>((seq - 1) / kIndexInterval);
  // Continue from the previous read when it stopped earlier in the same
  // block: sequential read() calls then cost one record each.
  if (hint_.seq != 0 && hint_.seq <= seq && (hint_.seq - 1) / kIndexInterval == k) return hint_;
  const auto off = seek_block(k);
  if (!off) return std::unexpected(off.error());
  if (seq > count_) return std::unexpected(Error::OutOfRange);  // a rebuild found fewer messages
  return Position{SeqNo{k} * kIndexInterval + 1, *off};
}

template <OutlogFsLike Fs>
std::expected<std::uint64_t, Error> BasicOutlogReader<Fs>::find(SeqNo seq) {
  const auto pos = locate(seq);
  if (!pos) return std::unexpected(pos.error());
  SeqNo s = pos->seq;
  std::uint64_t off = pos->off;
  while (s < seq) {
    const detail::RecordView rv = window_.record(off, end_off_);
    if (rv.status != detail::RecordStatus::Ok) return std::unexpected(status_error(rv.status));
    off += kLengthPrefixBytes + rv.msg.size();
    ++s;
  }
  hint_ = {seq, off};
  return off;
}

template <OutlogFsLike Fs>
void BasicOutlogReader<Fs>::note_boundary(SeqNo seq, std::uint64_t off) noexcept {
  // A scan that started at a trusted position knows the true offset of
  // every block start it crosses: confirm or correct the entry.
  const auto k = static_cast<std::size_t>((seq - 1) / kIndexInterval);
  if (k >= entries_.size()) return;
  if (entries_[k] != off) {
    entries_[k] = off;
    index_rebuilt_ = true;
  }
  trusted_[k] = 1;
}

template <OutlogFsLike Fs>
std::expected<std::uint64_t, Error> BasicOutlogReader<Fs>::offset_of(SeqNo seq) {
  if (!file_.valid()) return std::unexpected(Error::NotOpen);
  if (seq == count_ + 1) return end_off_;
  return find(seq);
}

template <OutlogFsLike Fs>
std::expected<std::span<const std::byte>, Error> BasicOutlogReader<Fs>::read(SeqNo seq, std::span<std::byte> scratch) {
  const auto off = find(seq);
  if (!off) return std::unexpected(off.error());
  const detail::RecordView rv = window_.record(*off, end_off_);
  if (rv.status != detail::RecordStatus::Ok) return std::unexpected(status_error(rv.status));
  if (rv.msg.size() > scratch.size()) return std::unexpected(Error::ScratchTooSmall);
  std::memcpy(scratch.data(), rv.msg.data(), rv.msg.size());
  hint_ = {seq + 1, *off + kLengthPrefixBytes + rv.msg.size()};
  return scratch.first(rv.msg.size());
}

}  // namespace lle::outlog
