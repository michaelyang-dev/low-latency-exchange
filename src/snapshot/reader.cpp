#include "snapshot/reader.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <bit>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <system_error>
#include <utility>

#include "common/crc32c.h"

namespace lle::snap {

namespace {

bool all_zero(const std::byte* p, std::size_t n) noexcept {
  for (std::size_t i = 0; i < n; ++i) {
    if (p[i] != std::byte{0}) return false;
  }
  return true;
}

}  // namespace

std::expected<Reader, LoadError> Reader::open(std::span<const std::byte> image) {
  const std::byte* p = image.data();
  const std::uint64_t size = image.size();

  // Header.
  if (size < kHeaderBytes) return std::unexpected(LoadError::Truncated);
  if (std::memcmp(p + hdr::kMagic, kMagic.data(), kMagic.size()) != 0) return std::unexpected(LoadError::BadMagic);
  if (load_le32(p + hdr::kVersion) != kVersion) return std::unexpected(LoadError::UnsupportedVersion);
  if (load_le32(p + hdr::kHeaderBytes) != kHeaderBytes) return std::unexpected(LoadError::BadHeader);
  const std::uint32_t header_crc = load_le32(p + hdr::kHeaderCrc);
  if (crc32c(p, hdr::kHeaderCrc) != header_crc) return std::unexpected(LoadError::BadHeaderCrc);
  if (load_le32(p + hdr::kFlags) != 0 || !all_zero(p + hdr::kReserved, hdr::kHeaderCrc - hdr::kReserved)) {
    return std::unexpected(LoadError::BadHeader);
  }

  // Layout: compute_layout bounds every size before any multiplication, so a
  // hostile header cannot overflow the arithmetic below.
  const std::uint32_t chunk_bytes = load_le32(p + hdr::kChunkBytes);
  if (!valid_chunk_bytes(chunk_bytes)) return std::unexpected(LoadError::BadChunkSize);
  const std::optional<SnapshotLayout> layout =
      compute_layout(chunk_bytes, load_le32(p + hdr::kSessionCount), load_le64(p + hdr::kPayloadBytes));
  if (!layout || layout->chunk_count != load_le32(p + hdr::kChunkCount)) {
    return std::unexpected(LoadError::BadChunkCount);
  }
  if (size < layout->file_bytes) return std::unexpected(LoadError::Truncated);
  if (size > layout->file_bytes) return std::unexpected(LoadError::BadLength);
  // From here on every offset the layout yields is < size: in bounds.

  // Trailer: self-consistent and bound to this header.
  const std::byte* t = p + (size - kTrailerBytes);
  if (std::memcmp(t + trl::kMagic, kTrailerMagic.data(), kTrailerMagic.size()) != 0 ||
      load_le64(t + trl::kFileBytes) != size || load_le32(t + trl::kHeaderCrc) != header_crc ||
      load_le32(t + trl::kTrailerCrc) != crc32c(t, trl::kTrailerCrc) || load_le32(t + trl::kPad) != 0) {
    return std::unexpected(LoadError::BadTrailer);
  }

  Reader r;
  r.image_ = image;
  r.layout_ = *layout;
  r.meta_.day = load_le32(p + hdr::kDay);
  r.meta_.epoch = load_le32(p + hdr::kEpoch);
  r.meta_.index = load_le64(p + hdr::kIndex);
  r.meta_.snapshot_id = load_le64(p + hdr::kSnapshotId);
  r.meta_.mold_seq = load_le64(p + hdr::kMoldSeq);
  r.meta_.state_hash = load_le64(p + hdr::kStateHash);
  r.meta_.build_id = load_le64(p + hdr::kBuildId);
  r.chunk_mask_ = std::uint64_t{chunk_bytes} - 1;
  r.chunk_shift_ = std::countr_zero(chunk_bytes);

  // Session table. Its size is part of file_bytes, which equals the image size,
  // so the allocation is bounded by the input length.
  const std::byte* table = p + kHeaderBytes;
  const std::size_t entries_bytes = std::size_t{kSessionEntryBytes} * layout->session_count;
  const std::byte* table_tail = table + entries_bytes;
  const std::uint32_t table_crc = load_le32(table_tail);
  if (crc32c(table, entries_bytes) != table_crc || load_le32(table_tail + 4) != 0) {
    return std::unexpected(LoadError::BadSessionTable);
  }
  r.sessions_.resize(layout->session_count);
  for (std::size_t i = 0; i < r.sessions_.size(); ++i) {
    const std::byte* e = table + i * kSessionEntryBytes;
    if (load_le32(e + 4) != 0) return std::unexpected(LoadError::BadSessionTable);
    r.sessions_[i] = SessionSeq{load_le32(e), load_le64(e + 8)};
  }
  if (!sessions_canonical(r.sessions_)) return std::unexpected(LoadError::UnsortedSessions);

  // Chunks, then the cross-section CRC over the stored CRCs, which catches a
  // chunk spliced in (with its own valid CRC) from another snapshot.
  std::byte crc_le[4];
  store_le32(crc_le, table_crc);
  std::uint32_t sections_crc = crc32c(crc_le, sizeof(crc_le));
  for (std::uint64_t k = 0; k < layout->chunk_count; ++k) {
    const std::uint64_t len = k + 1 < layout->chunk_count ? std::uint64_t{chunk_bytes}
                                                           : layout->payload_bytes - k * chunk_bytes;
    const std::byte* data = r.chunk_data(k);
    const std::byte* crc_p = data + len;
    const std::uint64_t pad = chunk_frame_bytes(len) - len - 4;
    if (!all_zero(crc_p + 4, static_cast<std::size_t>(pad))) return std::unexpected(LoadError::BadPadding);
    if (chunk_crc(k, std::span<const std::byte>(data, static_cast<std::size_t>(len))) != load_le32(crc_p)) {
      return std::unexpected(LoadError::BadChunkCrc);
    }
    sections_crc = crc32c_extend(sections_crc, crc_p, 4);
  }
  if (sections_crc != load_le32(t + trl::kSectionsCrc)) return std::unexpected(LoadError::BadTrailer);
  return r;
}

bool Reader::read(std::span<std::byte> out) noexcept {
  if (!ok_ || out.size() > remaining()) {
    ok_ = false;
    if (!out.empty()) std::memset(out.data(), 0, out.size());
    return false;
  }
  std::byte* dst = out.data();
  std::size_t n = out.size();
  while (n > 0) {
    const std::uint64_t off = pos_ & chunk_mask_;
    const std::uint64_t in_chunk = std::min<std::uint64_t>(layout_.chunk_bytes - off, remaining());
    const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(in_chunk, n));
    std::memcpy(dst, chunk_data(pos_ >> chunk_shift_) + off, take);
    dst += take;
    n -= take;
    pos_ += take;
  }
  return true;
}

bool Reader::skip(std::uint64_t n) noexcept {
  if (!ok_ || n > remaining()) {
    ok_ = false;
    return false;
  }
  pos_ += n;
  return true;
}

MappedSnapshot::MappedSnapshot(void* base, std::size_t len, Reader reader) noexcept
    : base_(base), len_(len), reader_(std::move(reader)) {}

MappedSnapshot::MappedSnapshot(MappedSnapshot&& o) noexcept
    : base_(std::exchange(o.base_, nullptr)), len_(std::exchange(o.len_, 0)), reader_(std::move(o.reader_)) {}

MappedSnapshot::~MappedSnapshot() {
  if (base_ != nullptr) ::munmap(base_, len_);
}

std::expected<MappedSnapshot, LoadError> MappedSnapshot::open(const std::string& path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return std::unexpected(LoadError::Io);
  struct stat st{};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      static_cast<std::uint64_t>(st.st_size) > std::numeric_limits<std::size_t>::max()) {
    ::close(fd);
    return std::unexpected(LoadError::Io);
  }
  const auto len = static_cast<std::size_t>(st.st_size);
  void* base = nullptr;
  if (len > 0) {  // mmap rejects length 0; an empty file then fails as Truncated
    base = ::mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
      ::close(fd);
      return std::unexpected(LoadError::Io);
    }
  }
  ::close(fd);  // the mapping keeps the file referenced
  auto r = Reader::open(std::span<const std::byte>(static_cast<const std::byte*>(base), len));
  if (!r) {
    if (base != nullptr) ::munmap(base, len);
    return std::unexpected(r.error());
  }
  return MappedSnapshot(base, len, std::move(*r));
}

std::expected<SnapshotMeta, LoadError> validate_file(const std::string& path) {
  auto m = MappedSnapshot::open(path);
  if (!m) return std::unexpected(m.error());
  return m->meta();
}

std::optional<SnapshotInfo> find_latest(const std::string& day_dir, std::uint64_t max_index) {
  namespace fs = std::filesystem;
  std::vector<std::pair<std::uint64_t, std::string>> candidates;
  std::error_code ec;
  fs::directory_iterator it(day_dir, ec);
  if (ec) return std::nullopt;
  for (const fs::directory_iterator end{}; it != end;) {
    const std::optional<std::uint64_t> index = parse_snapshot_file_name(it->path().filename().string());
    if (index && *index <= max_index) candidates.emplace_back(*index, it->path().string());
    it.increment(ec);
    // Treat unlisted entries as absent: any valid snapshot <= max_index is a
    // correct starting point for replay, just possibly an older one.
    if (ec) break;
  }
  // Directory order is unspecified; try newest first for a deterministic answer.
  std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
  for (const auto& [index, path] : candidates) {
    auto m = MappedSnapshot::open(path);
    if (m && m->meta().index == index) return SnapshotInfo{path, m->meta(), m->reader().layout()};
  }
  return std::nullopt;
}

std::expected<LoadedSnapshot, LoadError> LoadedSnapshot::open(Storage& storage, const std::string& path) {
  auto bytes = storage.read_all(path);
  if (!bytes) return std::unexpected(LoadError::Io);
  LoadedSnapshot s;
  s.image_ = std::move(*bytes);
  auto r = Reader::open(s.image_);
  if (!r) return std::unexpected(r.error());
  s.reader_.emplace(std::move(*r));
  return s;
}

std::optional<SnapshotInfo> find_latest(Storage& storage, const std::string& day_dir, std::uint64_t max_index) {
  std::vector<std::uint64_t> candidates;
  for (const std::string& name : storage.list(day_dir)) {
    const std::optional<std::uint64_t> index = parse_snapshot_file_name(name);
    if (index && *index <= max_index) candidates.push_back(*index);
  }
  std::sort(candidates.begin(), candidates.end(), std::greater<>());
  for (const std::uint64_t index : candidates) {
    const std::string path = snapshot_path(day_dir, index);
    auto s = LoadedSnapshot::open(storage, path);
    if (s && s->meta().index == index) return SnapshotInfo{path, s->meta(), s->reader().layout()};
  }
  return std::nullopt;
}

}  // namespace lle::snap
