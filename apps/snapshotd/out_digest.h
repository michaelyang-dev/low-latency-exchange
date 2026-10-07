#pragma once
// Output digests of a snapshot (06 §8-§9, ADR-029): what the node's output log must
// hold up to the snapshot, so recovery can trust it without replaying the engine.
//
// The output log is derived data and never synced; after a power cut it can keep a
// record whose length prefix and extent survived but whose payload did not. Recovery
// from a snapshot at P regenerates and compares only the outputs after P, so the
// outputs up to P need their own check. snapshotd, which regenerates those outputs
// itself while it replays the journal, writes next to every snapshot `<P>.snap` a
// sidecar `<P>.snap.out` with a rolling digest of the ITCH stream 1..S(P) and of each
// session's OUCH stream 1..next-1. Recovery reads the output log's prefix and hashes it
// (no engine work); a snapshot whose sidecar is missing or does not match is not used
// (an older one, or a full replay, then finds and rewrites the damage).
//
// Digest: FNV-1a 64 over, per message, its length as u16 big-endian then its bytes,
// i.e. over the stream exactly as the output log stores it.
//
// The sidecar also names record P by its content crc (LLEOUTD2): a snapshot describes
// the history up to P, and a rejoin can truncate that history and write other records
// at the same indices; snapshotd continues from a snapshot only if the journal's record
// P is still that record.
//
// Sidecar (little-endian):
//    0  char[8] "LLEOUTD2"   8 u64 index P   16 u64 itch count   24 u64 itch digest
//   32  u32 sessions         36 u32 record P's content crc ("LLEOUTD1": 0, not recorded)
//   40  sessions x { u32 session_id, u32 0, u64 count, u64 digest }   (ascending id)
//   ..  u32 crc32c of every byte before it, u32 0
// Published like a snapshot: written to `.tmp`, fsync, rename, fsync of the directory.
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/crc32c.h"
#include "common/endian.h"
#include "common/hash.h"

namespace lle::snapd {

struct StreamDigest {
  std::uint64_t count = 0;
  std::uint64_t digest = Fnv1a64::kOffset;
  void add(std::span<const std::byte> msg) noexcept {
    Fnv1a64 h(digest);
    const auto n = static_cast<std::uint16_t>(msg.size());
    const unsigned char len[2] = {static_cast<unsigned char>(n >> 8), static_cast<unsigned char>(n & 0xFF)};
    h.bytes(len, 2);
    h.bytes(msg);
    digest = h.value();
    ++count;
  }
  friend bool operator==(const StreamDigest&, const StreamDigest&) = default;
};

struct OutDigests {
  std::uint64_t index = 0;
  std::optional<std::uint32_t> record_crc;  // record P's content crc (absent from LLEOUTD1 sidecars)
  StreamDigest itch;
  std::vector<std::pair<std::uint32_t, StreamDigest>> sessions;  // ascending session id

  StreamDigest& session(std::uint32_t id) {
    auto it = std::lower_bound(sessions.begin(), sessions.end(), id,
                               [](const auto& p, std::uint32_t v) { return p.first < v; });
    if (it == sessions.end() || it->first != id) it = sessions.insert(it, {id, StreamDigest{}});
    return it->second;
  }
  [[nodiscard]] const StreamDigest* find(std::uint32_t id) const {
    const auto it = std::lower_bound(sessions.begin(), sessions.end(), id,
                                     [](const auto& p, std::uint32_t v) { return p.first < v; });
    return it == sessions.end() || it->first != id ? nullptr : &it->second;
  }
};

inline constexpr char kSidecarMagic[8] = {'L', 'L', 'E', 'O', 'U', 'T', 'D', '2'};
inline constexpr char kSidecarMagicV1[8] = {'L', 'L', 'E', 'O', 'U', 'T', 'D', '1'};

[[nodiscard]] inline std::string sidecar_path(const std::string& snapshot_path) { return snapshot_path + ".out"; }

[[nodiscard]] inline std::vector<std::byte> encode_sidecar(const OutDigests& d) {
  std::vector<std::byte> b(40 + 24 * d.sessions.size() + 8);
  std::memcpy(b.data(), d.record_crc ? kSidecarMagic : kSidecarMagicV1, 8);
  store_le64(b.data() + 8, d.index);
  store_le64(b.data() + 16, d.itch.count);
  store_le64(b.data() + 24, d.itch.digest);
  store_le32(b.data() + 32, static_cast<std::uint32_t>(d.sessions.size()));
  store_le32(b.data() + 36, d.record_crc.value_or(0));
  std::size_t at = 40;
  for (const auto& [id, s] : d.sessions) {
    store_le32(b.data() + at, id);
    store_le64(b.data() + at + 8, s.count);
    store_le64(b.data() + at + 16, s.digest);
    at += 24;
  }
  store_le32(b.data() + at, crc32c(b.data(), at));
  return b;
}

[[nodiscard]] inline std::optional<OutDigests> decode_sidecar(std::span<const std::byte> b) {
  if (b.size() < 48) return std::nullopt;
  const bool v2 = std::memcmp(b.data(), kSidecarMagic, 8) == 0;
  if (!v2 && std::memcmp(b.data(), kSidecarMagicV1, 8) != 0) return std::nullopt;
  const std::uint32_t n = load_le32(b.data() + 32);
  if ((!v2 && load_le32(b.data() + 36) != 0) || b.size() != 40 + 24 * std::size_t{n} + 8) return std::nullopt;
  const std::size_t at = 40 + 24 * std::size_t{n};
  if (load_le32(b.data() + at) != crc32c(b.data(), at) || load_le32(b.data() + at + 4) != 0) return std::nullopt;
  OutDigests d;
  d.index = load_le64(b.data() + 8);
  if (v2) d.record_crc = load_le32(b.data() + 36);
  d.itch.count = load_le64(b.data() + 16);
  d.itch.digest = load_le64(b.data() + 24);
  for (std::uint32_t i = 0; i < n; ++i) {
    const std::byte* e = b.data() + 40 + 24 * std::size_t{i};
    if (load_le32(e + 4) != 0) return std::nullopt;
    const std::uint32_t id = load_le32(e);
    if (!d.sessions.empty() && d.sessions.back().first >= id) return std::nullopt;  // ascending, unique
    d.sessions.emplace_back(id, StreamDigest{load_le64(e + 8), load_le64(e + 16)});
  }
  return d;
}

[[nodiscard]] inline std::optional<OutDigests> read_sidecar(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return std::nullopt;
  const std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return decode_sidecar(std::span<const std::byte>(reinterpret_cast<const std::byte*>(raw.data()), raw.size()));
}

// tmp, fsync, rename, fsync(dir): a crash leaves no sidecar or a complete one.
[[nodiscard]] inline bool write_sidecar(const std::string& path, const OutDigests& d) {
  const std::vector<std::byte> b = encode_sidecar(d);
  const std::string tmp = path + ".tmp";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) return false;
  const bool ok = ::write(fd, b.data(), b.size()) == static_cast<ssize_t>(b.size()) && ::fsync(fd) == 0;
  ::close(fd);
  if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) return false;
  const std::string dir = std::filesystem::path(path).parent_path().string();
  const int dfd = ::open(dir.c_str(), O_RDONLY | O_CLOEXEC);
  if (dfd < 0) return false;
  const bool synced = ::fsync(dfd) == 0;
  ::close(dfd);
  return synced;
}

}  // namespace lle::snapd
