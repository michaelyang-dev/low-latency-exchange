#pragma once
// Record format shared by SpscByteRing and BroadcastRing (08-concurrency-runtime §4,
// §6): every record starts on an 8-byte boundary with an 8-byte header
// {u32 len, u32 flags} followed by `len` payload bytes padded to a multiple of 8.
// A record never straddles the end of the buffer: when it does not fit before the
// end, the producer writes a pad record (flags & kPadFlag) covering the tail and
// places the record at offset 0. The pad and the record are published by one
// commit, so a consumer that sees a pad always finds a record after it.
//
// Include allowlist (08 §7): <atomic>, <cstddef>, <cstdint>, <type_traits> only.
#include <cstddef>
#include <cstdint>

namespace lle::conc::detail {

struct RecordHeader {
  std::uint32_t len;
  std::uint32_t flags;
};
static_assert(sizeof(RecordHeader) == 8);

inline constexpr std::uint32_t kPadFlag = 1u;
inline constexpr std::uint64_t kRecordAlign = 8;
inline constexpr std::uint64_t kHeaderBytes = sizeof(RecordHeader);
// Smallest buffer: one header plus 8 payload bytes must fit in half of it.
inline constexpr std::size_t kMinByteRingCapacity = 32;

constexpr std::uint64_t record_bytes(std::uint32_t payload) noexcept {
  return kHeaderBytes + ((static_cast<std::uint64_t>(payload) + (kRecordAlign - 1)) & ~(kRecordAlign - 1));
}

// The storage is caller-provided std::byte memory; headers are accessed through a
// void* hop so -Wcast-align stays quiet (alignment is guaranteed by init()).
inline RecordHeader* header_at(std::byte* base, std::uint64_t off) noexcept {
  return static_cast<RecordHeader*>(static_cast<void*>(base + off));
}
inline const RecordHeader* header_at(const std::byte* base, std::uint64_t off) noexcept {
  return static_cast<const RecordHeader*>(static_cast<const void*>(base + off));
}

// Field-by-field stores and loads: a struct temporary would lower to memcpy, which
// GenMC cannot model (verify/genmc/RESULTS.md); -O2 codegen is the same.
inline void write_header(std::byte* base, std::uint64_t off, std::uint32_t len, std::uint32_t flags) noexcept {
  RecordHeader* h = header_at(base, off);
  h->len = len;
  h->flags = flags;
}

constexpr bool valid_byte_ring_capacity(std::size_t cap) noexcept {
  return cap >= kMinByteRingCapacity && (cap & (cap - 1)) == 0 && cap <= (std::size_t{1} << 32);
}

// A placement decided by the producer for one record.
struct Placement {
  std::uint64_t start;  // position of the record header
  std::uint64_t end;    // position one past the record
  std::uint64_t pad;    // bytes of pad record before `start` (0 if none)
};

// Where a record of `need` bytes goes when the producer is at position `w`.
constexpr Placement place_record(std::uint64_t w, std::uint64_t need, std::uint64_t cap) noexcept {
  const std::uint64_t off = w & (cap - 1);
  const std::uint64_t tail_room = cap - off;
  if (need <= tail_room) return Placement{w, w + need, 0};
  return Placement{w + tail_room, w + tail_room + need, tail_room};
}

}  // namespace lle::conc::detail
