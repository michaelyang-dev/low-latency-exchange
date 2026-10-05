#include "log/file_format.h"

#include <bit>
#include <cstring>

#include "common/crc32c.h"
#include "common/endian.h"
#include "log/record.h"
#include "log/varint.h"

namespace lle::nlog::file {
namespace {

template <class T>
void put_le(std::vector<std::byte>& out, T v) {
  const std::size_t at = out.size();
  out.resize(at + sizeof(T));
  store_raw(out.data() + at, to_little(v));
}

void put_raw(std::vector<std::byte>& out, const void* p, std::size_t n) {
  const std::size_t at = out.size();
  out.resize(at + n);
  if (n != 0) std::memcpy(out.data() + at, p, n);
}

void put_str16(std::vector<std::byte>& out, std::string_view s) {
  const std::size_t n = s.size() > 0xFFFF ? 0xFFFF : s.size();
  put_le<std::uint16_t>(out, static_cast<std::uint16_t>(n));
  put_raw(out, s.data(), n);
}

}  // namespace

void append_file_header(std::vector<std::byte>& out, const FileHeader& h) {
  const std::size_t at = out.size();
  put_raw(out, kFileMagic.data(), kFileMagic.size());
  put_le<std::uint16_t>(out, kVersionMajor);
  put_le<std::uint16_t>(out, kVersionMinor);
  put_le<std::uint32_t>(out, kFileHeaderBytes);
  put_le<std::int64_t>(out, h.created_realtime_ns);
  put_le<std::uint64_t>(out, h.tsc_hz);
  std::array<char, kNodeBytes> node{};
  const std::size_t n = h.node.size() < kNodeBytes - 1 ? h.node.size() : kNodeBytes - 1;
  if (n != 0) std::memcpy(node.data(), h.node.data(), n);
  put_raw(out, node.data(), node.size());
  put_le<std::uint32_t>(out, h.flags);
  put_le<std::uint32_t>(out, crc32c(out.data() + at, kFileHeaderBytes - 4));
}

std::size_t begin_chunk(std::vector<std::byte>& out) {
  const std::size_t at = out.size();
  out.resize(at + kChunkHeaderBytes);
  return at;
}

void end_chunk(std::vector<std::byte>& out, std::size_t at, ChunkType type) {
  std::byte* h = out.data() + at;
  const std::size_t payload = out.size() - at - kChunkHeaderBytes;
  store_le32(h, kChunkMagic);
  store_le16(h + 4, static_cast<std::uint16_t>(type));
  store_le16(h + 6, 0);
  store_le32(h + 8, static_cast<std::uint32_t>(payload));
  std::uint32_t crc = crc32c_extend(0, h, 12);
  crc = crc32c_extend(crc, h + kChunkHeaderBytes, payload);
  store_le32(h + 12, crc);
}

void append_dict_chunk(std::vector<std::byte>& out, std::span<const DictEntry> entries) {
  const std::size_t at = begin_chunk(out);
  put_le<std::uint32_t>(out, static_cast<std::uint32_t>(entries.size()));
  for (const DictEntry& e : entries) {
    put_le<std::uint32_t>(out, e.idx);
    out.push_back(static_cast<std::byte>(e.level));
    const std::uint8_t nargs = e.nargs <= kMaxArgs ? e.nargs : static_cast<std::uint8_t>(kMaxArgs);
    out.push_back(static_cast<std::byte>(nargs));
    for (std::size_t i = 0; i < nargs; ++i) out.push_back(static_cast<std::byte>(e.kinds[i]));
    put_le<std::uint32_t>(out, e.line);
    put_str16(out, e.file);
    put_str16(out, e.fmt);
  }
  end_chunk(out, at, ChunkType::kDict);
}

void append_calib_chunk(std::vector<std::byte>& out, const Calibration& c) {
  const std::size_t at = begin_chunk(out);
  put_le<std::uint64_t>(out, c.tsc);
  put_le<std::int64_t>(out, c.realtime_ns);
  put_le<std::uint64_t>(out, c.tsc_hz);
  put_le<std::uint32_t>(out, c.window_ticks);
  put_le<std::uint32_t>(out, 0);
  end_chunk(out, at, ChunkType::kCalib);
}

void append_thread_chunk(std::vector<std::byte>& out, std::uint32_t thread_id, std::uint64_t ring_bytes,
                         std::string_view name) {
  const std::size_t at = begin_chunk(out);
  put_le<std::uint32_t>(out, thread_id);
  put_le<std::uint32_t>(out, 0);
  put_le<std::uint64_t>(out, ring_bytes);
  put_str16(out, name);
  end_chunk(out, at, ChunkType::kThread);
}

void append_drops_chunk(std::vector<std::byte>& out, std::uint32_t thread_id, std::uint64_t tsc,
                        std::uint64_t total_drops) {
  const std::size_t at = begin_chunk(out);
  put_le<std::uint32_t>(out, thread_id);
  put_le<std::uint32_t>(out, 0);
  put_le<std::uint64_t>(out, tsc);
  put_le<std::uint64_t>(out, total_drops);
  end_chunk(out, at, ChunkType::kDrops);
}

void append_thread_end_chunk(std::vector<std::byte>& out, std::uint32_t thread_id, std::uint64_t tsc) {
  const std::size_t at = begin_chunk(out);
  put_le<std::uint32_t>(out, thread_id);
  put_le<std::uint32_t>(out, 0);
  put_le<std::uint64_t>(out, tsc);
  end_chunk(out, at, ChunkType::kThreadEnd);
}

void append_end_chunk(std::vector<std::byte>& out, std::uint64_t tsc, std::uint64_t total_records,
                      std::uint64_t total_drops, std::uint64_t unregistered_drops) {
  const std::size_t at = begin_chunk(out);
  put_le<std::uint64_t>(out, tsc);
  put_le<std::uint64_t>(out, total_records);
  put_le<std::uint64_t>(out, total_drops);
  put_le<std::uint64_t>(out, unregistered_drops);
  end_chunk(out, at, ChunkType::kEnd);
}

// ---- ExtentBuilder ---------------------------------------------------------------
// Records are written through a raw cursor into capacity reserved up front (one
// bounds check per record): this is the backend's per-record path.

void ExtentBuilder::reset(std::uint32_t thread_id) noexcept {
  thread_id_ = thread_id;
  count_ = 0;
  base_tsc_ = 0;
  prev_tsc_ = 0;
  len_ = 0;
}

void ExtentBuilder::ensure(std::size_t extra) {
  if (body_.size() - len_ < extra) body_.resize(len_ + extra + body_.size() / 2);
}

std::byte* ExtentBuilder::put_header(std::byte* w, std::uint32_t site_idx, std::uint16_t flags,
                                     std::uint64_t tsc) noexcept {
  const std::uint64_t prev = count_ == 0 ? tsc : prev_tsc_;
  w += nlog::put_varint(w, (std::uint64_t{site_idx} << 2) | (flags & kRecFlagMask));
  // Deltas are signed: NLOG_EV timestamps need not be monotonic within a thread.
  w += nlog::put_varint(w, zigzag_encode(static_cast<std::int64_t>(tsc - prev)));
  return w;
}

bool ExtentBuilder::add_raw(std::uint32_t site_idx, std::uint16_t flags, std::uint64_t tsc, const ArgKinds& kinds,
                            std::uint8_t nargs, const std::byte* args, const std::byte* args_end) {
  ensure(kMaxCompactRecord);
  std::byte* w = put_header(body_.data() + len_, site_idx, flags, tsc);
  const std::byte* p = args;
  for (std::size_t i = 0; i < nargs && i < kMaxArgs; ++i) {
    const ArgKind k = kinds[i];
    const auto left = static_cast<std::size_t>(args_end - p);
    if (k == ArgKind::kStr) {
      if (left < 1) return false;
      const auto b = static_cast<std::uint8_t>(*p);
      const std::size_t n = b & 0x7Fu;
      if (n > kMaxStringBytes || left < 1 + n) return false;
      w += nlog::put_varint(w, (std::uint64_t{n} << 1) | ((b & kStrTruncatedBit) != 0 ? 1u : 0u));
      std::memcpy(w, p + 1, n);
      w += n;
      p += 1 + n;
      continue;
    }
    const std::size_t n = raw_size(k);
    if (n == 0 || left < n) return false;
    switch (k) {
      case ArgKind::kU8:
      case ArgKind::kI8:
      case ArgKind::kBool:
      case ArgKind::kChar: *w++ = *p; break;
      case ArgKind::kU16: w += nlog::put_varint(w, load_le16(p)); break;
      case ArgKind::kU32: w += nlog::put_varint(w, load_le32(p)); break;
      case ArgKind::kU64: w += nlog::put_varint(w, load_le64(p)); break;
      case ArgKind::kI16: w += nlog::put_varint(w, zigzag_encode(static_cast<std::int16_t>(load_le16(p)))); break;
      case ArgKind::kI32: w += nlog::put_varint(w, zigzag_encode(static_cast<std::int32_t>(load_le32(p)))); break;
      case ArgKind::kI64: w += nlog::put_varint(w, zigzag_encode(static_cast<std::int64_t>(load_le64(p)))); break;
      case ArgKind::kF64:
        std::memcpy(w, p, 8);
        w += 8;
        break;
      case ArgKind::kStr:
      case ArgKind::kNone: return false;
    }
    p += n;
  }
  // Commit (a malformed record returned above without touching len_ or the TSC state).
  if (count_ == 0) base_tsc_ = tsc;
  prev_tsc_ = tsc;
  len_ = static_cast<std::size_t>(w - body_.data());
  ++count_;
  return true;
}

void ExtentBuilder::add_values(std::uint32_t site_idx, std::uint16_t flags, std::uint64_t tsc,
                               std::span<const ArgValue> args) {
  ensure(kMaxCompactRecord);
  std::byte* w = put_header(body_.data() + len_, site_idx, flags, tsc);
  for (std::size_t i = 0; i < args.size() && i < kMaxArgs; ++i) {
    const ArgValue& a = args[i];
    switch (a.kind) {
      case ArgKind::kU8:
      case ArgKind::kBool:
      case ArgKind::kChar: *w++ = static_cast<std::byte>(a.u); break;
      case ArgKind::kI8: *w++ = static_cast<std::byte>(static_cast<std::uint8_t>(static_cast<std::int8_t>(a.i))); break;
      case ArgKind::kU16:
      case ArgKind::kU32:
      case ArgKind::kU64: w += nlog::put_varint(w, a.u); break;
      case ArgKind::kI16:
      case ArgKind::kI32:
      case ArgKind::kI64: w += nlog::put_varint(w, zigzag_encode(a.i)); break;
      case ArgKind::kF64:
        store_le64(w, std::bit_cast<std::uint64_t>(a.d));
        w += 8;
        break;
      case ArgKind::kStr: {
        const bool cut = a.truncated || a.s.size() > kMaxStringBytes;
        const std::size_t n = a.s.size() > kMaxStringBytes ? kMaxStringBytes : a.s.size();
        w += nlog::put_varint(w, (std::uint64_t{n} << 1) | (cut ? 1u : 0u));
        if (n != 0) std::memcpy(w, a.s.data(), n);
        w += n;
        break;
      }
      case ArgKind::kNone: break;
    }
  }
  if (count_ == 0) base_tsc_ = tsc;
  prev_tsc_ = tsc;
  len_ = static_cast<std::size_t>(w - body_.data());
  ++count_;
}

void ExtentBuilder::finish_into(std::vector<std::byte>& out) {
  if (count_ == 0) return;
  const std::size_t at = begin_chunk(out);
  const std::size_t h = out.size();
  out.resize(h + kExtentHeaderBytes);
  store_le32(out.data() + h, thread_id_);
  store_le32(out.data() + h + 4, count_);
  store_le64(out.data() + h + 8, base_tsc_);
  put_raw(out, body_.data(), len_);
  end_chunk(out, at, ChunkType::kExtent);
  reset(thread_id_);
}

}  // namespace lle::nlog::file
