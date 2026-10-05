#include "log/decoder.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <format>
#include <limits>
#include <queue>

#include "common/int128.h"
#include "common/crc32c.h"
#include "common/endian.h"
#include "log/format_text.h"
#include "log/level.h"
#include "log/record.h"
#include "log/varint.h"

namespace lle::nlog::decode {
namespace {


// Bounds-checked little-endian reader over a payload.
class Reader {
 public:
  Reader(const std::byte* p, const std::byte* end) noexcept : p_(p), end_(end) {}
  [[nodiscard]] std::size_t left() const noexcept { return static_cast<std::size_t>(end_ - p_); }
  template <class T>
  bool get(T& v) noexcept {
    if (left() < sizeof(T)) return false;
    v = to_little(load_raw<T>(p_));
    p_ += sizeof(T);
    return true;
  }
  bool str16(std::string_view& s) noexcept {
    std::uint16_t n = 0;
    if (!get(n) || left() < n) return false;
    s = std::string_view{reinterpret_cast<const char*>(p_), n};
    p_ += n;
    return true;
  }
  bool skip(std::size_t n) noexcept {
    if (left() < n) return false;
    p_ += n;
    return true;
  }

 private:
  const std::byte* p_;
  const std::byte* end_;
};

constexpr std::int64_t saturate(i128 v) noexcept {
  constexpr auto lo = static_cast<i128>(std::numeric_limits<std::int64_t>::min());
  constexpr auto hi = static_cast<i128>(std::numeric_limits<std::int64_t>::max());
  return static_cast<std::int64_t>(v < lo ? lo : (v > hi ? hi : v));
}

std::uint64_t max_for(ArgKind k) noexcept {
  switch (k) {
    case ArgKind::kU16: return 0xFFFF;
    case ArgKind::kU32: return 0xFFFF'FFFF;
    default: return ~std::uint64_t{0};
  }
}

bool signed_in_range(ArgKind k, std::int64_t v) noexcept {
  switch (k) {
    case ArgKind::kI16: return v >= -32768 && v <= 32767;
    case ArgKind::kI32: return v >= std::numeric_limits<std::int32_t>::min() && v <= std::numeric_limits<std::int32_t>::max();
    default: return true;
  }
}

}  // namespace

std::string_view status_name(Status s) noexcept {
  switch (s) {
    case Status::kOk: return "ok";
    case Status::kTruncated: return "truncated";
    case Status::kCorrupt: return "corrupt";
    case Status::kBadHeader: return "bad-header";
    case Status::kUnsupportedVersion: return "unsupported-version";
  }
  return "?";
}

// ---- parse -----------------------------------------------------------------------

void LogFile::parse_dict(std::span<const std::byte> p) {
  Reader r(p.data(), p.data() + p.size());
  std::uint32_t count = 0;
  if (!r.get(count)) {
    ++info_.malformed_chunks;
    return;
  }
  for (std::uint32_t e = 0; e < count; ++e) {
    SiteInfo s;
    std::uint8_t nargs = 0;
    if (!r.get(s.idx) || !r.get(s.level) || !r.get(nargs)) break;
    bool ok = nargs <= kMaxArgs;
    if (r.left() < nargs) break;
    for (std::size_t i = 0; i < nargs; ++i) {
      std::uint8_t k = 0;
      r.get(k);
      if (i < kMaxArgs) {
        if (!is_valid_kind(k)) ok = false;
        s.kinds[i] = static_cast<ArgKind>(k);
      }
    }
    s.nargs = nargs;
    if (!r.get(s.line) || !r.str16(s.file) || !r.str16(s.fmt)) break;
    if (ok) sites_.try_emplace(s.idx, s);
  }
}

LogFile LogFile::parse(std::span<const std::byte> bytes, const ParseOptions& opts) {
  LogFile f;
  f.bytes_ = bytes;
  ScanInfo& info = f.info_;
  const std::byte* base = bytes.data();
  const std::size_t size = bytes.size();
  if (size < file::kFileHeaderBytes || std::memcmp(base, file::kFileMagic.data(), file::kFileMagic.size()) != 0) {
    info.status = Status::kBadHeader;
    return f;
  }
  info.version_major = load_le16(base + 8);
  info.version_minor = load_le16(base + 10);
  const std::uint32_t header_bytes = load_le32(base + 12);
  if (info.version_major != file::kVersionMajor) {
    info.status = Status::kUnsupportedVersion;
    return f;
  }
  if (header_bytes < file::kFileHeaderBytes || header_bytes > size ||
      (opts.verify_crc && crc32c(base, file::kFileHeaderBytes - 4) != load_le32(base + 60))) {
    info.status = Status::kBadHeader;
    return f;
  }
  info.created_realtime_ns = static_cast<std::int64_t>(load_le64(base + 16));
  info.header_tsc_hz = load_le64(base + 24);
  const auto* node = reinterpret_cast<const char*>(base + 32);
  info.node.assign(node, strnlen(node, file::kNodeBytes));

  std::size_t off = header_bytes;
  info.valid_bytes = off;
  while (off < size) {
    if (size - off < file::kChunkHeaderBytes) {
      info.status = Status::kTruncated;
      break;
    }
    const std::byte* h = base + off;
    const std::uint32_t len = load_le32(h + 8);
    if (load_le32(h) != file::kChunkMagic || len > file::kMaxChunkPayload) {
      info.status = Status::kCorrupt;
      break;
    }
    if (size - off - file::kChunkHeaderBytes < len) {
      info.status = Status::kTruncated;
      break;
    }
    const std::byte* payload = h + file::kChunkHeaderBytes;
    if (opts.verify_crc) {
      std::uint32_t crc = crc32c_extend(0, h, 12);
      crc = crc32c_extend(crc, payload, len);
      if (crc != load_le32(h + 12)) {
        info.status = Status::kCorrupt;
        break;
      }
    }
    Reader r(payload, payload + len);
    switch (static_cast<file::ChunkType>(load_le16(h + 4))) {
      case file::ChunkType::kDict: f.parse_dict({payload, len}); break;
      case file::ChunkType::kCalib: {
        file::Calibration c;
        std::uint32_t reserved = 0;
        if (r.get(c.tsc) && r.get(c.realtime_ns) && r.get(c.tsc_hz) && r.get(c.window_ticks) && r.get(reserved)) {
          f.calibs_.push_back(c);
        } else {
          ++info.malformed_chunks;
        }
        break;
      }
      case file::ChunkType::kThread: {
        ThreadInfo t;
        std::uint32_t reserved = 0;
        if (r.get(t.id) && r.get(reserved) && r.get(t.ring_bytes) && r.str16(t.name)) {
          ThreadInfo& slot = f.threads_[t.id];
          slot.id = t.id;
          slot.ring_bytes = t.ring_bytes;
          slot.name = t.name;
        } else {
          ++info.malformed_chunks;
        }
        break;
      }
      case file::ChunkType::kExtent: {
        std::uint32_t tid = 0;
        if (r.get(tid) && len >= file::kExtentHeaderBytes) {
          f.extents_[tid].push_back(ExtentRef{off + file::kChunkHeaderBytes, len});
          if (f.threads_.find(tid) == f.threads_.end()) f.threads_[tid].id = tid;
          ++info.extents;
        } else {
          ++info.malformed_chunks;
        }
        break;
      }
      case file::ChunkType::kDrops: {
        std::uint32_t tid = 0, reserved = 0;
        std::uint64_t tsc = 0, total = 0;
        if (r.get(tid) && r.get(reserved) && r.get(tsc) && r.get(total)) {
          ThreadInfo& t = f.threads_[tid];
          t.id = tid;
          t.drops = std::max(t.drops, total);
        } else {
          ++info.malformed_chunks;
        }
        break;
      }
      case file::ChunkType::kThreadEnd: {
        std::uint32_t tid = 0;
        if (r.get(tid)) {
          ThreadInfo& t = f.threads_[tid];
          t.id = tid;
          t.ended = true;
        } else {
          ++info.malformed_chunks;
        }
        break;
      }
      case file::ChunkType::kEnd: {
        std::uint64_t tsc = 0;
        if (r.get(tsc) && r.get(info.end_total_records) && r.get(info.end_total_drops) &&
            r.get(info.end_unregistered_drops)) {
          info.clean_end = true;
        } else {
          ++info.malformed_chunks;
        }
        break;
      }
      default: ++info.unknown_chunks; break;
    }
    ++info.chunks;
    off += file::kChunkHeaderBytes + len;
    info.valid_bytes = off;
  }
  std::stable_sort(f.calibs_.begin(), f.calibs_.end(),
                   [](const file::Calibration& a, const file::Calibration& b) { return a.tsc < b.tsc; });
  return f;
}

const SiteInfo* LogFile::site(std::uint32_t idx) const noexcept {
  const auto it = sites_.find(idx);
  return it == sites_.end() ? nullptr : &it->second;
}

std::optional<std::int64_t> LogFile::to_wall_ns(std::uint64_t tsc) const noexcept {
  if (calibs_.empty()) return std::nullopt;
  const auto it = std::upper_bound(calibs_.begin(), calibs_.end(), tsc,
                                   [](std::uint64_t t, const file::Calibration& c) { return t < c.tsc; });
  const file::Calibration& c = it == calibs_.begin() ? *it : *(it - 1);
  if (it != calibs_.begin() && it != calibs_.end() && it->tsc > c.tsc) {
    // Interpolate between neighbouring calibrations (absorbs frequency error and
    // CLOCK_REALTIME slew). |dr| and dt are < 2^64, so the product fits in u128.
    const std::uint64_t dt = tsc - c.tsc;
    const std::uint64_t ds = it->tsc - c.tsc;
    const i128 dr = static_cast<i128>(it->realtime_ns) - c.realtime_ns;
    const auto mag = static_cast<u128>(dr < 0 ? -dr : dr);
    const auto step = static_cast<i128>(mag * dt / ds);
    return saturate(static_cast<i128>(c.realtime_ns) + (dr < 0 ? -step : step));
  }
  if (c.tsc_hz == 0) return std::nullopt;
  const i128 dticks = static_cast<i128>(tsc) - static_cast<i128>(c.tsc);
  return saturate(static_cast<i128>(c.realtime_ns) + dticks * 1'000'000'000 / static_cast<i128>(c.tsc_hz));
}

// ---- merge -----------------------------------------------------------------------

struct LogFile::Cursor {
  std::uint32_t thread_id = 0;
  const std::vector<ExtentRef>* extents = nullptr;
  std::size_t next_extent = 0;
  const std::byte* p = nullptr;
  const std::byte* end = nullptr;
  std::uint32_t remaining = 0;
  std::uint64_t prev_tsc = 0;
  Record cur;
};

bool LogFile::decode_record(Cursor& c, Record& r) const {
  std::uint64_t hdr = 0, delta = 0;
  if (!get_varint(c.p, c.end, hdr) || !get_varint(c.p, c.end, delta)) return false;
  if ((hdr >> 2) > 0xFFFF'FFFFu) return false;
  r.site_idx = static_cast<std::uint32_t>(hdr >> 2);
  r.flags = static_cast<std::uint16_t>(hdr & file::kRecFlagMask);
  r.tsc = c.prev_tsc + static_cast<std::uint64_t>(zigzag_decode(delta));
  c.prev_tsc = r.tsc;
  r.thread_id = c.thread_id;
  r.site = site(r.site_idx);
  if (r.site == nullptr) return false;
  r.nargs = r.site->nargs;
  for (std::size_t i = 0; i < r.nargs; ++i) {
    ArgValue& a = r.args[i];
    a = ArgValue{};
    a.kind = r.site->kinds[i];
    switch (a.kind) {
      case ArgKind::kU8:
      case ArgKind::kBool:
      case ArgKind::kChar:
      case ArgKind::kI8: {
        if (c.p == c.end) return false;
        const auto b = static_cast<std::uint8_t>(*c.p++);
        if (a.kind == ArgKind::kI8) {
          a.i = static_cast<std::int8_t>(b);
        } else if (a.kind == ArgKind::kBool) {
          a.u = b != 0 ? 1 : 0;
        } else {
          a.u = b;
        }
        break;
      }
      case ArgKind::kU16:
      case ArgKind::kU32:
      case ArgKind::kU64:
        if (!get_varint(c.p, c.end, a.u) || a.u > max_for(a.kind)) return false;
        break;
      case ArgKind::kI16:
      case ArgKind::kI32:
      case ArgKind::kI64: {
        std::uint64_t z = 0;
        if (!get_varint(c.p, c.end, z)) return false;
        a.i = zigzag_decode(z);
        if (!signed_in_range(a.kind, a.i)) return false;
        break;
      }
      case ArgKind::kF64: {
        if (c.end - c.p < 8) return false;
        a.d = std::bit_cast<double>(load_le64(c.p));
        c.p += 8;
        break;
      }
      case ArgKind::kStr: {
        std::uint64_t v = 0;
        if (!get_varint(c.p, c.end, v)) return false;
        const std::uint64_t n = v >> 1;
        if (n > kMaxStringBytes || static_cast<std::uint64_t>(c.end - c.p) < n) return false;
        a.s = std::string_view{reinterpret_cast<const char*>(c.p), static_cast<std::size_t>(n)};
        a.truncated = (v & 1) != 0;
        c.p += n;
        break;
      }
      case ArgKind::kNone: return false;
    }
  }
  r.wall_ns = to_wall_ns(r.tsc);
  return true;
}

bool LogFile::advance(Cursor& c, MergeStats& ms) const {
  for (;;) {
    if (c.remaining == 0) {
      if (c.next_extent >= c.extents->size()) return false;
      const ExtentRef e = (*c.extents)[c.next_extent++];
      const std::byte* p = bytes_.data() + e.offset;
      c.remaining = load_le32(p + 4);
      c.prev_tsc = load_le64(p + 8);
      c.p = p + file::kExtentHeaderBytes;
      c.end = p + e.len;
      continue;
    }
    if (!decode_record(c, c.cur)) {
      ++ms.bad_extents;
      c.remaining = 0;
      continue;
    }
    --c.remaining;
    return true;
  }
}

MergeStats LogFile::for_each(const std::function<bool(const Record&)>& f) const {
  MergeStats ms;
  std::vector<Cursor> cursors;
  cursors.reserve(extents_.size());
  for (const auto& [tid, list] : extents_) {
    Cursor c;
    c.thread_id = tid;
    c.extents = &list;
    cursors.push_back(c);
  }
  struct Item {
    std::uint64_t tsc;
    std::uint32_t thread;
    std::size_t cursor;
    bool operator>(const Item& o) const noexcept {
      if (tsc != o.tsc) return tsc > o.tsc;
      return thread > o.thread;
    }
  };
  std::priority_queue<Item, std::vector<Item>, std::greater<>> heap;
  for (std::size_t i = 0; i < cursors.size(); ++i) {
    if (advance(cursors[i], ms)) heap.push(Item{cursors[i].cur.tsc, cursors[i].thread_id, i});
  }
  while (!heap.empty()) {
    const Item top = heap.top();
    heap.pop();
    Cursor& c = cursors[top.cursor];
    ++ms.records;
    if (!f(c.cur)) break;
    if (advance(c, ms)) heap.push(Item{c.cur.tsc, c.thread_id, top.cursor});
  }
  return ms;
}

// ---- filtering and rendering -----------------------------------------------------

bool Filter::matches(const Record& r) const noexcept {
  if (min_level && (r.site == nullptr || r.site->level < *min_level)) return false;
  if (!sites.empty() && std::find(sites.begin(), sites.end(), r.site_idx) == sites.end()) return false;
  if (!threads.empty() && std::find(threads.begin(), threads.end(), r.thread_id) == threads.end()) return false;
  if (from_tsc && r.tsc < *from_tsc) return false;
  if (to_tsc && r.tsc >= *to_tsc) return false;
  if (from_ns || to_ns) {
    if (!r.wall_ns) return false;
    if (from_ns && *r.wall_ns < *from_ns) return false;
    if (to_ns && *r.wall_ns >= *to_ns) return false;
  }
  return true;
}

void render_record(std::string& out, const Record& r, const RenderOptions& opts) {
  const std::string_view file_name =
      r.site == nullptr ? std::string_view{"?"} : (opts.full_paths ? r.site->file : basename_of(r.site->file));
  const std::uint8_t level = r.site == nullptr ? 0xFF : r.site->level;
  const std::uint32_t line = r.site == nullptr ? 0 : r.site->line;
  const std::string_view fmt = r.site == nullptr ? std::string_view{} : r.site->fmt;
  const std::span<const ArgValue> args{r.args.data(), r.nargs};
  if (opts.format == OutputFormat::kText) {
    switch (opts.time) {
      case TimeMode::kWall:
        if (r.wall_ns) {
          append_utc_time(out, *r.wall_ns);
        } else {
          out += std::format("tsc:{}", r.tsc);
        }
        out += ' ';
        break;
      case TimeMode::kTsc: out += std::format("{} ", r.tsc); break;
      case TimeMode::kNone: break;
    }
    out += std::format("{:<5} t{} {}:{} ", level_name(level), r.thread_id, file_name, line);
    format_message(out, fmt, args, true);
    out += '\n';
    return;
  }
  out += std::format("{{\"tsc\":{}", r.tsc);
  if (opts.time != TimeMode::kNone && r.wall_ns) {
    out += std::format(",\"ts_ns\":{},\"time\":\"", *r.wall_ns);
    append_utc_time(out, *r.wall_ns);
    out += '"';
  }
  out += std::format(",\"level\":\"{}\",\"thread\":{},\"site\":{},\"file\":\"", level_name(level), r.thread_id,
                     r.site_idx);
  append_json_escaped(out, file_name);
  out += std::format("\",\"line\":{},\"msg\":\"", line);
  std::string msg;
  format_message(msg, fmt, args, false);
  append_json_escaped(out, msg);
  out += "\",\"args\":[";
  for (std::size_t i = 0; i < args.size(); ++i) {
    if (i != 0) out += ',';
    append_json_arg(out, args[i]);
  }
  out += ']';
  if ((r.flags & kFlagTruncated) != 0) out += ",\"truncated\":true";
  if ((r.flags & kFlagEventTs) != 0) out += ",\"ev\":true";
  out += "}\n";
}

RenderStats render(const LogFile& f, const RenderOptions& opts, const std::function<void(std::string_view)>& sink) {
  RenderStats rs;
  std::string line;
  rs.merge = f.for_each([&](const Record& r) {
    if (!opts.filter.matches(r)) return true;
    line.clear();
    render_record(line, r, opts);
    sink(line);
    ++rs.records_out;
    return true;
  });
  return rs;
}

std::string render_to_string(const LogFile& f, const RenderOptions& opts) {
  std::string out;
  render(f, opts, [&out](std::string_view s) { out.append(s); });
  return out;
}

std::string describe(const LogFile& f) {
  const ScanInfo& i = f.info();
  std::string out = std::format(
      "nlog file: version {}.{} node '{}' status {} valid_bytes {} chunks {} extents {} sites {} calibrations {} "
      "clean_end {}\n",
      i.version_major, i.version_minor, i.node, status_name(i.status), i.valid_bytes, i.chunks, i.extents,
      f.sites().size(), f.calibrations().size(), i.clean_end ? "yes" : "no");
  if (i.unknown_chunks != 0 || i.malformed_chunks != 0) {
    out += std::format("  skipped chunks: unknown {} malformed {}\n", i.unknown_chunks, i.malformed_chunks);
  }
  if (i.clean_end) {
    out += std::format("  end: records {} drops {} unregistered_drops {}\n", i.end_total_records, i.end_total_drops,
                       i.end_unregistered_drops);
  }
  for (const auto& [id, t] : f.threads()) {
    out += std::format("  thread {} '{}' ring {} drops {}{}\n", id, t.name, t.ring_bytes, t.drops,
                       t.ended ? " ended" : "");
  }
  return out;
}

std::string dictionary_text(const LogFile& f) {
  std::string out;
  for (const auto& [idx, s] : f.sites()) {
    out += std::format("{} {:<5} {}:{} [", idx, level_name(s.level), s.file, s.line);
    for (std::size_t k = 0; k < s.nargs && k < kMaxArgs; ++k) {
      if (k != 0) out += ',';
      out += kind_name(s.kinds[k]);
    }
    out += "] ";
    out += s.fmt;
    out += '\n';
  }
  return out;
}

}  // namespace lle::nlog::decode
