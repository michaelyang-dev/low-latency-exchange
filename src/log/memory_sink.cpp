#include "log/memory_sink.h"

#include <bit>
#include <format>

#include "common/endian.h"
#include "common/hash.h"
#include "log/format_text.h"
#include "log/record.h"
#include "log/registry.h"

namespace lle::nlog {

MemorySink::~MemorySink() { detach(); }

bool MemorySink::attach() noexcept {
  if (attached_) return true;
  attached_ = detail::acquire_consumer();
  return attached_;
}

void MemorySink::detach() noexcept {
  if (!attached_) return;
  detail::release_consumer();
  attached_ = false;
}

std::size_t MemorySink::drain() {
  if (!attached_) return 0;
  std::size_t total = 0;
  std::size_t n = 0;
  while ((n = detail::poll_rings(*this, 4096)) != 0) total += n;
  return total;
}

void MemorySink::on_record(const detail::ThreadBuffer& b, const std::byte* p, std::uint32_t len) {
  if (len < kRecordHeaderBytes) {
    ++bad_records_;
    return;
  }
  const RawHeader h = read_raw_header(p);
  const std::uint32_t idx = canonical_site(h.site_idx);  // one ID per site (site.h)
  const LogSite* site = site_at(idx);
  if (h.len < kRecordHeaderBytes || h.len > len || site == nullptr) {
    ++bad_records_;
    return;
  }
  MemRecord r;
  r.thread_id = b.thread_id;
  r.tsc = h.tsc;
  r.site_idx = idx;
  r.site = site;
  r.flags = h.flags;
  r.nargs = site->nargs;
  const std::byte* q = p + kRecordHeaderBytes;
  const std::byte* end = p + h.len;
  for (std::size_t i = 0; i < site->nargs; ++i) {
    ArgValue& a = r.raw[i];
    a.kind = site->kinds[i];
    const std::size_t need = a.kind == ArgKind::kStr ? 1 : raw_size(a.kind);
    if (need == 0 || static_cast<std::size_t>(end - q) < need) {
      ++bad_records_;
      return;
    }
    switch (a.kind) {
      case ArgKind::kU8:
      case ArgKind::kChar: a.u = static_cast<std::uint8_t>(*q); break;
      case ArgKind::kBool: a.u = *q != std::byte{0} ? 1 : 0; break;
      case ArgKind::kU16: a.u = load_le16(q); break;
      case ArgKind::kU32: a.u = load_le32(q); break;
      case ArgKind::kU64: a.u = load_le64(q); break;
      case ArgKind::kI8: a.i = static_cast<std::int8_t>(*q); break;
      case ArgKind::kI16: a.i = static_cast<std::int16_t>(load_le16(q)); break;
      case ArgKind::kI32: a.i = static_cast<std::int32_t>(load_le32(q)); break;
      case ArgKind::kI64: a.i = static_cast<std::int64_t>(load_le64(q)); break;
      case ArgKind::kF64: a.d = std::bit_cast<double>(load_le64(q)); break;
      case ArgKind::kStr: {
        const auto b0 = static_cast<std::uint8_t>(*q);
        const std::size_t n = b0 & 0x7Fu;
        if (n > kMaxStringBytes || static_cast<std::size_t>(end - q) < 1 + n) {
          ++bad_records_;
          return;
        }
        r.strings[i].assign(reinterpret_cast<const char*>(q + 1), n);
        a.truncated = (b0 & kStrTruncatedBit) != 0;
        q += 1 + n;
        continue;
      }
      case ArgKind::kNone: break;
    }
    q += need;
  }
  records_.push_back(std::move(r));
}

void MemorySink::on_drops(const detail::ThreadBuffer& b, std::uint64_t total) {
  for (auto& [id, d] : drops_) {
    if (id == b.thread_id) {
      d = total;
      return;
    }
  }
  drops_.emplace_back(b.thread_id, total);
}

std::uint64_t MemorySink::drops(std::uint32_t thread_id) const noexcept {
  for (const auto& [id, d] : drops_)
    if (id == thread_id) return d;
  return 0;
}

std::string MemorySink::format(const MemRecord& r) {
  std::string out = std::format("{} {:<5} t{} {}:{} ", r.tsc, level_name(r.site->level), r.thread_id,
                                basename_of(r.site->file), r.site->line);
  std::array<ArgValue, kMaxArgs> args;
  for (std::size_t i = 0; i < r.nargs; ++i) args[i] = r.arg(i);
  format_message(out, r.site->fmt, std::span<const ArgValue>{args.data(), r.nargs}, true);
  return out;
}

std::string MemorySink::text() const {
  std::string out;
  for (const MemRecord& r : records_) {
    out += format(r);
    out += '\n';
  }
  return out;
}

std::uint64_t MemorySink::hash(bool include_thread_ids) const noexcept {
  Fnv1a64 h;
  for (const MemRecord& r : records_) {
    h.u(r.tsc);
    if (include_thread_ids) h.u(r.thread_id);
    h.str(r.site->fmt);
    h.str(basename_of(r.site->file));
    h.u(r.site->line);
    h.u(r.flags);
    for (std::size_t i = 0; i < r.nargs; ++i) {
      const ArgValue a = r.arg(i);
      h.u(static_cast<std::uint8_t>(a.kind));
      switch (a.kind) {
        case ArgKind::kStr:
          h.u(a.s.size());
          h.str(a.s);
          h.u(a.truncated ? 1u : 0u);
          break;
        case ArgKind::kF64: h.u(std::bit_cast<std::uint64_t>(a.d)); break;
        default:
          h.u(is_signed_kind(a.kind) ? static_cast<std::uint64_t>(a.i) : a.u);
          break;
      }
    }
  }
  return h.value();
}

}  // namespace lle::nlog
