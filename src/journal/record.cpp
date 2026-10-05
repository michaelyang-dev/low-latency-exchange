#include "journal/record.h"

#include <algorithm>

#include "common/crc32c.h"

namespace lle::journal {

namespace {

constexpr std::byte kZero8[8] = {};

// A^8: the CRC register transition over 8 zero bytes. By linearity,
// crc32c_extend(s, z) ^ crc32c_extend(0, z) is the register s advanced over z.
std::uint32_t advance8_slow(std::uint32_t m) noexcept {
  static const std::uint32_t kZeroCrc = crc32c_extend(0, kZero8, sizeof(kZero8));
  return crc32c_extend(m, kZero8, sizeof(kZero8)) ^ kZeroCrc;
}

// A^8 is linear over GF(2), so it is the XOR of its images of the register's four
// bytes: four table lookups per step instead of a CRC call (Sealer construction).
struct Advance8Table {
  std::array<std::array<std::uint32_t, 256>, 4> t{};
  Advance8Table() noexcept {
    for (std::uint32_t k = 0; k < 4; ++k) {
      for (std::uint32_t b = 0; b < 256; ++b) t[k][b] = advance8_slow(b << (8 * k));
    }
  }
};

std::uint32_t advance8(std::uint32_t m) noexcept {
  static const Advance8Table kT;
  return kT.t[0][m & 0xFFu] ^ kT.t[1][(m >> 8) & 0xFFu] ^ kT.t[2][(m >> 16) & 0xFFu] ^ kT.t[3][m >> 24];
}

// Field accessors for payload decoding; the caller has bounded `off + width` by the
// record length.
std::uint16_t u16_at(const RecordView& r, std::size_t off) noexcept { return load_le16(r.data() + kHeaderBytes + off); }
std::uint32_t u32_at(const RecordView& r, std::size_t off) noexcept { return load_le32(r.data() + kHeaderBytes + off); }
std::uint64_t u64_at(const RecordView& r, std::size_t off) noexcept { return load_le64(r.data() + kHeaderBytes + off); }

// Fixed-size payloads: type and exact record length.
std::expected<void, DecodeError> check_fixed(const RecordView& r, RecordType t, std::uint32_t psize) noexcept {
  if (r.type() != t) return std::unexpected(DecodeError::WrongType);
  if (r.len() != record_bytes_for_payload(psize)) return std::unexpected(DecodeError::BadSize);
  return {};
}

// Variable payloads: a fixed head followed by `var` bytes; the record length must be
// exactly the aligned size (canonical form: no trailing garbage beyond padding).
std::expected<void, DecodeError> check_var(const RecordView& r, RecordType t, std::uint32_t head) noexcept {
  if (r.type() != t) return std::unexpected(DecodeError::WrongType);
  if (r.len() < record_bytes_for_payload(head)) return std::unexpected(DecodeError::BadSize);
  return {};
}

// Canonical form: payload bytes [from, to) and the record padding after `psize` are zero.
bool zero_bytes(const RecordView& r, std::size_t from, std::size_t to) noexcept {
  for (std::size_t i = from; i < to; ++i) {
    if (r.data()[kHeaderBytes + i] != std::byte{0}) return false;
  }
  return true;
}
bool canonical(const RecordView& r, std::uint32_t psize, std::size_t res_off = 0, std::size_t res_len = 0) noexcept {
  return zero_bytes(r, psize, r.len() - kHeaderBytes) && zero_bytes(r, res_off, res_off + res_len);
}

void copy_name(std::byte* p, const SessionName& n) noexcept { std::memcpy(p, n.data(), n.size()); }
SessionName load_name(const std::byte* p) noexcept {
  SessionName n{};
  std::memcpy(n.data(), p, n.size());
  return n;
}

}  // namespace

std::string_view to_string(RecordType t) noexcept {
  switch (t) {
    case RecordType::DayStart: return "DayStart";
    case RecordType::Config: return "Config";
    case RecordType::SessionEvent: return "SessionEvent";
    case RecordType::OuchInbound: return "OuchInbound";
    case RecordType::Timer: return "Timer";
    case RecordType::Admin: return "Admin";
    case RecordType::SnapshotMark: return "SnapshotMark";
    case RecordType::EpochStart: return "EpochStart";
    case RecordType::DayEnd: return "DayEnd";
    case RecordType::Pad: return "Pad";
  }
  return "Unknown";
}

std::string_view to_string(ParseError e) noexcept {
  switch (e) {
    case ParseError::Truncated: return "truncated";
    case ParseError::BadLength: return "bad length";
    case ParseError::BadType: return "bad type";
  }
  return "unknown";
}

std::string_view to_string(DecodeError e) noexcept {
  switch (e) {
    case DecodeError::WrongType: return "wrong type";
    case DecodeError::BadSize: return "bad size";
    case DecodeError::BadField: return "bad field";
    case DecodeError::NonCanonical: return "non-canonical (reserved or padding bytes set)";
  }
  return "unknown";
}

std::uint32_t content_crc(const std::byte* rec, std::uint32_t len) noexcept {
  static constexpr std::byte kZero4[4] = {};
  std::uint32_t c = crc32c_extend(0, rec, hdr::kCrc);
  c = crc32c_extend(c, kZero4, sizeof(kZero4));
  return crc32c_extend(c, rec + hdr::kCrc + 4, len - (hdr::kCrc + 4));
}

std::uint32_t nonce_seed(std::uint64_t nonce) noexcept {
  std::byte b[8];
  store_le64(b, nonce);
  return crc32c_extend(0, b, sizeof(b));
}

Sealer::Sealer() noexcept { masks_.fill(0); }

Sealer::Sealer(std::uint64_t nonce) noexcept : nonce_(nonce), seed_(nonce == 0 ? 0 : nonce_seed(nonce)) {
  // M(0) = seed; M(8k+8) = A^8(M(8k)).
  std::uint32_t m = seed_;
  for (std::size_t i = 0; i < masks_.size(); ++i) {
    masks_[i] = m;
    m = advance8(m);
  }
}

std::uint32_t Sealer::seal(std::byte* rec) const noexcept {
  const std::uint32_t len = load_le32(rec + hdr::kLen);
  const std::uint32_t c = content_crc(rec, len);
  store_le32(rec + hdr::kCrc, c ^ mask(len));
  return c;
}

std::uint32_t Sealer::reseal(std::byte* rec, const Sealer& from) const noexcept {
  const std::uint32_t len = load_le32(rec + hdr::kLen);
  const std::uint32_t c = load_le32(rec + hdr::kCrc) ^ from.mask(len);
  store_le32(rec + hdr::kCrc, c ^ mask(len));
  return c;
}

std::uint32_t Sealer::content_of(const std::byte* rec) const noexcept {
  return load_le32(rec + hdr::kCrc) ^ mask(load_le32(rec + hdr::kLen));
}

std::optional<std::uint32_t> Sealer::verify(const std::byte* rec) const noexcept {
  const std::uint32_t len = load_le32(rec + hdr::kLen);
  const std::uint32_t c = content_crc(rec, len);
  if ((c ^ mask(len)) != load_le32(rec + hdr::kCrc)) return std::nullopt;
  return c;
}

std::expected<RecordView, ParseError> parse_record(std::span<const std::byte> buf) noexcept {
  if (buf.size() < kHeaderBytes) return std::unexpected(ParseError::Truncated);
  const std::uint32_t len = load_le32(buf.data() + hdr::kLen);
  if (len < kHeaderBytes || len % kRecordAlign != 0 || len > kMaxRecordBytes) {
    return std::unexpected(ParseError::BadLength);
  }
  if (len > buf.size()) return std::unexpected(ParseError::Truncated);
  if (!valid_record_type(load_le16(buf.data() + hdr::kType))) return std::unexpected(ParseError::BadType);
  return RecordView(buf.first(len));
}

// ---- encoders ---------------------------------------------------------------------

void encode_payload(std::byte* p, const DayStart& v) noexcept {
  store_le32(p + 0, v.format_version);
  store_le32(p + 4, v.trading_date);
  store_le64(p + 8, static_cast<std::uint64_t>(v.local_midnight_ns));
  store_le64(p + 16, v.build_id);
  copy_name(p + 24, v.mold_session);
  copy_name(p + 34, v.soup_session);
  store_le32(p + 44, 0);
}

void encode_payload(std::byte* p, const ConfigChunk& v) noexcept {
  store_le16(p + 0, static_cast<std::uint16_t>(v.table));
  store_le16(p + 2, v.chunk_index);
  store_le16(p + 4, v.chunk_count);
  store_le16(p + 6, 0);
  store_le32(p + 8, v.table_bytes);
  store_le32(p + 12, static_cast<std::uint32_t>(v.bytes.size()));
  if (!v.bytes.empty()) std::memcpy(p + ConfigChunk::kHeadBytes, v.bytes.data(), v.bytes.size());
}

void encode_payload(std::byte* p, const SessionEvent& v) noexcept {
  store_le32(p + 0, v.session_id);
  store_le16(p + 4, v.instance);
  p[6] = static_cast<std::byte>(v.event);
  p[7] = std::byte{0};
  store_le64(p + 8, v.requested_seq);
}

void encode_payload(std::byte* p, const OuchInbound& v) noexcept {
  store_le32(p + 0, v.session_id);
  store_le32(p + 4, v.account);
  store_le16(p + 8, v.instance);
  store_le16(p + 10, static_cast<std::uint16_t>(v.msg.size()));
  store_le32(p + 12, 0);
  if (!v.msg.empty()) std::memcpy(p + OuchInbound::kHeadBytes, v.msg.data(), v.msg.size());
}

void encode_payload(std::byte* p, const Timer& v) noexcept {
  store_le32(p + 0, v.timer_id);
  store_le16(p + 4, static_cast<std::uint16_t>(v.kind));
  store_le16(p + 6, 0);
  store_le64(p + 8, static_cast<std::uint64_t>(v.scheduled_ns));
}

void encode_payload(std::byte* p, const Admin& v) noexcept {
  store_le16(p + 0, v.command);
  store_le16(p + 2, v.tlv_version);
  store_le32(p + 4, v.operator_id);
  store_le32(p + 8, static_cast<std::uint32_t>(v.args.size()));
  store_le32(p + 12, 0);
  if (!v.args.empty()) std::memcpy(p + Admin::kHeadBytes, v.args.data(), v.args.size());
}

void encode_payload(std::byte* p, const SnapshotMark& v) noexcept { store_le64(p, v.snapshot_id); }

void encode_payload(std::byte* p, const EpochStart& v) noexcept {
  store_le32(p + 0, v.epoch);
  store_le32(p + 4, v.primary_node);
  store_le64(p + 8, v.config_digest);
}

void encode_payload(std::byte* p, const DayEnd& v) noexcept {
  store_le64(p + 0, v.final_index);
  store_le64(p + 8, v.itch_messages);
  store_le64(p + 16, v.soup_messages);
}

// ---- decoders ---------------------------------------------------------------------

std::expected<DayStart, DecodeError> decode_day_start(const RecordView& r) noexcept {
  if (auto ok = check_fixed(r, RecordType::DayStart, payload_size(DayStart{})); !ok) return std::unexpected(ok.error());
  if (!canonical(r, 48, 44, 4)) return std::unexpected(DecodeError::NonCanonical);
  DayStart v;
  v.format_version = u32_at(r, 0);
  v.trading_date = u32_at(r, 4);
  v.local_midnight_ns = static_cast<Nanos>(u64_at(r, 8));
  v.build_id = u64_at(r, 16);
  v.mold_session = load_name(r.data() + kHeaderBytes + 24);
  v.soup_session = load_name(r.data() + kHeaderBytes + 34);
  return v;
}

std::expected<ConfigChunk, DecodeError> decode_config(const RecordView& r) noexcept {
  if (auto ok = check_var(r, RecordType::Config, ConfigChunk::kHeadBytes); !ok) return std::unexpected(ok.error());
  ConfigChunk v;
  const std::uint16_t table = u16_at(r, 0);
  v.chunk_index = u16_at(r, 2);
  v.chunk_count = u16_at(r, 4);
  v.table_bytes = u32_at(r, 8);
  const std::uint32_t n = u32_at(r, 12);
  if (n > ConfigChunk::kMaxChunkBytes || r.len() != record_bytes_for_payload(ConfigChunk::kHeadBytes + n)) {
    return std::unexpected(DecodeError::BadSize);
  }
  if (table < 1 || table > kMaxConfigTable || v.chunk_count == 0 || v.chunk_index >= v.chunk_count ||
      n > v.table_bytes) {
    return std::unexpected(DecodeError::BadField);
  }
  if (!canonical(r, ConfigChunk::kHeadBytes + n, 6, 2)) return std::unexpected(DecodeError::NonCanonical);
  v.table = static_cast<ConfigTable>(table);
  v.bytes = r.payload().subspan(ConfigChunk::kHeadBytes, n);
  return v;
}

std::expected<SessionEvent, DecodeError> decode_session_event(const RecordView& r) noexcept {
  if (auto ok = check_fixed(r, RecordType::SessionEvent, payload_size(SessionEvent{})); !ok) {
    return std::unexpected(ok.error());
  }
  const auto ev = static_cast<std::uint8_t>(r.payload()[6]);
  if (ev < 1 || ev > kMaxSessionEventKind) return std::unexpected(DecodeError::BadField);
  if (!canonical(r, 16, 7, 1)) return std::unexpected(DecodeError::NonCanonical);
  SessionEvent v;
  v.session_id = u32_at(r, 0);
  v.instance = u16_at(r, 4);
  v.event = static_cast<SessionEventKind>(ev);
  v.requested_seq = u64_at(r, 8);
  return v;
}

std::expected<OuchInbound, DecodeError> decode_ouch_inbound(const RecordView& r) noexcept {
  if (auto ok = check_var(r, RecordType::OuchInbound, OuchInbound::kHeadBytes); !ok) return std::unexpected(ok.error());
  const std::uint32_t n = u16_at(r, 10);
  if (r.len() != record_bytes_for_payload(OuchInbound::kHeadBytes + n)) return std::unexpected(DecodeError::BadSize);
  if (!canonical(r, OuchInbound::kHeadBytes + n, 12, 4)) return std::unexpected(DecodeError::NonCanonical);
  OuchInbound v;
  v.session_id = u32_at(r, 0);
  v.account = u32_at(r, 4);
  v.instance = u16_at(r, 8);
  v.msg = r.payload().subspan(OuchInbound::kHeadBytes, n);
  return v;
}

std::expected<Timer, DecodeError> decode_timer(const RecordView& r) noexcept {
  if (auto ok = check_fixed(r, RecordType::Timer, payload_size(Timer{})); !ok) return std::unexpected(ok.error());
  const std::uint16_t kind = u16_at(r, 4);
  if (kind < 1 || kind > kMaxTimerKind) return std::unexpected(DecodeError::BadField);
  if (!canonical(r, 16, 6, 2)) return std::unexpected(DecodeError::NonCanonical);
  Timer v;
  v.timer_id = u32_at(r, 0);
  v.kind = static_cast<TimerKind>(kind);
  v.scheduled_ns = static_cast<Nanos>(u64_at(r, 8));
  return v;
}

std::expected<Admin, DecodeError> decode_admin(const RecordView& r) noexcept {
  if (auto ok = check_var(r, RecordType::Admin, Admin::kHeadBytes); !ok) return std::unexpected(ok.error());
  const std::uint32_t n = u32_at(r, 8);
  if (n > kMaxPayloadBytes - Admin::kHeadBytes || r.len() != record_bytes_for_payload(Admin::kHeadBytes + n)) {
    return std::unexpected(DecodeError::BadSize);
  }
  if (!canonical(r, Admin::kHeadBytes + n, 12, 4)) return std::unexpected(DecodeError::NonCanonical);
  Admin v;
  v.command = u16_at(r, 0);
  v.tlv_version = u16_at(r, 2);
  v.operator_id = u32_at(r, 4);
  v.args = r.payload().subspan(Admin::kHeadBytes, n);
  return v;
}

std::expected<SnapshotMark, DecodeError> decode_snapshot_mark(const RecordView& r) noexcept {
  if (auto ok = check_fixed(r, RecordType::SnapshotMark, payload_size(SnapshotMark{})); !ok) {
    return std::unexpected(ok.error());
  }
  return SnapshotMark{u64_at(r, 0)};
}

std::expected<EpochStart, DecodeError> decode_epoch_start(const RecordView& r) noexcept {
  if (auto ok = check_fixed(r, RecordType::EpochStart, payload_size(EpochStart{})); !ok) return std::unexpected(ok.error());
  return EpochStart{u32_at(r, 0), u32_at(r, 4), u64_at(r, 8)};
}

std::expected<DayEnd, DecodeError> decode_day_end(const RecordView& r) noexcept {
  if (auto ok = check_fixed(r, RecordType::DayEnd, payload_size(DayEnd{})); !ok) return std::unexpected(ok.error());
  return DayEnd{u64_at(r, 0), u64_at(r, 8), u64_at(r, 16)};
}

void build_pad(std::byte* out, std::uint32_t len, const ChainState& c, const Sealer& sealer) noexcept {
  RecordHeader h;
  h.len = len;
  h.index = c.last_index;
  h.ts_ns = c.last_ts;
  h.epoch = c.epoch;
  h.type = static_cast<std::uint16_t>(RecordType::Pad);
  h.prev_crc = c.last_crc;
  encode_header(out, h);
  std::memset(out + kHeaderBytes, 0, len - kHeaderBytes);
  (void)sealer.seal(out);
}

bool same_content(const RecordView& a, const RecordView& b) noexcept {
  if (a.len() != b.len()) return false;
  // Everything but the 4-byte seal at [4, 8).
  return std::memcmp(a.data(), b.data(), hdr::kCrc) == 0 &&
         std::memcmp(a.data() + hdr::kCrc + 4, b.data() + hdr::kCrc + 4, a.len() - (hdr::kCrc + 4)) == 0;
}

}  // namespace lle::journal
