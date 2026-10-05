#include "journal/describe.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>

namespace lle::journal {

namespace {

std::string fmt(const char* f, auto... args) {
  char buf[256];
  std::snprintf(buf, sizeof(buf), f, args...);
  return buf;
}

std::string name(const SessionName& n) {
  std::string s(n.data(), n.size());
  while (!s.empty() && (s.back() == ' ' || s.back() == '\0')) s.pop_back();
  return s;
}

std::string hex_prefix(std::span<const std::byte> b, std::size_t max = 24) {
  std::string s;
  for (std::size_t i = 0; i < b.size() && i < max; ++i) s += fmt("%02x", static_cast<unsigned>(b[i]));
  if (b.size() > max) s += "..";
  return s;
}

template <class T>
std::string or_error(const std::expected<T, DecodeError>& d, auto render) {
  if (!d) return "<" + std::string(to_string(d.error())) + ">";
  return render(*d);
}

std::string payload_text(const RecordView& r) {
  switch (r.type()) {
    case RecordType::DayStart:
      return or_error(decode_day_start(r), [](const DayStart& v) {
        return fmt("date=%u version=%u midnight=%" PRId64 " build=%" PRIx64 " mold=%s soup=%s", v.trading_date,
                   v.format_version, v.local_midnight_ns, v.build_id, name(v.mold_session).c_str(),
                   name(v.soup_session).c_str());
      });
    case RecordType::Config:
      return or_error(decode_config(r), [](const ConfigChunk& v) {
        return fmt("table=%u chunk=%u/%u table_bytes=%u bytes=%zu", static_cast<unsigned>(v.table), v.chunk_index + 1u,
                   static_cast<unsigned>(v.chunk_count), v.table_bytes, v.bytes.size());
      });
    case RecordType::SessionEvent:
      return or_error(decode_session_event(r), [](const SessionEvent& v) {
        static constexpr const char* kNames[] = {"?", "login", "logout", "disconnect", "mirror-attach", "instance-down"};
        return fmt("session=%u instance=%u event=%s requested_seq=%" PRIu64, v.session_id, v.instance,
                   kNames[static_cast<unsigned>(v.event)], v.requested_seq);
      });
    case RecordType::OuchInbound:
      return or_error(decode_ouch_inbound(r), [](const OuchInbound& v) {
        const char t = v.msg.empty() ? '-' : static_cast<char>(v.msg[0]);
        return fmt("session=%u account=%u instance=%u len=%zu type=%c bytes=%s", v.session_id, v.account, v.instance,
                   v.msg.size(), (t >= 0x20 && t < 0x7f) ? t : '?', hex_prefix(v.msg).c_str());
      });
    case RecordType::Timer:
      return or_error(decode_timer(r), [](const Timer& v) {
        return fmt("timer=%u kind=%u scheduled=%" PRId64, v.timer_id, static_cast<unsigned>(v.kind), v.scheduled_ns);
      });
    case RecordType::Admin:
      return or_error(decode_admin(r), [](const Admin& v) {
        return fmt("command=0x%04x tlv_version=%u operator=%u args=%s", v.command, v.tlv_version, v.operator_id,
                   hex_prefix(v.args).c_str());
      });
    case RecordType::SnapshotMark:
      return or_error(decode_snapshot_mark(r),
                      [](const SnapshotMark& v) { return fmt("snapshot_id=%" PRIu64, v.snapshot_id); });
    case RecordType::EpochStart:
      return or_error(decode_epoch_start(r), [](const EpochStart& v) {
        return fmt("epoch=%u primary=%u config_digest=%016" PRIx64, v.epoch, v.primary_node, v.config_digest);
      });
    case RecordType::DayEnd:
      return or_error(decode_day_end(r), [](const DayEnd& v) {
        return fmt("final_index=%" PRIu64 " itch=%" PRIu64 " soup=%" PRIu64, v.final_index, v.itch_messages,
                   v.soup_messages);
      });
    case RecordType::Pad:
      return fmt("pad=%u", r.len());
  }
  return "<unknown type>";
}

}  // namespace

std::string describe(const RecordView& r, std::uint32_t content_crc) {
  return fmt("%10" PRIu64 " ts=%" PRId64 " epoch=%u %-12s flags=%04x len=%u crc=%08x prev=%08x  ", r.index(), r.ts_ns(),
             r.epoch(), std::string(to_string(r.type())).c_str(), r.flags(), r.len(), content_crc, r.prev_crc()) +
         payload_text(r);
}

std::string_view first_difference(const RecordView& a, const RecordView& b) noexcept {
  if (a.len() != b.len()) return "len";
  if (a.index() != b.index()) return "index";
  if (a.ts_ns() != b.ts_ns()) return "ts_ns";
  if (a.epoch() != b.epoch()) return "epoch";
  if (a.type_raw() != b.type_raw()) return "type";
  if (a.flags() != b.flags()) return "flags";
  if (a.prev_crc() != b.prev_crc()) return "prev_crc";
  if (a.reserved() != b.reserved()) return "reserved";
  if (std::memcmp(a.payload().data(), b.payload().data(), a.payload().size()) != 0) return "payload";
  return "";
}

std::string_view schema_text() noexcept {
  return R"(LLE journal format version 1 (06-sequencer-journal-recovery §3, 01-architecture §6)

Record header (40 bytes, little-endian, records 8-byte aligned, len multiple of 8):
  off size field
    0   4  len        total bytes incl. header, payload and zero padding (40..32768)
    4   4  crc32c     seal: CRC32C(le64(nonce) || record with this field zeroed)
    8   8  index      dense, starts at 1 each trading day
   16   8  ts_ns      exchange time, ns since the UNIX epoch, strictly increasing
   24   4  epoch      replication epoch, monotonic
   28   2  type       RecordType
   30   2  flags      bit 0: malformed inbound (OuchInbound)
   32   4  prev_crc   content crc (seed 0, crc field zeroed) of the previous non-Pad record
   36   4  reserved   0

Record types and payloads (offsets from the payload start; canonical: reserved = 0, padding = 0):
   1 DayStart      0 u32 format_version  4 u32 trading_date  8 i64 local_midnight_ns  16 u64 build_id
                   24 char[10] mold_session  34 char[10] soup_session  44 u32 reserved            (48)
   2 Config        0 u16 table  2 u16 chunk_index  4 u16 chunk_count  6 u16 reserved
                   8 u32 table_bytes  12 u32 chunk_bytes  16 bytes[chunk_bytes]
                   tables: 1 symbols 2 firms 3 accounts 4 sessions 5 risk limits 6 schedule
   3 SessionEvent  0 u32 session_id  4 u16 instance  6 u8 event  7 u8 reserved  8 u64 requested_seq  (16)
                   events: 1 login 2 logout 3 disconnect 4 mirror-attach 5 instance-down
   4 OuchInbound   0 u32 session_id  4 u32 account  8 u16 instance  10 u16 msg_len  12 u32 reserved
                   16 bytes[msg_len]  (raw OUCH wire bytes)
   5 Timer         0 u32 timer_id  4 u16 kind  6 u16 reserved  8 i64 scheduled_ns                    (16)
                   kinds: 1 system event 2 EOII 3 NOII 4 cross 5 state change 6 expiry sweep 7 day end
   6 Admin         0 u16 command  2 u16 tlv_version  4 u32 operator_id  8 u32 args_len  12 u32 reserved
                   16 bytes[args_len]  (versioned TLV)
   7 SnapshotMark  0 u64 snapshot_id                                                                 (8)
   8 EpochStart    0 u32 epoch  4 u32 primary_node  8 u64 config_digest                              (16)
   9 DayEnd        0 u64 final_index  8 u64 itch_messages  16 u64 soup_messages                      (24)
  10 Pad           zeros; repeats index and prev_crc of the last record; not chained

Segment file journal/<day>/<epoch:04>-<first_index:020>.seg (records from offset 4096; writes are
whole 4 KiB blocks, each batch closed by a Pad):
    0 char[8] "LLEJRNL1"   8 u32 version (1)   12 u32 header_bytes (4096)   16 u32 day
   20 u32 epoch   24 u64 first_index (0: prepared)   32 u64 nonce   40 u32 prev_last_crc
   44 u32 reserved   48 u64 segment_bytes   4092 u32 crc32c(bytes [0, 4092))

Validity (recovery, 06 §7): len in bounds; seal verifies with the segment nonce; index = previous + 1;
prev_crc = previous content crc; epoch monotonic. A sealed record more than QD x 64 KiB beyond the
first invalid position is corruption; otherwise the tail is torn and is truncated.
)";
}

}  // namespace lle::journal
