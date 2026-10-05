#pragma once
// Engine input records and their payloads (01-architecture §6, 06-sequencer §3,
// ADR-028).
//
// The engine consumes `InputRecord`s: one journaled record's header fields and
// payload. `engine/journal_adapter.h` builds one from a `journal::RecordView`
// field by field. Payloads use the journal's layouts exactly (little-endian),
// so the sequencer's records are the engine's input with no translation; this
// header re-states those layouts so the engine core does not link the journal
// (a test checks the two encoders produce identical bytes).
//
// The engine owns what the journal treats as opaque:
//   - the configuration tables carried in Config chunks (symbols, accounts and
//     firms, sessions, risk limits, schedule), each versioned;
//   - the Schedule table, which gives every Timer record its meaning (the
//     Timer payload carries only id, kind and time);
//   - the Admin command arguments (versioned TLV).
// Builders append to byte vectors (cold path: tests, generators, the
// sequencer's day plan, lle-admin). Parsers are allocation-free.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "common/alpha.h"
#include "common/endian.h"
#include "common/time.h"
#include "common/types.h"

namespace lle::engine {

// Values match journal::RecordType (01 §6).
enum class RecordType : std::uint16_t {
  DayStart = 1,
  Config,
  SessionEvent,
  OuchInbound,
  Timer,
  Admin,
  SnapshotMark,
  EpochStart,
  DayEnd,
  Pad,
};

// journal::kFlagMalformedInput: the gateway truncated an over-long packet.
inline constexpr std::uint16_t kFlagMalformedInput = 1;

struct InputRecord {
  std::uint64_t index = 0;  // journal index: dense, total order, time priority
  std::int64_t ts_ns = 0;   // exchange time (UNIX ns) assigned by the sequencer
  std::uint16_t type = 0;   // RecordType
  std::uint16_t flags = 0;  // journal record flags
  std::span<const std::byte> payload;  // may include the record's zero padding
  std::uint32_t epoch = 0;
};

// ============================================================================ journal payloads

// DayStart (48): u32 format_version | u32 YYYYMMDD | i64 local midnight (UNIX ns) | u64 build id
// | char[10] mold session | char[10] soup session | u32 0. Wire timestamps are ts_ns - midnight.
struct DayStart {
  static constexpr std::size_t kLen = 48;
  static constexpr std::uint32_t kFormatVersion = 1;
  std::uint32_t date = 0;
  Nanos local_midnight_ns = 0;
  std::uint64_t build_id = 0;
  Alpha<10> mold_session{};
  Alpha<10> soup_session{};
};

// Config chunk (16 + n): u16 table | u16 chunk index | u16 chunk count | u16 0 | u32 table
// bytes | u32 chunk bytes | bytes. Tables longer than one record are split into chunks
// (journal::ConfigChunk::kMaxChunkBytes); the engine reassembles them in order.
enum class ConfigTable : std::uint16_t { Symbols = 1, Firms, Accounts, Sessions, RiskLimits, Schedule };
inline constexpr std::size_t kConfigChunkHead = 16;
inline constexpr std::size_t kMaxConfigChunkBytes = 32 * 1024 - 40 - kConfigChunkHead;

// SessionEvent (16): u32 session | u16 instance | u8 event | u8 0 | u64 requested sequence.
enum class SessionEventKind : std::uint8_t { Login = 1, Logout = 2, Disconnect = 3, MirrorAttach = 4, InstanceDown = 5 };
struct SessionEvent {
  static constexpr std::size_t kLen = 16;
  std::uint32_t session_id = 0;
  std::uint16_t instance = 0;
  SessionEventKind event = SessionEventKind::Login;
  std::uint64_t requested_seq = 0;
};

// OuchInbound (16 + n): u32 session | u32 account | u16 instance | u16 len | u32 0 | raw OUCH bytes.
struct OuchInboundHeader {
  static constexpr std::size_t kLen = 16;
  std::uint32_t session_id = 0;
  std::uint32_t account = 0;
  std::uint16_t instance = 0;
};

// Timer (16): u32 timer id | u16 kind | u16 0 | i64 scheduled (UNIX ns). Kinds match
// journal::TimerKind; the meaning of each id (event code, cross type, milestone) is
// its Schedule table entry.
enum class TimerKind : std::uint16_t { SystemEvent = 1, Eoii, Noii, Cross, StateChange, ExpirySweep, DayEnd };
struct TimerRecord {
  static constexpr std::size_t kLen = 16;
  std::uint32_t timer_id = 0;
  TimerKind kind = TimerKind::SystemEvent;
  Nanos scheduled_ns = 0;
};

// Admin (16 + n): u16 command | u16 TLV version | u32 operator | u32 args length | u32 0 | args.
struct AdminHeader {
  static constexpr std::size_t kLen = 16;
  std::uint16_t command = 0;
  std::uint16_t tlv_version = 1;
  std::uint32_t operator_id = 0;
};

// ============================================================================ engine tables
// Every table body: u16 version | u16 0 | u32 count | count fixed-size entries.
inline constexpr std::size_t kTableHead = 8;

// Symbols v1 (32): char symbol[8] | u32 round lot | u32 tick | i64 prior close (NOCP, PxE4)
// | u8 market category | u8 LULD tier | u8 flags | u8 Reg SHO state | u32 ADV (shares).
// Locate = 1 + position. `tick` is the grid for prices >= $1 and must divide $1.00; below
// $1 the grid is $0.0001 (Rule 612). Reg SHO state: '0' no test, '2' restriction carried
// from the prior day, ' ' unknown (short sales then get 0x0032).
struct SymbolEntry {
  static constexpr std::uint16_t kVersion = 1;
  static constexpr std::size_t kLen = 32;
  static constexpr std::uint8_t kFlagTest = 1;
  static constexpr std::uint8_t kFlagEtp = 2;
  Symbol8 symbol{};
  std::uint32_t round_lot = 100;
  std::uint32_t tick = 100;
  PxE4 prior_close = 0;
  char market_category = 'Q';
  char luld_tier = '1';
  std::uint8_t flags = 0;
  char regsho = '0';
  std::uint32_t adv = 0;
};

// Accounts v1 (20): u32 account | char firm[4][4]. Blank firms are unused; the first is the
// default (orders without Firm tag 2).
struct AccountEntry {
  static constexpr std::uint16_t kVersion = 1;
  static constexpr std::size_t kLen = 20;
  static constexpr std::size_t kMaxFirms = 4;
  std::uint32_t account_id = 0;
  std::array<Mpid4, kMaxFirms> firms{};
};

// Sessions v1 (16): u32 session | u32 account | u8 flags | u8 default AIQ | u8 late cross
// policy | u8 0 | u32 0.
enum class LateCrossPolicy : std::uint8_t { Accept = 0, Reprice = 1, Reject = 2 };
struct SessionEntry {
  static constexpr std::uint16_t kVersion = 1;
  static constexpr std::size_t kLen = 16;
  static constexpr std::uint8_t kCancelOnDisconnect = 1;  // 05 §4 step 8
  static constexpr std::uint8_t kKeepCrossOrders = 2;     // spare cross orders on disconnect
  static constexpr std::uint8_t kMarketOrders = 4;        // market orders allowed (else 0x002C)
  static constexpr std::uint8_t kPostOnlyCancel = 8;      // post-only cancels instead of sliding
  std::uint32_t session_id = 0;
  std::uint32_t account_id = 0;
  std::uint8_t flags = kCancelOnDisconnect | kMarketOrders;
  char default_aiq = 'N';
  LateCrossPolicy late_cross = LateCrossPolicy::Reprice;
};

// RiskLimits v1 (24): u32 account | u16 kind | u16 0 | i64 value | char symbol[8] (blank
// unless the kind is per symbol). Admin RiskLimit changes use the same fields.
enum class RiskKind : std::uint16_t {
  Permissions = 1,      // bit set of RiskPerm (0 = everything allowed)
  MaxOrderQty = 2,      // 0x0031
  MaxOrderNotional = 3, // 0x0030, notional in PxE4 x shares
  FatFingerBps = 4,     // 0x0026, limit beyond the BBO by more than bps of it
  FatFingerAbs = 5,     // 0x0026, ... or by more than this PxE4 amount
  Lop = 6,              // 0x0006, Limit Order Protection on (1) / off (0)
  DupWindowSec = 7,     // 0x002A, duplicate window in seconds (0..30)
  PortRate = 8,         // 0x0029, messages per second per session
  SymbolRate = 9,       // 0x0028, orders per second per (session, symbol)
  GrossExposure = 10,   // 0x0020, open + executed notional
  SymbolNotional = 11,  // 0x001F, open notional in one symbol
  AdvPct = 12,          // 0x0025, order quantity above this % of the symbol's ADV
  Restricted = 13,      // 0x0022, symbol on the restricted list
  HardToBorrow = 14,    // 0x0027, short sale needs SharesLocated = Y
  KillExposure = 15,    // executed notional that latches the kill switch
};
enum RiskPerm : std::uint32_t {
  kNoPreMarket = 1,      // 0x002D
  kNoPostMarket = 2,     // 0x002E
  kNoShortSell = 4,      // 0x002B
  kNoShortExempt = 8,    // 0x002F
  kNoMarketOrders = 16,  // 0x002C
  kNoIpoMarketBuy = 32,  // 0x0033
  kNoThroughBand = 64,   // 0x0021: limit priced through the far LULD band (market impact)
};
struct RiskEntry {
  static constexpr std::uint16_t kVersion = 1;
  static constexpr std::size_t kLen = 24;
  std::uint32_t account_id = 0;
  RiskKind kind = RiskKind::Permissions;
  std::int64_t value = 0;
  Symbol8 symbol{};
};

// Schedule v1 (16): u32 timer id | u16 kind | u16 arg | i64 time (ns since local midnight).
// Timer entries (id >= 1) give each Timer record its meaning:
//   SystemEvent arg = ITCH system event code (O S Q M E C)
//   Eoii / Noii arg = cross type 'O' or 'C'; Noii 'H' is the 1 Hz clock that drives halt,
//                     LULD, IPO and MWCB periods, GTT expiry and midpoint-peg pulls
//   Cross       arg = 'O' (opening cross, then Regular session) or 'C' (closing cross)
//   StateChange arg = Milestone
//   ExpirySweep arg = 'D' (Day orders after the close) or 'X' (extended-hours orders)
// Parameter entries (id 0, kind 0): arg = Param, time field = value.
enum class Milestone : std::uint16_t {
  PreMarket = 'P',   // 04:00: system hours open
  OpenFreeze = 'F',  // 09:25: on-open orders can no longer be cancelled or modified
  MooCutoff = 'M',   // 09:28: MOO entry closes; late LOO period starts
  LooCutoff = 'L',   // 09:29:30: LOO entry closes
  CloseFreeze = 'f', // 15:50: on-close changes only to correct errors (Admin permit)
  MocCutoff = 'm',   // 15:55: MOC entry closes; late LOC period starts
  LocCutoff = 'l',   // 15:58: LOC entry closes; no cancel or modify for any reason
  SystemClose = 'X', // 20:00: system hours end
};
enum class Param : std::uint16_t {
  InitialSession = 1,  // value = Session char: 'C' closed, 'P' pre-market, 'R' regular, 'A' post-market
  ThresholdBps = 2,    // open/close threshold: max(bps of the QBBO midpoint, ThresholdMin)
  ThresholdMin = 3,
  PriceTestBps = 4,    // opening cross price tests A-C: max(bps, PriceTestMin) of the reference
  PriceTestMin = 5,
  PriceTests = 6,      // bit mask: 1 A (prior close), 2 B (last sale), 4 C (bid/offer); 0 = off
  HaltPeriodSec = 7,   // display-only period of a news halt (300)
  LuldPauseSec = 8,    // LULD pause (300)
  MwcbPeriodSec = 9,   // MWCB level 1/2 reopening (900)
  LimitStateSec = 10,  // LULD limit state before a pause (15)
  ExtensionSec = 11,   // halt cross extension period (300)
};
struct ScheduleEntry {
  static constexpr std::uint16_t kVersion = 1;
  static constexpr std::size_t kLen = 16;
  std::uint32_t timer_id = 0;
  TimerKind kind = TimerKind::SystemEvent;  // ignored (0) for parameter entries
  std::uint16_t arg = 0;
  Nanos time_ns = 0;  // since local midnight; the value for parameter entries
};

// ============================================================================ admin commands
// Arguments are TLV elements: u16 tag | u16 length | value (little-endian integers).
enum class AdminCommand : std::uint16_t {
  Halt = 1,               // symbol, reason: ITCH H state H
  QuoteOnly = 2,          // symbol, reason, [price]: display-only resumption period (news halt)
  Resume = 3,             // symbol: operator release (halt cross without collars)
  IpoSchedule = 4,        // symbol, time (release, s since midnight), price, qualifier: ITCH K
  IpoQuote = 5,           // symbol: IPO quoting period starts (H Q IPOQ)
  IpoRelease = 6,         // symbol, band: underwriter "go"; pre-launch until the cross qualifies
  LuldBands = 7,          // symbol, lower, upper (band feed)
  MwcbLevels = 8,         // level1..3 (PxE8): ITCH V
  MwcbBreach = 9,         // level: ITCH W; levels 1-2 halt and reopen, level 3 halts for the day
  KillSwitch = 10,        // account: mass cancel and entry disabled until reset
  KillReset = 11,         // account
  RiskLimit = 12,         // account, kind, value, [symbol]
  CrossCancelPermit = 13, // account: on-close orders may be changed until 15:58 (error correction)
  RegSho = 14,            // symbol, action ('0', '1', '2'): ITCH Y
};
enum class AdminTag : std::uint16_t {
  Symbol = 1,     // 8 bytes
  Reason = 2,     // 4 bytes
  Price = 3,      // i64 PxE4
  Lower = 4,      // i64 PxE4
  Upper = 5,      // i64 PxE4
  Time = 6,       // u32 seconds since midnight
  Account = 7,    // u32
  Kind = 8,       // u16
  Value = 9,      // i64
  Level = 10,     // u8
  Qualifier = 11, // u8
  Band = 12,      // i64 PxE4
  Level1 = 13,    // i64 PxE8
  Level2 = 14,
  Level3 = 15,
  Action = 16,    // u8
};

// Decoded arguments: one member per tag plus a presence mask.
struct AdminArgs {
  std::uint32_t present = 0;
  Symbol8 symbol{};
  Alpha<4> reason{};
  PxE4 price = 0, lower = 0, upper = 0, band = 0;
  std::uint32_t time = 0;
  std::uint32_t account = 0;
  std::uint16_t kind = 0;
  std::int64_t value = 0;
  std::uint8_t level = 0, qualifier = 0, action = 0;
  std::int64_t level1 = 0, level2 = 0, level3 = 0;
  [[nodiscard]] bool has(AdminTag t) const noexcept { return (present >> static_cast<unsigned>(t)) & 1u; }
};

// ============================================================================ builders

namespace detail {
inline void put_bytes(std::vector<std::byte>& out, const void* p, std::size_t n) {
  const auto* b = static_cast<const std::byte*>(p);
  out.insert(out.end(), b, b + n);
}
inline void put_u8(std::vector<std::byte>& out, std::uint8_t v) { out.push_back(static_cast<std::byte>(v)); }
inline void put_u16(std::vector<std::byte>& out, std::uint16_t v) {
  std::byte b[2];
  store_le16(b, v);
  put_bytes(out, b, 2);
}
inline void put_u32(std::vector<std::byte>& out, std::uint32_t v) {
  std::byte b[4];
  store_le32(b, v);
  put_bytes(out, b, 4);
}
inline void put_u64(std::vector<std::byte>& out, std::uint64_t v) {
  std::byte b[8];
  store_le64(b, v);
  put_bytes(out, b, 8);
}
}  // namespace detail

inline std::vector<std::byte> encode_day_start(const DayStart& d) {
  std::vector<std::byte> o;
  detail::put_u32(o, DayStart::kFormatVersion);
  detail::put_u32(o, d.date);
  detail::put_u64(o, static_cast<std::uint64_t>(d.local_midnight_ns));
  detail::put_u64(o, d.build_id);
  detail::put_bytes(o, d.mold_session.c.data(), 10);
  detail::put_bytes(o, d.soup_session.c.data(), 10);
  detail::put_u32(o, 0);
  return o;
}

// One Config chunk payload.
inline std::vector<std::byte> encode_config_chunk(ConfigTable table, std::uint16_t index, std::uint16_t count,
                                                  std::uint32_t table_bytes, std::span<const std::byte> chunk) {
  std::vector<std::byte> o;
  o.reserve(kConfigChunkHead + chunk.size());
  detail::put_u16(o, static_cast<std::uint16_t>(table));
  detail::put_u16(o, index);
  detail::put_u16(o, count);
  detail::put_u16(o, 0);
  detail::put_u32(o, table_bytes);
  detail::put_u32(o, static_cast<std::uint32_t>(chunk.size()));
  detail::put_bytes(o, chunk.data(), chunk.size());
  return o;
}

// A whole table as Config chunk payloads (one per record).
inline std::vector<std::vector<std::byte>> config_chunks(ConfigTable table, std::span<const std::byte> body) {
  std::vector<std::vector<std::byte>> out;
  const std::size_t n = body.empty() ? 1 : (body.size() + kMaxConfigChunkBytes - 1) / kMaxConfigChunkBytes;
  for (std::size_t k = 0; k < n; ++k) {
    const std::size_t off = k * kMaxConfigChunkBytes;
    const std::size_t len = std::min(kMaxConfigChunkBytes, body.size() - off);
    out.push_back(encode_config_chunk(table, static_cast<std::uint16_t>(k), static_cast<std::uint16_t>(n),
                                      static_cast<std::uint32_t>(body.size()), body.subspan(off, len)));
  }
  return out;
}

inline void put_table_head(std::vector<std::byte>& o, std::uint16_t version, std::size_t count) {
  detail::put_u16(o, version);
  detail::put_u16(o, 0);
  detail::put_u32(o, static_cast<std::uint32_t>(count));
}

inline std::vector<std::byte> encode_symbols(std::span<const SymbolEntry> syms) {
  std::vector<std::byte> o;
  put_table_head(o, SymbolEntry::kVersion, syms.size());
  for (const SymbolEntry& s : syms) {
    detail::put_bytes(o, s.symbol.c.data(), 8);
    detail::put_u32(o, s.round_lot);
    detail::put_u32(o, s.tick);
    detail::put_u64(o, static_cast<std::uint64_t>(s.prior_close));
    detail::put_u8(o, static_cast<std::uint8_t>(s.market_category));
    detail::put_u8(o, static_cast<std::uint8_t>(s.luld_tier));
    detail::put_u8(o, s.flags);
    detail::put_u8(o, static_cast<std::uint8_t>(s.regsho));
    detail::put_u32(o, s.adv);
  }
  return o;
}

inline std::vector<std::byte> encode_accounts(std::span<const AccountEntry> accts) {
  std::vector<std::byte> o;
  put_table_head(o, AccountEntry::kVersion, accts.size());
  for (const AccountEntry& a : accts) {
    detail::put_u32(o, a.account_id);
    for (const Mpid4& f : a.firms) detail::put_bytes(o, f.c.data(), 4);
  }
  return o;
}

inline std::vector<std::byte> encode_sessions(std::span<const SessionEntry> sess) {
  std::vector<std::byte> o;
  put_table_head(o, SessionEntry::kVersion, sess.size());
  for (const SessionEntry& s : sess) {
    detail::put_u32(o, s.session_id);
    detail::put_u32(o, s.account_id);
    detail::put_u8(o, s.flags);
    detail::put_u8(o, static_cast<std::uint8_t>(s.default_aiq));
    detail::put_u8(o, static_cast<std::uint8_t>(s.late_cross));
    detail::put_u8(o, 0);
    detail::put_u32(o, 0);
  }
  return o;
}

inline std::vector<std::byte> encode_risk(std::span<const RiskEntry> rs) {
  std::vector<std::byte> o;
  put_table_head(o, RiskEntry::kVersion, rs.size());
  for (const RiskEntry& r : rs) {
    detail::put_u32(o, r.account_id);
    detail::put_u16(o, static_cast<std::uint16_t>(r.kind));
    detail::put_u16(o, 0);
    detail::put_u64(o, static_cast<std::uint64_t>(r.value));
    detail::put_bytes(o, r.symbol.c.data(), 8);
  }
  return o;
}

inline std::vector<std::byte> encode_schedule(std::span<const ScheduleEntry> ev) {
  std::vector<std::byte> o;
  put_table_head(o, ScheduleEntry::kVersion, ev.size());
  for (const ScheduleEntry& e : ev) {
    detail::put_u32(o, e.timer_id);
    detail::put_u16(o, static_cast<std::uint16_t>(e.kind));
    detail::put_u16(o, e.arg);
    detail::put_u64(o, static_cast<std::uint64_t>(e.time_ns));
  }
  return o;
}

inline std::vector<std::byte> encode_session_event(const SessionEvent& e) {
  std::vector<std::byte> o;
  detail::put_u32(o, e.session_id);
  detail::put_u16(o, e.instance);
  detail::put_u8(o, static_cast<std::uint8_t>(e.event));
  detail::put_u8(o, 0);
  detail::put_u64(o, e.requested_seq);
  return o;
}

inline std::vector<std::byte> encode_ouch_inbound(const OuchInboundHeader& h, std::span<const std::byte> msg) {
  std::vector<std::byte> o;
  o.reserve(OuchInboundHeader::kLen + msg.size());
  detail::put_u32(o, h.session_id);
  detail::put_u32(o, h.account);
  detail::put_u16(o, h.instance);
  detail::put_u16(o, static_cast<std::uint16_t>(msg.size()));
  detail::put_u32(o, 0);
  detail::put_bytes(o, msg.data(), msg.size());
  return o;
}

inline std::vector<std::byte> encode_timer(const TimerRecord& t) {
  std::vector<std::byte> o;
  detail::put_u32(o, t.timer_id);
  detail::put_u16(o, static_cast<std::uint16_t>(t.kind));
  detail::put_u16(o, 0);
  detail::put_u64(o, static_cast<std::uint64_t>(t.scheduled_ns));
  return o;
}

// TLV argument builder.
class AdminArgsBuilder {
 public:
  AdminArgsBuilder& symbol(const Symbol8& s) { return raw(AdminTag::Symbol, s.c.data(), 8); }
  AdminArgsBuilder& symbol(std::string_view s) { return symbol(Symbol8(s)); }
  AdminArgsBuilder& reason(const Alpha<4>& r) { return raw(AdminTag::Reason, r.c.data(), 4); }
  AdminArgsBuilder& reason(std::string_view r) { return reason(Alpha<4>(r)); }
  AdminArgsBuilder& i64(AdminTag t, std::int64_t v) {
    std::byte b[8];
    store_le64(b, static_cast<std::uint64_t>(v));
    return raw(t, b, 8);
  }
  AdminArgsBuilder& u32(AdminTag t, std::uint32_t v) {
    std::byte b[4];
    store_le32(b, v);
    return raw(t, b, 4);
  }
  AdminArgsBuilder& u16(AdminTag t, std::uint16_t v) {
    std::byte b[2];
    store_le16(b, v);
    return raw(t, b, 2);
  }
  AdminArgsBuilder& u8(AdminTag t, std::uint8_t v) {
    const std::byte b = static_cast<std::byte>(v);
    return raw(t, &b, 1);
  }
  AdminArgsBuilder& raw(AdminTag t, const void* p, std::size_t n) {
    detail::put_u16(b_, static_cast<std::uint16_t>(t));
    detail::put_u16(b_, static_cast<std::uint16_t>(n));
    detail::put_bytes(b_, p, n);
    return *this;
  }
  [[nodiscard]] const std::vector<std::byte>& bytes() const noexcept { return b_; }

 private:
  std::vector<std::byte> b_;
};

inline std::vector<std::byte> encode_admin(const AdminHeader& h, std::span<const std::byte> args) {
  std::vector<std::byte> o;
  detail::put_u16(o, h.command);
  detail::put_u16(o, h.tlv_version);
  detail::put_u32(o, h.operator_id);
  detail::put_u32(o, static_cast<std::uint32_t>(args.size()));
  detail::put_u32(o, 0);
  detail::put_bytes(o, args.data(), args.size());
  return o;
}
inline std::vector<std::byte> encode_admin(AdminCommand c, const AdminArgsBuilder& args, std::uint32_t op = 0) {
  return encode_admin(AdminHeader{static_cast<std::uint16_t>(c), 1, op}, args.bytes());
}

// ============================================================================ parsers

[[nodiscard]] inline std::optional<DayStart> parse_day_start(std::span<const std::byte> p) noexcept {
  if (p.size() < DayStart::kLen || load_le32(p.data()) != DayStart::kFormatVersion) return std::nullopt;
  DayStart d;
  d.date = load_le32(p.data() + 4);
  d.local_midnight_ns = static_cast<Nanos>(load_le64(p.data() + 8));
  d.build_id = load_le64(p.data() + 16);
  d.mold_session = Alpha<10>::from_wire(p.data() + 24);
  d.soup_session = Alpha<10>::from_wire(p.data() + 34);
  return d;
}

struct ConfigChunkView {
  ConfigTable table;
  std::uint16_t index;
  std::uint16_t count;
  std::uint32_t table_bytes;
  std::span<const std::byte> bytes;
};

[[nodiscard]] inline std::optional<ConfigChunkView> parse_config_chunk(std::span<const std::byte> p) noexcept {
  if (p.size() < kConfigChunkHead) return std::nullopt;
  ConfigChunkView c{static_cast<ConfigTable>(load_le16(p.data())), load_le16(p.data() + 2), load_le16(p.data() + 4),
                    load_le32(p.data() + 8), {}};
  const std::size_t n = load_le32(p.data() + 12);
  if (p.size() - kConfigChunkHead < n || c.count == 0 || c.index >= c.count) return std::nullopt;
  c.bytes = p.subspan(kConfigChunkHead, n);
  return c;
}

struct TableView {
  std::uint16_t version;
  std::uint32_t count;
  std::span<const std::byte> body;
};

// Checks the table head and that the body holds exactly count entries of `entry_len`.
[[nodiscard]] inline std::optional<TableView> parse_table(std::span<const std::byte> t, std::size_t entry_len,
                                                          std::uint16_t version) noexcept {
  if (t.size() < kTableHead || load_le16(t.data()) != version || load_le16(t.data() + 2) != 0) return std::nullopt;
  TableView v{version, load_le32(t.data() + 4), t.subspan(kTableHead)};
  if (v.body.size() != static_cast<std::size_t>(v.count) * entry_len) return std::nullopt;
  return v;
}

[[nodiscard]] inline SymbolEntry parse_symbol_entry(const std::byte* p) noexcept {
  SymbolEntry s;
  s.symbol = Symbol8::from_wire(p);
  s.round_lot = load_le32(p + 8);
  s.tick = load_le32(p + 12);
  s.prior_close = static_cast<PxE4>(load_le64(p + 16));
  s.market_category = std::to_integer<char>(p[24]);
  s.luld_tier = std::to_integer<char>(p[25]);
  s.flags = std::to_integer<std::uint8_t>(p[26]);
  s.regsho = std::to_integer<char>(p[27]);
  s.adv = load_le32(p + 28);
  return s;
}

[[nodiscard]] inline AccountEntry parse_account_entry(const std::byte* p) noexcept {
  AccountEntry a;
  a.account_id = load_le32(p);
  for (std::size_t i = 0; i < AccountEntry::kMaxFirms; ++i) a.firms[i] = Mpid4::from_wire(p + 4 + 4 * i);
  return a;
}

[[nodiscard]] inline SessionEntry parse_session_entry(const std::byte* p) noexcept {
  SessionEntry s;
  s.session_id = load_le32(p);
  s.account_id = load_le32(p + 4);
  s.flags = std::to_integer<std::uint8_t>(p[8]);
  s.default_aiq = std::to_integer<char>(p[9]);
  s.late_cross = static_cast<LateCrossPolicy>(std::to_integer<std::uint8_t>(p[10]));
  return s;
}

[[nodiscard]] inline RiskEntry parse_risk_entry(const std::byte* p) noexcept {
  RiskEntry r;
  r.account_id = load_le32(p);
  r.kind = static_cast<RiskKind>(load_le16(p + 4));
  r.value = static_cast<std::int64_t>(load_le64(p + 8));
  r.symbol = Symbol8::from_wire(p + 16);
  return r;
}

[[nodiscard]] inline ScheduleEntry parse_schedule_entry(const std::byte* p) noexcept {
  ScheduleEntry e;
  e.timer_id = load_le32(p);
  e.kind = static_cast<TimerKind>(load_le16(p + 4));
  e.arg = load_le16(p + 6);
  e.time_ns = static_cast<Nanos>(load_le64(p + 8));
  return e;
}

[[nodiscard]] inline std::optional<SessionEvent> parse_session_event(std::span<const std::byte> p) noexcept {
  if (p.size() < SessionEvent::kLen) return std::nullopt;
  SessionEvent e;
  e.session_id = load_le32(p.data());
  e.instance = load_le16(p.data() + 4);
  e.event = static_cast<SessionEventKind>(std::to_integer<std::uint8_t>(p[6]));
  e.requested_seq = load_le64(p.data() + 8);
  return e;
}

struct OuchInbound {
  OuchInboundHeader hdr;
  std::span<const std::byte> msg;
};

[[nodiscard]] inline std::optional<OuchInbound> parse_ouch_inbound(std::span<const std::byte> p) noexcept {
  if (p.size() < OuchInboundHeader::kLen) return std::nullopt;
  OuchInbound r;
  r.hdr.session_id = load_le32(p.data());
  r.hdr.account = load_le32(p.data() + 4);
  r.hdr.instance = load_le16(p.data() + 8);
  const std::size_t len = load_le16(p.data() + 10);
  if (p.size() - OuchInboundHeader::kLen < len) return std::nullopt;
  r.msg = p.subspan(OuchInboundHeader::kLen, len);
  return r;
}

[[nodiscard]] inline std::optional<TimerRecord> parse_timer(std::span<const std::byte> p) noexcept {
  if (p.size() < TimerRecord::kLen) return std::nullopt;
  TimerRecord t;
  t.timer_id = load_le32(p.data());
  t.kind = static_cast<TimerKind>(load_le16(p.data() + 4));
  t.scheduled_ns = static_cast<Nanos>(load_le64(p.data() + 8));
  return t;
}

struct AdminRecord {
  AdminHeader hdr;
  std::span<const std::byte> args;
};

[[nodiscard]] inline std::optional<AdminRecord> parse_admin(std::span<const std::byte> p) noexcept {
  if (p.size() < AdminHeader::kLen) return std::nullopt;
  AdminRecord a;
  a.hdr.command = load_le16(p.data());
  a.hdr.tlv_version = load_le16(p.data() + 2);
  a.hdr.operator_id = load_le32(p.data() + 4);
  const std::size_t n = load_le32(p.data() + 8);
  if (p.size() - AdminHeader::kLen < n) return std::nullopt;
  a.args = p.subspan(AdminHeader::kLen, n);
  return a;
}

// TLV v1 arguments; nullopt on a malformed element, an unknown tag, a wrong value length
// or a repeated tag.
[[nodiscard]] inline std::optional<AdminArgs> parse_admin_args(std::span<const std::byte> a,
                                                               std::uint16_t version) noexcept {
  if (version != 1) return std::nullopt;
  AdminArgs r;
  std::size_t i = 0;
  while (i < a.size()) {
    if (a.size() - i < 4) return std::nullopt;
    const auto tag = static_cast<AdminTag>(load_le16(a.data() + i));
    const std::size_t len = load_le16(a.data() + i + 2);
    i += 4;
    if (a.size() - i < len) return std::nullopt;
    const std::byte* v = a.data() + i;
    i += len;
    const unsigned bit = static_cast<unsigned>(tag);
    if (bit == 0 || bit >= 32 || ((r.present >> bit) & 1u) != 0) return std::nullopt;
    auto want = [&](std::size_t n) { return len == n; };
    switch (tag) {
      case AdminTag::Symbol:
        if (!want(8)) return std::nullopt;
        r.symbol = Symbol8::from_wire(v);
        break;
      case AdminTag::Reason:
        if (!want(4)) return std::nullopt;
        r.reason = Alpha<4>::from_wire(v);
        break;
      case AdminTag::Price:
      case AdminTag::Lower:
      case AdminTag::Upper:
      case AdminTag::Band:
      case AdminTag::Value:
      case AdminTag::Level1:
      case AdminTag::Level2:
      case AdminTag::Level3: {
        if (!want(8)) return std::nullopt;
        const auto x = static_cast<std::int64_t>(load_le64(v));
        if (tag == AdminTag::Price) r.price = x;
        if (tag == AdminTag::Lower) r.lower = x;
        if (tag == AdminTag::Upper) r.upper = x;
        if (tag == AdminTag::Band) r.band = x;
        if (tag == AdminTag::Value) r.value = x;
        if (tag == AdminTag::Level1) r.level1 = x;
        if (tag == AdminTag::Level2) r.level2 = x;
        if (tag == AdminTag::Level3) r.level3 = x;
        break;
      }
      case AdminTag::Time:
      case AdminTag::Account:
        if (!want(4)) return std::nullopt;
        (tag == AdminTag::Time ? r.time : r.account) = load_le32(v);
        break;
      case AdminTag::Kind:
        if (!want(2)) return std::nullopt;
        r.kind = load_le16(v);
        break;
      case AdminTag::Level:
      case AdminTag::Qualifier:
      case AdminTag::Action:
        if (!want(1)) return std::nullopt;
        (tag == AdminTag::Level ? r.level : (tag == AdminTag::Qualifier ? r.qualifier : r.action)) =
            std::to_integer<std::uint8_t>(v[0]);
        break;
      default: return std::nullopt;
    }
    r.present |= 1u << bit;
  }
  return r;
}

// ============================================================================ the standard day

// NASDAQ's schedule (R2 D2.1, D2.8; 06 §10) as Schedule table entries, ids dense from 1 in
// (time, id) order: system events, session milestones, EOII every 10 s from 09:25 and
// 15:50, NOII every 1 s from 09:28 and 15:55, the crosses, the expiry sweeps, and the
// 1 Hz Noii 'H' clock through system hours. `early_close` moves the close to 13:00.
inline std::vector<ScheduleEntry> standard_schedule(bool early_close = false, bool clock = true) {
  std::vector<ScheduleEntry> v;
  const Nanos close = early_close ? hms_ns(13, 0, 0) : hms_ns(16, 0, 0);
  struct Ev {
    Nanos t;
    int order;  // tie-break at equal times
    TimerKind k;
    std::uint16_t arg;
  };
  std::vector<Ev> ev;
  auto add = [&](Nanos t, int order, TimerKind k, std::uint16_t arg) { ev.push_back(Ev{t, order, k, arg}); };
  add(hms_ns(3, 0, 0), 0, TimerKind::SystemEvent, 'O');
  add(hms_ns(4, 0, 0), 0, TimerKind::SystemEvent, 'S');
  add(hms_ns(4, 0, 0), 1, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::PreMarket));
  add(hms_ns(9, 25, 0), 0, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::OpenFreeze));
  for (Nanos t = hms_ns(9, 25, 0); t < hms_ns(9, 28, 0); t += 10 * kNsPerSec) add(t, 2, TimerKind::Eoii, 'O');
  add(hms_ns(9, 28, 0), 0, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::MooCutoff));
  for (Nanos t = hms_ns(9, 28, 0); t < hms_ns(9, 30, 0); t += kNsPerSec) add(t, 2, TimerKind::Noii, 'O');
  add(hms_ns(9, 29, 30), 1, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::LooCutoff));
  add(hms_ns(9, 30, 0), 0, TimerKind::SystemEvent, 'Q');
  add(hms_ns(9, 30, 0), 1, TimerKind::Cross, 'O');
  const Nanos f = close - 10 * 60 * kNsPerSec, m = close - 5 * 60 * kNsPerSec, l = close - 2 * 60 * kNsPerSec;
  add(f, 0, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::CloseFreeze));
  for (Nanos t = f; t < m; t += 10 * kNsPerSec) add(t, 2, TimerKind::Eoii, 'C');
  add(m, 0, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::MocCutoff));
  for (Nanos t = m; t < close; t += kNsPerSec) add(t, 2, TimerKind::Noii, 'C');
  add(l, 1, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::LocCutoff));
  add(close, 0, TimerKind::SystemEvent, 'M');
  add(close, 1, TimerKind::Cross, 'C');
  add(close, 3, TimerKind::ExpirySweep, 'D');
  add(hms_ns(20, 0, 0), 0, TimerKind::ExpirySweep, 'X');
  add(hms_ns(20, 0, 0), 1, TimerKind::SystemEvent, 'E');
  add(hms_ns(20, 0, 0), 2, TimerKind::StateChange, static_cast<std::uint16_t>(Milestone::SystemClose));
  add(hms_ns(20, 5, 0), 0, TimerKind::SystemEvent, 'C');
  if (clock) {
    for (Nanos t = hms_ns(4, 0, 0) + kNsPerSec; t < hms_ns(20, 0, 0); t += kNsPerSec) add(t, 9, TimerKind::Noii, 'H');
  }
  std::stable_sort(ev.begin(), ev.end(), [](const Ev& a, const Ev& b) { return a.t != b.t ? a.t < b.t : a.order < b.order; });
  v.reserve(ev.size() + 1);
  ScheduleEntry init;
  init.timer_id = 0;
  init.kind = static_cast<TimerKind>(0);
  init.arg = static_cast<std::uint16_t>(Param::InitialSession);
  init.time_ns = 'C';
  v.push_back(init);
  std::uint32_t id = 1;
  for (const Ev& e : ev) v.push_back(ScheduleEntry{id++, e.k, e.arg, e.t});
  return v;
}

}  // namespace lle::engine
