#pragma once
// Record-stream builder for tests, harnesses and benchmarks (not used by the
// engine itself). A Scenario owns the payload bytes of the records it builds,
// assigns dense journal indexes and a strictly increasing exchange clock, and
// has shorthands for the configuration tables, timers (by Schedule entry),
// admin commands and the OUCH inbound messages.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string_view>
#include <vector>

#include "common/alpha.h"
#include "common/time.h"
#include "common/types.h"
#include "engine/records.h"
#include "proto/ouch50/ouch50.h"

namespace lle::engine {

// Encodes one inbound OUCH message with optional tags.
template <class Msg>
[[nodiscard]] std::vector<std::byte> ouch_bytes(const Msg& m, const ouch50::TagSet& tags = {}) {
  std::vector<std::byte> b(ouch50::kMaxInboundOuchLen + 64);
  ouch50::MessageWriter<Msg> w(std::span<std::byte>(b), m);
  if constexpr (Msg::kRule != ouch50::AppendageRule::None) ouch50::put_tags(w.tags(), tags);
  b.resize(w.finish());
  return b;
}

class Scenario {
 public:
  // 2026-10-01, local midnight 04:00 UTC (EDT), first record at 09:30.
  static constexpr Nanos kMidnight = 1'790'827'200'000'000'000;
  static constexpr Nanos kOpen = hms_ns(9, 30, 0);

  explicit Scenario(Nanos midnight = kMidnight, Nanos start = kOpen, Nanos step = 1'000)
      : midnight_(midnight), ts_(midnight + start), step_(step) {}

  // Current exchange time, as ns since midnight (the wire timestamp of the next record).
  [[nodiscard]] Nanos now() const noexcept { return ts_ - midnight_; }
  // Moves the clock forward (never backward) to `since_midnight`.
  void set_time(Nanos since_midnight) noexcept {
    if (midnight_ + since_midnight > ts_) ts_ = midnight_ + since_midnight;
  }
  void set_step(Nanos step) noexcept { step_ = step; }

  const InputRecord& add(RecordType t, std::vector<std::byte> payload, std::uint16_t flags = 0) {
    payloads_.push_back(std::move(payload));
    InputRecord r;
    r.index = next_index_++;
    r.ts_ns = ts_;
    r.type = static_cast<std::uint16_t>(t);
    r.flags = flags;
    r.payload = std::span<const std::byte>(payloads_.back());
    r.epoch = 1;
    ts_ += step_;
    records_.push_back(r);
    return records_.back();
  }

  const InputRecord& day_start(std::uint32_t date = 20261001) {
    DayStart d;
    d.date = date;
    d.local_midnight_ns = midnight_;
    d.mold_session = Alpha<10>("LLE0000001");
    d.soup_session = Alpha<10>("LLE0000001");
    return add(RecordType::DayStart, encode_day_start(d));
  }
  // One Config record per chunk; returns the last one.
  const InputRecord& config(ConfigTable t, std::span<const std::byte> body) {
    const InputRecord* last = nullptr;
    for (auto& c : config_chunks(t, body)) last = &add(RecordType::Config, std::move(c));
    return *last;
  }
  const InputRecord& symbols(std::span<const SymbolEntry> s) { return config(ConfigTable::Symbols, encode_symbols(s)); }
  const InputRecord& accounts(std::span<const AccountEntry> a) { return config(ConfigTable::Accounts, encode_accounts(a)); }
  const InputRecord& sessions(std::span<const SessionEntry> s) { return config(ConfigTable::Sessions, encode_sessions(s)); }
  const InputRecord& risk(std::span<const RiskEntry> r) { return config(ConfigTable::RiskLimits, encode_risk(r)); }
  const InputRecord& schedule(std::span<const ScheduleEntry> e) {
    schedule_.assign(e.begin(), e.end());
    return config(ConfigTable::Schedule, encode_schedule(e));
  }
  const InputRecord& session_event(std::uint32_t session, std::uint16_t instance, SessionEventKind k) {
    return add(RecordType::SessionEvent, encode_session_event(SessionEvent{session, instance, k, 0}));
  }
  // A Timer record for a schedule entry, at its scheduled time (the clock moves there).
  const InputRecord& fire(const ScheduleEntry& e) {
    set_time(e.time_ns);
    return add(RecordType::Timer, encode_timer(TimerRecord{e.timer_id, e.kind, midnight_ + e.time_ns}));
  }
  // The first loaded schedule entry of (kind, arg) at or after `from` (ns since midnight).
  [[nodiscard]] const ScheduleEntry* find(TimerKind k, std::uint16_t arg, Nanos from = 0) const {
    for (const ScheduleEntry& e : schedule_)
      if (e.timer_id != 0 && e.kind == k && e.arg == arg && e.time_ns >= from) return &e;
    return nullptr;
  }
  // Fires every loaded timer with time in [now, until] in schedule order; returns how many.
  std::size_t run_until(Nanos until) {
    std::size_t n = 0;
    for (const ScheduleEntry& e : schedule_) {
      if (e.timer_id == 0 || e.time_ns < now() || e.time_ns > until) continue;
      fire(e);
      ++n;
    }
    set_time(until);
    return n;
  }
  const InputRecord& admin(AdminCommand c, const AdminArgsBuilder& args) {
    return add(RecordType::Admin, encode_admin(c, args));
  }
  const InputRecord& ouch(std::uint32_t session, std::uint32_t account, std::span<const std::byte> msg,
                          std::uint16_t instance = 0, std::uint16_t flags = 0) {
    return add(RecordType::OuchInbound, encode_ouch_inbound(OuchInboundHeader{session, account, instance}, msg), flags);
  }

  [[nodiscard]] const std::deque<InputRecord>& records() const noexcept { return records_; }
  [[nodiscard]] const InputRecord& operator[](std::size_t i) const noexcept { return records_[i]; }
  [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }
  [[nodiscard]] Nanos midnight() const noexcept { return midnight_; }

 private:
  Nanos midnight_;
  Nanos ts_;
  Nanos step_;
  std::uint64_t next_index_ = 1;
  std::deque<std::vector<std::byte>> payloads_;  // stable addresses for the spans
  std::deque<InputRecord> records_;
  std::vector<ScheduleEntry> schedule_;
};

// A schedule with only parameter entries: the initial session and nothing timed.
inline std::vector<ScheduleEntry> params_only(char session = 'R') {
  ScheduleEntry e;
  e.arg = static_cast<std::uint16_t>(Param::InitialSession);
  e.time_ns = session;
  e.kind = static_cast<TimerKind>(0);
  return {e};
}

// ---- message shorthands (tests and examples)

struct EnterArgs {
  UserRefNum urn = 1;
  ouch50::Side side = ouch50::Side::Buy;
  Qty qty = 100;
  std::string_view symbol = "AAPL";
  std::uint64_t price = 1'000'000;  // $100.0000
  ouch50::TimeInForce tif = ouch50::TimeInForce::Day;
  ouch50::Display display = ouch50::Display::Visible;
  ouch50::CrossType cross = ouch50::CrossType::Continuous;
  ouch50::IsoEligibility iso = ouch50::IsoEligibility::NotEligible;
  std::string_view cl_ord_id = "";
};

[[nodiscard]] inline std::vector<std::byte> enter_msg(const EnterArgs& a, const ouch50::TagSet& tags = {}) {
  ouch50::in::EnterOrder m;
  m.user_ref_num = a.urn;
  m.side = a.side;
  m.quantity = a.qty;
  m.symbol = Symbol8(a.symbol);
  m.price = a.price;
  m.time_in_force = a.tif;
  m.display = a.display;
  m.capacity = ouch50::Capacity::Agency;
  m.inter_market_sweep_eligibility = a.iso;
  m.cross_type = a.cross;
  m.cl_ord_id = Alpha<14>(a.cl_ord_id);
  return ouch_bytes(m, tags);
}

struct ReplaceArgs {
  UserRefNum orig = 1;
  UserRefNum urn = 2;
  Qty qty = 100;
  std::uint64_t price = 1'000'000;
  ouch50::TimeInForce tif = ouch50::TimeInForce::Day;
  ouch50::Display display = ouch50::Display::Visible;
  ouch50::IsoEligibility iso = ouch50::IsoEligibility::NotEligible;
  std::string_view cl_ord_id = "";
};

[[nodiscard]] inline std::vector<std::byte> replace_msg(const ReplaceArgs& a, const ouch50::TagSet& tags = {}) {
  ouch50::in::ReplaceOrder m;
  m.orig_user_ref_num = a.orig;
  m.user_ref_num = a.urn;
  m.quantity = a.qty;
  m.price = a.price;
  m.time_in_force = a.tif;
  m.display = a.display;
  m.inter_market_sweep_eligibility = a.iso;
  m.cl_ord_id = Alpha<14>(a.cl_ord_id);
  return ouch_bytes(m, tags);
}

[[nodiscard]] inline std::vector<std::byte> cancel_msg(UserRefNum urn, Qty qty, const ouch50::TagSet& tags = {}) {
  ouch50::in::CancelOrder m;
  m.user_ref_num = urn;
  m.quantity = qty;
  return ouch_bytes(m, tags);
}

[[nodiscard]] inline std::vector<std::byte> modify_msg(UserRefNum urn, ouch50::Side side, Qty qty,
                                                       const ouch50::TagSet& tags = {}) {
  ouch50::in::ModifyOrder m;
  m.user_ref_num = urn;
  m.side = side;
  m.quantity = qty;
  return ouch_bytes(m, tags);
}

[[nodiscard]] inline std::vector<std::byte> mass_cancel_msg(UserRefNum urn, std::string_view firm,
                                                            std::string_view symbol = "",
                                                            const ouch50::TagSet& tags = {}) {
  ouch50::in::MassCancel m;
  m.user_ref_num = urn;
  m.firm = Mpid4(firm);
  m.symbol = Symbol8(symbol);
  return ouch_bytes(m, tags);
}

[[nodiscard]] inline std::vector<std::byte> disable_msg(UserRefNum urn, std::string_view firm,
                                                        const ouch50::TagSet& tags = {}) {
  ouch50::in::DisableOrderEntry m;
  m.user_ref_num = urn;
  m.firm = Mpid4(firm);
  return ouch_bytes(m, tags);
}

[[nodiscard]] inline std::vector<std::byte> enable_msg(UserRefNum urn, std::string_view firm,
                                                       const ouch50::TagSet& tags = {}) {
  ouch50::in::EnableOrderEntry m;
  m.user_ref_num = urn;
  m.firm = Mpid4(firm);
  return ouch_bytes(m, tags);
}

[[nodiscard]] inline std::vector<std::byte> account_query_msg(const ouch50::TagSet& tags = {}) {
  return ouch_bytes(ouch50::in::AccountQuery{}, tags);
}

}  // namespace lle::engine
