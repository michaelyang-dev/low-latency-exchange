#pragma once
// The trading day's configuration for the sequencer, built from the matching
// engine's tables (ADR-028; engine/records.h). One source gives both
//  - the Config tables the sequencer journals at day start, in the order the
//    engine needs them (Symbols, Accounts, Sessions, RiskLimits, Schedule:
//    risk limits resolve against the first three, and reloading any of those
//    clears them), and
//  - the sequencer's timer list: one ScheduleEntry per engine Schedule entry
//    with a timer id, at local midnight + its time, sorted by (time, id).
// Every Timer record the sequencer writes therefore carries the id and kind
// the engine's Schedule table gives meaning to.
//
// The journal payload layouts (journal/record.h) and the engine's parsers
// (engine/records.h) are the same layouts; tests/unit/sequencer checks it.
// Cold path: builds owning storage once per day.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "common/types.h"
#include "engine/records.h"
#include "journal/record.h"
#include "sequencer/sequencer.h"

namespace lle::seq {

struct EngineTables {
  std::span<const engine::SymbolEntry> symbols;
  std::span<const engine::AccountEntry> accounts;
  std::span<const engine::SessionEntry> sessions;
  std::span<const engine::RiskEntry> risk;  // empty: no RiskLimits table
  std::span<const engine::ScheduleEntry> schedule;
};

// Owns the table bodies; `config` and `timers` are ready for Sequencer::start_day
// and the Sequencer constructor. Not copyable once built (spans into `bodies`).
class EngineDay {
 public:
  EngineDay(const EngineTables& t, Nanos local_midnight) {
    bodies_.reserve(5);
    std::vector<journal::ConfigTable> tables;
    auto add = [&](journal::ConfigTable table, std::vector<std::byte> body) {
      bodies_.push_back(std::move(body));
      tables.push_back(table);
    };
    add(journal::ConfigTable::Symbols, engine::encode_symbols(t.symbols));
    add(journal::ConfigTable::Accounts, engine::encode_accounts(t.accounts));
    add(journal::ConfigTable::Sessions, engine::encode_sessions(t.sessions));
    if (!t.risk.empty()) add(journal::ConfigTable::RiskLimits, engine::encode_risk(t.risk));
    add(journal::ConfigTable::Schedule, engine::encode_schedule(t.schedule));
    for (std::size_t i = 0; i < bodies_.size(); ++i) config_.push_back(ConfigBlob{tables[i], bodies_[i]});
    for (const engine::ScheduleEntry& e : t.schedule) {
      if (e.timer_id == 0) continue;  // parameter entries are not timers
      timers_.push_back(ScheduleEntry{local_midnight + e.time_ns, static_cast<journal::TimerKind>(e.kind), e.timer_id});
    }
    std::sort(timers_.begin(), timers_.end(), [](const ScheduleEntry& a, const ScheduleEntry& b) {
      return a.time != b.time ? a.time < b.time : a.id < b.id;
    });
  }
  EngineDay(const EngineDay&) = delete;
  EngineDay& operator=(const EngineDay&) = delete;

  [[nodiscard]] std::span<const ConfigBlob> config() const noexcept { return config_; }
  [[nodiscard]] std::span<const ScheduleEntry> timers() const noexcept { return timers_; }

 private:
  std::vector<std::vector<std::byte>> bodies_;
  std::vector<ConfigBlob> config_;
  std::vector<ScheduleEntry> timers_;
};

// The journal and engine enumerations the sequencer writes must agree.
static_assert(static_cast<std::uint16_t>(journal::ConfigTable::Schedule) ==
              static_cast<std::uint16_t>(engine::ConfigTable::Schedule));
static_assert(static_cast<std::uint16_t>(journal::ConfigTable::RiskLimits) ==
              static_cast<std::uint16_t>(engine::ConfigTable::RiskLimits));
static_assert(static_cast<std::uint16_t>(journal::TimerKind::DayEnd) ==
              static_cast<std::uint16_t>(engine::TimerKind::DayEnd));
static_assert(static_cast<std::uint8_t>(journal::SessionEventKind::InstanceDown) ==
              static_cast<std::uint8_t>(engine::SessionEventKind::InstanceDown));

}  // namespace lle::seq
