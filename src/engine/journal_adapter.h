#pragma once
// journal::RecordView -> engine::InputRecord (01 §8: the engine consumes
// journal records). Header-only: the engine library does not depend on the
// journal; callers that hold RecordViews (replay, recovery, the engine stage)
// include this. The payload span aliases the record bytes, which carry zero
// padding to the 8-byte record alignment; the engine's payload parsers use
// the length fields and ignore it.
#include <span>

#include "engine/records.h"
#include "journal/record.h"

namespace lle::engine {

static_assert(static_cast<std::uint16_t>(RecordType::DayStart) ==
              static_cast<std::uint16_t>(journal::RecordType::DayStart));
static_assert(static_cast<std::uint16_t>(RecordType::Pad) == static_cast<std::uint16_t>(journal::RecordType::Pad));
static_assert(kFlagMalformedInput == journal::kFlagMalformedInput);
static_assert(static_cast<std::uint16_t>(ConfigTable::Schedule) ==
              static_cast<std::uint16_t>(journal::ConfigTable::Schedule));
static_assert(static_cast<std::uint16_t>(TimerKind::DayEnd) == static_cast<std::uint16_t>(journal::TimerKind::DayEnd));

[[nodiscard]] inline InputRecord to_input(const journal::RecordView& v) noexcept {
  InputRecord r;
  r.index = v.index();
  r.ts_ns = v.ts_ns();
  r.type = v.type_raw();
  r.flags = v.flags();
  r.payload = v.payload();
  r.epoch = v.epoch();
  return r;
}

}  // namespace lle::engine
