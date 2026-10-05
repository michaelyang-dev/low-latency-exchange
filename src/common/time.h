#pragma once
// Time helpers. Exchange time is ns since the UNIX epoch (journal ts_ns);
// wire timestamps (ITCH/OUCH) are ns since midnight America/New_York.
#include <cstdint>

#include "common/types.h"

namespace lle {

constexpr Nanos hms_ns(int h, int m, int s, Nanos ns = 0) noexcept {
  return ((static_cast<Nanos>(h) * 60 + m) * 60 + s) * kNsPerSec + ns;
}

// Converts exchange time to ns since local midnight given the UTC offset of the
// trading day (e.g. -4h during EDT, -5h during EST) and the day's local midnight
// expressed in UNIX ns. Kept integer-only and table-free: the offset is carried
// in the DayStart/Config records, so replay never consults a tz database.
constexpr Nanos since_midnight(Nanos unix_ns, Nanos local_midnight_unix_ns) noexcept {
  return unix_ns - local_midnight_unix_ns;
}

}  // namespace lle
