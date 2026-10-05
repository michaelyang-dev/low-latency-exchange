#pragma once
// loadgen v2 profile file: the T20 mix and risk profile (METHODOLOGY §15, §18; 07 §3
// "loadgen" mix; 05 §7 risk; ADR-014). One file feeds both sides: loadgen builds its
// schedule from it, and `loadgen profile --exchanged-risk` prints the [risk] rows the
// exchange's configuration needs, so the limits loadgen checks its schedule against are
// the limits the engine applies.
//
//   # comment
//   status = TBD_BY_PILOT        # or "registered" once fixed in METHODOLOGY §18
//   [mix]       enter = 45  cancel = 40  replace = 10  ioc = 5        (percent, sum 100)
//   [book]      symbols = 2000  depth_ticks = 10  tick = 0.01  prefill_per_symbol = 8
//               lot = 100  lots = 1-10  ioc_unit = 1  ioc = 1-5  dup_guard = 16
//   [sessions]  count = 16  user_base = 1  account = per-session | shared
//   [risk]      max-order-qty = N  max-order-notional = N  port-rate = N  symbol-rate = N
//               gross-exposure = N  symbol-notional = N  dup-window-sec = N  kill-exposure = N
//               (exchanged's names and units: notionals in PxE4 x shares), plus any other
//               exchanged risk kind, passed through to --exchanged-risk unchecked
//
// A profile whose status is not "registered" may be used for pilots and development
// only; the T20 campaign refuses it (lab/run_campaign.sh, TBD_BY_PILOT).
#include <cstdint>
#include <expected>
#include <string>
#include <utility>
#include <vector>

#include "client/loadgen.h"

namespace lle::client::lg {

struct Profile {
  std::string path;
  std::string status = "TBD_BY_PILOT";
  ScheduleConfig base;             // mix, book, sizes, duplicate guard, sessions, risk
  std::uint32_t user_base = 1;
  std::vector<std::pair<std::string, std::int64_t>> risk_rows;  // every [risk] row, file order
  [[nodiscard]] bool registered() const noexcept { return status == "registered"; }
};

[[nodiscard]] std::expected<Profile, std::string> parse_profile(const std::string& text, const std::string& name);
[[nodiscard]] std::expected<Profile, std::string> load_profile(const std::string& path);

// exchanged [risk] rows ("ACCOUNT KIND VALUE") for accounts first_account..+count-1.
[[nodiscard]] std::string exchanged_risk_rows(const Profile& p, std::uint32_t first_account, std::uint32_t count);

}  // namespace lle::client::lg
