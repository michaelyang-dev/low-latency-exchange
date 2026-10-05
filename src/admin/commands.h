#pragma once
// Operator command words -> an engine Admin command and its TLV arguments
// (engine/records.h). Shared by lle-admin, luld_feed and the scripted-day
// runner so the three speak the same language. Prices are decimal dollars
// parsed exactly into integers (no floating point).
//
//   halt SYMBOL [REASON]                        news/regulatory halt (H 'H')
//   quote-only SYMBOL [--price P] [--reason R]  quotation-only period, collars around P
//   resume SYMBOL                               operator release: the halt cross
//   ipo-schedule SYMBOL PRICE HH:MM:SS [--qualifier A|C]
//   ipo-quote SYMBOL                            IPO quotation period (H 'Q' IPOQ)
//   ipo-release SYMBOL [--band B]               underwriter "go"; B = $ around the expected price
//   luld-bands SYMBOL LOWER UPPER
//   mwcb-levels L1 L2 L3                        index levels (8 decimals), ITCH 'V'
//   mwcb-breach 1|2|3                           ITCH 'W'
//   kill-switch ACCOUNT | kill-reset ACCOUNT
//   risk-limit ACCOUNT KIND VALUE [SYMBOL]      KIND: name (max-order-qty, ...) or number;
//                                               notional kinds take dollars x shares as an
//                                               integer of PxE4 x shares (engine units)
//   cross-cancel-permit ACCOUNT
//   regsho SYMBOL 0|1|2
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/types.h"

namespace lle::admin {

struct Command {
  std::uint16_t command = 0;  // engine::AdminCommand
  std::vector<std::byte> args;
};

// argv: the words after the program options, e.g. {"halt", "AAPL", "T1"}.
[[nodiscard]] std::expected<Command, std::string> parse_command(std::span<const std::string_view> words);

// "12.3456" -> 123456 with `decimals` = 4. At most `decimals` fraction digits,
// no sign, no exponent; overflow is an error.
[[nodiscard]] std::expected<std::int64_t, std::string> parse_decimal(std::string_view s, int decimals);
// "HH:MM:SS" -> seconds since midnight.
[[nodiscard]] std::expected<std::uint32_t, std::string> parse_hms(std::string_view s);
// Unsigned decimal integer.
[[nodiscard]] std::expected<std::uint64_t, std::string> parse_uint(std::string_view s);
// "max-order-qty" etc. or a number -> engine::RiskKind value.
[[nodiscard]] std::expected<std::uint16_t, std::string> parse_risk_kind(std::string_view s);

}  // namespace lle::admin
