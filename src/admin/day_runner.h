#pragma once
// Scripted trading days (05 §10 E-15): a whole day run in-process and
// deterministically through the real sequencer (manual clock, SCQ queues, the
// L2 ring) into the engine, from a small script. Used by apps/scripted_day and
// by the tests of the T03 halt and IPO days.
//
// Script: one item per line; '#' starts a comment. Setup lines first:
//   day YYYYMMDD [early-close]
//   symbol SYM [prior=P] [lot=N] [tick=T] [tier=1|2] [adv=N] [etp] [regsho=0|2|x]
//   account ID FIRM[,FIRM...]
//   session ID account=ACCOUNT [flags=cod,market,keepcross,postonlycancel] [late=accept|reprice|reject]
//   risk ACCOUNT KIND VALUE [SYMBOL]               (as lle-admin risk-limit, journaled in the RiskLimits table)
//   param NAME VALUE                                (halt-period, luld-pause, extension, limit-state,
//                                                    mwcb-period, threshold-bps, threshold-min, price-test-bps,
//                                                    price-test-min, price-tests)
// then timed actions, in time order ("HH:MM:SS[.fraction]" since local midnight):
//   T login SESSION | T logout SESSION | T disconnect SESSION
//   T enter SESSION URN B|S|T|E QTY SYMBOL PRICE|MKT [tif=day|ioc|gtx|gtt|ah] [display=Y|N|A]
//           [cross=N|O|C|H] [maxfloor=N] [minqty=N] [peg] [io] [postonly] [expire=HH:MM:SS]
//   T cancel SESSION URN QTY
//   T replace SESSION ORIG NEW QTY PRICE|MKT
//   T admin COMMAND ARGS...                         (lle-admin words, admin/commands.h; operator 1)
//   T run                                           (just advance the clock: timers fire)
// The schedule is engine::standard_schedule (with the 1 Hz clock) plus the
// params; the day ends at the last action's time unless `end` is given.
#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <vector>

#include "common/types.h"

namespace lle::admin {

struct DayResult {
  std::vector<std::vector<std::byte>> itch;  // every ITCH message, in order
  std::uint64_t ouch = 0;                    // OUCH messages
  std::map<char, std::uint64_t> itch_types;
  std::map<char, std::uint64_t> liquidity;   // OUCH 'E' liquidity flags
  std::uint64_t records = 0;                 // journal records applied
  std::uint64_t timers = 0;
  std::uint64_t audits = 0;
  std::uint64_t invalid_itch = 0;            // strict validator failures
  std::uint64_t state_hash = 0;
  std::uint64_t live_orders = 0;
};

// Parses and runs a script (the text of a script file).
[[nodiscard]] std::expected<DayResult, std::string> run_day(const std::string& script);

// Writes ITCH messages as a NASDAQ BinaryFILE ([u16 BE length][message], then a
// zero-length record).
[[nodiscard]] bool write_binary_file(const std::string& path, const std::vector<std::vector<std::byte>>& msgs);

}  // namespace lle::admin
