#pragma once
// itch2ouch's divergence report (07 §3, WP N-19): the order-flow script of an
// ITCH day is fed, record by record, through the real sequencer and matching
// engine in-process (EngineDriver), and the engine's book and executions are
// compared with the ITCH day's.
//
// Per script record, the engine's outputs for that record are classified
// against what the source day did:
//   Enter    ok | rejected (by reason) | crossed on entry (executed against the
//            engine's book; split by whether the source add also locked or
//            crossed the source book, whether the symbol was halted in the
//            source, or neither: a consequence of an earlier divergence) |
//            accepted without being displayed
//   Cancel   ok | the engine had no such live order | a different number of
//            shares left the order
//   Replace  ok | no live original | rejected | original cancelled | crossed
//   IOC      exact (all shares against the source's resting order) | partly or
//            wholly against other orders | short (fewer shares executed) |
//            nothing executed | rejected
// and the source-only events are counted: executions against non-displayed
// liquidity (P), cross prints (Q), executions at a price other than the
// displayed one (C). Executions and cancels the engine produced on its own
// (crosses, sweeps, expiry) are counted separately.
//
// Book comparison: the source book (every ITCH message applied) and the
// engine's book translated into source terms (engine references mapped to
// source references through the Accepted/Replaced messages, engine locates to
// source locates) are compared at checkpoints: digests and per-order
// differences (missing, extra, different shares or price, different queue order).
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "client/itch2ouch.h"
#include "common/types.h"

namespace lle::client::i2o {

struct DivergenceConfig {
  std::string itch_path;
  std::uint64_t max_messages = 0;     // a slice: the first N source records (0 = the whole day)
  std::uint16_t sessions = 4;
  std::uint32_t date = 20190130;
  std::vector<Nanos> checkpoint_times;     // ns since midnight
  std::uint64_t checkpoint_every = 0;      // also every N source records
  std::size_t reserve_orders = std::size_t{1} << 22;
  std::string script_out;                  // also write the script (optional)
  bool synthetic = false;                  // header flag of the written script
  std::uint64_t progress_every = 0;        // print progress to stderr every N records
};

struct BookDiff {
  SeqNo seq = 0;
  Nanos time = 0;
  std::uint64_t source_orders = 0, engine_orders = 0;
  std::uint64_t identical = 0, shares_differ = 0, price_differs = 0;
  std::uint64_t missing_in_engine = 0, extra_in_engine = 0;
  std::uint64_t levels_compared = 0, levels_queue_order_differs = 0;
  std::uint64_t source_digest = 0, engine_digest = 0;
};

struct DivergenceReport {
  ConvertStats convert;
  std::uint64_t records = 0, engine_records = 0, engine_timers = 0;
  // Enter
  std::uint64_t enter_ok = 0, enter_rejected = 0, enter_not_displayed = 0;
  std::uint64_t enter_crossed = 0, enter_crossed_shares = 0;
  std::uint64_t enter_crossed_source_locked = 0;  // the source add locked/crossed the source book too
  std::uint64_t enter_crossed_source_halted = 0;  // the symbol was halted or paused in the source
  std::uint64_t enter_crossed_cascade = 0;        // neither: the engine's book had diverged before
  // Cancel
  std::uint64_t cancel_ok = 0, cancel_no_order = 0, cancel_shares_differ = 0;
  // Replace
  std::uint64_t replace_ok = 0, replace_no_order = 0, replace_rejected = 0, replace_original_cancelled = 0;
  std::uint64_t replace_crossed = 0, replace_crossed_shares = 0;
  // IOC (from E and C)
  std::uint64_t ioc_exact = 0, ioc_other_orders = 0, ioc_short = 0, ioc_none = 0, ioc_rejected = 0;
  std::uint64_t ioc_shares_expected = 0, ioc_shares_executed = 0, ioc_shares_on_target = 0;
  std::uint64_t ioc_target_absent = 0;  // the source's resting order was not in the engine's book
  // Rejects by reason code (low 8 bits of the u16 code).
  std::array<std::uint64_t, 256> reject_reasons{};
  // The engine on its own.
  std::uint64_t engine_executions_unsolicited = 0, engine_cancels_unsolicited = 0, engine_cross_prints = 0;
  std::uint64_t engine_hidden_executions = 0;
  std::uint64_t unmapped_engine_orders = 0;
  // Books.
  std::vector<BookDiff> checkpoints;
  Nanos elapsed_ns = 0;
};

// Runs the conversion and the in-process engine replay. False with *err on failure.
bool run_divergence(const DivergenceConfig& cfg, DivergenceReport& out, std::string* err);

// The report as a JSON object (cold path).
[[nodiscard]] std::string divergence_json(const DivergenceConfig& cfg, const DivergenceReport& r);

}  // namespace lle::client::i2o
