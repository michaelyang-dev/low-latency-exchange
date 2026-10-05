#pragma once
// T18 tick-to-trade: ttt_harness's plan, per-trigger records and analysis
// (METHODOLOGY §12, §13; 07 §3 "ttt_harness", §4 "T18"; WP N-12).
//
// Plan (precomputed before the run, open loop; plan 12 §5):
//   - background: the day's messages at a constant rate, message i due at i * 1e9 / rate;
//   - triggers: Poisson arrivals at trigger_rate from the seed;
//   - the stream: seq 1 is the trigger symbol's Stock Directory; after it, background
//     messages and triggers in schedule order (a background message due at the same
//     time as a trigger goes first); each trigger is an Add Order at the trigger price
//     followed at once by its Order Delete, so trigger k has sequence number
//         trigger_seq[k] = 2 + bg_before(T_k) + 2k
//     and the client's ClOrdID (the trigger's sequence in decimal) identifies k without
//     any shared state between the harness's transmit and receive threads.
//
// Per-trigger record: the scheduled time (monotonic and, when a PHC map exists, on the
// PHC), the software hand-off time, the TX timestamps of the packet carrying the
// trigger on line A and on line B, and the RX timestamp of the frame that carried the
// Enter Order with ClOrdID = trigger_seq[k], all on the harness port's PHC.
//
// Analysis (per run, triggers scheduled after the warm-up only):
//   TTT_raw    = RX_hw(order frame) - min(TX_hw(line A), TX_hw(line B))
//   TTT_cal    = TTT_raw - 2c (c from the reflector calibration)
//   TTT_client = TX_hw(order frame at C) - RX_hw(winning trigger frame at C), from
//                refclient's order-stamp log
//   lateness   = min(TX_hw A, B) - scheduled (PHC domain); software lateness alongside
//   consistency: |median(TTT_raw) - median(TTT_client) - 2c| <= 250 ns
// A run is valid only if the TTT_raw pairs pass the hardware-timestamp rules (>= 99.9%
// hardware pairs, 0 software stamps, one PHC), lateness p99.9 <= 1 us, at least
// min_triggers measured triggers, and the TX stamps were attributed without loss. A
// failed consistency rule holds the run for investigation (reported, and not valid).
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "client/histogram.h"
#include "client/hwts_log.h"
#include "common/types.h"
#include "net/hwts/clock_domain.h"

namespace lle::client {
class JsonObject;
}

namespace lle::client::ttt {

struct PlanConfig {
  std::uint64_t seed = 1;
  std::uint64_t trigger_rate = 10'000;          // Poisson, per second
  std::uint64_t background_rate = 1'000'000;    // constant, messages per second (0: none)
  Nanos duration = 110 * kNsPerSec;             // schedule length, warm-up included
  std::uint64_t background_available = ~0ull;   // messages the input day provides
};

struct Plan {
  PlanConfig cfg;
  std::vector<Nanos> trigger_time;  // ns from the run start
  std::vector<SeqNo> trigger_seq;   // ascending
  std::uint64_t background = 0;     // background messages scheduled within the duration

  [[nodiscard]] Nanos bg_time(std::uint64_t i) const noexcept;
  // Background messages due at or before t (capped at `background`).
  [[nodiscard]] std::uint64_t bg_before(Nanos t) const noexcept;
  // Trigger index for a sequence number, or -1.
  [[nodiscard]] std::int64_t trigger_of(SeqNo seq) const noexcept;
  // Messages in the whole stream (directory + background + 2 per trigger).
  [[nodiscard]] std::uint64_t messages() const noexcept { return 1 + background + 2 * trigger_seq.size(); }
};

[[nodiscard]] Plan build_plan(const PlanConfig& c);

struct TriggerRecord {
  SeqNo seq = 0;
  std::int64_t sched = 0;      // ns from the run start (CLOCK_MONOTONIC_RAW)
  std::int64_t sched_phc = 0;  // the scheduled time on the PHC (0: no PHC map)
  std::int64_t tx_sw = 0;      // ns from the run start when the packet was handed to the NIC
  std::int64_t tx_hw[2]{};     // line A, line B TX stamps (PHC; 0 = none)
  std::int64_t tx_swts[2]{};   // software TX stamps (kernel sockets in software mode)
  std::int64_t rx_hw = 0;      // RX stamp of the order frame (PHC; 0 = none)
  std::int64_t rx_sw = 0;      // software RX stamp (0 = none)
  std::int32_t phc = -1;       // PHC index of the harness port
  std::uint8_t tx_flags = 0;
  std::uint8_t rx_flags = 0;   // written by the receive thread only
  std::uint16_t reserved = 0;

  static constexpr std::uint8_t kSent = 1;
  static constexpr std::uint8_t kOrder = 1;        // an Enter Order with this ClOrdID arrived
  static constexpr std::uint8_t kSharedRead = 2;   // ...in a read whose stamp belongs to a later order
  static constexpr std::uint8_t kDuplicate = 4;    // more than one order for this trigger

  [[nodiscard]] net::hwts::PhcStamp first_tx() const noexcept;
  [[nodiscard]] net::hwts::PhcStamp order_rx() const noexcept;
};
static_assert(sizeof(TriggerRecord) == 88);

struct RunHeader {
  std::uint64_t seed = 0;
  std::int64_t start_realtime_ns = 0;  // CLOCK_REALTIME at the run start
  std::int64_t start_mono_ns = 0;
  std::int32_t phc = -1;
  std::uint32_t reserved = 0;
};

// "LLETTT01", u32 version 1, u32 record size, RunHeader, u64 count, records.
bool write_triggers(const std::string& path, const RunHeader& h, std::span<const TriggerRecord> recs);
bool read_triggers(const std::string& path, RunHeader& h, std::vector<TriggerRecord>& out, std::string* err);

struct Calibration {
  bool have = false;
  bool valid = false;  // the calibration run itself passed the hardware-timestamp rules
  Nanos c = 0;         // one-way harness-side MAC/PHY + cable (ns)
};

struct AnalysisConfig {
  Nanos warmup = 10 * kNsPerSec;
  std::uint64_t min_triggers = 1'000'000;
  Nanos max_lateness_p999 = 1'000;
  Nanos consistency_tolerance = 250;
};

struct Analysis {
  std::uint64_t triggers = 0;         // in the plan
  std::uint64_t sent = 0;
  std::uint64_t measured = 0;         // scheduled after the warm-up
  std::uint64_t orders = 0, shared_reads = 0, duplicates = 0, no_order = 0;
  net::hwts::IntervalAccounting raw_acc;
  Histogram raw;
  Histogram lateness_hw, lateness_sw, ab_gap;
  bool lateness_hw_available = false;
  // Client side.
  bool have_client = false;
  net::hwts::IntervalAccounting client_acc;
  Histogram client;
  std::uint64_t client_records = 0, client_measured = 0, client_not_in_packet = 0, client_unknown = 0;
  // Calibration and the consistency rule.
  Calibration cal;
  bool consistency_evaluated = false, consistency_ok = false;
  Nanos consistency_ns = 0;  // median(raw) - median(client) - 2c
  // Verdict.
  bool valid = false;
  std::string invalid_reasons;
};

// `client` may be empty (no client log). `tx_stamps_aligned` and `software_seen` come
// from the run (TX attribution intact; any software stamp seen by a port).
[[nodiscard]] Analysis analyze(const Plan& plan, std::span<const TriggerRecord> recs,
                               std::span<const OrderStampRecord> client, const Calibration& cal,
                               const AnalysisConfig& cfg, bool tx_stamps_aligned, bool software_seen);

// Flat run-NN.json members (tools/results reads the numeric ones). The TTT verdict is
// "ttt_valid"; the caller writes the run's overall "valid" (which adds run-level checks).
void analysis_json(JsonObject& j, const Analysis& a);

// ---- reflector calibration (METHODOLOGY §13 "TTT_cal") ----
// One probe: RTT on the harness port, turnaround on the reflector's port, each a
// difference of two stamps of one PHC. c = (RTT_A - turnaround_C) / 2.
struct ProbeResult {
  net::hwts::PhcStamp a_tx, a_rx;  // harness port
  net::hwts::PhcStamp c_rx, c_tx;  // reflector port
};
struct CalibrationResult {
  net::hwts::IntervalAccounting rtt_acc, turn_acc;
  Histogram c2;  // 2c per probe (ns)
  Nanos c = 0;   // median 2c / 2
  bool valid = false;
};
[[nodiscard]] CalibrationResult calibrate(std::span<const ProbeResult> probes);

}  // namespace lle::client::ttt
