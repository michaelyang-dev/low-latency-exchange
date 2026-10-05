#pragma once
// loadgen v1 (07 §3 "loadgen", WP N-05): open-loop OUCH load over K SoupBinTCP
// sessions with the pre-registered mix, and the accounting of every response.
//
// Schedule (precomputed before the run from one seed; plan 12 §5): send times
// are Poisson arrivals (or a constant rate) at the offered rate, so they never
// depend on responses. Each message has a kind drawn from the mix
//   45% Enter (non-marketable limits over S symbols, realistic depth),
//   40% Cancel, 10% Replace, 5% marketable IOC,
// against a model of the book the schedule itself builds: every symbol has a
// fixed mid price; bids rest 1..L ticks below it and offers 1..L ticks above it
// (nearer ticks more likely), so Enters never cross; a Cancel or a Replace picks
// a random live order; an IOC takes the best opposite level for at most its
// size, so it is marketable and fills completely, against known orders in FIFO
// order. A symbol is always traded on one session (symbol mod K), so the
// per-symbol order of messages survives K independent TCP connections. When a
// kind needs a live order and none exists, an Enter is sent instead (counted).
// The first `prefill` messages are Enters that build depth; they are excluded
// from the latency statistics.
//
// Accounting: every message has an expected response type: Enter -> Accepted
// (Live), Cancel -> Canceled, Replace -> Replaced (Live), IOC -> Accepted (Live)
// then Executed for its full size. Executions on resting orders (the passive side
// of an IOC) are expected consequences. Anything else -- Rejected, Cancel Reject,
// an IOC accepted Dead or cancelled with a remainder, a response for no message
// -- is counted as unexpected, and a message without its response at the end is
// missing. Latency is measured from each message's SCHEDULED send time to its
// response (no coordinated omission); lateness = actual send - scheduled.
//
// v2 (07 §3 "loadgen v2", METHODOLOGY §15; WP N-16) adds, with v1 defaults that keep
// v1 schedules bit-identical:
//   - sizes from the profile (Enter/Replace lots, IOC size unit and range);
//   - a duplicate guard: an Enter's content (symbol, side, price, size, time in force)
//     never repeats among the session's last `dup_guard` Enters, so the engine's
//     duplicate filter (8 contents per account and second, Enter only) never fires;
//   - a split over generator threads: schedule t of T covers the sessions s with
//     s % T == t and their symbols, at the matching share of the rate (each thread owns
//     its sessions, so per-symbol order still holds);
//   - a pre-trade risk budget check against the profile's limits (05 §7, the engine's
//     RiskGate rules), evaluated on the schedule itself: rate buckets on schedule time,
//     size, order notional, symbol and gross exposure (open + executed, both sides of
//     every IOC fill on the same account). A schedule that would draw a reject is
//     refused before the run (0 Rejected is a T20 validity condition).
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "common/alpha.h"
#include "common/int128.h"
#include "common/types.h"
#include "proto/ouch50/ouch50.h"

struct hdr_histogram;

namespace lle::client {
class Histogram;
}

namespace lle::client::lg {

enum class Kind : std::uint8_t { Enter = 0, Cancel = 1, Replace = 2, Ioc = 3 };
inline constexpr std::size_t kKinds = 4;
[[nodiscard]] constexpr const char* kind_name(Kind k) noexcept {
  constexpr const char* kNames[kKinds] = {"enter", "cancel", "replace", "ioc"};
  return kNames[static_cast<std::size_t>(k)];
}

struct MixConfig {
  std::uint32_t enter_pct = 45, cancel_pct = 40, replace_pct = 10, ioc_pct = 5;
};

// Pre-trade limits the exchange applies per account (engine RiskKind; 0 = off).
struct RiskLimits {
  std::int64_t max_qty = 0;          // max-order-qty
  std::int64_t max_notional = 0;     // max-order-notional (PxE4 x shares)
  std::int64_t port_rate = 0;        // port-rate (messages / s / session)
  std::int64_t symbol_rate = 0;      // symbol-rate (orders / s / (session, symbol))
  std::int64_t gross = 0;            // gross-exposure (PxE4 x shares, open + executed)
  std::int64_t symbol_notional = 0;  // symbol-notional (PxE4 x shares, open)
  std::int64_t dup_window_sec = 0;   // dup-window-sec
  std::int64_t kill_exposure = 0;    // kill-exposure (executed PxE4 x shares)
};

struct RiskCheck {
  std::uint64_t checked = 0;  // orders evaluated (Enter, IOC, Replace)
  std::uint64_t over_qty = 0, over_notional = 0, over_port_rate = 0, over_symbol_rate = 0;
  std::uint64_t over_gross = 0, over_symbol_notional = 0, dup_guard_short = 0, over_kill = 0;
  std::uint64_t dup_unresolved = 0;  // the duplicate guard found no distinct size (a reject if the filter is on)
  std::uint64_t dup_unresolved_rejects = 0;  // ... with dup-window-sec > 0
  i128 peak_gross = 0, peak_symbol_notional = 0, peak_executed = 0;
  [[nodiscard]] std::uint64_t violations() const noexcept {
    return over_qty + over_notional + over_port_rate + over_symbol_rate + over_gross + over_symbol_notional +
           dup_guard_short + over_kill + dup_unresolved_rejects;
  }
};

struct ScheduleConfig {
  std::uint64_t seed = 1;
  std::uint32_t sessions = 4;
  std::uint32_t symbols = 2000;
  std::uint64_t rate = 10'000;        // messages per second over all sessions
  Nanos duration = 10 * kNsPerSec;    // measured part
  std::uint64_t prefill = 0;          // Enter-only messages before the measured part (0: symbols x 8)
  bool poisson = true;                // else a constant rate
  MixConfig mix{};
  std::uint32_t depth_ticks = 10;     // non-marketable prices 1..depth_ticks from the mid
  PxE4 tick = 100;                    // $0.01
  // v2 (defaults reproduce v1).
  std::uint32_t lot = 100;                          // Enter / Replace size = lot x [lots_min, lots_max]
  std::uint32_t lots_min = 1, lots_max = 10;
  std::uint32_t ioc_unit = 100;                     // IOC size = unit x [ioc_min, ioc_max], capped by the level
  std::uint32_t ioc_min = 1, ioc_max = 10;
  std::uint32_t dup_guard = 0;                      // 0: off
  std::uint32_t threads = 1, thread_index = 0;
  Nanos warmup = 0;                                 // items scheduled before this are warm-up (no statistics)
  RiskLimits risk{};
  bool shared_account = false;                      // every session on one account (threads == 1 only)
};

// "S0001".."S9999": the symbol names loadgen and the loopback server agree on.
[[nodiscard]] Symbol8 symbol_name(std::uint32_t index);
// The fixed mid price of symbol `index` for a seed ($10.00-$199.00, whole dollars).
[[nodiscard]] PxE4 symbol_mid(std::uint64_t seed, std::uint32_t index);

struct Item {
  Nanos t = 0;              // offset of the scheduled send time from the start
  std::uint32_t urn = 0;    // UserRefNum it consumes (Enter/Replace/IOC) or names (Cancel)
  std::uint32_t orig = 0;   // Replace: the original's UserRefNum
  std::uint32_t qty = 0;    // Enter/IOC: shares; Replace: chain total; Cancel: 0
  std::uint32_t price = 0;  // PxE4
  std::uint16_t symbol = 0;
  std::uint16_t session = 0;  // 0-based
  Kind kind = Kind::Enter;
  char side = 'B';
  bool warmup = false;
};

struct ScheduleStats {
  std::array<std::uint64_t, kKinds> kinds{};
  std::uint64_t fallbacks = 0;  // Cancel/Replace/IOC turned into an Enter (no live order)
  std::uint64_t prefill = 0;
  std::uint64_t live_at_end = 0;
  std::uint64_t ioc_shares = 0;
  std::uint64_t passive_fills = 0;  // resting orders an IOC is expected to hit
};

struct Schedule {
  ScheduleConfig cfg;
  std::vector<Item> items;
  std::vector<std::uint32_t> urns_per_session;  // highest UserRefNum used per session
  ScheduleStats stats;
  RiskCheck risk;
  std::uint64_t dup_bumps = 0;                  // Enter sizes changed by the duplicate guard
};

// True if session s belongs to schedule thread t of T.
[[nodiscard]] constexpr bool session_of_thread(std::uint32_t s, std::uint32_t t, std::uint32_t threads) noexcept {
  return threads <= 1 || s % threads == t;
}

[[nodiscard]] Schedule build_schedule(const ScheduleConfig& cfg);

// The OUCH bytes of one item (Enter, Cancel, Replace or IOC Enter). Returns the length.
std::size_t encode_item(const Item& it, std::span<std::byte> out);

// --- response accounting -------------------------------------------------------------
struct Latency {
  hdr_histogram* h = nullptr;
  Latency();
  ~Latency();
  Latency(const Latency&) = delete;
  Latency& operator=(const Latency&) = delete;
  void record(Nanos v) noexcept;
  [[nodiscard]] std::int64_t percentile(double p) const noexcept;
  [[nodiscard]] std::int64_t max() const noexcept;
  [[nodiscard]] std::int64_t count() const noexcept;
};

struct AccountingStats {
  std::uint64_t sent = 0, acked = 0, missing = 0;
  std::array<std::uint64_t, kKinds> acked_by_kind{};
  std::uint64_t ioc_fills = 0, ioc_shares = 0;     // aggressor executions of IOCs
  std::uint64_t passive_fills = 0, passive_shares = 0;
  std::uint64_t system_events = 0;
  std::uint64_t unexpected = 0;
  std::uint64_t rejected = 0, cancel_rejects = 0, ioc_dead = 0, ioc_remainder = 0, unknown_urn = 0;
  std::uint64_t duplicate_ack = 0, wrong_state = 0, other = 0;
  std::array<std::uint64_t, 256> reject_reasons_low{};  // Rejected by reason code (low byte)
};

class Accounting {
 public:
  explicit Accounting(const Schedule& s);
  // Item `i` was written at `sent`; `t0` is the schedule's start (absolute).
  void on_sent(std::size_t i, Nanos t0, Nanos sent) noexcept;
  // One sequenced OUCH message from session `s` received at `now`.
  void on_response(std::uint16_t s, std::span<const std::byte> m, Nanos now) noexcept;
  // Counts what never got its response.
  void finish() noexcept;
  [[nodiscard]] bool complete() const noexcept { return acked_ + missing_counted_ >= sent_target_; }
  [[nodiscard]] std::uint64_t outstanding() const noexcept { return st_.sent - st_.acked; }

  [[nodiscard]] const AccountingStats& stats() const noexcept { return st_; }
  // The schedule index of the message the last expected response answered (-1: none
  // since reset): NIC-to-NIC probes look up their ack with it.
  [[nodiscard]] std::int64_t last_acked_item() const noexcept { return last_acked_; }
  void reset_last_acked() noexcept { last_acked_ = -1; }
  // Latency samples also go to intervals[(scheduled - t0) / 1 s] (clamped to the last).
  void set_intervals(std::vector<Histogram*> intervals, Nanos t0) {
    intervals_ = std::move(intervals);
    interval_t0_ = t0;
  }
  [[nodiscard]] const Latency& latency() const noexcept { return all_; }
  [[nodiscard]] const Latency& latency(Kind k) const noexcept { return by_kind_[static_cast<std::size_t>(k)]; }
  [[nodiscard]] const Latency& lateness() const noexcept { return late_; }

 private:
  struct Track {
    Nanos sched = 0;          // absolute scheduled time of the message awaiting its response
    Nanos cancel_sched = 0;   // a Cancel naming this order, awaiting 'C'
    std::uint32_t item = 0;
    std::uint32_t cancel_item = 0;
    std::uint32_t ioc_left = 0;
    Kind kind = Kind::Enter;
    bool awaiting = false;
    bool cancel_awaiting = false;
    bool warmup = false;
    bool cancel_warmup = false;
  };
  void ack(std::uint32_t item, Nanos sched, bool warmup, Kind k, Nanos now) noexcept;
  void unexpected(std::uint64_t& counter) noexcept {
    ++counter;
    ++st_.unexpected;
  }

  const Schedule& s_;
  std::vector<std::vector<Track>> tracks_;  // [session][urn]
  AccountingStats st_;
  Latency all_, late_;
  std::array<Latency, kKinds> by_kind_;
  std::uint64_t acked_ = 0, missing_counted_ = 0, sent_target_ = 0;
  std::int64_t last_acked_ = -1;
  std::vector<Histogram*> intervals_;
  Nanos interval_t0_ = 0;
};

}  // namespace lle::client::lg
