#pragma once
// The node's metrics segment (11 §3, T32): /lle-stats-<node>, read by lle-top. Each
// counter has one writer, the stage that owns it, which copies its stats into the
// segment every 1,024 polls (relaxed stores; no read-modify-write across threads).
// With metrics disabled the same layout lives in process memory, so stages never
// test for it.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include "exchanged/ring_gauge.h"
#include "md/work_meter.h"
#include "metrics/segment.h"

namespace lle::exch {

// Counter names (11 §3 per component). Gauges hold a current value.
//
// Work time (METHODOLOGY §16, T32; md/work_meter.h): <stage>_work_tsc is the cycle
// counter time of the stage's polls that processed at least one item, <stage>_work_items
// the items in them, tsc_hz the counter's frequency (lle_top shows ns per item). Items:
//   gw0, gw1   port events, released OUCH messages delivered, staged messages and session
//              events pushed, session timer actions
//   seq        records sequenced
//   engine     records applied
//   io         records journaled, output-log messages written, output-log flushes
//   md         released ITCH messages, republished messages, re-requests, end of session
//   repl       datagrams received and sent, records appended or teed, state hashes,
//              forwarded inputs, pushed session events
//   glimpse    output-log messages applied, port events, session timer actions
// The per-message cost of T32 is the sum of the stages' work time over inbound messages.
//
// Rings (ring_gauge.h; T20 validity): l2 and tee in bytes (seq writes them, with ouch and
// events in slots), egress in bytes (engine). cap 0: the ring is absent (tee outside
// split paired mode). node_start_ns: the process start (realtime), to tell a restart.
#define LLE_EXCH_COUNTERS(X)                                                                                         \
  X(seq_records, kCounter) X(seq_ouch, kCounter) X(seq_session_events, kCounter) X(seq_admin, kCounter)              \
  X(seq_timers, kCounter) X(seq_backpressure, kCounter) X(seq_last_index, kGauge)                                     \
  X(engine_records, kCounter) X(engine_orders, kCounter) X(engine_fills, kCounter) X(engine_rejects, kCounter)       \
  X(engine_cancels, kCounter) X(engine_audits, kCounter) X(engine_itch, kCounter) X(engine_ouch, kCounter)           \
  X(engine_halts, kCounter) X(engine_crosses, kCounter) X(engine_applied, kGauge) X(engine_live_orders, kGauge)      \
  X(engine_state_hash, kGauge) X(engine_replaced, kCounter) X(engine_supervisory_cancels, kCounter)                 \
  X(engine_lag, kGauge) X(engine_books_active, kGauge) X(engine_book_levels, kGauge)                                  \
  X(io_durable_index, kGauge) X(io_records, kCounter) X(io_segments, kCounter) X(io_l2_lag, kGauge)                  \
  X(outlog_itch, kCounter) X(outlog_soup, kCounter) X(outlog_errors, kCounter) X(release_index, kGauge)              \
  X(io_batches, kCounter)                                                                                             \
  X(gw0_sessions, kGauge) X(gw0_logins, kCounter) X(gw0_login_rejects, kCounter) X(gw0_msgs_in, kCounter)          \
  X(gw0_msgs_out, kCounter) X(gw0_mpsc_full, kCounter) X(gw0_decode_errors, kCounter) X(gw0_disconnects, kCounter)  \
  X(gw0_ouch_malformed, kCounter) X(gw0_cod_triggers, kCounter) X(gw0_replays, kCounter)                            \
  X(gw1_sessions, kGauge) X(gw1_logins, kCounter) X(gw1_login_rejects, kCounter) X(gw1_msgs_in, kCounter)          \
  X(gw1_msgs_out, kCounter) X(gw1_mpsc_full, kCounter) X(gw1_decode_errors, kCounter) X(gw1_disconnects, kCounter)  \
  X(gw1_ouch_malformed, kCounter) X(gw1_cod_triggers, kCounter) X(gw1_replays, kCounter)                            \
  X(md_messages, kCounter) X(md_packets_a, kCounter) X(md_packets_b, kCounter) X(md_heartbeats, kCounter)           \
  X(md_rerequests, kCounter) X(md_rerequests_served, kCounter) X(md_next_seq, kGauge)                               \
  X(md_rerequests_refused, kCounter)                                                                                  \
  X(repl_role, kGauge) X(repl_epoch, kGauge) X(repl_commit, kGauge) X(repl_ack_lag, kGauge)                         \
  X(repl_forwards, kCounter) X(repl_alarms, kCounter) X(repl_heartbeat_misses, kCounter)                           \
  X(repl_hash_checks, kCounter) X(repl_retransmits, kCounter) X(repl_tail, kGauge) X(repl_commit_lag, kGauge)       \
  X(tsc_hz, kGauge)                                                                                                   \
  X(gw0_work_tsc, kCounter) X(gw0_work_items, kCounter) X(gw1_work_tsc, kCounter) X(gw1_work_items, kCounter)       \
  X(seq_work_tsc, kCounter) X(seq_work_items, kCounter) X(engine_work_tsc, kCounter) X(engine_work_items, kCounter) \
  X(io_work_tsc, kCounter) X(io_work_items, kCounter) X(md_work_tsc, kCounter) X(md_work_items, kCounter)           \
  X(repl_work_tsc, kCounter) X(repl_work_items, kCounter) X(glimpse_work_tsc, kCounter)                             \
  X(glimpse_work_items, kCounter)                                                                                    \
  X(node_start_ns, kGauge)                                                                                            \
  LLE_EXCH_RING(X, l2) LLE_EXCH_RING(X, egress) LLE_EXCH_RING(X, ouch) LLE_EXCH_RING(X, events) LLE_EXCH_RING(X, tee)

// ring_<R>_{cap,used,hwm,peak,window} (ring_gauge.h), in this order.
#define LLE_EXCH_RING(X, r)                                                                                          \
  X(ring_##r##_cap, kGauge) X(ring_##r##_used, kGauge) X(ring_##r##_hwm, kGauge) X(ring_##r##_peak, kGauge)        \
  X(ring_##r##_window, kCounter)

enum class Ctr : std::size_t {
#define LLE_EXCH_ENUM(name, kind) name,
  LLE_EXCH_COUNTERS(LLE_EXCH_ENUM)
#undef LLE_EXCH_ENUM
      kCount
};

class NodeMetrics {
 public:
  // shm segment /lle-stats-<node> when `shared`, else process memory.
  [[nodiscard]] static std::expected<std::unique_ptr<NodeMetrics>, std::string> create(std::string_view node,
                                                                                       bool shared);

  [[nodiscard]] metrics::Counter c(Ctr id) const noexcept { return seg_->counter(static_cast<std::size_t>(id)); }
  void set(Ctr id, std::uint64_t v) noexcept { c(id).set(v); }
  // A stage's work time: `tsc` is its <stage>_work_tsc; <stage>_work_items follows it.
  void set_work(Ctr tsc, const md::WorkStats& w) noexcept {
    set(tsc, w.tsc);
    set(static_cast<Ctr>(static_cast<std::size_t>(tsc) + 1), w.items);
  }
  // A ring's gauges: `cap` is its ring_<R>_cap; used, hwm, peak and window follow it.
  void set_ring(Ctr cap, const RingGauge& g) noexcept {
    const auto at = [cap](std::size_t k) { return static_cast<Ctr>(static_cast<std::size_t>(cap) + k); };
    set(at(0), g.cap);
    set(at(1), g.used);
    set(at(2), g.hwm);
    set(at(3), g.peak);
    set(at(4), g.window);
  }
  // Histograms, in schema order (metrics.cpp).
  [[nodiscard]] metrics::Histogram md_batch() const noexcept { return seg_->histogram(std::size_t{0}); }
  [[nodiscard]] metrics::Histogram repl_ack_rtt() const noexcept { return seg_->histogram(std::size_t{1}); }
  [[nodiscard]] metrics::Histogram journal_commit() const noexcept { return seg_->histogram(std::size_t{2}); }
  [[nodiscard]] metrics::Histogram engine_reject_codes() const noexcept { return seg_->histogram(std::size_t{3}); }
  void heartbeat() noexcept { seg_->heartbeat(); }

 private:
  NodeMetrics() = default;
  std::unique_ptr<std::byte[]> mem_;
  std::unique_ptr<metrics::Segment> seg_;
};

}  // namespace lle::exch
