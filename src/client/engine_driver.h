#pragma once
// The real sequencer and matching engine, driven in-process (07 §3: itch2ouch's
// divergence report; loadgen's loopback OUCH server). Records in, ITCH/OUCH out:
// OUCH messages and session events go into the sequencer's input queues, the
// sequencer journals them into an L2 ring (with Timer records when the clock
// passes a schedule entry), and the engine applies every record, emitting its
// outputs to the caller's sink (engine::OutputSink). This is the wiring of
// src/admin/day_runner.cpp with a caller-driven clock and an incremental API;
// neither the sequencer nor the engine is modified.
//
// Clock: exchange time = local midnight of the trading day + the time the caller
// advances to. advance(t) walks through every scheduled time on the way to t, so
// each Timer record is stamped when it is due.
// Cold path at construction (queues, ring, engine pools, the day's tables).
#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "common/assert.h"
#include "common/time.h"
#include "common/types.h"
#include "concurrent/mpsc_scq.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "engine/records.h"
#include "journal/l2_ring.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"

namespace lle::client {

struct EngineDayConfig {
  std::uint32_t date = 20261001;  // YYYYMMDD
  std::vector<engine::SymbolEntry> symbols;
  std::vector<engine::AccountEntry> accounts;
  std::vector<engine::SessionEntry> sessions;
  std::vector<engine::RiskEntry> risk;
  std::vector<engine::ScheduleEntry> params;  // parameter entries appended to the standard schedule
  bool early_close = false;
  bool clock_1hz = true;                      // the 1 Hz clock (halts, LULD, GTT, pegs)
  engine::EngineConfig engine{};
  std::size_t ring_bytes = std::size_t{16} << 20;
};

// UNIX ns of local midnight for YYYYMMDD at UTC-4 (the convention of the
// scripted days, src/admin/day_runner.cpp). Wire timestamps only depend on the
// difference to it, so the offset is immaterial to the outputs.
[[nodiscard]] constexpr Nanos local_midnight_ns(std::uint32_t date) noexcept {
  const int y0 = static_cast<int>(date / 10000), m = static_cast<int>(date / 100 % 100), d = static_cast<int>(date % 100);
  const int y = m <= 2 ? y0 - 1 : y0;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const int yoe = y - era * 400;
  const int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const std::int64_t days = std::int64_t{era} * 146097 + doe - 719468;
  return (days * 86'400 + 4 * 3'600) * kNsPerSec;
}

template <engine::OutputSink Sink>
class EngineDriver {
 public:
  struct Clock {
    Nanos real = 0;
    Nanos now_mono() noexcept { return real; }
    Nanos now_real() noexcept { return real; }
    std::uint64_t tsc() noexcept { return 0; }
  };
  struct Env {
    using Clock = EngineDriver::Clock;
    using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 1024>;
    using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 64>;
    using AdminQueue = conc::MpscScqRing<seq::AdminMsg, 64>;
    using Ring = journal::L2Ring<1>;
  };

  EngineDriver(const EngineDayConfig& cfg, Sink& sink)
      : cfg_(cfg),
        sink_(&sink),
        midnight_(local_midnight_ns(cfg.date)),
        sched_(make_schedule(cfg)),
        day_(std::make_unique<seq::EngineDay>(
            seq::EngineTables{cfg_.symbols, cfg_.accounts, cfg_.sessions, cfg_.risk, sched_}, midnight_)),
        oq_(std::make_unique<typename Env::OuchQueue>()),
        sq_(std::make_unique<typename Env::SessionQueue>()),
        aq_(std::make_unique<typename Env::AdminQueue>()),
        storage_(std::make_unique<std::uint64_t[]>(cfg.ring_bytes / 8)),
        engine_(std::make_unique<engine::Engine>(cfg.engine)) {
    ring_.init(reinterpret_cast<std::byte*>(storage_.get()), cfg.ring_bytes, 0x5C1D7EDDA75EED01ull);
    seq_ = std::make_unique<seq::Sequencer<Env>>(clock_, *oq_, *sq_, *aq_, ring_, day_->timers());
  }
  EngineDriver(const EngineDriver&) = delete;
  EngineDriver& operator=(const EngineDriver&) = delete;

  // Day start at `t` (ns since local midnight): DayStart, the tables, EpochStart.
  [[nodiscard]] bool start(Nanos t) {
    clock_.real = midnight_ + t;
    while (next_timer_ < day_->timers().size() && day_->timers()[next_timer_].time <= clock_.real) ++next_timer_;
    journal::DayStart ds;
    ds.trading_date = cfg_.date;
    ds.local_midnight_ns = midnight_;
    ds.mold_session = {'L', 'L', 'E', '0', '0', '0', '0', '0', '0', '1'};
    ds.soup_session = ds.mold_session;
    if (!seq_->start_day(ds, day_->config(), 1, 1)) return false;
    drain();
    return true;
  }

  // Moves the clock to `t` (ns since midnight), firing every timer due on the way.
  void advance(Nanos t) {
    const auto timers = day_->timers();
    while (next_timer_ < timers.size() && timers[next_timer_].time <= midnight_ + t) {
      if (timers[next_timer_].time > clock_.real) clock_.real = timers[next_timer_].time;
      ++next_timer_;
      settle();
    }
    if (midnight_ + t > clock_.real) clock_.real = midnight_ + t;
    settle();
  }

  // One inbound OUCH message from `session` (its account), sequenced and applied now.
  bool submit_ouch(std::uint32_t session, std::uint32_t account, std::span<const std::byte> bytes,
                   std::uint16_t instance = 0) {
    seq::InboundMsg m;
    m.session_id = session;
    m.account = account;
    m.instance = instance;
    if (bytes.size() > seq::InboundMsg::kMaxBytes) {
      m.flags = journal::kFlagMalformedInput;
      m.len = static_cast<std::uint16_t>(seq::InboundMsg::kMaxBytes);
    } else {
      m.len = static_cast<std::uint16_t>(bytes.size());
    }
    std::copy_n(bytes.begin(), m.len, m.bytes);
    if (!oq_->try_push(m)) {
      settle();
      if (!oq_->try_push(m)) return false;
    }
    settle();
    return true;
  }

  bool submit_session(std::uint32_t session, journal::SessionEventKind kind, std::uint16_t instance = 0) {
    if (!sq_->try_push(seq::SessionEventMsg{session, instance, kind, 0})) return false;
    settle();
    return true;
  }

  // Applies everything queued.
  void settle() {
    for (;;) {
      const bool progress = seq_->poll();
      if (drain() == 0 && !progress) break;
    }
  }

  [[nodiscard]] Nanos now() const noexcept { return clock_.real - midnight_; }
  [[nodiscard]] Nanos midnight() const noexcept { return midnight_; }
  [[nodiscard]] const engine::Engine& engine() const noexcept { return *engine_; }
  [[nodiscard]] std::uint64_t records() const noexcept { return records_; }
  [[nodiscard]] std::uint64_t timer_records() const noexcept { return timer_records_; }
  // Journal index of the last record applied.
  [[nodiscard]] std::uint64_t last_index() const noexcept { return last_index_; }
  [[nodiscard]] const EngineDayConfig& config() const noexcept { return cfg_; }

 private:
  static std::vector<engine::ScheduleEntry> make_schedule(const EngineDayConfig& c) {
    std::vector<engine::ScheduleEntry> s = engine::standard_schedule(c.early_close, c.clock_1hz);
    s.insert(s.end(), c.params.begin(), c.params.end());
    return s;
  }

  std::size_t drain() {
    std::size_t n = 0, k = 0;
    do {
      k = ring_.drain(
          0,
          [&](const journal::RecordView& v) {
            ++records_;
            last_index_ = v.index();
            if (v.type() == journal::RecordType::Timer) ++timer_records_;
            engine_->apply(engine::to_input(v), *sink_);
          },
          4096);
      n += k;
    } while (k != 0);
    return n;
  }

  EngineDayConfig cfg_;
  Sink* sink_;
  Nanos midnight_;
  std::vector<engine::ScheduleEntry> sched_;
  std::unique_ptr<seq::EngineDay> day_;
  Clock clock_;
  std::unique_ptr<typename Env::OuchQueue> oq_;
  std::unique_ptr<typename Env::SessionQueue> sq_;
  std::unique_ptr<typename Env::AdminQueue> aq_;
  std::unique_ptr<std::uint64_t[]> storage_;
  journal::L2Ring<1> ring_;
  std::unique_ptr<seq::Sequencer<Env>> seq_;
  std::unique_ptr<engine::Engine> engine_;
  std::size_t next_timer_ = 0;
  std::uint64_t records_ = 0, timer_records_ = 0, last_index_ = 0;
};

}  // namespace lle::client
