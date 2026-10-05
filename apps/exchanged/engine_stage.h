#pragma once
// The engine stage (01 §4 step 4, §7 CPU 11): applies journal records from its L2
// cursor, in index order, up to the apply limit (solo and primary: everything
// sequenced; backup: the announced commit, 10 §3), and appends every output, tagged
// with the record's index, to the egress ring. The release-gated egress stages take
// it from there (ADR-005).
//
// One record can produce many outputs (a cross). If the egress ring cannot take them
// all, the rest wait in a staging buffer, in order, and no further record is applied
// until it is empty: back-pressure, never loss. `applied` is published only when every
// output of the record is in the ring (egress.h, done-watermarks).
//
// Observability (11 §3, T32) without touching the engine: the sink adapter observes
// what the engine emits (OUCH accepts, executions, rejects with their codes, cancels;
// ITCH system events, trading actions, crosses) and its audit events; Admin records
// are logged as they are applied. Rejects, halts, crosses and audits are logged every
// time; accepts and executions are sampled.
//
// Work time (T32, md/work_meter.h): items are the records applied. Generic over the
// clock the meter reads (only its tsc(); the engine itself never reads a clock, 01 §6),
// so the simulator runs this stage on virtual time; EngineStage is the production binding.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "common/endian.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "exchanged/clock.h"
#include "exchanged/shared.h"
#include "journal/record.h"
#include "log/nlog.h"
#include "md/egress.h"
#include "md/work_meter.h"

namespace lle::exch {

struct EngineStageConfig {
  std::size_t batch = 256;                 // records per poll
  std::uint64_t hash_interval = 0;         // state-hash checkpoints (paired mode: 10 §3); 0 = off
  std::uint32_t sample_every = 1024;       // accept/execution log sampling
  std::size_t overflow_reserve = std::size_t{1} << 20;
};

struct EngineStats {
  std::uint64_t records = 0;
  std::uint64_t itch = 0, ouch = 0, audits = 0;
  std::uint64_t accepted = 0, replaced = 0, canceled = 0, executed = 0, rejected = 0;
  std::uint64_t halts = 0, crosses = 0, admin = 0, timers = 0;
  std::uint64_t overflow_records = 0;  // records whose outputs did not fit the egress ring at once
  std::uint64_t reject_codes[64] = {};  // by OUCH reject reason (low 6 bits)
  std::uint64_t state_hash = 0;
  std::uint64_t hash_index = 0;
};

template <class ClockT>
class BasicEngineStage {
 public:
  BasicEngineStage(Shared& sh, engine::Engine& eng, const EngineStageConfig& cfg, std::uint64_t applied,
                   const ClockT& clock)
      : sh_(&sh), eng_(&eng), cfg_(cfg), applied_(applied), work_(&clock) {
    ov_entries_.reserve(cfg.overflow_reserve / 64);
    ov_bytes_.reserve(cfg.overflow_reserve);
    sh_->egress_state.applied.store(applied_);
  }

  bool poll() {
    const bool did = run();
    work_.finish();
    return did;
  }

  [[nodiscard]] std::uint64_t applied() const noexcept { return applied_; }

  // A rejoin's reloaded outputs that egress has not had yet (RecoveredDay::deferred:
  // records <= the recovered index, in emission order, possibly the DayEnd marker last).
  // They go to the egress ring before any new record, through the overflow staging, so
  // the release-gated egress stages hand them on only once released (DST-013). Until
  // they are all in the ring, `applied` is published as the record before the first.
  // Call before the stages run.
  template <class Range>
  void stage_deferred(const Range& outs) {
    for (const auto& o : outs) {
      ov_entries_.push_back(Staged{o.index, o.session, o.kind, static_cast<std::uint32_t>(ov_bytes_.size()),
                                   static_cast<std::uint32_t>(o.bytes.size())});
      ov_bytes_.insert(ov_bytes_.end(), o.bytes.begin(), o.bytes.end());
    }
    if (!ov_entries_.empty()) sh_->egress_state.applied.store(ov_entries_.front().index - 1);
  }
  [[nodiscard]] const EngineStats& stats() const noexcept { return stats_; }
  [[nodiscard]] const md::WorkStats& work() const noexcept { return work_.stats(); }
  [[nodiscard]] const engine::Engine& engine() const noexcept { return *eng_; }

 private:
  bool run() {
    bool did = false;
    if (!ov_entries_.empty()) {
      if (!flush_overflow()) return true;
      publish_applied();
      did = true;
    }
    const std::uint64_t limit = sh_->apply_limit.load();
    for (std::size_t n = 0; n < cfg_.batch; ++n) {
      const journal::RecordView v = sh_->l2.peek(kL2Engine);
      if (v.empty() || v.index() > limit) break;
      if (v.index() <= applied_) {  // already applied by recovery
        sh_->l2.release(kL2Engine);
        continue;
      }
      work_.start();
      work_.add();
      apply(v);
      sh_->l2.release(kL2Engine);
      did = true;
      if (!ov_entries_.empty()) {
        ++stats_.overflow_records;
        if (!flush_overflow()) return true;
      }
      publish_applied();
    }
    return did;
  }

  struct Sink {
    BasicEngineStage* s;
    void itch(std::uint64_t idx, std::span<const std::byte> b) { s->on_itch(idx, b); }
    void ouch(std::uint64_t idx, std::uint32_t session, std::span<const std::byte> b) { s->on_ouch(idx, session, b); }
    void audit(std::uint64_t idx, const engine::AuditEvent& a) { s->on_audit(idx, a); }
  };
  struct Staged {
    std::uint64_t index;
    std::uint32_t session;
    md::OutKind kind;
    std::uint32_t off;
    std::uint32_t len;
  };

  void apply(const journal::RecordView& v) {
    ++stats_.records;
    const auto type = v.type();
    if (type == journal::RecordType::Admin) {
      ++stats_.admin;
      if (const auto a = journal::decode_admin(v)) {
        NLOG_INFO("engine admin command {} operator {} at index {}", a->command, a->operator_id, v.index());
      }
    } else if (type == journal::RecordType::Timer) {
      ++stats_.timers;
    }
    Sink sink{this};
    eng_->apply(engine::to_input(v), sink);
    applied_ = v.index();
    if (type == journal::RecordType::DayEnd) {
      emit(v.index(), md::OutKind::DayEnd, 0, {});
      sh_->day_end_index.store(v.index());
      NLOG_INFO("engine day end at index {} S(P) {}", v.index(), eng_->itch_count());
    }
    if (cfg_.hash_interval != 0 && applied_ % cfg_.hash_interval == 0) {
      stats_.state_hash = eng_->state_hash();
      stats_.hash_index = applied_;
      (void)sh_->hashes.try_push(StateHashMsg{applied_, stats_.state_hash});
    }
  }

  void publish_applied() {
    sh_->itch_total.store(itch_total_);
    sh_->soup_total.store(soup_total_);
    sh_->egress_state.applied.store(applied_);
  }

  void on_itch(std::uint64_t idx, std::span<const std::byte> b) {
    ++stats_.itch;
    ++itch_total_;
    switch (static_cast<char>(b[0])) {
      case 'S': NLOG_INFO("engine system event '{}' at index {}", static_cast<char>(b[11]), idx); break;
      case 'H':
        ++stats_.halts;
        NLOG_INFO("engine trading action locate {} state '{}' at index {}", load_be16(b.data() + 1),
                  static_cast<char>(b[19]), idx);
        break;
      case 'Q':
        ++stats_.crosses;
        NLOG_INFO("engine cross locate {} shares {} type '{}' at index {}", load_be16(b.data() + 1),
                  load_be64(b.data() + 11), static_cast<char>(b[39]), idx);
        break;
      default: break;
    }
    emit(idx, md::OutKind::Itch, 0, b);
  }

  void on_ouch(std::uint64_t idx, std::uint32_t session, std::span<const std::byte> b) {
    ++stats_.ouch;
    ++soup_total_;
    switch (static_cast<char>(b[0])) {
      case 'A':
        ++stats_.accepted;
        if (stats_.accepted % cfg_.sample_every == 1)
          NLOG_INFO("engine order accepted session {} urn {} ref {} (sampled)", session, load_be32(b.data() + 9),
                    load_be64(b.data() + 36));
        break;
      case 'U': ++stats_.replaced; break;
      case 'C': ++stats_.canceled; break;
      case 'E':
        ++stats_.executed;
        if (stats_.executed % cfg_.sample_every == 1)
          NLOG_INFO("engine execution session {} urn {} qty {} (sampled)", session, load_be32(b.data() + 9),
                    load_be32(b.data() + 13));
        break;
      case 'J': {
        ++stats_.rejected;
        const std::uint16_t code = load_be16(b.data() + 13);
        ++stats_.reject_codes[code & 63u];
        NLOG_WARN("engine reject session {} urn {} code {} at index {}", session, load_be32(b.data() + 9), code, idx);
        break;
      }
      default: break;
    }
    emit(idx, md::OutKind::Ouch, session, b);
  }

  void on_audit(std::uint64_t idx, const engine::AuditEvent& a) {
    ++stats_.audits;
    NLOG_WARN("engine audit code {} session {} detail {} at index {}", static_cast<std::uint16_t>(a.code), a.session_id,
              a.detail, idx);
  }

  void emit(std::uint64_t idx, md::OutKind kind, std::uint32_t session, std::span<const std::byte> b) {
    if (ov_entries_.empty() && sh_->egress.try_push(idx, kind, session, b)) return;
    // Staged in order; the vectors were reserved at start and grow only for a record
    // whose outputs exceed the reserve (cold).
    ov_entries_.push_back(Staged{idx, session, kind, static_cast<std::uint32_t>(ov_bytes_.size()),
                                 static_cast<std::uint32_t>(b.size())});
    ov_bytes_.insert(ov_bytes_.end(), b.begin(), b.end());
  }

  bool flush_overflow() {
    while (ov_head_ < ov_entries_.size()) {
      const Staged& e = ov_entries_[ov_head_];
      if (!sh_->egress.try_push(e.index, e.kind, e.session,
                                std::span<const std::byte>(ov_bytes_.data() + e.off, e.len))) {
        return false;
      }
      ++ov_head_;
    }
    ov_entries_.clear();
    ov_bytes_.clear();
    ov_head_ = 0;
    return true;
  }

  Shared* sh_;
  engine::Engine* eng_;
  EngineStageConfig cfg_;
  std::uint64_t applied_ = 0;
  std::uint64_t itch_total_ = 0;
  std::uint64_t soup_total_ = 0;
  std::vector<Staged> ov_entries_;
  std::vector<std::byte> ov_bytes_;
  std::size_t ov_head_ = 0;
  EngineStats stats_{};
  md::WorkMeter<ClockT> work_;

 public:
  // After recovery: the totals the engine reached before this stage starts.
  void set_totals(std::uint64_t itch, std::uint64_t soup) {
    itch_total_ = itch;
    soup_total_ = soup;
    publish_applied();
  }
};

using EngineStage = BasicEngineStage<NodeClock>;

}  // namespace lle::exch
