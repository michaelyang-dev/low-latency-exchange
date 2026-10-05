#include "client/ttt.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "client/poisson.h"
#include "client/report.h"
#include "common/hash.h"
#include "common/int128.h"

namespace lle::client::ttt {

// ---- plan ---------------------------------------------------------------------------------

Nanos Plan::bg_time(std::uint64_t i) const noexcept {
  if (cfg.background_rate == 0) return 0;
  return static_cast<Nanos>(static_cast<u128>(i) * static_cast<std::uint64_t>(kNsPerSec) / cfg.background_rate);
}

std::uint64_t Plan::bg_before(Nanos t) const noexcept {
  if (t < 0 || cfg.background_rate == 0) return 0;
  // bg_time(i) <= t  <=>  i * 1e9 < (t + 1) * rate  <=>  i < ceil((t + 1) * rate / 1e9).
  const u128 num = static_cast<u128>(static_cast<std::uint64_t>(t) + 1) * cfg.background_rate;
  const auto n = static_cast<std::uint64_t>((num + static_cast<std::uint64_t>(kNsPerSec) - 1) /
                                            static_cast<std::uint64_t>(kNsPerSec));
  return std::min(n, background);
}

std::int64_t Plan::trigger_of(SeqNo seq) const noexcept {
  const auto it = std::lower_bound(trigger_seq.begin(), trigger_seq.end(), seq);
  if (it == trigger_seq.end() || *it != seq) return -1;
  return it - trigger_seq.begin();
}

Plan build_plan(const PlanConfig& c) {
  Plan p;
  p.cfg = c;
  if (c.background_rate != 0) {
    const auto n = static_cast<std::uint64_t>(static_cast<u128>(c.background_rate) * static_cast<std::uint64_t>(c.duration) /
                                              static_cast<std::uint64_t>(kNsPerSec));
    p.background = std::min(n, c.background_available);
  }
  if (c.trigger_rate != 0) {
    p.trigger_time.reserve(static_cast<std::size_t>(
        static_cast<u128>(c.trigger_rate) * static_cast<std::uint64_t>(c.duration) / static_cast<std::uint64_t>(kNsPerSec) * 11 / 10 + 16));
    Arrivals arr(mix64(c.seed ^ 0x5454'4854'5249'4701ull), c.trigger_rate, true);
    for (;;) {
      const Nanos t = arr.next();
      if (t >= c.duration) break;
      p.trigger_time.push_back(t);
    }
  }
  p.trigger_seq.resize(p.trigger_time.size());
  for (std::size_t k = 0; k < p.trigger_time.size(); ++k) p.trigger_seq[k] = 2 + p.bg_before(p.trigger_time[k]) + 2 * k;
  return p;
}

// ---- records --------------------------------------------------------------------------------

net::hwts::PhcStamp TriggerRecord::first_tx() const noexcept {
  if (tx_hw[0] != 0 && tx_hw[1] != 0) return {phc, std::min(tx_hw[0], tx_hw[1])};
  if (tx_hw[0] != 0 || tx_hw[1] != 0) return {phc, 0};  // one copy unstamped: the minimum is unknown
  if (tx_swts[0] != 0 || tx_swts[1] != 0) return {-1, std::max(tx_swts[0], tx_swts[1])};
  return {phc, 0};
}

net::hwts::PhcStamp TriggerRecord::order_rx() const noexcept {
  if (rx_hw != 0) return {phc, rx_hw};
  if (rx_sw != 0) return {-1, rx_sw};
  return {phc, 0};
}

namespace {
constexpr char kMagic[8] = {'L', 'L', 'E', 'T', 'T', 'T', '0', '1'};
}

bool write_triggers(const std::string& path, const RunHeader& h, std::span<const TriggerRecord> recs) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) return false;
  const std::uint32_t ver = 1, size = sizeof(TriggerRecord);
  const std::uint64_t n = recs.size();
  bool ok = std::fwrite(kMagic, 1, 8, f) == 8 && std::fwrite(&ver, 4, 1, f) == 1 && std::fwrite(&size, 4, 1, f) == 1 &&
            std::fwrite(&h, sizeof h, 1, f) == 1 && std::fwrite(&n, 8, 1, f) == 1;
  if (ok && n != 0) ok = std::fwrite(recs.data(), sizeof(TriggerRecord), recs.size(), f) == recs.size();
  ok = std::fclose(f) == 0 && ok;
  return ok;
}

bool read_triggers(const std::string& path, RunHeader& h, std::vector<TriggerRecord>& out, std::string* err) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    if (err) *err = "cannot open " + path;
    return false;
  }
  char magic[8];
  std::uint32_t ver = 0, size = 0;
  std::uint64_t n = 0;
  bool ok = std::fread(magic, 1, 8, f) == 8 && std::memcmp(magic, kMagic, 8) == 0 && std::fread(&ver, 4, 1, f) == 1 &&
            std::fread(&size, 4, 1, f) == 1 && ver == 1 && size == sizeof(TriggerRecord) &&
            std::fread(&h, sizeof h, 1, f) == 1 && std::fread(&n, 8, 1, f) == 1 && n < (std::uint64_t{1} << 32);
  if (ok) {
    out.resize(n);
    ok = n == 0 || std::fread(out.data(), sizeof(TriggerRecord), n, f) == n;
  }
  std::fclose(f);
  if (!ok && err) *err = path + ": not an LLETTT01 trigger file (or truncated)";
  return ok;
}

// ---- analysis -------------------------------------------------------------------------------

namespace {
void reason(Analysis& a, const std::string& r) {
  if (!a.invalid_reasons.empty()) a.invalid_reasons += "; ";
  a.invalid_reasons += r;
}
}  // namespace

Analysis analyze(const Plan& plan, std::span<const TriggerRecord> recs, std::span<const OrderStampRecord> client,
                 const Calibration& cal, const AnalysisConfig& cfg, bool tx_stamps_aligned, bool software_seen) {
  Analysis a;
  a.triggers = recs.size();
  a.cal = cal;
  bool any_sched_phc = false;
  for (const TriggerRecord& r : recs) {
    if ((r.tx_flags & TriggerRecord::kSent) != 0) ++a.sent;
    if (r.sched < cfg.warmup) continue;
    ++a.measured;
    if ((r.rx_flags & TriggerRecord::kOrder) != 0) ++a.orders;
    else ++a.no_order;
    if ((r.rx_flags & TriggerRecord::kSharedRead) != 0) ++a.shared_reads;
    if ((r.rx_flags & TriggerRecord::kDuplicate) != 0) ++a.duplicates;
    const net::hwts::PhcStamp tx = r.first_tx();
    if (const auto d = a.raw_acc.record(r.order_rx(), tx)) a.raw.record(*d);
    if ((r.tx_flags & TriggerRecord::kSent) != 0) a.lateness_sw.record(r.tx_sw - r.sched);  // <= 0: below_range
    if (r.sched_phc != 0) {
      any_sched_phc = true;
      if (tx.phc >= 0 && tx.ns != 0) a.lateness_hw.record(tx.ns - r.sched_phc);  // <= 0 (map error): below_range
    }
    if (r.tx_hw[0] != 0 && r.tx_hw[1] != 0) a.ab_gap.record(r.tx_hw[1] - r.tx_hw[0]);
  }
  a.lateness_hw_available = any_sched_phc && a.lateness_hw.count() > 0;

  if (!client.empty()) {
    a.have_client = true;
    a.client_records = client.size();
    for (const OrderStampRecord& c : client) {
      const std::int64_t k = plan.trigger_of(c.trigger_seq);
      if (k < 0) {
        ++a.client_unknown;
        continue;
      }
      if (plan.trigger_time[static_cast<std::size_t>(k)] < cfg.warmup) continue;
      ++a.client_measured;
      if ((c.flags & OrderStampRecord::kInPacket) == 0) {
        ++a.client_not_in_packet;
        continue;
      }
      if (const auto d = a.client_acc.record(c.tx_stamp(), c.rx_stamp())) a.client.record(*d);
    }
  }

  if (cal.have && a.have_client && a.raw.count() > 0 && a.client.count() > 0) {
    a.consistency_evaluated = true;
    a.consistency_ns = a.raw.percentile(50.0) - a.client.percentile(50.0) - 2 * cal.c;
    a.consistency_ok = (a.consistency_ns < 0 ? -a.consistency_ns : a.consistency_ns) <= cfg.consistency_tolerance;
  }

  // Verdict (METHODOLOGY §12, §13; plan 12 §4).
  if (software_seen || a.raw_acc.software != 0) reason(a, "software timestamps present");
  if (a.raw_acc.cross_phc != 0) reason(a, "intervals across PHCs");
  if (!a.raw_acc.valid()) reason(a, "fewer than 99.9% hardware TTT_raw pairs");
  if (!tx_stamps_aligned) reason(a, "TX timestamps could not be attributed without loss");
  if (a.measured < cfg.min_triggers) reason(a, "fewer measured triggers than required");
  if (!a.lateness_hw_available) {
    reason(a, "no PHC-domain generator lateness (no PHC map or no hardware TX stamps)");
  } else if (a.lateness_hw.percentile(99.9) > cfg.max_lateness_p999) {
    reason(a, "generator lateness p99.9 above the bound");
  }
  if (a.consistency_evaluated && !a.consistency_ok) reason(a, "consistency rule failed (investigate before publishing)");
  a.valid = a.invalid_reasons.empty();
  return a;
}

void analysis_json(JsonObject& j, const Analysis& a) {
  j.boolean("ttt_valid", a.valid).str("invalid_reasons", a.invalid_reasons);
  j.num("triggers", a.triggers).num("triggers_sent", a.sent).num("triggers_measured", a.measured);
  j.num("orders", a.orders).num("orders_missing", a.no_order).num("orders_shared_read", a.shared_reads);
  j.num("orders_duplicate", a.duplicates);
  j.num("raw_pairs_ok", a.raw_acc.ok).num("raw_pairs_missing", a.raw_acc.missing);
  j.num("raw_pairs_software", a.raw_acc.software).num("raw_pairs_cross_phc", a.raw_acc.cross_phc);
  a.raw.json(j, "ttt_raw_");
  if (a.cal.have) {
    j.inum("cal_c_ns", a.cal.c).boolean("cal_valid", a.cal.valid);
    for (const auto& [name, p] : {std::pair{"p50", 50.0}, {"p90", 90.0}, {"p99", 99.0}, {"p999", 99.9}}) {
      j.inum(std::string("ttt_cal_") + name + "_ns", a.raw.count() ? a.raw.percentile(p) - 2 * a.cal.c : 0);
    }
  }
  j.boolean("lateness_hw_available", a.lateness_hw_available);
  a.lateness_hw.json(j, "lateness_hw_");
  a.lateness_sw.json(j, "lateness_sw_");
  a.ab_gap.json(j, "line_ab_gap_");
  if (a.have_client) {
    j.num("client_records", a.client_records).num("client_measured", a.client_measured);
    j.num("client_not_in_packet", a.client_not_in_packet).num("client_unknown", a.client_unknown);
    j.num("client_pairs_ok", a.client_acc.ok).num("client_pairs_missing", a.client_acc.missing);
    j.num("client_pairs_software", a.client_acc.software).num("client_pairs_cross_phc", a.client_acc.cross_phc);
    j.boolean("client_valid", a.client_acc.valid());
    a.client.json(j, "ttt_client_");
  }
  j.boolean("consistency_evaluated", a.consistency_evaluated);
  if (a.consistency_evaluated) j.boolean("consistency_ok", a.consistency_ok).inum("consistency_ns", a.consistency_ns);
}

// ---- calibration ----------------------------------------------------------------------------

CalibrationResult calibrate(std::span<const ProbeResult> probes) {
  CalibrationResult r;
  for (const ProbeResult& p : probes) {
    const auto rtt = r.rtt_acc.record(p.a_rx, p.a_tx);
    const auto turn = r.turn_acc.record(p.c_tx, p.c_rx);
    if (rtt && turn) r.c2.record(*rtt - *turn);
  }
  r.c = r.c2.count() > 0 ? r.c2.percentile(50.0) / 2 : 0;
  r.valid = r.rtt_acc.valid() && r.turn_acc.valid() && r.c2.count() > 0 && r.c2.below_range() == 0;
  return r;
}

}  // namespace lle::client::ttt
