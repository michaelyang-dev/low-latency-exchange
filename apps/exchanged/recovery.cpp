#include "exchanged/recovery.h"

#include <algorithm>
#include <cstdio>
#include <memory>

#include "exchanged/recovery_impl.h"
#include "outlog/reader.h"
#include "outlog/repair.h"
#include "snapshot/reader.h"
#include "snapshotd/out_digest.h"

namespace lle::exch {

RecoveryLayout recovery_layout(const ExchangeConfig& cfg) {
  RecoveryLayout l;
  l.outlog_root = cfg.outlog_root();
  l.date = cfg.date;
  for (const auto& s : cfg.sessions) l.session_ids.push_back(s.session_id);
  std::sort(l.session_ids.begin(), l.session_ids.end());
  return l;
}

std::expected<void, std::string> reset_outlog(outlog::OutlogDay& out, const ExchangeConfig& cfg) {
  PosixRecoveryIo io;
  return basic_reset_outlog(io, out, recovery_layout(cfg));
}

std::expected<RecoveredDay, std::string> replay_day(SegDir& dir, const journal::RecoveryResult& rr,
                                                    engine::Engine& eng, outlog::OutlogDay& out,
                                                    const ExchangeConfig& cfg,
                                                    std::span<const seq::ConfigBlob> expected_config,
                                                    const std::string& snapshot_dir) {
  PosixRecoveryIo io;
  return basic_replay_day(io, dir, rr, eng, out, recovery_layout(cfg), expected_config, snapshot_dir);
}

}  // namespace lle::exch
