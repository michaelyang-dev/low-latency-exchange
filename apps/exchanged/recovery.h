#pragma once
// Node start-up on an existing journal (06 §7 steps 4-5, §8): after journal::recover()
// has established the valid prefix, replay it through the engine and regenerate the
// output log from it.
//
//   - Every record 1..last is applied to the node's engine (no snapshot is used: the
//     whole day is replayed; snapshotd is not part of M9).
//   - The engine's outputs are the regeneration of the output log: messages the files
//     already hold are compared byte for byte (the log is derived data, ADR-029) and
//     the rest are appended. A file that differs is cut back to the first difference
//     and rewritten from the journal.
//   - The journaled configuration must equal the configuration file's tables (ADR-028:
//     the journal is the truth for the day; a different file would give the gateways a
//     different session map than the engine's).
//   - What the sequencer needs to continue: the chain tail, Timer records already
//     journaled, SnapshotMark ids, the config digest, and the session instances that
//     were live when the process died (they are gone now: InstanceDown, so that
//     cancel-on-disconnect sees the disconnect, 05 §4 step 8).
// The work is generic over the storage (recovery_impl.h: basic_replay_day,
// basic_reset_outlog), so the simulator runs it on its disk; the functions below are
// the POSIX binding.
// Cold path.
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/types.h"
#include "engine/engine.h"
#include "exchanged/config.h"
#include "exchanged/io_stage.h"
#include "journal/recovery.h"
#include "outlog/day.h"
#include "sequencer/sequencer.h"

namespace lle::exch {

struct RecoveredDay {
  journal::ChainState chain;        // last record replayed
  std::size_t timers = 0;           // Timer records journaled
  std::uint64_t next_snapshot_id = 1;
  std::uint64_t config_digest = 0;  // from the last EpochStart
  std::uint32_t epoch = 0;
  bool started = false;             // the day start (through its EpochStart) is complete
  bool ended = false;               // DayEnd journaled
  std::uint64_t day_end_index = 0;
  std::vector<std::pair<std::uint32_t, std::uint16_t>> live;  // (session, instance) still logged in
  std::uint64_t itch_total = 0;
  std::uint64_t soup_total = 0;
  std::uint64_t outlog_verified = 0;   // messages found in the log and equal to the regeneration
  std::uint64_t outlog_appended = 0;   // messages regenerated into the log
  std::uint64_t outlog_rewritten = 0;  // files cut back at a difference
  std::uint64_t snapshot_index = 0;    // the engine started from the snapshot at this index (0: none)
  std::uint64_t state_hash = 0;        // engine state hash after the replay
  std::uint64_t itch_kept = 0;         // itch.bin messages that were there and verified before recovery
                                       // (md republishes the rest: MdConfig::republish_from)
};

// What recovery needs of the day's configuration.
struct RecoveryLayout {
  std::string outlog_root;
  std::uint32_t date = 0;
  std::vector<std::uint32_t> session_ids;  // sorted ascending
};
[[nodiscard]] RecoveryLayout recovery_layout(const ExchangeConfig& cfg);

// Replays records 1..rr.chain.last_index of `dir` into `eng` (reset first) and makes
// `out` (open) equal to the regenerated output. `expected_config`: the configuration
// file's tables, compared with the journaled Config records.
// Cuts every output-log file of the day to zero messages (a rejoin from an empty
// journal); `out` is reopened.
[[nodiscard]] std::expected<void, std::string> reset_outlog(outlog::OutlogDay& out, const ExchangeConfig& cfg);

// Recovery steps 3-4 (06 §7): the engine from the newest valid snapshot at or below the
// journal's end in `snapshot_dir` (written by snapshotd, ADR-007; empty: none), then the
// journal after it; without a usable snapshot, the whole day. A snapshot is used only if
// the output log still holds everything up to it (S(P) ITCH messages and each session's
// next sequence - 1): the outputs after it are compared with the log and regenerated.
// Records up to the snapshot are still read (not applied) for what the sequencer and
// the gateways need: config, timers, snapshot ids, live sessions.
[[nodiscard]] std::expected<RecoveredDay, std::string> replay_day(SegDir& dir, const journal::RecoveryResult& rr,
                                                                  engine::Engine& eng, outlog::OutlogDay& out,
                                                                  const ExchangeConfig& cfg,
                                                                  std::span<const seq::ConfigBlob> expected_config,
                                                                  const std::string& snapshot_dir = {});

}  // namespace lle::exch
