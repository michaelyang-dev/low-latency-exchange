#pragma once
// The engine section of a snapshot (06 §9): how the matching engine's state is
// stored in the snapshot container (snapshot/format.h) and loaded back.
//
// The container's payload is the engine's canonical state encoding
// (Engine::snapshot, engine/engine.cpp walk()), little-endian throughout:
//
//   u64  magic   "LLEENGS1" (0x3153474E45454C4C)
//   u32  version 1
//   day          local midnight, date, started flag, session, initial session,
//                milestones, next exchange reference, next match number,
//                ITCH message count (= S(P)), MWCB state, market parameters
//   schedule     every Schedule entry (timers and parameters) as loaded
//   symbols      static data, cross/halt/LULD/IPO state, reference prices
//   accounts     firms, entry-disabled bits, cross permits, UserRefNum trackers
//   sessions     id, account, flags, live instances, OUCH messages sent
//   orders       record count, then per symbol: bids best to worst, asks best to
//                worst (displayed then non-displayed FIFO per level, reserve
//                records included), the pending cross list, the midpoint pegs
//   risk gate    limits, open and executed notional, kill switches, symbol
//                rules, rate buckets, duplicate filters (engine/risk/risk_gate.h)
//
// Equal states give equal bytes, so state_hash() (FNV-1a 64 of the payload) is
// comparable across primary, backup and replay. The header carries what
// recovery needs before it touches the payload: S(P) = Engine::itch_count()
// and the SoupBinTCP next sequence number per session (OUCH messages sent + 1).
//
// This library (lle_snapshot_engine) is the only place that ties the container
// to the engine; lle_snapshot itself stays engine-independent.
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "engine/engine.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshot/writer.h"

namespace lle::snap {

inline constexpr std::uint64_t kEngineMagic = 0x3153474E45454C4Cull;  // "LLEENGS1"
inline constexpr std::uint32_t kEngineVersion = 1;
static_assert(kEngineMagic == engine::Engine::kMagic && kEngineVersion == engine::Engine::kVersion);

// Identity fields the engine does not know (from the journal and the build).
struct EngineSnapshotIds {
  std::uint32_t day = 0;  // YYYYMMDD (0: the engine's date)
  std::uint32_t epoch = 0;
  std::uint64_t index = 0;  // P: the last journal index applied
  std::uint64_t snapshot_id = 0;
  std::uint64_t build_id = 0;
};

[[nodiscard]] SnapshotMeta engine_meta(const engine::Engine& e, const EngineSnapshotIds& ids);
// Ascending by session id; next_seq = OUCH messages sent + 1.
[[nodiscard]] std::vector<SessionSeq> engine_sessions(const engine::Engine& e);

// The engine payload into an open writer (created with engine_meta/engine_sessions).
void write_engine(const engine::Engine& e, Writer& w);
// File: snap/<day>/<index:020>.snap in `day_dir`, published atomically; returns the path.
[[nodiscard]] std::expected<std::string, Error> save_engine(const engine::Engine& e, const EngineSnapshotIds& ids,
                                                            const std::string& day_dir,
                                                            const WriterOptions& opts = {});
// Like save_engine(), published through `storage` (snapshot/storage.h: the simulator's
// disk) with the same sequence as on POSIX.
[[nodiscard]] std::expected<std::string, Error> save_engine(Storage& storage, const engine::Engine& e,
                                                            const EngineSnapshotIds& ids, const std::string& day_dir,
                                                            const WriterOptions& opts = {});
// Memory image with the same bytes (tests, the simulator).
[[nodiscard]] std::expected<std::vector<std::byte>, Error> engine_image(const engine::Engine& e,
                                                                        const EngineSnapshotIds& ids,
                                                                        const WriterOptions& opts = {});

enum class EngineLoadError : std::uint8_t {
  NotEngine,     // payload too short or wrong magic
  BadVersion,    // engine section version
  Restore,       // the engine rejected the payload
  StateHash,     // restored state hash != header state_hash
  MoldSeq,       // restored ITCH count != header S(P)
  Sessions,      // session table != the restored sessions' OUCH counts
};
[[nodiscard]] std::string_view to_string(EngineLoadError e) noexcept;

// Loads the payload of a validated snapshot (Reader::open) into `e` and checks
// it against the header. On failure the engine is reset (empty day).
[[nodiscard]] std::expected<void, EngineLoadError> load_engine(Reader& r, engine::Engine& e);

}  // namespace lle::snap
