#pragma once
// The exchange worlds' truth (sim worlds `exchange` and `exchange_ha`): a node's journal
// replayed through a fresh engine (regeneration), with what the oracles need from it:
// every record, the ITCH stream, each session's OUCH stream, the life of every order
// (accepted, executions, closed) and the consuming responses per UserRefNum. Also the
// durable time of every journal record (DurableTap, from the node's journal device)
// and whether an auction is collecting interest (snapshot probes).
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/types.h"
#include "engine/engine.h"
#include "engine/records.h"
#include "journal/record.h"
#include "proto/ouch50/ouch50.h"
#include "sim/node.h"
#include "sim/world.h"
#include "sim/worlds/journal_device.h"

namespace lle::sim::exch {

struct Out {
  std::uint64_t index = 0;
  std::vector<std::byte> bytes;
};
struct Rec {
  journal::RecordType type = journal::RecordType::Pad;
  Nanos ts = 0;
  std::uint32_t session = 0;  // OUCH / SessionEvent
  journal::SessionEventKind event = journal::SessionEventKind::Login;
  std::uint16_t instance = 0;
  SeqNo requested = 0;
  std::vector<std::byte> payload;  // OUCH payload
  std::uint16_t flags = 0;
  std::uint32_t epoch = 0;     // the record's epoch (paired: EpochStart numbering)
  std::uint16_t admin = 0;     // Admin: engine::AdminCommand
  std::uint32_t primary = 0;   // EpochStart: the epoch's primary node
};
struct OrderLife {
  std::uint32_t session = 0;
  std::uint32_t urn = 0;
  std::uint64_t accepted = 0;  // index of the record that made it live
  std::uint64_t closed = 0;    // index at which its open quantity reached 0 (0: open at the end)
  std::int64_t open = 0;
  std::vector<std::uint64_t> executions;  // record indices
  std::vector<Nanos> execution_ts;
  ouch50::CrossType cross = ouch50::CrossType::Continuous;
};
struct Truth {
  bool ok = false;
  std::string error;
  std::vector<Rec> recs;  // index i at recs[i-1]
  std::vector<std::uint32_t> crc;  // content crc of record i at crc[i-1]
  std::vector<Out> itch;
  std::map<std::uint32_t, std::vector<Out>> ouch;
  std::map<std::pair<std::uint32_t, std::uint32_t>, OrderLife> orders;  // (session, urn)
  // (session, urn) -> consuming responses (A, U-new, J) with their indices.
  std::map<std::pair<std::uint32_t, std::uint32_t>, std::vector<std::uint64_t>> consumed;
  std::uint64_t day_end = 0;
  std::uint64_t state_hash = 0;  // the fresh engine's, after the last record
  // The opening freeze (09:25 StateChange) and the opening cross (09:30 Cross 'O'):
  // on-open and held orders are frozen in between; on-close orders from the closing
  // freeze (15:50) until the close, with no cross-cancel permit in the worlds; and
  // cancel-on-disconnect spares frozen orders (matching-rules.md 13.2, 13.6).
  std::uint64_t open_freeze = 0, open_cross = 0, close_freeze = 0;
  [[nodiscard]] bool frozen_at(std::uint64_t d, const OrderLife& o) const {
    if (o.cross == ouch50::CrossType::Closing) {
      // Until the symbol closes: its closing cross, or later for a symbol halted then
      // (the engine keeps it frozen); its orders are gone after the close either way.
      return close_freeze != 0 && d >= close_freeze;
    }
    if (open_freeze == 0 || d < open_freeze) return false;
    if (open_cross != 0 && d >= open_cross) return false;
    return open_cross == 0 || o.accepted < open_cross;
  }
};

// What one subscriber delivered.
struct SubTruth {
  std::vector<std::vector<std::byte>> msgs;  // msgs[k-1]: message k as delivered (empty: covered by a snapshot)
  std::vector<Nanos> rx_at;                  // its delivery time (0: covered by a snapshot)
  SeqNo next = 1;                            // next sequence the feed must deliver
  std::uint64_t delivered = 0, snapshots = 0, snapshot_failures = 0, covered = 0;
  bool ended = false;
  SeqNo end_at = 0;
};

// Replays the journal at `journal_prefix` on node `n`'s disk (read-only) through a
// fresh engine. `schedule` names the timers (opening freeze and cross). Truth::crc
// holds every record's canonical content crc.
[[nodiscard]] Truth regenerate(Node& n, const std::string& journal_prefix, std::uint32_t date,
                               const std::vector<engine::ScheduleEntry>& schedule);
// The canonical content crc of every record of a node's journal (index i at [i-1]).
[[nodiscard]] std::vector<std::uint32_t> canonical_crcs(Node& n, const std::string& journal_prefix,
                                                       std::uint32_t date);

// The durable time of journal records, keyed by (index, content crc): a record of an
// earlier history that recovery left on the disk vouches only for itself.
using DurableMap = std::map<std::pair<std::uint64_t, std::uint32_t>, Nanos>;

// Durable journal records, from the node's journal device. On every write that
// completed durably the records it carried are parsed from the durable image (a batch
// is a 4 KiB-padded run of whole records starting at a block boundary); on a sync or a
// header write the whole durable image is scanned block by block. A record counts only
// if its seal verifies under the segment's nonce (stale bytes of a recycled spare do
// not). Each record keeps the first time it was seen durable.
class DurableTap final : public worlds::JournalDurableObserver {
 public:
  DurableTap(World& w, DurableMap& durable_at) : w_(w), durable_at_(durable_at) {}
  void on_durable(Disk& disk, std::uint32_t fidx, std::uint64_t off, std::uint32_t len) override;

 private:
  std::uint64_t parse(std::span<const std::byte> img, std::uint64_t from, std::uint64_t to, const journal::Sealer& s,
                      Nanos now);
  World& w_;
  DurableMap& durable_at_;
  std::map<std::uint32_t, std::unique_ptr<journal::Sealer>> sealers_;  // per file, the segment's nonce
};

// An auction is collecting interest: the opening or closing cross is frozen and not
// done for some symbol, or a symbol is halted (its halt cross is pending).
[[nodiscard]] bool auction_in_progress(const engine::Engine& e);

}  // namespace lle::sim::exch
