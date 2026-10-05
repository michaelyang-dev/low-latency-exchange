#pragma once
// Rejoin truncation of the L3 journal (10 §5 step 2): drop every record after index t.
//
// The truncation point comes from the epoch-based EPOCH_END handshake, never from CRC
// comparison. Records after t were never committed in the current history (the
// primary's log does not contain them), so removing them is safe even if they are
// durable here. Cold path; the journal writer must be quiesced (no writes in flight)
// and is repositioned afterwards by recover() + resume_writer().
//
// Order makes a crash at any point harmless:
//   1. segments whose first index is > t are recycled (re-zeroed, re-nonced: their
//      records can never validate again), newest first;
//   2. in the segment holding t, everything after t is zeroed and the 4 KiB block is
//      closed with a Pad (exactly what recovery does for a torn tail), then synced.
// A crash after step 1 leaves a valid journal that still ends after t; the rejoining
// node then simply truncates again. A crash never leaves a chain break.
//
// This belongs next to journal recovery; it lives in lle::repl until the journal owner
// adopts it (docs/design/replication.md, "Shared requests").
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "env/concepts.h"
#include "journal/journal_device.h"
#include "journal/recovery.h"
#include "journal/segment.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "journal/segment_scan.h"

namespace lle::repl {

struct TruncateResult {
  bool ok = false;
  journal::ChainState chain;     // the last record kept (index t, or 0 for an empty journal)
  std::size_t recycled = 0;      // segments re-prepared
  std::uint64_t zeroed_from = 0; // offset in the segment holding t where zeros begin
  std::string detail;
};

template <journal::SegmentDirLike Dir, env::RngLike Rng>
TruncateResult truncate_journal(Dir& dir, journal::SegmentPreparer<Dir, Rng>& prep, std::uint32_t day,
                                std::uint64_t t) {
  using namespace journal;
  TruncateResult r;
  detail::HeaderScan hs = detail::scan_headers(dir, day);
  struct Seg {
    std::size_t handle = 0;
    SegmentHeader header;
    std::uint64_t data_end = 0;
    std::uint64_t last_index = 0;
  };
  std::vector<Seg> segs;
  std::optional<std::size_t> holder;  // index into segs of the segment holding t
  std::uint64_t t_end = 0;            // offset just after record t
  ChainState chain_t{};
  ChainState chain{};
  bool first = true;
  auto sealer = std::make_unique<Sealer>();
  for (const auto& e : hs.assigned) {
    if (first) {
      chain = ChainState{e.header.first_index - 1, e.header.prev_last_crc, 0, 0};
      first = false;
    } else if (e.header.first_index != chain.last_index + 1 || e.header.prev_last_crc != chain.last_crc) {
      r.detail = "segment chain break";
      return r;
    }
    auto& dev = dir.device(e.handle);
    const std::uint64_t limit = std::min(dev.size(), e.header.segment_bytes);
    ChunkedReader<typename Dir::Device> rd(dev, limit);
    *sealer = Sealer(e.header.nonce);
    const WalkResult w = walk_segment(rd, *sealer, chain, kSegmentHeaderBytes,
                                      [&](const RecordView& v, std::uint64_t off, bool pad) {
                                        if (!pad && v.index() == t) {
                                          holder = segs.size();
                                          t_end = off + v.len();
                                          chain_t = ChainState{v.index(), sealer->content_of(v.data()), v.ts_ns(),
                                                               v.epoch()};
                                        }
                                        return true;
                                      });
    if (rd.io_error()) {
      r.detail = "read error";
      return r;
    }
    segs.push_back(Seg{e.handle, e.header, w.end, chain.last_index});
  }
  if (t != 0 && !holder) {
    if (segs.empty() || t >= chain.last_index) {
      // Nothing after t: the journal already ends at or before t.
      r.ok = t >= chain.last_index;
      r.chain = chain;
      r.detail = r.ok ? "nothing to truncate" : "truncation point not found";
      return r;
    }
    r.detail = "truncation point not found";
    return r;
  }
  // 1. Recycle every segment that starts after t, newest first.
  for (std::size_t k = segs.size(); k > 0; --k) {
    const Seg& s = segs[k - 1];
    if (s.header.first_index <= t) continue;
    if (!prep.recycle(s.handle)) {
      r.detail = "recycle failed";
      return r;
    }
    ++r.recycled;
  }
  // 2. Zero everything after t in its segment and close the block with a Pad.
  if (holder) {
    const Seg& s = segs[*holder];
    auto& dev = dir.device(s.handle);
    const std::uint64_t limit = std::min(dev.size(), s.header.segment_bytes);
    r.zeroed_from = t_end;
    if (s.data_end > t_end) {
      if (!detail::zero_range(dev, t_end, s.data_end, limit)) {
        r.detail = "zeroing failed";
        return r;
      }
    }
    const auto gap = static_cast<std::uint32_t>(align_up_block(t_end) - t_end);
    if (gap != 0) {
      const std::uint32_t pad_len = gap >= kHeaderBytes ? gap : gap + kBlockBytes;
      if (t_end + pad_len <= limit) {
        const Sealer seg_sealer(s.header.nonce);
        if (!detail::write_pad(dev, t_end, pad_len, chain_t, seg_sealer)) {
          r.detail = "pad failed";
          return r;
        }
      }
    }
    if (sync_device(dev) != 0) {
      r.detail = "sync failed";
      return r;
    }
    r.chain = chain_t;
  }
  r.ok = true;
  r.detail = "truncated to " + std::to_string(t);
  return r;
}

}  // namespace lle::repl
