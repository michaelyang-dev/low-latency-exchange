#pragma once
// Journal replay (06 §1, §11): engine state at index i = fold(apply, initial state,
// records 1..i). replay() walks the valid journal prefix in [from, to] and hands every
// record to a sink. The engine plugs in as a sink (its apply() takes a RecordView,
// 01 §8); tools use counting/validating sinks. A sink returns false to stop.
#include <array>
#include <concepts>
#include <cstdint>
#include <limits>

#include "journal/reader.h"
#include "journal/record.h"
#include "journal/segment_dir.h"

namespace lle::journal {

template <class S>
concept ReplaySink = requires(S& s, const RecordView& r) {
  { s.on_record(r) } -> std::same_as<bool>;
};

struct ReplayRange {
  std::uint64_t from = 1;
  std::uint64_t to = std::numeric_limits<std::uint64_t>::max();
};

struct ReplayStats {
  ReadStop stop = ReadStop::Empty;
  std::uint64_t first_index = 0;
  std::uint64_t last_index = 0;
  std::uint64_t records = 0;
  std::array<std::uint64_t, kMaxRecordType + 1> by_type{};
};

template <SegmentDirLike Dir, ReplaySink S>
ReplayStats replay(Dir& dir, const ReplayRange& range, S& sink, std::uint32_t day = 0) {
  ReplayStats st;
  ReadOptions o;
  o.day = day;
  o.from_index = range.from;
  o.to_index = range.to;
  const ReadSummary sum = read_journal(dir, o, [&](const RecordView& r, const RecordLocation&) {
    if (st.records == 0) st.first_index = r.index();
    st.last_index = r.index();
    ++st.records;
    ++st.by_type[r.type_raw()];
    return sink.on_record(r);
  });
  st.stop = sum.stop;
  return st;
}

}  // namespace lle::journal
