#pragma once
// ReplayStore: the released sequenced messages of one SoupBinTCP session, for
// re-login replay (03 §5 "Replay", 06 §8, N-17). soup::SequencedStoreLike.
//
//   - the newest messages live in an in-memory ring (mold::MessageRing: fixed
//     message and byte budgets, oldest evicted first, allocated at construction);
//   - older ones are read back from the session's output-log file
//     (outlog/<day>/soup-<session>.bin), which the io stage appends every released
//     message to (06 §8). A message's SoupBinTCP sequence number is its position in
//     that file, so the file and the ring number messages identically.
//
// After a restart the ring starts empty at the output log's next sequence number
// (recovery regenerates the log from the journal first, 06 §8), and everything before
// it is served from the file.
//
// The io stage writes asynchronously; a message evicted from the ring is normally in
// the file long before anyone asks for it (the ring holds far more than the io
// stage's write buffer). If it is not there yet, get() reports it unavailable and the
// SoupBinTCP session closes (StoreUnavailable); the client logs in again and resumes
// (03 §5). append() and ring reads never allocate; the first fallback read opens the
// reader (cold path).
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include "common/types.h"
#include "outlog/format.h"
#include "outlog/reader.h"
#include "proto/moldudp64/message_store.h"
#include "proto/soupbin/sequenced_store.h"

namespace lle::gw {

struct ReplayStoreStats {
  std::uint64_t ring_reads = 0;
  std::uint64_t log_reads = 0;
  std::uint64_t misses = 0;
};

template <class Reader = outlog::OutlogReader>
class ReplayStore {
 public:
  // `first_seq`: the sequence number the next appended message gets (1 at day start,
  // log count + 1 after recovery). `log_path`: the session's output-log data file
  // (empty: no fallback).
  ReplayStore(std::size_t ring_messages, std::size_t ring_bytes, SeqNo first_seq, std::string log_path)
      : ring_(ring_messages, ring_bytes, first_seq),
        path_(std::move(log_path)),
        scratch_(std::make_unique<std::byte[]>(outlog::kMaxMessageBytes)) {}
  ReplayStore(const ReplayStore&) = delete;
  ReplayStore& operator=(const ReplayStore&) = delete;

  [[nodiscard]] SeqNo next_seq() const noexcept { return ring_.highest() + 1; }

  bool append(std::span<const std::byte> msg) noexcept { return ring_.append(msg); }

  [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo seq) const noexcept {
    if (seq == 0 || seq > ring_.highest()) return std::nullopt;
    if (seq >= ring_.lowest()) {
      ++stats_.ring_reads;
      return ring_.get(seq);
    }
    return from_log(seq);
  }

  [[nodiscard]] SeqNo ring_lowest() const noexcept { return ring_.lowest(); }
  [[nodiscard]] const ReplayStoreStats& stats() const noexcept { return stats_; }

 private:
  std::optional<std::span<const std::byte>> from_log(SeqNo seq) const noexcept {
    if (path_.empty()) return miss();
    if (!opened_) {
      if (!reader_.open(path_)) return miss();
      opened_ = true;
    }
    if (seq > reader_.count()) {
      if (!reader_.refresh() || seq > reader_.count()) return miss();
    }
    auto r = reader_.read(seq, std::span<std::byte>(scratch_.get(), outlog::kMaxMessageBytes));
    if (!r) return miss();
    ++stats_.log_reads;
    return *r;
  }
  std::optional<std::span<const std::byte>> miss() const noexcept {
    ++stats_.misses;
    return std::nullopt;
  }

  mold::MessageRing ring_;
  std::string path_;
  mutable Reader reader_;
  mutable bool opened_ = false;
  std::unique_ptr<std::byte[]> scratch_;
  mutable ReplayStoreStats stats_;
};

static_assert(soup::SequencedStoreLike<ReplayStore<>>);

}  // namespace lle::gw
