#pragma once
// ItchStore: the released ITCH stream for the MoldUDP64 re-request server (03 §6,
// 07 §3 N-18: "the re-request server, reading the in-memory ring and then the output
// log"). mold::MessageStoreLike.
//
// The newest messages are in a mold::MessageRing; older ones are read from the
// output log's itch.bin, whose message k is MoldUDP64 sequence k (06 §8). With the
// log attached the store claims everything from sequence 1: a request the log cannot
// serve yet (the io stage writes asynchronously) is answered "unavailable" by the
// server, and the receiver asks again (03 §6, R1b D1).
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

namespace lle::md {

template <class Reader = outlog::OutlogReader>
class ItchStore {
 public:
  ItchStore(std::size_t ring_messages, std::size_t ring_bytes, SeqNo first_seq, std::string log_path)
      : ring_(ring_messages, ring_bytes, first_seq),
        path_(std::move(log_path)),
        scratch_(std::make_unique<std::byte[]>(outlog::kMaxMessageBytes)) {}
  ItchStore(const ItchStore&) = delete;
  ItchStore& operator=(const ItchStore&) = delete;

  bool append(std::span<const std::byte> msg) noexcept { return ring_.append(msg); }

  [[nodiscard]] SeqNo highest() const noexcept { return ring_.highest(); }
  [[nodiscard]] SeqNo lowest() const noexcept { return path_.empty() ? ring_.lowest() : 1; }
  [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo seq) const noexcept {
    if (seq == 0 || seq > ring_.highest()) return std::nullopt;
    if (seq >= ring_.lowest()) return ring_.get(seq);
    if (path_.empty()) return std::nullopt;
    if (!opened_) {
      if (!reader_.open(path_)) return std::nullopt;
      opened_ = true;
    }
    if (seq > reader_.count() && (!reader_.refresh() || seq > reader_.count())) return std::nullopt;
    auto r = reader_.read(seq, std::span<std::byte>(scratch_.get(), outlog::kMaxMessageBytes));
    if (!r) return std::nullopt;
    ++log_reads_;
    return *r;
  }

  [[nodiscard]] std::uint64_t log_reads() const noexcept { return log_reads_; }

 private:
  mold::MessageRing ring_;
  std::string path_;
  mutable Reader reader_;
  mutable bool opened_ = false;
  std::unique_ptr<std::byte[]> scratch_;
  mutable std::uint64_t log_reads_ = 0;
};

static_assert(mold::MessageStoreLike<ItchStore<>>);

}  // namespace lle::md
