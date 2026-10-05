#pragma once
// SoupBinTCP sequenced store over a bounded ring of the most recent messages (the
// loopback OUCH server's sessions and ttt_harness's order desk). Re-login replays what
// the ring still holds.
#include <cstddef>
#include <optional>
#include <span>

#include "common/types.h"
#include "proto/moldudp64/message_store.h"
#include "proto/soupbin/sequenced_store.h"

namespace lle::client {

class RingSequencedStore {
 public:
  RingSequencedStore(std::size_t max_messages, std::size_t max_bytes) : ring_(max_messages, max_bytes) {}
  [[nodiscard]] SeqNo next_seq() const noexcept { return ring_.highest() + 1; }
  bool append(std::span<const std::byte> m) noexcept { return ring_.append(m); }
  [[nodiscard]] std::optional<std::span<const std::byte>> get(SeqNo s) const noexcept { return ring_.get(s); }

 private:
  mold::MessageRing ring_;
};
static_assert(soup::SequencedStoreLike<RingSequencedStore>);

}  // namespace lle::client
