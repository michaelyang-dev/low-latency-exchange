#pragma once
// The gateway's only check on order-entry payloads (ADR-027): framing and length.
// SoupBinTCP framing is the ServerSession's; here a delivered Unsequenced Data payload
// becomes the sequencer's InboundMsg with its routing metadata. Every OUCH decode,
// validation and client-visible reject happens in the engine, from the journaled
// bytes, so primary and mirror streams stay identical (03 §4, 07 §3).
//
// A payload longer than the queue slot (seq::InboundMsg::kMaxBytes, above the largest
// legal inbound OUCH message) is forwarded truncated with journal::kFlagMalformedInput:
// the engine still decides the reject (journal/record.h).
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "journal/record.h"
#include "sequencer/sequencer.h"

namespace lle::gw {

inline void make_inbound(seq::InboundMsg& m, std::uint32_t session_id, std::uint32_t account, std::uint16_t instance,
                         std::span<const std::byte> payload, std::uint64_t rx_tsc) noexcept {
  m.session_id = session_id;
  m.account = account;
  m.instance = instance;
  m.rx_tsc = rx_tsc;
  m.reserved = 0;
  const std::size_t n = std::min(payload.size(), seq::InboundMsg::kMaxBytes);
  m.len = static_cast<std::uint16_t>(n);
  m.flags = payload.size() > seq::InboundMsg::kMaxBytes ? journal::kFlagMalformedInput : std::uint16_t{0};
  if (n != 0) std::memcpy(m.bytes, payload.data(), n);
}

}  // namespace lle::gw
