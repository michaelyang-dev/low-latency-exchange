#pragma once
// Discrete events (09 §2): every stage poll, packet arrival, disk completion
// and fault is one Event in the world's heap, ordered by (virtual time, seq).
// seq is a global insertion counter, so ordering is total and deterministic.
#include <cstdint>

#include "common/types.h"

namespace lle::sim {

using NodeId = std::uint32_t;
inline constexpr NodeId kNoNode = 0xFFFF'FFFFu;
using HandlerId = std::uint16_t;

struct Event {
  Nanos at = 0;
  std::uint64_t seq = 0;
  std::uint64_t a = 0;       // handler-defined payload
  std::uint64_t b = 0;       // handler-defined payload
  std::uint64_t digest = 0;  // payload digest folded into the trace hash
  NodeId node = kNoNode;
  HandlerId handler = 0;
  std::uint16_t kind = 0;  // handler-defined subtype
};

// What a handler reports back. Stale events (cancelled by a generation bump)
// return counted=false and are left out of the event count and trace hash.
struct Dispatch {
  bool counted = true;
  std::uint64_t result = 0;  // outcome digest (e.g. "stage did work"), hashed
};

using HandlerFn = Dispatch (*)(void* ctx, const Event& ev);

}  // namespace lle::sim
