#pragma once
// Lingering close for SoupBinTCP servers (gateway, GLIMPSE).
//
// A session that ends (End of Session 'Z', Login Rejected, a protocol violation) has
// usually just produced its last bytes. Closing the port right away can lose them:
// a port that stages transmit data in user space (io_uring: a SEND still in flight is
// cancelled by close()) drops whatever it holds, and any remainder the port did not
// accept is never written. A closing connection therefore keeps flushing until both
// the session's transmit buffer and the port's staging are empty, or a bound expires,
// and only then is the port closed. Ports that hand bytes straight to the kernel
// (sockets) report nothing pending; the kernel sends what it holds before the FIN.
#include <concepts>
#include <cstddef>

#include "common/types.h"
#include "env/concepts.h"

namespace lle::md {

// Default bound on a lingering close (a peer that stops reading cannot hold a slot).
inline constexpr Nanos kDefaultCloseLinger = 1'000'000'000;

// Bytes the port accepted but has not handed to the kernel yet (0 when the port does
// not stage transmit data).
template <class Port>
[[nodiscard]] std::size_t port_tx_pending(const Port& p, env::ConnId c) noexcept {
  if constexpr (requires {
                  { p.tx_pending(c) } -> std::convertible_to<std::size_t>;
                }) {
    return p.tx_pending(c);
  } else {
    return 0;
  }
}

}  // namespace lle::md
