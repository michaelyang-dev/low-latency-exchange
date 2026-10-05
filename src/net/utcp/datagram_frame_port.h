#pragma once
// DatagramFramePort: a utcp FramePort over any env::DatagramPortLike, carrying raw IPv4
// packets (StackConfig::link = LinkType::RawIp) as datagram payloads. This is how the
// deterministic simulator runs the real utcp code (07 §2.4, 09 `utcp` world): each node
// binds a sim::DatagramPort on `link_port`, and the simulator's loss, duplication,
// reordering, delay and partitions apply to utcp segments.
//
// The destination node is taken from the IPv4 destination address of each packet:
// datagram endpoint {dst_ip, link_port}.
#include <cstddef>
#include <cstdint>
#include <span>

#include "common/endian.h"
#include "common/types.h"
#include "env/concepts.h"
#include "net/utcp/wire.h"

namespace lle::net::utcp {

template <env::DatagramPortLike D>
class DatagramFramePort {
 public:
  DatagramFramePort(D& port, std::uint16_t link_port) : port_(port), link_port_(link_port) {}

  bool send_frame(std::span<const std::byte> f) {
    if (f.size() < kIpv4HeaderLen) return false;
    return port_.send(env::Endpoint{load_be32(f.data() + 16), link_port_}, f);
  }

  template <class Cb>
  std::size_t poll_frames(Cb&& cb) {
    return port_.poll_rx([&](const env::RxDatagram& r) { cb(r.data, r.hw_rx_ns); });
  }

 private:
  D& port_;
  std::uint16_t link_port_;
};

}  // namespace lle::net::utcp
