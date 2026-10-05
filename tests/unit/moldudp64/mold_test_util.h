#pragma once
// Helpers shared by the MoldUDP64 unit tests.
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "common/hash.h"
#include "proto/moldudp64/line_arbiter.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::mold::test {

using Bytes = std::vector<std::byte>;

inline const Session kSession("TEST000001");

// Deterministic message for sequence `s`: 4..23 bytes.
inline Bytes msg_for(SeqNo s) {
  Bytes m(4 + s % 20);
  for (std::size_t i = 0; i < m.size(); ++i) m[i] = static_cast<std::byte>(mix64(s * 131 + i));
  return m;
}

// A data packet carrying messages [first, first + count) built with msg_for().
inline Bytes data_packet(SeqNo first, std::uint16_t count, const Session& s = kSession) {
  Bytes buf(65536);
  PacketBuilder b(buf, s, first);
  for (SeqNo q = first; q < first + count; ++q) {
    const Bytes m = msg_for(q);
    b.add(m);
  }
  const auto pkt = b.finish();
  return Bytes(pkt.begin(), pkt.end());
}

inline Bytes control_packet(SeqNo next, bool eos, const Session& s = kSession) {
  Bytes b(kHeaderLen);
  encode_control(b, s, next, eos);
  return b;
}

struct ArbiterSink {
  std::vector<std::pair<SeqNo, Bytes>> delivered;
  std::vector<std::pair<Server, RequestPacket>> requests;
  std::vector<std::pair<SeqNo, SeqNo>> snapshots;
  std::vector<SeqNo> ends;

  void on_message(SeqNo s, std::span<const std::byte> m) { delivered.emplace_back(s, Bytes(m.begin(), m.end())); }
  void send_request(Server v, std::span<const std::byte> b) {
    const auto r = decode_request(b);
    requests.emplace_back(v, r ? *r : RequestPacket{});
  }
  void on_snapshot_needed(SeqNo next, SeqNo known_end) { snapshots.emplace_back(next, known_end); }
  void on_end_of_session(SeqNo e) { ends.push_back(e); }

  // True iff delivered == [from, to) in order with msg_for() content.
  [[nodiscard]] bool delivered_range(SeqNo from, SeqNo to, std::size_t start_index = 0) const {
    if (delivered.size() - start_index != to - from) return false;
    for (SeqNo s = from; s < to; ++s) {
      const auto& d = delivered[start_index + (s - from)];
      if (d.first != s || d.second != msg_for(s)) return false;
    }
    return true;
  }
};

}  // namespace lle::mold::test
