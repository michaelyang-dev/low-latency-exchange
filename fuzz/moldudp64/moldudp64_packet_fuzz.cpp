// Fuzz target: MoldUDP64 packet decode, Depacketizer and re-request handling.
// The input is a sequence of [u16 big-endian length][bytes] chunks; each chunk
// is offered as a downstream packet to PacketView, a Depacketizer (both gap
// policies) and as a request to a RerequestServer.
// Properties: no crash; parse accepts exactly the packets whose blocks fill
// them; the depacketizer delivers strictly consecutive sequences; every reply
// the server sends is itself a valid packet within max_packet.
#include <cstdint>
#include <span>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "proto/moldudp64/depacketizer.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/moldudp64/rerequest_server.h"

using namespace lle;
using namespace lle::mold;

namespace {

// Drop policy: deliveries are consecutive from first_seq. Skip policy: they
// jump over gaps by design, so they are only strictly increasing.
struct CheckSink {
  bool consecutive = true;
  SeqNo last = 0;
  bool any = false;
  void on_message(SeqNo s, std::span<const std::byte>) {
    if (consecutive) {
      LLE_ASSERT(any ? s == last + 1 : s == 1, "depacketizer delivered out of order");
    } else {
      LLE_ASSERT(!any || s > last, "depacketizer delivered a sequence twice");
    }
    last = s;
    any = true;
  }
  void on_gap(SeqNo a, SeqNo b) { LLE_ASSERT(a < b); }
  void on_end_of_session(SeqNo) {}
};

// Independent re-check of the strict packet grammar.
bool well_formed(std::span<const std::byte> p) {
  if (p.size() < kHeaderLen) return false;
  const std::uint16_t count = load_be16(p.data() + 18);
  const std::size_t n = count == kEndOfSessionCount ? 0 : count;
  if (load_be64(p.data() + 10) > ~SeqNo{0} - n) return false;
  std::size_t at = kHeaderLen;
  for (std::size_t i = 0; i < n; ++i) {
    if (p.size() - at < 2) return false;
    const std::size_t len = load_be16(p.data() + at);
    at += 2;
    if (p.size() - at < len) return false;
    at += len;
  }
  return at == p.size();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> in(reinterpret_cast<const std::byte*>(data), size);
  static MessageRing store = [] {
    MessageRing r(4096, 1 << 18);
    for (SeqNo s = 1; s <= 3000; ++s) {
      std::byte m[40];
      for (std::size_t i = 0; i < sizeof m; ++i) m[i] = static_cast<std::byte>(s + i);
      r.append(std::span<const std::byte>(m, 1 + s % 40));
    }
    return r;
  }();
  RerequestConfig rc;
  rc.session = Session("FUZZSESS01");
  rc.max_packet = 512;
  rc.bucket_capacity = 8;
  rc.max_sources = 4;
  RerequestServer<MessageRing> server(rc, store);

  Depacketizer drop(DepacketizerConfig{Session(), 1, GapPolicy::Drop});
  Depacketizer skip(DepacketizerConfig{Session(), 1, GapPolicy::Skip});
  CheckSink sd, ss;
  ss.consecutive = false;
  std::size_t at = 0;
  Nanos now = 0;
  while (size - at >= 2) {
    const std::size_t len = load_be16(in.data() + at);
    at += 2;
    const std::size_t n = std::min(len, size - at);
    const auto chunk = in.subspan(at, n);
    at += n;
    now += 1000;

    const auto pv = PacketView::parse(chunk);
    LLE_ASSERT(pv.has_value() == well_formed(chunk), "parse disagrees with the packet grammar");
    if (pv) {
      std::size_t count = 0;
      SeqNo expect = pv->seq();
      pv->for_each([&](SeqNo s, std::span<const std::byte> m) {
        LLE_ASSERT(s == expect++);
        LLE_ASSERT(m.data() >= chunk.data() && m.data() + m.size() <= chunk.data() + chunk.size());
        ++count;
      });
      LLE_ASSERT(count == pv->message_count());
    }
    drop.on_packet(chunk, sd);
    skip.on_packet(chunk, ss);
    (void)decode_request(chunk);
    server.on_request(chunk, env::Endpoint{static_cast<std::uint32_t>(n % 7), 1}, now,
                      [&](const env::Endpoint&, std::span<const std::byte> reply) {
                        LLE_ASSERT(reply.size() <= rc.max_packet);
                        const auto rp = PacketView::parse(reply);
                        LLE_ASSERT(rp.has_value() && rp->message_count() >= 1, "server sent a bad reply");
                      });
  }
  return 0;
}

// Seeds: a framed data packet, heartbeat, end of session and a valid request.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 4 || cap < 512) return 0;
  std::vector<std::byte> pkt(256);
  std::size_t n = 0;
  const Session s = index == 3 ? Session("FUZZSESS01") : Session("ANYSESSION");
  if (index == 0) {
    PacketBuilder b(pkt, s, 1);
    const std::byte m[5] = {std::byte{'A'}, std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    b.add(m);
    b.add({});
    b.add(m);
    n = b.finish().size();
  } else if (index <= 2) {
    n = encode_control(pkt, s, 4, index == 2);
  } else {
    n = encode_request(pkt, RequestPacket{s, 10, 50});
  }
  store_be16(buf, static_cast<std::uint16_t>(n));
  std::memcpy(buf + 2, pkt.data(), n);
  return n + 2;
}
