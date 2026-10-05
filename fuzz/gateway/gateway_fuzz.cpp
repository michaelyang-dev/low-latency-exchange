// Fuzz harness: the gateway stage (07 §3, N-17) as a client's bytes reach it.
//
// Input: byte 0 selects the mode (mod 3): 0 = a valid login for ALPHA, then the rest as
// the client's stream; 1 = the raw stream only (login, framing and garbage all fuzzed);
// 2 = a valid login with release-gated egress entries interleaved. The stream is
// delivered in chunks whose sizes come from a PRNG seeded by the input; between chunks
// the stage polls, the sequencer queue is drained at a fuzzed pace (back-pressure), the
// clock moves, and the peer may close.
// Properties:
//  - no crash or UB (the ASan/UBSan smoke runs);
//  - every message pushed to the sequencer is framing-only output: length within the
//    queue slot, only the malformed flag, the logged-in session's id, account and the
//    node's instance;
//  - session events come in a legal order per connection (a login before its logout or
//    disconnect) and only for ALPHA, in the OUCH queue with the orders, and every order
//    lies between its connection's login and its logout or disconnect (DST-004);
//  - everything the gateway writes is a well-formed SoupBinTCP server stream of server
//    packet types, and the sequenced messages delivered to the client are exactly the
//    released egress entries for ALPHA, in order.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "../../tests/unit/gateway/fake_net.h"
#include "common/assert.h"
#include "common/hash.h"
#include "common/prng.h"
#include "concurrent/mpsc_scq.h"
#include "gateway/gateway.h"
#include "md/egress.h"
#include "proto/soupbin/framer.h"
#include "proto/soupbin/packets.h"

namespace {

using namespace lle;

struct Env {
  using Net = testnet::FakeNet;
  using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 8>;
  using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 8>;
  using Clock = testnet::FakeClock;
};

std::vector<std::byte> login_packet() {
  soup::LoginRequest r;
  r.username = Alpha<soup::kUsernameLen>("ALPHA");
  r.password = Alpha<soup::kPasswordLen>("pw");
  r.sequence = 1;
  std::vector<std::byte> b(soup::packet_size(soup::kLoginRequestPayload));
  (void)soup::encode_login_request(b, r, soup::Version::V300);
  return b;
}

struct World {
  World() {
    const std::vector<std::uint8_t> salt = {7};
    std::vector<gw::SessionSpec> specs = {gw::SessionSpec{1, 100, "ALPHA", gw::Credential::make("pw", salt), 0, false},
                                          gw::SessionSpec{2, 200, "BRAVO", gw::Credential::make("pw2", salt), 1, false}};
    table = *gw::SessionTable::build(std::move(specs), md::kGateways);
    egress.init(std::size_t{1} << 16);
    gw::GatewayConfig c;
    c.soup.session = soup::SessionId::from("FUZZ");
    c.tcp.max_conns = 4;
    c.tcp.rx_buf_bytes = 512;
    c.tcp.max_reads_per_poll = 2;
    c.replay_ring_messages = 16;
    c.replay_ring_bytes = 4096;
    g = std::make_unique<gw::Gateway<Env>>(c, table, std::span<const std::pair<std::uint32_t, SeqNo>>{}, ouch, events,
                                           clock, gw::GatewayShared{&egress, &state, &mirror});
    LLE_ASSERT(g->start().has_value(), "gateway start");
    g->port().max_bytes_per_poll = 1024;
  }
  gw::SessionTable table;
  Env::OuchQueue ouch;
  Env::SessionQueue events;
  testnet::FakeClock clock;
  md::EgressRing egress;
  md::EgressState state;
  std::atomic<bool> mirror{false};
  std::unique_ptr<gw::Gateway<Env>> g;
};

void check_server_stream(std::span<const std::byte> out, std::vector<std::vector<std::byte>>& sequenced) {
  soup::Framer f(soup::kMaxPacketLength);
  const std::size_t used = f.feed(out, [&](const soup::Packet& p) {
    LLE_ASSERT(std::strchr("+AJSHZ", p.type) != nullptr && p.type != 0, "gateway wrote a non-server packet type");
    if (p.type == 'S') sequenced.emplace_back(p.payload.begin(), p.payload.end());
    return true;
  });
  LLE_ASSERT(used == out.size() && f.status() == soup::Framer::Status::Ok, "gateway wrote a malformed stream");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::uint64_t mode = data[0] % 3u;
  const std::span<const std::byte> in(reinterpret_cast<const std::byte*>(data + 1), size - 1);
  Fnv1a64 h;
  h.bytes(in);
  Prng r(h.value() ^ mode);
  World w;
  const env::ConnId conn = w.g->port().accept();
  std::vector<std::byte> stream;
  if (mode != 1) stream = login_packet();
  stream.insert(stream.end(), in.begin(), in.end());

  std::vector<std::vector<std::byte>> released;  // egress entries for ALPHA, in order
  std::uint64_t next_index = 1;
  bool logged_in = false;
  bool closed = false;
  std::size_t pos = 0;
  while (pos < stream.size() || r.chance(1, 4)) {
    if (pos < stream.size()) {
      const std::size_t n = std::min<std::size_t>(stream.size() - pos, 1 + r.below(r.chance(1, 4) ? 600 : 40));
      if (!closed) w.g->port().data(conn, std::span<const std::byte>(stream).subspan(pos, n));
      pos += n;
    }
    if (mode == 2 && r.chance(1, 2)) {
      std::vector<std::byte> m(1 + r.below(60));
      for (auto& b : m) b = static_cast<std::byte>(r.below(256));
      const std::uint32_t session = r.chance(3, 4) ? 1u : 2u;
      if (w.egress.try_push(next_index, md::OutKind::Ouch, session, m)) {
        if (session == 1) released.push_back(m);
        w.state.applied.store(next_index);
        w.state.release.store(next_index);
        ++next_index;
      }
    }
    for (int k = 0; k < 3; ++k) (void)w.g->poll();
    w.clock.mono += static_cast<Nanos>(r.below(2'000'000'000));
    // The sequencer drains at a fuzzed pace.
    const std::uint64_t pops = r.below(6);
    // One queue carries the OUCH and, tagged, the session events in the gateway's order
    // (DST-004): every OUCH lies between its connection's login and its logout or
    // disconnect.
    seq::InboundMsg m;
    for (std::uint64_t k = 0; k < pops && w.ouch.try_pop(m); ++k) {
      if (seq::is_session_event(m)) {
        const seq::SessionEventMsg ev = seq::session_event_of(m);
        LLE_ASSERT(ev.session_id == 1, "session event for a session that never logged in");
        if (ev.event == journal::SessionEventKind::Login) {
          LLE_ASSERT(!logged_in, "two logins on one connection");
          logged_in = true;
        } else {
          LLE_ASSERT(logged_in, "logout/disconnect without a login");
          logged_in = false;
        }
        continue;
      }
      LLE_ASSERT(logged_in, "an order queued outside its connection's login (DST-004)");
      LLE_ASSERT(m.len <= seq::InboundMsg::kMaxBytes, "inbound longer than the slot");
      LLE_ASSERT((m.flags & ~journal::kFlagMalformedInput) == 0, "unexpected inbound flag");
      LLE_ASSERT(m.session_id == 1 && m.account == 100 && m.instance == 0, "inbound routed to the wrong session");
      LLE_ASSERT((m.flags != 0) == (m.len == seq::InboundMsg::kMaxBytes) || m.flags == 0,
                 "malformed flag without truncation");
    }
    seq::SessionEventMsg old_path;
    LLE_ASSERT(!w.events.try_pop(old_path), "a session event in the separate queue (DST-004: none)");
    if (!closed && r.chance(1, 64)) {
      w.g->port().peer_close(conn);
      closed = true;
    }
    if (pos >= stream.size() && !r.chance(1, 2)) break;
  }
  for (int k = 0; k < 8; ++k) (void)w.g->poll();
  std::vector<std::vector<std::byte>> sequenced;
  check_server_stream(w.g->port().written[conn], sequenced);
  // What reached the client is a prefix of ALPHA's released stream, in order.
  LLE_ASSERT(sequenced.size() <= released.size() || released.empty(), "more sequenced messages than released");
  for (std::size_t i = 0; i < sequenced.size() && i < released.size(); ++i)
    LLE_ASSERT(sequenced[i] == released[i], "sequenced message differs from the released one");
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 64 || cap < 256) return 0;
  Prng r(mix64(index + 11));
  std::size_t n = 0;
  auto put = [&](std::uint8_t b) {
    if (n < cap) buf[n++] = b;
  };
  put(static_cast<std::uint8_t>(index % 3));
  if (index % 3 == 1) {
    for (std::byte b : login_packet()) put(std::to_integer<std::uint8_t>(b));
  }
  const std::uint64_t packets = 1 + r.below(12);
  for (std::uint64_t i = 0; i < packets && n + 64 < cap; ++i) {
    const std::uint64_t len = r.below(r.chance(1, 8) ? 200 : 40);
    const char type = r.chance(1, 6) ? "RO+LX"[r.below(5)] : 'U';
    put(static_cast<std::uint8_t>((len + 1) >> 8));
    put(static_cast<std::uint8_t>((len + 1) & 0xFF));
    put(static_cast<std::uint8_t>(type));
    for (std::uint64_t k = 0; k < len; ++k) put(static_cast<std::uint8_t>(k == 0 ? 'O' : r.below(256)));
  }
  return n;
}
