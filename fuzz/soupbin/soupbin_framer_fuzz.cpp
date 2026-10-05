// Fuzz harness: SoupBinTCP framer and sessions (03-protocols s9).
// Byte 0 selects the target (mod 4): framer, server session (3.00), server
// session (4.10), client session; the rest is the peer's byte stream, fed in
// chunks whose sizes come from a PRNG seeded by the input itself. Properties:
//  - no crash / UB; consumed never exceeds the input; Closed is sticky;
//  - framer: the packet sequence does not depend on segmentation;
//  - sessions: everything a session writes is a well-formed SoupBinTCP stream
//    of packet types legal for its role; client sequence numbers are contiguous.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/hash.h"
#include "common/prng.h"
#include "proto/soupbin/soupbin.h"

namespace {

using namespace lle;
using namespace lle::soup;

struct Policy {
  LoginDecision authorize(const LoginRequest& r) {
    if (!credential_equals(std::as_bytes(std::span(r.username.c)), "USER")) return LoginDecision::NotAuthorized;
    return credential_equals(std::as_bytes(std::span(r.password.c)), "pw") ? LoginDecision::Accept
                                                                           : LoginDecision::SessionUnavailable;
  }
};

// Checks that `out` is a sequence of complete packets of allowed types.
void check_stream(std::span<const std::byte> out, const char* allowed) {
  Framer f(kMaxPacketLength);
  const std::size_t used = f.feed(out, [&](const Packet& p) {
    LLE_ASSERT(std::strchr(allowed, p.type) != nullptr && p.type != 0, "illegal packet type emitted");
    return true;
  });
  LLE_ASSERT(used == out.size() && f.status() == Framer::Status::Ok && f.buffered() == 0,
             "session emitted a malformed stream");
}

std::vector<std::span<const std::byte>> chunks(std::span<const std::byte> in) {
  Fnv1a64 h;
  h.bytes(in);
  Prng r(h.value());
  std::vector<std::span<const std::byte>> out;
  std::size_t pos = 0;
  while (pos < in.size()) {
    const std::size_t n = std::min<std::size_t>(in.size() - pos, 1 + r.below(r.chance(1, 4) ? 512 : 16));
    out.push_back(in.subspan(pos, n));
    pos += n;
  }
  return out;
}

void fuzz_framer(std::span<const std::byte> in, std::size_t max_len) {
  std::vector<std::string> whole, split;
  Framer a(max_len);
  a.feed(in, [&](const Packet& p) {
    whole.push_back(std::string(1, p.type) + std::string(reinterpret_cast<const char*>(p.payload.data()), p.payload.size()));
    return true;
  });
  Framer b(max_len);
  for (auto c : chunks(in)) {
    const std::size_t used = b.feed(c, [&](const Packet& p) {
      LLE_ASSERT(p.payload.size() + 1 <= max_len);
      split.push_back(std::string(1, p.type) + std::string(reinterpret_cast<const char*>(p.payload.data()), p.payload.size()));
      return true;
    });
    LLE_ASSERT(used <= c.size());
    if (b.status() != Framer::Status::Ok) break;
  }
  LLE_ASSERT(a.status() == b.status(), "framing error depends on segmentation");
  LLE_ASSERT(whole == split, "packets depend on segmentation");
}

void fuzz_server(std::span<const std::byte> in, Version v) {
  MemorySequencedStore store(64, 4096);
  for (int i = 0; i < 5; ++i) {
    const std::byte m[3] = {std::byte{'m'}, static_cast<std::byte>('0' + i), std::byte{'!'}};
    store.append(m);
  }
  Policy pol;
  ServerConfig cfg;
  cfg.session = SessionId::from("FUZZ");
  cfg.version = v;
  cfg.tx_capacity = 512;
  cfg.max_replay_per_call = 3;
  ServerSession<MemorySequencedStore, Policy> s(cfg, store, pol, 0);
  const char* allowed = v == Version::V410 ? "+AJSHZU" : "+AJSHZ";
  Nanos now = 0;
  bool closed = false;
  for (auto c : chunks(in)) {
    now += 7 * 1'000'000;
    std::size_t pos = 0;
    while (pos < c.size()) {
      const Actions& a = s.on_bytes(c.subspan(pos), now);
      LLE_ASSERT(a.consumed <= c.size() - pos);
      LLE_ASSERT(!closed || (a.close && a.delivered.empty()), "Closed must be sticky");
      closed = a.close;
      check_stream(a.write, allowed);
      s.consume_tx(a.write.size());
      if (a.consumed == 0) break;
      pos += a.consumed;
    }
    const Actions& t = s.on_timer(now);
    check_stream(t.write, allowed);
    s.consume_tx(t.write.size());
    if (!closed) {
      const std::byte m[2] = {std::byte{'x'}, std::byte{'y'}};
      check_stream(s.send_sequenced(m, now).write, allowed);
      s.consume_tx(s.actions().write.size());
    }
  }
  check_stream(s.on_timer(now + 60 * kNsPerSec).write, allowed);
}

void fuzz_client(std::span<const std::byte> in) {
  ClientConfig cfg;
  cfg.username = Alpha<6>("USER");
  cfg.password = Alpha<10>("pw");
  cfg.tx_capacity = 512;
  ClientSession c(cfg);
  check_stream(c.connect(0).write, "+LURO");
  c.consume_tx(c.actions().write.size());
  Nanos now = 0;
  SeqNo expect = 0;
  for (auto ch : chunks(in)) {
    now += 3 * 1'000'000;
    std::size_t pos = 0;
    while (pos < ch.size()) {
      const Actions& a = c.on_bytes(ch.subspan(pos), now);
      LLE_ASSERT(a.consumed <= ch.size() - pos);
      for (const Event& e : a.events)
        if (e.kind == EventKind::LoggedIn) expect = e.seq;
      for (const Delivered& d : a.delivered) {
        if (d.seq == 0) continue;
        LLE_ASSERT(d.seq == expect, "client sequence numbers must be contiguous");
        ++expect;
      }
      check_stream(a.write, "+LURO");
      c.consume_tx(a.write.size());
      if (a.consumed == 0) break;
      pos += a.consumed;
    }
    const std::byte m[1] = {std::byte{'o'}};
    check_stream(c.send_unsequenced(m, now).write, "+LURO");
    c.consume_tx(c.actions().write.size());
    check_stream(c.on_timer(now).write, "+LURO");
    c.consume_tx(c.actions().write.size());
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) return 0;
  const auto in = std::as_bytes(std::span<const std::uint8_t>(data + 2, size - 2));
  switch (data[0] & 3u) {
    case 0: fuzz_framer(in, 1 + data[1] * 4u); break;
    case 1: fuzz_server(in, Version::V300); break;
    case 2: fuzz_server(in, Version::V410); break;
    default: fuzz_client(in); break;
  }
  return 0;
}

// Structured inputs: streams of plausible packets (valid and broken logins,
// data, heartbeats, logouts, debug, unknown types, bad lengths).
// Seed corpus for the shared mutation driver (fuzz/common/fuzz_driver_main.cpp).
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 2048 || cap < 128) return 0;
  Prng r(mix64(index + 1));
  std::size_t n = 0;
  auto put = [&](std::uint8_t b) {
    if (n < cap) buf[n++] = b;
  };
  auto pkt = [&](char type, const std::string& payload) {
    const std::size_t len = payload.size() + 1;
    put(static_cast<std::uint8_t>(len >> 8));
    put(static_cast<std::uint8_t>(len & 0xFF));
    put(static_cast<std::uint8_t>(type));
    for (char ch : payload) put(static_cast<std::uint8_t>(ch));
  };
  put(static_cast<std::uint8_t>(r.below(4)));
  put(static_cast<std::uint8_t>(r.below(256)));
  const bool server_side = (buf[0] & 3u) == 3u;
  const std::uint64_t count = r.below(24);
  for (std::uint64_t i = 0; i < count && n + 80 < cap; ++i) {
    const std::uint64_t k = r.below(12);
    std::string seq = std::to_string(r.chance(1, 4) ? r.below(10) : r.next_u64() % 1000);
    seq = r.chance(1, 2) ? std::string(20 - seq.size(), ' ') + seq : seq + std::string(20 - seq.size(), ' ');
    if (server_side) {
      switch (k) {
        case 0: pkt('A', std::string(r.chance(1, 2) ? "      FUZZ" : "FUZZ      ") + seq); break;
        case 1: pkt('J', r.chance(1, 2) ? "A" : "S"); break;
        case 2:
        case 3:
        case 4: pkt('S', std::string(static_cast<std::size_t>(r.below(40)), 'q')); break;
        case 5: pkt('H', ""); break;
        case 6: pkt('Z', ""); break;
        case 7: pkt('U', "u"); break;
        case 8: pkt('+', "dbg"); break;
        default: pkt(static_cast<char>(r.below(256)), std::string(static_cast<std::size_t>(r.below(8)), 'z')); break;
      }
    } else {
      switch (k) {
        case 0:
        case 1: {
          std::string login = std::string(r.chance(3, 4) ? "USER  " : "user  ") +
                              std::string(r.chance(3, 4) ? "pw        " : "nope      ") +
                              std::string(r.chance(1, 2) ? "          " : "      FUZZ") + seq;
          if (r.chance(1, 4)) login += r.chance(1, 2) ? "  250" : "     ";
          if (r.chance(1, 8)) login.resize(static_cast<std::size_t>(r.below(login.size())));
          pkt('L', login);
          break;
        }
        case 2:
        case 3:
        case 4: pkt('U', std::string(static_cast<std::size_t>(r.below(60)), 'o')); break;
        case 5: pkt('R', ""); break;
        case 6: pkt('O', ""); break;
        case 7: pkt('+', "hello"); break;
        case 8:  // oversize header
          put(0x04);
          put(0x01);
          break;
        default: pkt(static_cast<char>(r.below(256)), std::string(static_cast<std::size_t>(r.below(8)), 'z')); break;
      }
    }
  }
  if (n > 2 && r.chance(1, 6)) buf[2 + r.below(n - 2)] = static_cast<std::uint8_t>(r.below(256));
  return n;
}
