// SoupBinTCP 3.00 packets, framer and session decision tables (03-protocols s5).
// Packet bytes are hand-assembled from the spec tables (SoupBinTCP 3.00 s2).
#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "common/prng.h"
#include "proto/soupbin/soupbin.h"
#include "soup_test_util.h"

namespace lle::soup {
namespace {

using test::Bytes;
using test::bytes;
using test::cat;
using test::login_payload;
using test::packet;
using test::pad_left;
using test::pad_right;
using test::parse_all;
using test::str;
using test::TestPolicy;

constexpr Nanos kSec = kNsPerSec;
constexpr Nanos kMs = 1'000'000;

std::span<const std::byte> sp(const Bytes& b) { return {b.data(), b.size()}; }

// ============================================================================ packets

TEST(SoupPackets, GoldenServerPackets) {
  std::array<std::byte, 128> buf{};
  // '+' Debug: length 1 + N.
  std::size_t n = encode_debug(buf, "hello");
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x06+hello", 8));
  // 'A' Login Accepted: length 31; Session(3/10) and Sequence(13/20) left-padded with spaces.
  n = encode_login_accepted(buf, SessionId::from("ABC"), 42);
  ASSERT_EQ(n, 33u);
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x1f" "A", 3) + "       ABC" + pad_left("42", 20));
  // 'J' Login Rejected: length 2.
  n = encode_login_rejected(buf, LoginRejectReason::NotAuthorized);
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x02JA", 4));
  n = encode_login_rejected(buf, LoginRejectReason::SessionUnavailable);
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x02JS", 4));
  // 'S' Sequenced Data, 'H' Server Heartbeat, 'Z' End of Session.
  const Bytes msg = bytes("OUCH!");
  n = encode_packet(buf, PacketType::SequencedData, msg);
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x06SOUCH!", 8));
  n = encode_packet(buf, PacketType::ServerHeartbeat, {});
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x01H", 3));
  n = encode_packet(buf, PacketType::EndOfSession, {});
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x01Z", 3));
}

TEST(SoupPackets, GoldenClientPackets) {
  std::array<std::byte, 128> buf{};
  LoginRequest r;
  r.username = Alpha<6>("user");
  r.password = Alpha<10>("pw");
  r.session = SessionId();
  r.sequence = 1;
  // 'L' Login Request: length 47; Username(3/6) Password(9/10) right-padded;
  // Requested Session(19/10) all blanks = current; Requested Sequence(29/20).
  std::size_t n = encode_login_request(buf, r, Version::V300);
  ASSERT_EQ(n, 49u);
  EXPECT_EQ(str(std::span(buf.data(), n)),
            std::string("\x00\x2fL", 3) + "user  " + "pw        " + std::string(10, ' ') + pad_left("1", 20));
  // 4.10: length 52, Heartbeat Timeout(49/5) in ms.
  r.heartbeat_timeout_ms = 2500;
  n = encode_login_request(buf, r, Version::V410);
  ASSERT_EQ(n, 54u);
  EXPECT_EQ(str(std::span(buf.data() + 49, 5)), " 2500");
  EXPECT_EQ(load_be16(buf.data()), 52u);
  // 'U' Unsequenced Data, 'R' Client Heartbeat, 'O' Logout Request.
  const Bytes msg = bytes("Q");
  n = encode_packet(buf, PacketType::UnsequencedData, msg);
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x02UQ", 4));
  n = encode_packet(buf, PacketType::ClientHeartbeat, {});
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x01R", 3));
  n = encode_packet(buf, PacketType::LogoutRequest, {});
  EXPECT_EQ(str(std::span(buf.data(), n)), std::string("\x00\x01O", 3));
}

TEST(SoupPackets, EncoderLimits) {
  std::array<std::byte, 4> small{};
  EXPECT_EQ(encode_debug(small, "hello"), 0u);
  EXPECT_EQ(encode_login_accepted(small, SessionId::from("A"), 1), 0u);
  std::vector<std::byte> big(kMaxPayload + 10);
  std::vector<std::byte> payload(kMaxPayload + 1);
  EXPECT_EQ(encode_packet(big, PacketType::SequencedData, payload), 0u);
  payload.resize(kMaxPayload);
  EXPECT_EQ(encode_packet(big, PacketType::SequencedData, payload), kMaxPayload + 3);
  EXPECT_EQ(load_be16(big.data()), 0xFFFFu);
}

TEST(SoupPackets, NumericFields) {
  auto p = [](std::string_view s) { return parse_numeric(std::as_bytes(std::span(s.data(), s.size()))); };
  EXPECT_EQ(p(pad_left("17", 20)), 17u);   // left-padded (what we emit)
  EXPECT_EQ(p(pad_right("17", 20)), 17u);  // right-padded (accepted)
  EXPECT_EQ(p("  17  "), 17u);
  EXPECT_EQ(p("00000000000000000017"), 17u);
  EXPECT_EQ(p("0"), 0u);
  EXPECT_EQ(p("18446744073709551615"), 18446744073709551615ull);
  EXPECT_EQ(p("18446744073709551616"), std::nullopt);  // overflow
  EXPECT_EQ(p("99999999999999999999"), std::nullopt);
  EXPECT_EQ(p(std::string(20, ' ')), std::nullopt);     // blank: no digits
  EXPECT_EQ(p("1 7"), std::nullopt);                     // interior space
  EXPECT_EQ(p("-1"), std::nullopt);
  EXPECT_EQ(p("1x"), std::nullopt);
  std::array<std::byte, 5> f{};
  EXPECT_TRUE(format_numeric(f.data(), 5, 99999));
  EXPECT_EQ(str(f), "99999");
  EXPECT_FALSE(format_numeric(f.data(), 5, 100000));
  EXPECT_TRUE(format_numeric(f.data(), 5, 0));
  EXPECT_EQ(str(f), "    0");
}

TEST(SoupPackets, SessionIdPadding) {
  const Bytes left = bytes("   SESS001");
  const Bytes right = bytes("SESS001   ");
  EXPECT_EQ(SessionId::from_field(left.data()), SessionId::from("SESS001"));
  EXPECT_EQ(SessionId::from_field(right.data()), SessionId::from("SESS001"));
  EXPECT_TRUE(SessionId::from_field(bytes("          ").data()).blank());
  std::array<std::byte, 10> out{};
  SessionId::from("SESS001").write_field(out.data());
  EXPECT_EQ(str(out), "   SESS001");
  EXPECT_EQ(SessionId::from("ABCDEFGHIJKL").view(), "ABCDEFGHIJ");  // truncated to 10
}

TEST(SoupPackets, CredentialsCaseInsensitive) {
  auto eq = [](std::string_view field, std::string_view want) {
    return credential_equals(std::as_bytes(std::span(field.data(), field.size())), want);
  };
  EXPECT_TRUE(eq("user  ", "USER"));
  EXPECT_TRUE(eq("  UsEr", "user"));
  EXPECT_FALSE(eq("users ", "user"));
  EXPECT_FALSE(eq("      ", "user"));
  EXPECT_TRUE(eq("      ", ""));
}

TEST(SoupPackets, LoginRequestParsing) {
  const std::string p300 = login_payload("u", "p", pad_right("S1", 10), pad_right("5", 20));
  ASSERT_EQ(p300.size(), 46u);
  auto r = parse_login_request(sp(bytes(p300)), Version::V300);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->session, SessionId::from("S1"));
  EXPECT_EQ(r->sequence, 5u);
  EXPECT_EQ(r->heartbeat_timeout_ms, 0u);
  EXPECT_FALSE(parse_login_request(sp(bytes(p300 + " ")), Version::V300).has_value());
  EXPECT_FALSE(parse_login_request(sp(bytes(p300 + "  100")), Version::V300).has_value());  // 4.10 form in 3.00 mode
  r = parse_login_request(sp(bytes(p300 + "  100")), Version::V410);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->heartbeat_timeout_ms, 100u);
  r = parse_login_request(sp(bytes(p300 + "     ")), Version::V410);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->heartbeat_timeout_ms, 0u);
  EXPECT_TRUE(parse_login_request(sp(bytes(p300)), Version::V410).has_value());  // 3.00 form in 4.10 mode
  EXPECT_FALSE(parse_login_request(sp(bytes(p300 + " x100")), Version::V410).has_value());
  const std::string bad_seq = login_payload("u", "p", std::string(10, ' '), std::string(20, ' '));
  EXPECT_FALSE(parse_login_request(sp(bytes(bad_seq)), Version::V300).has_value());
}

// ============================================================================ framer

struct Collected {
  std::vector<Packet> packets;
  std::vector<std::string> payloads;  // copied inside the callback
};

TEST(SoupFramer, WholeAndByteByByte) {
  const Bytes stream = cat({packet('S', "abc"), packet('H'), packet('S', ""), packet('+', "debug text")});
  for (std::size_t chunk : {stream.size(), std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{5}}) {
    Framer f(1024);
    std::vector<std::string> got;
    for (std::size_t pos = 0; pos < stream.size(); pos += chunk) {
      const auto part = sp(stream).subspan(pos, std::min(chunk, stream.size() - pos));
      const std::size_t used = f.feed(part, [&](const Packet& p) {
        got.push_back(std::string(1, p.type) + str(p.payload));
        return true;
      });
      EXPECT_EQ(used, part.size());
    }
    EXPECT_EQ(got, (std::vector<std::string>{"Sabc", "H", "S", "+debug text"})) << chunk;
    EXPECT_EQ(f.buffered(), 0u);
  }
}

TEST(SoupFramer, PayloadSpansValidUntilNextFeed) {
  // One call completes a reassembled packet and also stores a new trailing
  // partial: the first payload must survive until the next feed().
  const Bytes stream = cat({packet('S', "first-packet"), packet('S', "second"), packet('S', "third-partial")});
  Framer f(1024);
  std::vector<std::span<const std::byte>> spans;
  auto keep = [&](const Packet& p) {
    spans.push_back(p.payload);
    return true;
  };
  f.feed(sp(stream).first(5), keep);  // partial of packet 1
  EXPECT_TRUE(spans.empty());
  f.feed(sp(stream).first(stream.size() - 3).subspan(5), keep);  // completes 1 and 2, leaves 3 partial
  ASSERT_EQ(spans.size(), 2u);
  EXPECT_EQ(str(spans[0]), "first-packet");
  EXPECT_EQ(str(spans[1]), "second");
  spans.clear();
  f.feed(sp(stream).last(3), keep);
  ASSERT_EQ(spans.size(), 1u);
  EXPECT_EQ(str(spans[0]), "third-partial");
}

TEST(SoupFramer, RandomSegmentation) {
  Prng rng(42);
  for (int round = 0; round < 500; ++round) {
    std::vector<std::string> sent;
    Bytes stream;
    const int n = static_cast<int>(rng.below(30));
    for (int i = 0; i < n; ++i) {
      std::string payload(static_cast<std::size_t>(rng.below(rng.chance(1, 10) ? 1000 : 40)), 'x');
      for (char& c : payload) c = static_cast<char>(rng.below(256));
      const char type = "SHUZ+"[rng.below(5)];
      const Bytes p = packet(type, payload);
      stream.insert(stream.end(), p.begin(), p.end());
      sent.push_back(std::string(1, type) + payload);
    }
    Framer f(1024);
    std::vector<std::string> got;
    std::size_t pos = 0;
    while (pos < stream.size()) {
      const std::size_t len = std::min<std::size_t>(stream.size() - pos, 1 + rng.below(200));
      std::vector<std::span<const std::byte>> spans;
      std::vector<char> types;
      f.feed(sp(stream).subspan(pos, len), [&](const Packet& p) {
        spans.push_back(p.payload);
        types.push_back(p.type);
        return true;
      });
      for (std::size_t i = 0; i < spans.size(); ++i) got.push_back(std::string(1, types[i]) + str(spans[i]));
      pos += len;
    }
    ASSERT_EQ(got, sent) << round;
  }
}

TEST(SoupFramer, Errors) {
  {
    Framer f(1024);
    const Bytes zero = {std::byte{0}, std::byte{0}};
    f.feed(sp(zero), [](const Packet&) { return true; });
    EXPECT_EQ(f.status(), Framer::Status::ZeroLength);
  }
  {
    // Over the limit: detected from the header alone, before the payload arrives.
    Framer f(1024);
    const Bytes hdr = {std::byte{0x04}, std::byte{0x01}};  // 1025
    f.feed(sp(hdr), [](const Packet&) { return true; });
    EXPECT_EQ(f.status(), Framer::Status::TooLong);
    EXPECT_EQ(f.feed(sp(packet('H')), [](const Packet&) { return true; }), 0u);  // sticky
  }
  {
    // Header split across calls.
    Framer f(1024);
    f.feed(sp(Bytes{std::byte{0x04}}), [](const Packet&) { return true; });
    EXPECT_EQ(f.status(), Framer::Status::Ok);
    f.feed(sp(Bytes{std::byte{0x01}}), [](const Packet&) { return true; });
    EXPECT_EQ(f.status(), Framer::Status::TooLong);
  }
  {
    Framer f(1024);  // exactly at the limit is fine
    const Bytes p = packet('U', std::string(1023, 'a'));
    int n = 0;
    f.feed(sp(p), [&](const Packet&) { return ++n, true; });
    EXPECT_EQ(n, 1);
    EXPECT_EQ(f.status(), Framer::Status::Ok);
  }
}

TEST(SoupFramer, CallbackStop) {
  const Bytes stream = cat({packet('U', "1"), packet('U', "2"), packet('U', "3")});
  Framer f(1024);
  int seen = 0;
  const std::size_t used = f.feed(sp(stream), [&](const Packet&) { return ++seen < 2; });
  EXPECT_EQ(seen, 2);
  EXPECT_EQ(used, 8u);
  f.feed(sp(stream).subspan(used), [&](const Packet& p) {
    EXPECT_EQ(str(p.payload), "3");
    return true;
  });
}

// ============================================================================ server session

using Server = ServerSession<MemorySequencedStore, TestPolicy>;

struct ServerFixture : ::testing::Test {
  ServerConfig cfg = [] {
    ServerConfig c;
    c.session = SessionId::from("SESSION1");
    return c;
  }();
  MemorySequencedStore store{1000, 1 << 20};
  TestPolicy policy;

  void fill(int n) {
    for (int i = 1; i <= n; ++i) store.append(sp(bytes("msg" + std::to_string(i))));
  }
  static Bytes login(std::string_view session_field = "          ", std::string_view seq_field = "",
                     std::string_view user = "USER", std::string_view pass = "secret") {
    const std::string seq = seq_field.empty() ? pad_left("1", 20) : std::string(seq_field);
    return packet('L', login_payload(user, pass, session_field, seq));
  }
  static std::vector<test::Parsed> drain(Server& s) {
    const auto out = parse_all(s.actions().write);
    s.consume_tx(s.actions().write.size());
    return out;
  }
};

bool has_event(const Actions& a, EventKind k, CloseReason r = CloseReason::None) {
  for (const Event& e : a.events)
    if (e.kind == k && (k != EventKind::Closed || e.reason == r)) return true;
  return false;
}

TEST_F(ServerFixture, LoginBlankSessionSequenceOne) {
  Server s(cfg, store, policy, 0);
  const auto& a = s.on_bytes(sp(login()), 5);
  ASSERT_TRUE(has_event(a, EventKind::LoggedIn));
  EXPECT_EQ(a.events[0].seq, 1u);
  EXPECT_FALSE(a.close);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'A');
  EXPECT_EQ(out[0].payload, "  SESSION1" + pad_left("1", 20));  // left-padded on output
  EXPECT_EQ(s.state(), Server::State::Active);
}

TEST_F(ServerFixture, ReplayFromRequestedSequence) {
  fill(5);
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login("          ", pad_left("3", 20))), 1);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 4u);
  EXPECT_EQ(out[0].payload.substr(10), pad_left("3", 20));
  EXPECT_EQ(out[1].payload, "msg3");
  EXPECT_EQ(out[2].payload, "msg4");
  EXPECT_EQ(out[3].payload, "msg5");
  EXPECT_EQ(s.next_to_send(), 6u);
  // Live messages follow immediately once caught up.
  s.send_sequenced(sp(bytes("msg6")), 2);
  const auto live = drain(s);
  ASSERT_EQ(live.size(), 1u);
  EXPECT_EQ(live[0].type, 'S');
  EXPECT_EQ(live[0].payload, "msg6");
}

TEST_F(ServerFixture, SequenceZeroStartsAtMostRecent) {
  fill(5);
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login("          ", pad_left("0", 20))), 1);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].payload.substr(10), pad_left("5", 20));
  EXPECT_EQ(out[1].payload, "msg5");
}

TEST_F(ServerFixture, SequenceZeroOnEmptyStream) {
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login("          ", pad_left("0", 20))), 1);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].payload.substr(10), pad_left("1", 20));  // max(1, highest = 0)
}

TEST_F(ServerFixture, SequenceEqualToNextReplaysNothing) {
  fill(5);
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login("          ", pad_left("6", 20))), 1);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'A');
}

TEST_F(ServerFixture, SequenceAheadRejectedWithDebugAndAlarm) {
  fill(5);
  Server s(cfg, store, policy, 0);
  const auto& a = s.on_bytes(sp(login("          ", pad_left("7", 20))), 1);
  EXPECT_TRUE(a.close);
  ASSERT_TRUE(has_event(a, EventKind::SequenceAhead));
  for (const Event& e : a.events)
    if (e.kind == EventKind::SequenceAhead) {
      EXPECT_EQ(e.seq, 7u);
      EXPECT_EQ(e.aux, 6u);
    }
  EXPECT_TRUE(has_event(a, EventKind::LoginRejected));
  EXPECT_TRUE(has_event(a, EventKind::Closed, CloseReason::LoginRejected));
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].type, '+');
  EXPECT_EQ(out[0].payload, "requested sequence 7 is ahead of next 6");
  EXPECT_EQ(out[1].type, 'J');
  EXPECT_EQ(out[1].payload, "S");
}

TEST_F(ServerFixture, SessionMatchingAcceptsEitherPadding) {
  for (std::string field : {pad_left("SESSION1", 10), pad_right("SESSION1", 10)}) {
    Server s(cfg, store, policy, 0);
    EXPECT_TRUE(has_event(s.on_bytes(sp(login(field, pad_right("1", 20))), 1), EventKind::LoggedIn)) << field;
  }
}

TEST_F(ServerFixture, UnknownSessionRejectedS) {
  Server s(cfg, store, policy, 0);
  const auto& a = s.on_bytes(sp(login(pad_left("OLDSESSION", 10))), 1);
  EXPECT_TRUE(a.close);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].type, '+');
  EXPECT_EQ(out[1].type, 'J');
  EXPECT_EQ(out[1].payload, "S");
}

TEST_F(ServerFixture, BadCredentialsRejectedA) {
  Server s(cfg, store, policy, 0);
  const auto& a = s.on_bytes(sp(login("          ", "", "USER", "wrong")), 1);
  EXPECT_TRUE(a.close);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);  // 'J' is the only non-debug packet
  EXPECT_EQ(out[0].type, 'J');
  EXPECT_EQ(out[0].payload, "A");
}

TEST_F(ServerFixture, CredentialsCaseInsensitive) {
  Server s(cfg, store, policy, 0);
  EXPECT_TRUE(has_event(s.on_bytes(sp(login("          ", "", "user", "SECRET")), 1), EventKind::LoggedIn));
}

TEST_F(ServerFixture, SecondLoginOnSamePortRejectedExistingStays) {
  Server first(cfg, store, policy, 0);
  ASSERT_TRUE(has_event(first.on_bytes(sp(login()), 1), EventKind::LoggedIn));
  drain(first);
  policy.live = true;  // the gateway's port table now has USER live
  Server second(cfg, store, policy, 2);
  const auto& a = second.on_bytes(sp(login()), 3);
  EXPECT_TRUE(a.close);
  const auto out = drain(second);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].payload, "S");
  // The live connection is unaffected and keeps streaming.
  first.send_sequenced(sp(bytes("after")), 4);
  const auto live = drain(first);
  ASSERT_EQ(live.size(), 1u);
  EXPECT_EQ(live[0].payload, "after");
  EXPECT_EQ(first.state(), Server::State::Active);
}

TEST_F(ServerFixture, ProtocolViolationsSendDebugThenClose) {
  struct Case {
    Bytes input;
    std::string debug;
  };
  const Case cases[] = {
      {packet('U', "data"), "data before login"},
      {packet('R'), "data before login"},
      {packet('X'), "data before login"},
      {packet('L', "short"), "malformed login request"},
      {packet('L', login_payload("USER", "secret", std::string(10, ' '), std::string(20, ' '))),
       "malformed login request"},
      {packet('L', login_payload("USER", "secret", std::string(10, ' '), "12345678901234567x90")),
       "malformed login request"},
      {Bytes{std::byte{0x04}, std::byte{0x01}}, "packet too long"},  // header of a 1025-byte packet
      {Bytes{std::byte{0}, std::byte{0}}, "zero-length packet"},
      {cat({login(), packet('X')}), "unknown packet type"},
      {cat({login(), login()}), "duplicate login request"},
      {cat({login(), packet('R', "x")}), "malformed client heartbeat"},
  };
  for (const auto& c : cases) {
    Server s(cfg, store, policy, 0);
    const auto& a = s.on_bytes(sp(c.input), 1);
    EXPECT_TRUE(a.close) << c.debug;
    EXPECT_TRUE(has_event(a, EventKind::Closed, CloseReason::ProtocolViolation)) << c.debug;
    EXPECT_EQ(a.consumed, c.input.size());
    const auto out = drain(s);
    ASSERT_FALSE(out.empty()) << c.debug;
    EXPECT_EQ(out.back().type, '+') << c.debug;
    EXPECT_EQ(out.back().payload, c.debug);
    // Further input is ignored.
    EXPECT_TRUE(s.on_bytes(sp(packet('U', "x")), 2).delivered.empty());
  }
}

TEST_F(ServerFixture, LogoutAndDebugAndUnsequenced) {
  Server s(cfg, store, policy, 0);
  const Bytes in = cat({login(), packet('+', "client says hi"), packet('U', "order1"), packet('R'),
                        packet('U', ""), packet('O'), packet('U', "ignored")});
  const auto& a = s.on_bytes(sp(in), 1);
  ASSERT_EQ(a.delivered.size(), 2u);
  EXPECT_EQ(str(a.delivered[0].data), "order1");
  EXPECT_EQ(a.delivered[0].seq, 0u);
  EXPECT_TRUE(a.delivered[1].data.empty());
  EXPECT_TRUE(a.close);
  EXPECT_TRUE(has_event(a, EventKind::Closed, CloseReason::LogoutRequested));
}

TEST_F(ServerFixture, LogoutBeforeLoginJustCloses) {
  Server s(cfg, store, policy, 0);
  const auto& a = s.on_bytes(sp(packet('O')), 1);
  EXPECT_TRUE(a.close);
  EXPECT_TRUE(a.write.empty());
}

TEST_F(ServerFixture, DeliveredListBoundedConsumedReportsRest) {
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 0);
  drain(s);
  Bytes in;
  for (int i = 0; i < 100; ++i) {
    const Bytes p = packet('U', std::to_string(i));
    in.insert(in.end(), p.begin(), p.end());
  }
  std::vector<std::string> got;
  std::size_t pos = 0;
  int calls = 0;
  while (pos < in.size()) {
    const auto& a = s.on_bytes(sp(in).subspan(pos), 1);
    for (const auto& d : a.delivered) got.push_back(str(d.data));
    pos += a.consumed;
    ++calls;
  }
  ASSERT_EQ(got.size(), 100u);
  EXPECT_EQ(got[99], "99");
  EXPECT_EQ(calls, 2);
}

TEST_F(ServerFixture, HeartbeatTimer) {
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 10 * kMs);
  drain(s);
  EXPECT_EQ(s.actions().deadline, 10 * kMs + kSec);  // next heartbeat
  EXPECT_TRUE(s.on_timer(10 * kMs + kSec - 1).write.empty());
  auto out = parse_all(s.on_timer(10 * kMs + kSec).write);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'H');
  s.consume_tx(3);
  // Sending data resets the heartbeat timer.
  s.send_sequenced(sp(bytes("x")), 10 * kMs + kSec + 500 * kMs);
  drain(s);
  EXPECT_TRUE(s.on_timer(10 * kMs + 2 * kSec + 499 * kMs).write.empty());
  out = parse_all(s.on_timer(10 * kMs + 2 * kSec + 500 * kMs).write);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'H');
}

TEST_F(ServerFixture, IdleTimeoutAfterFifteenSeconds) {
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 0);
  s.on_bytes(sp(packet('R')), 2 * kSec);
  EXPECT_FALSE(s.on_timer(17 * kSec - 1).close);
  const auto& a = s.on_timer(17 * kSec);
  EXPECT_TRUE(a.close);
  EXPECT_TRUE(has_event(a, EventKind::Closed, CloseReason::IdleTimeout));
}

TEST_F(ServerFixture, LoginTimeoutThirtySeconds) {
  Server s(cfg, store, policy, 100);
  EXPECT_EQ(s.on_timer(100).deadline, 100 + 30 * kSec);
  EXPECT_FALSE(s.on_timer(100 + 30 * kSec - 1).close);
  const auto& a = s.on_timer(100 + 30 * kSec);
  EXPECT_TRUE(a.close);
  EXPECT_TRUE(has_event(a, EventKind::Closed, CloseReason::LoginTimeout));
}

TEST_F(ServerFixture, ConfigurableHeartbeatDownToOneMs) {
  cfg.heartbeat_interval = kMs;
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 0);
  drain(s);
  int beats = 0;
  for (Nanos t = 0; t <= 10 * kMs; t += kMs / 2) {
    const auto out = parse_all(s.on_timer(t).write);
    beats += static_cast<int>(out.size());
    s.consume_tx(s.actions().write.size());
  }
  EXPECT_EQ(beats, 10);
}

TEST_F(ServerFixture, BackpressureReplayResumes) {
  fill(200);
  cfg.tx_capacity = 64;  // a few packets at a time
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 1);
  std::vector<std::string> got;
  for (int guard = 0; guard < 1000 && got.size() < 200; ++guard) {
    for (const auto& p : parse_all(s.actions().write))
      if (p.type == 'S') got.push_back(p.payload);
    const bool more = s.consume_tx(s.actions().write.size());
    if (more) {
      EXPECT_LE(s.actions().deadline, 2);
      s.on_timer(2);
    }
  }
  ASSERT_EQ(got.size(), 200u);
  for (int i = 0; i < 200; ++i) EXPECT_EQ(got[static_cast<std::size_t>(i)], "msg" + std::to_string(i + 1));
}

TEST_F(ServerFixture, ReplayWorkBoundedPerCall) {
  fill(50);
  cfg.max_replay_per_call = 10;
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 1);
  EXPECT_EQ(drain(s).size(), 11u);  // 'A' + 10
  EXPECT_EQ(s.actions().deadline, 1);  // more replay due now
  s.on_timer(1);
  EXPECT_EQ(drain(s).size(), 10u);
}

TEST_F(ServerFixture, EndOfSessionAfterReplay) {
  fill(3);
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 1);
  const auto& a = s.end_session(2);
  EXPECT_TRUE(a.close);
  EXPECT_TRUE(has_event(a, EventKind::EndOfSession));
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 5u);  // A, S, S, S, Z
  EXPECT_EQ(out.back().type, 'Z');
  EXPECT_FALSE(s.send_sequenced(sp(bytes("late")), 3).accepted);
}

TEST_F(ServerFixture, EndOfSessionWaitsForBackpressuredReplay) {
  fill(20);
  cfg.tx_capacity = 40;
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 1);
  s.end_session(1);
  std::string types;
  for (int guard = 0; guard < 100 && s.state() != Server::State::Closed; ++guard) {
    for (const auto& p : parse_all(s.actions().write)) types += p.type;
    s.consume_tx(s.actions().write.size());
    s.on_timer(1);
  }
  for (const auto& p : parse_all(s.actions().write)) types += p.type;
  EXPECT_EQ(types, "A" + std::string(20, 'S') + "Z");
}

TEST_F(ServerFixture, StoreFullEvent) {
  MemorySequencedStore tiny(2, 100);
  Server s(cfg, tiny, policy, 0);
  EXPECT_TRUE(s.send_sequenced(sp(bytes("a")), 0).accepted);
  EXPECT_TRUE(s.send_sequenced(sp(bytes("b")), 0).accepted);
  const auto& a = s.send_sequenced(sp(bytes("c")), 0);
  EXPECT_FALSE(a.accepted);
  EXPECT_TRUE(has_event(a, EventKind::StoreFull));
}

TEST_F(ServerFixture, MessagesStoredBeforeLoginAreReplayed) {
  Server s(cfg, store, policy, 0);
  s.send_sequenced(sp(bytes("early")), 0);
  EXPECT_TRUE(s.actions().write.empty());
  s.on_bytes(sp(login()), 1);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[1].payload, "early");
}

TEST_F(ServerFixture, ZeroLengthSequencedMessage) {
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 0);
  drain(s);
  s.send_sequenced({}, 1);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'S');
  EXPECT_TRUE(out[0].payload.empty());
}

// ---------------------------------------------------------------------------- 4.10 mode

TEST_F(ServerFixture, V410HeartbeatTimeoutFromLogin) {
  cfg.version = Version::V410;
  Server s(cfg, store, policy, 0);
  const Bytes l = packet('L', login_payload("USER", "secret", std::string(10, ' '), pad_left("1", 20)) + "  500");
  ASSERT_TRUE(has_event(s.on_bytes(sp(l), 0), EventKind::LoggedIn));
  EXPECT_EQ(s.idle_timeout(), 500 * kMs);
  EXPECT_FALSE(s.on_timer(500 * kMs - 1).close);
  EXPECT_TRUE(has_event(s.on_timer(500 * kMs), EventKind::Closed, CloseReason::IdleTimeout));
}

TEST_F(ServerFixture, V410ServerUnsequenced) {
  Server s300(cfg, store, policy, 0);
  s300.on_bytes(sp(login()), 0);
  EXPECT_FALSE(s300.send_unsequenced(sp(bytes("note")), 1).accepted);
  cfg.version = Version::V410;
  Server s(cfg, store, policy, 0);
  s.on_bytes(sp(login()), 0);  // a 3.00-form login is accepted in 4.10 mode
  drain(s);
  EXPECT_TRUE(s.send_unsequenced(sp(bytes("note")), 1).accepted);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'U');
  EXPECT_EQ(out[0].payload, "note");
  EXPECT_EQ(s.next_to_send(), 1u);  // does not consume a sequence number
}

TEST_F(ServerFixture, V410LoginFormRejectedIn300Mode) {
  Server s(cfg, store, policy, 0);
  const Bytes l = packet('L', login_payload("USER", "secret", std::string(10, ' '), pad_left("1", 20)) + "  500");
  EXPECT_TRUE(has_event(s.on_bytes(sp(l), 0), EventKind::Closed, CloseReason::ProtocolViolation));
}

// ============================================================================ client session

ClientConfig client_cfg() {
  ClientConfig c;
  c.username = Alpha<6>("USER");
  c.password = Alpha<10>("secret");
  return c;
}

TEST(SoupClient, ConnectSendsLogin) {
  ClientSession c(client_cfg());
  const auto& a = c.connect(0);
  const auto out = parse_all(a.write);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'L');
  EXPECT_EQ(out[0].payload, login_payload("USER", "secret", std::string(10, ' '), pad_left("1", 20)));
  EXPECT_EQ(a.deadline, 30 * kSec);
  EXPECT_EQ(c.state(), ClientSession::State::AwaitingLoginResponse);
}

TEST(SoupClient, AcceptedThenSequencedHeartbeatEnd) {
  ClientSession c(client_cfg());
  c.connect(0);
  c.consume_tx(c.actions().write.size());
  const Bytes in = cat({packet('+', "hello"), packet('A', "  SESSION1" + pad_left("7", 20)), packet('S', "m7"),
                        packet('H'), packet('S', "m8")});
  const auto& a = c.on_bytes(sp(in), 1);
  ASSERT_TRUE(has_event(a, EventKind::LoggedIn));
  ASSERT_EQ(a.delivered.size(), 2u);
  EXPECT_EQ(a.delivered[0].seq, 7u);
  EXPECT_EQ(str(a.delivered[0].data), "m7");
  EXPECT_EQ(a.delivered[1].seq, 8u);
  EXPECT_EQ(c.next_expected(), 9u);
  EXPECT_EQ(c.session(), SessionId::from("SESSION1"));
  const ClientConfig r = c.resume_config();
  EXPECT_EQ(r.sequence, 9u);
  EXPECT_EQ(r.session, SessionId::from("SESSION1"));
  const auto& z = c.on_bytes(sp(packet('Z')), 2);
  EXPECT_TRUE(has_event(z, EventKind::EndOfSession));
  EXPECT_TRUE(z.close);
}

TEST(SoupClient, Rejected) {
  ClientSession c(client_cfg());
  c.connect(0);
  const auto& a = c.on_bytes(sp(packet('J', "A")), 1);
  ASSERT_TRUE(has_event(a, EventKind::LoginRejected));
  EXPECT_EQ(a.events[0].code, 'A');
  EXPECT_TRUE(a.close);
}

TEST(SoupClient, ViolationsClose) {
  for (const Bytes& in : {packet('S', "x"), packet('H'), packet('Z'), packet('L'), packet('U', "x"),
                          cat({packet('A', "  SESSION1" + pad_left("1", 20)), packet('A', "  SESSION1" + pad_left("1", 20))}),
                          cat({packet('A', "  SESSION1" + pad_left("1", 20)), packet('J', "S")}),
                          packet('A', "short"), packet('A', "  SESSION1" + pad_left("0", 20))}) {
    ClientSession c(client_cfg());
    c.connect(0);
    const auto& a = c.on_bytes(sp(in), 1);
    EXPECT_TRUE(has_event(a, EventKind::Closed, CloseReason::ProtocolViolation)) << str(in);
  }
}

TEST(SoupClient, HeartbeatsAndDeadLink) {
  ClientSession c(client_cfg());
  c.connect(0);
  c.consume_tx(c.actions().write.size());
  EXPECT_TRUE(c.on_timer(2 * kSec).write.empty());  // no 'R' before Login Accepted
  // The Login Request went out at t=0, so once logged in at t=2 s more than
  // 1 s has passed since the client last sent anything: 'R' is due at once.
  c.on_bytes(sp(packet('A', "  SESSION1" + pad_left("1", 20))), 2 * kSec);
  EXPECT_LE(c.actions().deadline, 2 * kSec);
  const auto out = parse_all(c.on_timer(2 * kSec).write);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'R');
  c.consume_tx(3);
  EXPECT_EQ(c.actions().deadline, 3 * kSec);
  c.on_bytes(sp(packet('H')), 4 * kSec);
  EXPECT_FALSE(c.on_timer(19 * kSec - 1).close);
  EXPECT_TRUE(has_event(c.on_timer(19 * kSec), EventKind::Closed, CloseReason::IdleTimeout));
}

TEST(SoupClient, LoginTimeoutAndUnsequencedGating) {
  ClientSession c(client_cfg());
  EXPECT_FALSE(c.send_unsequenced(sp(bytes("x")), 0).accepted);  // not connected
  c.connect(0);
  EXPECT_FALSE(c.send_unsequenced(sp(bytes("x")), 0).accepted);  // before Login Accepted (spec 1.2)
  EXPECT_TRUE(has_event(c.on_timer(30 * kSec), EventKind::Closed, CloseReason::LoginTimeout));
}

TEST(SoupClient, LogoutAndV410) {
  ClientConfig cfg = client_cfg();
  cfg.version = Version::V410;
  cfg.heartbeat_timeout_ms = 250;
  ClientSession c(cfg);
  auto out = parse_all(c.connect(0).write);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].payload.size(), kLoginRequestPayload41);
  EXPECT_EQ(out[0].payload.substr(46), "  250");
  c.consume_tx(c.actions().write.size());
  const auto& a = c.on_bytes(sp(cat({packet('A', "  SESSION1" + pad_left("1", 20)), packet('U', "note"),
                                     packet('S', "m1")})),
                             1);
  ASSERT_EQ(a.delivered.size(), 2u);
  EXPECT_EQ(a.delivered[0].seq, 0u);  // unsequenced: no sequence number
  EXPECT_EQ(a.delivered[1].seq, 1u);
  const auto& l = c.logout(2);
  EXPECT_TRUE(l.close);
  out = parse_all(l.write);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 'O');
}

}  // namespace
}  // namespace lle::soup
