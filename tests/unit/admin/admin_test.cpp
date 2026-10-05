// The admin channel (05 §10 E-15): HMAC-SHA256, the frame format, the
// verifier's rejections, the admin port into the sequencer's queue and on to a
// journaled Admin record, the command parser, LULD bands, and the TCP layer.
#include <gtest/gtest.h>

#include <atomic>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "admin/admin_port.h"
#include "admin/commands.h"
#include "admin/luld.h"
#include "admin/net.h"
#include "admin/protocol.h"
#include "common/time.h"
#include "engine/records.h"
#include "sequencer_test_env.h"

namespace lle::admin {
namespace {

std::string hex(std::span<const std::uint8_t> b) {
  static constexpr char k[] = "0123456789abcdef";
  std::string s;
  for (std::uint8_t x : b) {
    s += k[x >> 4];
    s += k[x & 15];
  }
  return s;
}
std::span<const std::byte> bytes_of(std::string_view s) { return std::as_bytes(std::span<const char>(s)); }

TEST(Admin, HmacSha256Rfc4231) {
  const Key k1(20, 0x0b);
  EXPECT_EQ(hex(hmac_sha256(k1, bytes_of("Hi There"))),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  const Key k2 = {'J', 'e', 'f', 'e'};
  EXPECT_EQ(hex(hmac_sha256(k2, bytes_of("what do ya want for nothing?"))),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  const Key k6(131, 0xaa);  // longer than a block: hashed first
  EXPECT_EQ(hex(hmac_sha256(k6, bytes_of("Test Using Larger Than Block-Size Key - Hash Key First"))),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

const Key kKey = parse_key_hex("000102030405060708090a0b0c0d0e0f1011121314151617").value();

std::vector<std::byte> halt_frame(std::uint64_t seq, std::uint32_t op = 7, const Key& key = kKey) {
  const auto args = engine::AdminArgsBuilder{}.symbol("AAPL").bytes();
  return encode_request(Request{op, seq, 1, 1, args}, key);
}

TEST(Admin, RequestFrameLayout) {
  const auto f = halt_frame(1);
  // len | ver | 'R' | operator | sequence | command | tlv ver | n | TLV(Symbol, 8, "AAPL    ") | mac
  std::vector<std::uint8_t> head;
  for (std::size_t i = 0; i < 34; ++i) head.push_back(std::to_integer<std::uint8_t>(f[i]));
  EXPECT_EQ(hex(head), "0040" "01" "52" "00000007" "0000000000000001" "0001" "0001" "000c" "0100" "0800"
                       "4141504c20202020");
  ASSERT_EQ(f.size(), 66u);
  const Mac mac = hmac_sha256(kKey, std::span<const std::byte>(f).subspan(2, 32));
  EXPECT_TRUE(equal_ct(mac, std::span<const std::byte>(f).subspan(34)));
}

TEST(Admin, VerifierAcceptsAndRejects) {
  Verifier v;
  v.add_operator(7, kKey);
  auto ok = v.verify(halt_frame(5));
  ASSERT_TRUE(ok.has_value());
  EXPECT_EQ(ok->operator_id, 7u);
  EXPECT_EQ(ok->sequence, 5u);
  EXPECT_EQ(ok->command, 1u);
  // Not consumed until commit: the same sequence verifies again.
  EXPECT_TRUE(v.verify(halt_frame(5)).has_value());
  v.commit(*ok);
  EXPECT_EQ(v.verify(halt_frame(5)).error(), NackReason::Replay);
  EXPECT_EQ(v.verify(halt_frame(4)).error(), NackReason::Replay);
  EXPECT_TRUE(v.verify(halt_frame(6)).has_value());
  EXPECT_EQ(v.verify(halt_frame(9, 8)).error(), NackReason::UnknownOperator);
  Key other = kKey;
  other[0] ^= 1;
  EXPECT_EQ(v.verify(halt_frame(9, 7, other)).error(), NackReason::BadMac);
  auto tampered = halt_frame(9);
  tampered[30] = std::byte{'B'};  // inside the symbol
  EXPECT_EQ(v.verify(tampered).error(), NackReason::BadMac);
  EXPECT_EQ(v.verify(encode_request(Request{7, 10, 0, 1, {}}, kKey)).error(), NackReason::UnknownCommand);
  EXPECT_EQ(v.verify(encode_request(Request{7, 10, 15, 1, {}}, kKey)).error(), NackReason::UnknownCommand);
  EXPECT_EQ(v.verify(encode_request(Request{7, 10, 1, 2, {}}, kKey)).error(), NackReason::BadArgs);  // TLV version
  const std::vector<std::byte> bad_tlv = {std::byte{1}, std::byte{0}, std::byte{9}, std::byte{0}};  // truncated
  EXPECT_EQ(v.verify(encode_request(Request{7, 10, 1, 1, bad_tlv}, kKey)).error(), NackReason::BadArgs);
  auto shortf = halt_frame(10);
  shortf.pop_back();
  EXPECT_EQ(v.verify(shortf).error(), NackReason::Malformed);
  auto oversize = halt_frame(10);
  store_be16(oversize.data() + 20, 241);
  EXPECT_EQ(v.verify(oversize).error(), NackReason::Malformed);
}

TEST(Admin, ResponsesAreSigned) {
  Verifier v;
  v.add_operator(7, kKey);
  const auto a = v.respond(Response{true, 7, 12, NackReason::None});
  const auto r = decode_response(a, kKey);
  ASSERT_TRUE(r.has_value());
  EXPECT_TRUE(r->accepted);
  EXPECT_EQ(r->sequence, 12u);
  Key other = kKey;
  other[3] ^= 0x40;
  EXPECT_EQ(decode_response(a, other, false).error(), NackReason::BadMac);
  // An unknown operator gets an unsigned nack.
  const auto n = v.respond(Response{false, 99, 1, NackReason::UnknownOperator});
  const auto rn = decode_response(n, kKey, true);
  ASSERT_TRUE(rn.has_value());
  EXPECT_FALSE(rn->accepted);
  EXPECT_EQ(rn->reason, NackReason::UnknownOperator);
  EXPECT_FALSE(decode_response(n, kKey, false).has_value());
}

TEST(Admin, FrameAssemblerSplitsAStream) {
  FrameAssembler a;
  const auto f1 = halt_frame(1), f2 = halt_frame(2);
  std::vector<std::byte> stream(f1);
  stream.insert(stream.end(), f2.begin(), f2.end());
  a.feed(std::span<const std::byte>(stream).first(10));
  EXPECT_TRUE(a.next().empty());
  a.feed(std::span<const std::byte>(stream).subspan(10));
  auto x = a.next();
  ASSERT_EQ(x.size(), f1.size());
  EXPECT_TRUE(std::equal(x.begin(), x.end(), f1.begin()));
  x = a.next();
  ASSERT_EQ(x.size(), f2.size());
  EXPECT_TRUE(a.next().empty());
  FrameAssembler bad;
  const std::byte huge[2] = {std::byte{0xFF}, std::byte{0xFF}};
  bad.feed(huge);
  EXPECT_TRUE(bad.next().empty());
  EXPECT_TRUE(bad.poisoned());
}

TEST(Admin, PortFeedsTheSequencerWhichJournalsAnAdminRecord) {
  seq::testing::Rig rig;
  rig.start();
  (void)rig.take(0);
  (void)rig.take(1);
  Verifier v;
  v.add_operator(7, kKey);
  AdminPort<seq::testing::TestEnv::AdminQueue> port(v, *rig.admin);
  FrameAssembler conn;
  std::vector<std::byte> out;
  const auto cmd = parse_command(std::vector<std::string_view>{"luld-bands", "AAPL", "95.00", "105.00"});
  ASSERT_TRUE(cmd.has_value());
  const auto f = encode_request(Request{7, 1, cmd->command, 1, cmd->args}, kKey);
  ASSERT_TRUE(port.on_bytes(conn, f, out));
  const auto resp = decode_response(out, kKey);
  ASSERT_TRUE(resp.has_value());
  EXPECT_TRUE(resp->accepted);
  while (rig.seq->poll()) {
  }
  const auto recs = rig.take(0);
  ASSERT_EQ(recs.size(), 1u);
  const auto view = journal::parse_record(recs[0]);
  ASSERT_TRUE(view.has_value());
  EXPECT_EQ(view->type(), journal::RecordType::Admin);
  const auto a = engine::parse_admin(view->payload());
  ASSERT_TRUE(a.has_value());
  EXPECT_EQ(a->hdr.command, static_cast<std::uint16_t>(engine::AdminCommand::LuldBands));
  EXPECT_EQ(a->hdr.operator_id, 7u);
  const auto args = engine::parse_admin_args(a->args, a->hdr.tlv_version);
  ASSERT_TRUE(args.has_value());
  EXPECT_EQ(args->symbol, Symbol8("AAPL"));
  EXPECT_EQ(args->lower, 950'000);
  EXPECT_EQ(args->upper, 1'050'000);
}

TEST(Admin, PortSaysBusyWhenTheQueueIsFullAndTheSequenceIsNotConsumed) {
  auto q = std::make_unique<seq::testing::TestEnv::AdminQueue>();
  Verifier v;
  v.add_operator(7, kKey);
  AdminPort<seq::testing::TestEnv::AdminQueue> port(v, *q);
  std::uint64_t seq = 1;
  for (;; ++seq) {
    const auto r = port.handle(halt_frame(seq));
    const auto d = decode_response(r, kKey);
    ASSERT_TRUE(d.has_value());
    if (!d->accepted) {
      EXPECT_EQ(d->reason, NackReason::Busy);
      break;
    }
    ASSERT_LT(seq, 1000u);
  }
  seq::AdminMsg m;
  ASSERT_TRUE(q->try_pop(m));
  const auto again = decode_response(port.handle(halt_frame(seq)), kKey);  // the same sequence
  ASSERT_TRUE(again.has_value());
  EXPECT_TRUE(again->accepted);
  EXPECT_EQ(port.stats().busy, 1u);
}

TEST(Admin, CommandParser) {
  auto words = [](std::initializer_list<std::string_view> w) { return std::vector<std::string_view>(w); };
  auto args = [](const Command& c) { return engine::parse_admin_args(c.args, 1).value(); };
  auto c = parse_command(words({"halt", "AAPL", "T1"}));
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(c->command, 1u);
  EXPECT_EQ(args(*c).reason, Alpha<4>("T1"));
  c = parse_command(words({"quote-only", "AAPL", "--price", "100.25"}));
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(args(*c).price, 1'002'500);
  c = parse_command(words({"ipo-schedule", "NEWCO", "25.00", "10:15:00", "--qualifier", "C"}));
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(args(*c).time, 36'900u);
  EXPECT_EQ(args(*c).qualifier, 'C');
  c = parse_command(words({"mwcb-levels", "6367.25", "5956.46", "5477.20"}));
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(args(*c).level1, 636'725'000'000);
  c = parse_command(words({"risk-limit", "100", "max-order-qty", "500", "AAPL"}));
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(args(*c).kind, static_cast<std::uint16_t>(engine::RiskKind::MaxOrderQty));
  EXPECT_EQ(args(*c).value, 500);
  EXPECT_EQ(args(*c).account, 100u);
  EXPECT_TRUE(parse_command(words({"kill-switch", "100"})).has_value());
  EXPECT_TRUE(parse_command(words({"regsho", "AAPL", "1"})).has_value());
  EXPECT_FALSE(parse_command(words({"regsho", "AAPL", "3"})).has_value());
  EXPECT_FALSE(parse_command(words({"halt", "aapl"})).has_value());
  EXPECT_FALSE(parse_command(words({"luld-bands", "AAPL", "95.123456", "105"})).has_value());
  EXPECT_FALSE(parse_command(words({"bogus"})).has_value());
  EXPECT_EQ(parse_decimal("0.0001", 4).value(), 1);
  EXPECT_EQ(parse_decimal("199999.99", 4).value(), 1'999'999'900);
  EXPECT_EQ(parse_decimal("7", 4).value(), 70'000);
  EXPECT_FALSE(parse_decimal("1.23456", 4).has_value());
  EXPECT_FALSE(parse_decimal("-1", 4).has_value());
  EXPECT_FALSE(parse_decimal("1e3", 4).has_value());
  EXPECT_EQ(parse_hms("09:30:00").value(), 34'200u);
  EXPECT_FALSE(parse_hms("24:00:00").has_value());
}

TEST(Admin, LuldBandsByTierAndTime) {
  const Nanos ten = hms_ns(10, 0, 0), open = hms_ns(9, 35, 0);
  EXPECT_EQ(luld_bands(500'000, '1', ten), (LuldBands{475'000, 525'000, 500'000}));  // 5%
  EXPECT_EQ(luld_bands(500'000, '1', open), (LuldBands{450'000, 550'000, 500'000}));  // doubled
  EXPECT_EQ(luld_bands(500'000, '2', ten), (LuldBands{450'000, 550'000, 500'000}));  // 10%
  EXPECT_EQ(luld_bands(30'000, '1', ten), (LuldBands{24'000, 36'000, 30'000}));      // $3.00: 20%
  EXPECT_EQ(luld_bands(20'000, '2', ten), (LuldBands{16'000, 24'000, 20'000}));
  EXPECT_EQ(luld_bands(5'000, '2', ten), (LuldBands{3'500, 6'500, 5'000}));         // min($0.15, 75%)
  EXPECT_EQ(luld_bands(5'000, '2', open), (LuldBands{2'000, 8'000, 5'000}));
  EXPECT_EQ(luld_bands(346'900, '2', ten), (LuldBands{312'200, 381'600, 346'900}));  // rounded to the penny
}

TEST(Admin, LuldReferencePriceMovesByOnePercent) {
  LuldSymbol s('1');
  EXPECT_FALSE(s.on_trade(hms_ns(9, 29, 0), 500'000).has_value());  // before the open
  auto b = s.on_trade(hms_ns(10, 0, 0), 500'000);                    // the opening print
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(*b, (LuldBands{475'000, 525'000, 500'000}));
  EXPECT_FALSE(s.on_trade(hms_ns(10, 1, 0), 504'000).has_value());  // mean 502,000: < 1%
  b = s.on_trade(hms_ns(10, 2, 0), 512'000);                         // mean 505,333: >= 1%
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(*b, (LuldBands{480'100, 530'600, 505'333}));
  b = s.on_time(hms_ns(15, 35, 0));  // the closing doubling
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(*b, (LuldBands{454'800, 555'900, 505'333}));
  EXPECT_FALSE(s.on_time(hms_ns(16, 0, 0)).has_value());
}

TEST(Admin, TcpRoundTrip) {
  auto q = std::make_unique<seq::testing::TestEnv::AdminQueue>();
  Verifier v;
  v.add_operator(7, kKey);
  AdminPort<seq::testing::TestEnv::AdminQueue> port(v, *q);
  std::vector<FrameAssembler> conns(64);
  auto l = TcpListener::open(0, [&](std::size_t id, std::span<const std::byte> in, std::vector<std::byte>& out) {
    return port.on_bytes(conns[id % conns.size()], in, out);
  });
  ASSERT_TRUE(l.has_value()) << l.error();
  std::atomic<bool> stop{false};
  std::thread t([&] {
    while (!stop.load()) (void)l->step(10);
  });
  const auto r = exchange("127.0.0.1", l->port(), halt_frame(1));
  stop = true;
  t.join();
  ASSERT_TRUE(r.has_value()) << r.error();
  const auto d = decode_response(*r, kKey);
  ASSERT_TRUE(d.has_value());
  EXPECT_TRUE(d->accepted);
  seq::AdminMsg m;
  ASSERT_TRUE(q->try_pop(m));
  EXPECT_EQ(m.command, 1u);
  EXPECT_EQ(m.operator_id, 7u);
}

}  // namespace
}  // namespace lle::admin
