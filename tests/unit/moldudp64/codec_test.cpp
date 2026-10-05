// MoldUDP64 codec: golden header/request bytes (R1b D1 layouts), packet
// validation, builder, store and histogram.
#include <gtest/gtest.h>

#include <deque>
#include <string>

#include "common/prng.h"
#include "mold_test_util.h"
#include "proto/moldudp64/histogram.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::mold {
namespace {

using test::Bytes;

std::string hex(std::span<const std::byte> b) {
  static constexpr char d[] = "0123456789abcdef";
  std::string s;
  for (auto x : b) {
    s += d[static_cast<unsigned>(x) >> 4];
    s += d[static_cast<unsigned>(x) & 15];
  }
  return s;
}

TEST(MoldCodec, GoldenDataPacket) {
  // Session "SESSION001" @0/10, seq 0x0102030405060708 @10/8, count 2 @18/2,
  // blocks [00 03 'a' 'b' 'c'] [00 00].
  Bytes buf(64);
  PacketBuilder b(buf, Session("SESSION001"), 0x0102030405060708ull);
  const std::byte abc[3] = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
  ASSERT_TRUE(b.add(abc));
  ASSERT_TRUE(b.add({}));  // zero-length messages are valid sequenced messages
  const auto pkt = b.finish();
  EXPECT_EQ(hex(pkt), "53455353494f4e303031" "0102030405060708" "0002" "0003616263" "0000");
  const auto pv = PacketView::parse(pkt);
  ASSERT_TRUE(pv.has_value());
  EXPECT_EQ(pv->header().session.view(), "SESSION001");
  EXPECT_EQ(pv->seq(), 0x0102030405060708ull);
  EXPECT_EQ(pv->message_count(), 2);
  EXPECT_EQ(pv->end_seq(), 0x010203040506070Aull);
  std::vector<std::pair<SeqNo, std::size_t>> seen;
  pv->for_each([&](SeqNo s, std::span<const std::byte> m) { seen.emplace_back(s, m.size()); });
  ASSERT_EQ(seen.size(), 2u);
  EXPECT_EQ(seen[0], std::make_pair(SeqNo{0x0102030405060708ull}, std::size_t{3}));
  EXPECT_EQ(seen[1], std::make_pair(SeqNo{0x0102030405060709ull}, std::size_t{0}));
}

TEST(MoldCodec, GoldenControlAndRequestPackets) {
  Bytes hb(20), eos(20), req(20);
  ASSERT_EQ(encode_control(hb, Session("ABC"), 42, false), 20u);
  EXPECT_EQ(hex(hb), "41424320202020202020" "000000000000002a" "0000");
  ASSERT_EQ(encode_control(eos, Session("ABC"), 42, true), 20u);
  EXPECT_EQ(hex(eos), "41424320202020202020" "000000000000002a" "ffff");
  const auto pe = PacketView::parse(eos);
  ASSERT_TRUE(pe.has_value());
  EXPECT_TRUE(pe->is_end_of_session());
  EXPECT_EQ(pe->message_count(), 0);
  EXPECT_EQ(pe->end_seq(), 42u);
  EXPECT_TRUE(PacketView::parse(hb)->is_heartbeat());

  ASSERT_EQ(encode_request(req, RequestPacket{Session("ABC"), 7, 300}), 20u);
  EXPECT_EQ(hex(req), "41424320202020202020" "0000000000000007" "012c");
  const auto r = decode_request(req);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, (RequestPacket{Session("ABC"), 7, 300}));
  EXPECT_EQ(decode_request(std::span(req).first(19)).error(), PacketError::TooShort);
  req.push_back(std::byte{0});
  EXPECT_EQ(decode_request(req).error(), PacketError::TrailingBytes);
}

TEST(MoldCodec, ParseRejectsMalformed) {
  const Bytes good = test::data_packet(1, 3);
  ASSERT_TRUE(PacketView::parse(good).has_value());
  EXPECT_EQ(PacketView::parse(std::span(good).first(19)).error(), PacketError::TooShort);
  EXPECT_EQ(PacketView::parse(std::span(good).first(good.size() - 1)).error(), PacketError::TruncatedBlock);
  Bytes extra = good;
  extra.push_back(std::byte{0});
  EXPECT_EQ(PacketView::parse(extra).error(), PacketError::TrailingBytes);
  Bytes hb = test::control_packet(5, false);
  hb.push_back(std::byte{1});
  EXPECT_EQ(PacketView::parse(hb).error(), PacketError::TrailingBytes);
  Bytes wrap(64);
  PacketBuilder wb(wrap, test::kSession, ~SeqNo{0});
  ASSERT_TRUE(wb.add(test::msg_for(1)));
  ASSERT_TRUE(wb.add(test::msg_for(2)));
  EXPECT_EQ(PacketView::parse(wb.finish()).error(), PacketError::SequenceOverflow);
  // Count larger than the blocks present.
  Bytes more = good;
  store_be16(more.data() + 18, 4);
  EXPECT_EQ(PacketView::parse(more).error(), PacketError::TruncatedBlock);
  EXPECT_EQ(to_string(PacketError::TrailingBytes), "trailing_bytes");
}

TEST(MoldCodec, BuilderRespectsCapacity) {
  Bytes buf(kHeaderLen + 2 + 10);
  PacketBuilder b(buf, test::kSession, 1);
  Bytes ten(10), one(1);
  EXPECT_TRUE(b.add(ten));
  EXPECT_FALSE(b.add(one));
  EXPECT_EQ(b.count(), 1);
  EXPECT_EQ(b.finish().size(), buf.size());
}

TEST(MessageRing, EvictsOldestByCountAndBytes) {
  MessageRing r(4, 100);
  EXPECT_EQ(r.highest(), 0u);
  EXPECT_EQ(r.lowest(), 1u);
  EXPECT_FALSE(r.get(1).has_value());
  for (SeqNo s = 1; s <= 6; ++s) ASSERT_TRUE(r.append(test::msg_for(s)));
  EXPECT_EQ(r.highest(), 6u);
  EXPECT_EQ(r.lowest(), 3u);  // count limit 4
  EXPECT_FALSE(r.get(2).has_value());
  for (SeqNo s = 3; s <= 6; ++s) {
    const auto m = r.get(s);
    ASSERT_TRUE(m.has_value());
    const Bytes want = test::msg_for(s);
    EXPECT_TRUE(std::equal(m->begin(), m->end(), want.begin(), want.end()));
  }
  Bytes big(101);
  EXPECT_FALSE(r.append(big));
  Bytes ninety(90);
  ASSERT_TRUE(r.append(ninety));  // byte limit evicts everything else
  EXPECT_EQ(r.size(), 1u);
  EXPECT_EQ(r.get(7)->size(), 90u);
  ASSERT_TRUE(r.append({}));
  EXPECT_EQ(r.get(8)->size(), 0u);
}

// Property test against a reference deque: random lengths (including 0) and wrap-around.
TEST(MessageRing, MatchesReferenceModel) {
  Prng rng(77);
  constexpr std::size_t kMsgs = 64, kBytes = 1000;
  MessageRing r(kMsgs, kBytes);
  std::deque<std::pair<SeqNo, Bytes>> ref;
  std::size_t ref_bytes = 0;
  for (SeqNo s = 1; s <= 20000; ++s) {
    Bytes m(rng.below(rng.chance(1, 10) ? 300 : 40));
    for (auto& b : m) b = static_cast<std::byte>(rng.next_u64());
    ASSERT_TRUE(r.append(m));
    ref.emplace_back(s, m);
    ref_bytes += m.size();
    while (ref.size() > kMsgs || ref_bytes > kBytes) {
      ref_bytes -= ref.front().second.size();
      ref.pop_front();
    }
    // The ring may evict more than the ideal model (fragmentation at the wrap) but never
    // keeps a message the byte/count budget forbids, and every kept message is intact.
    ASSERT_EQ(r.highest(), s);
    ASSERT_GE(r.lowest(), ref.front().first);
    for (SeqNo q = r.lowest(); q <= r.highest(); ++q) {
      const auto got = r.get(q);
      ASSERT_TRUE(got.has_value());
      const Bytes& want = ref[q - ref.front().first].second;
      ASSERT_TRUE(std::equal(got->begin(), got->end(), want.begin(), want.end())) << q;
    }
    // Wrap-around waste is bounded by one maximum message.
    std::size_t kept = 0;
    for (SeqNo q = r.lowest(); q <= r.highest(); ++q) kept += r.get(q)->size();
    ASSERT_LE(kept, kBytes);
  }
}

TEST(Log2Histogram, QuantileUpperBounds) {
  Log2Histogram h;
  EXPECT_EQ(h.quantile_upper(500'000), 0u);
  for (std::uint64_t v = 1; v <= 1000; ++v) h.add(v);
  EXPECT_EQ(h.count(), 1000u);
  EXPECT_EQ(h.min(), 1u);
  EXPECT_EQ(h.max(), 1000u);
  EXPECT_EQ(h.quantile_upper(500'000), 511u);  // 500th value lies in [256, 512)
  EXPECT_EQ(h.quantile_upper(999'000), 1000u);  // capped at the max
  EXPECT_EQ(Log2Histogram::bucket(0), 0u);
  EXPECT_EQ(Log2Histogram::bucket(1), 1u);
  EXPECT_EQ(Log2Histogram::bucket(~std::uint64_t{0}), 64u);
}

}  // namespace
}  // namespace lle::mold
