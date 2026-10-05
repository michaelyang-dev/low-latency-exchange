// Golden format test for journal records and segment headers (06 §3, 01 §6).
// Expected bytes and CRC values were hand-assembled from the layout tables in
// journal/record.h and journal/segment.h and computed with an independent bitwise
// CRC32C implementation (poly 0x82F63B78), not with lle::crc32c.
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <vector>

#include "common/crc32c.h"
#include "common/prng.h"
#include "journal/record.h"
#include "journal/segment.h"

namespace lle::journal {
namespace {

std::vector<std::byte> bytes_of(std::initializer_list<int> v) {
  std::vector<std::byte> out;
  for (int x : v) out.push_back(static_cast<std::byte>(x));
  return out;
}

constexpr std::uint64_t kNonce = 0x0123456789ABCDEFull;
constexpr std::byte kMsg[] = {std::byte{'O'}, std::byte{'U'}, std::byte{'C'}, std::byte{'H'},
                              std::byte{'M'}, std::byte{'S'}, std::byte{'G'}};

TEST(JournalFormat, HeaderLayoutIsPinned) {
  static_assert(sizeof(RecordHeader) == 40);
  static_assert(alignof(RecordHeader) == 8);
  EXPECT_EQ(hdr::kLen, 0u);
  EXPECT_EQ(hdr::kCrc, 4u);
  EXPECT_EQ(hdr::kIndex, 8u);
  EXPECT_EQ(hdr::kTs, 16u);
  EXPECT_EQ(hdr::kEpoch, 24u);
  EXPECT_EQ(hdr::kType, 28u);
  EXPECT_EQ(hdr::kFlags, 30u);
  EXPECT_EQ(hdr::kPrevCrc, 32u);
  EXPECT_EQ(hdr::kReserved, 36u);
  EXPECT_EQ(static_cast<int>(RecordType::DayStart), 1);
  EXPECT_EQ(static_cast<int>(RecordType::Config), 2);
  EXPECT_EQ(static_cast<int>(RecordType::SessionEvent), 3);
  EXPECT_EQ(static_cast<int>(RecordType::OuchInbound), 4);
  EXPECT_EQ(static_cast<int>(RecordType::Timer), 5);
  EXPECT_EQ(static_cast<int>(RecordType::Admin), 6);
  EXPECT_EQ(static_cast<int>(RecordType::SnapshotMark), 7);
  EXPECT_EQ(static_cast<int>(RecordType::EpochStart), 8);
  EXPECT_EQ(static_cast<int>(RecordType::DayEnd), 9);
  EXPECT_EQ(static_cast<int>(RecordType::Pad), 10);
}

TEST(JournalFormat, OuchInboundGoldenBytes) {
  const auto expected = bytes_of({
      0x40, 0x00, 0x00, 0x00,                          // len 64
      0xcf, 0x68, 0x11, 0x54,                          // seal 0x541168CF
      0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // index 7
      0x15, 0xcd, 0x85, 0x3d, 0xfe, 0x9c, 0x97, 0x17,  // ts 1700000000123456789
      0x03, 0x00, 0x00, 0x00,                          // epoch 3
      0x04, 0x00,                                      // type OuchInbound
      0x00, 0x00,                                      // flags
      0xef, 0xbe, 0xad, 0xde,                          // prev_crc 0xDEADBEEF
      0x00, 0x00, 0x00, 0x00,                          // reserved
      0x44, 0x33, 0x22, 0x11,                          // session_id
      0x88, 0x77, 0x66, 0x55,                          // account
      0x02, 0x01,                                      // instance
      0x07, 0x00,                                      // msg_len 7
      0x00, 0x00, 0x00, 0x00,                          // reserved
      0x4f, 0x55, 0x43, 0x48, 0x4d, 0x53, 0x47,        // "OUCHMSG"
      0x00,                                            // padding
  });
  const Sealer sealer(kNonce);
  const OuchInbound o{0x11223344u, 0x55667788u, 0x0102u, std::span<const std::byte>(kMsg)};
  ASSERT_EQ(record_size(o), 64u);
  std::array<std::byte, 64> out{};
  const std::uint32_t content = build_record(out.data(), Stamp{7, 1'700'000'000'123'456'789, 3, 0xDEADBEEFu, 0}, o, sealer);
  EXPECT_EQ(std::vector<std::byte>(out.begin(), out.end()), expected);
  EXPECT_EQ(content, 0xC8735372u);
  EXPECT_EQ(nonce_seed(kNonce), 0x65B0D823u);

  // The seal is literally CRC32C(le64(nonce) || record with crc zeroed).
  std::array<std::byte, 72> cat{};
  store_le64(cat.data(), kNonce);
  std::memcpy(cat.data() + 8, out.data(), 64);
  std::memset(cat.data() + 8 + hdr::kCrc, 0, 4);
  EXPECT_EQ(crc32c(cat.data(), cat.size()), 0x541168CFu);
  EXPECT_EQ(crc32c_extend(nonce_seed(kNonce), cat.data() + 8, 64), 0x541168CFu);

  // Views decode it back.
  const auto v = parse_record(std::span<const std::byte>(out));
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->len(), 64u);
  EXPECT_EQ(v->index(), 7u);
  EXPECT_EQ(v->ts_ns(), 1'700'000'000'123'456'789);
  EXPECT_EQ(v->epoch(), 3u);
  EXPECT_EQ(v->type(), RecordType::OuchInbound);
  EXPECT_EQ(v->prev_crc(), 0xDEADBEEFu);
  EXPECT_EQ(v->content(), 0xC8735372u);
  EXPECT_EQ(sealer.verify(out.data()), std::optional<std::uint32_t>(0xC8735372u));
  EXPECT_EQ(sealer.content_of(out.data()), 0xC8735372u);
  const auto d = decode_ouch_inbound(*v);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->session_id, 0x11223344u);
  EXPECT_EQ(d->account, 0x55667788u);
  EXPECT_EQ(d->instance, 0x0102u);
  ASSERT_EQ(d->msg.size(), 7u);
  EXPECT_EQ(std::memcmp(d->msg.data(), kMsg, 7), 0);
}

TEST(JournalFormat, SegmentHeaderGoldenBytes) {
  SegmentHeader h;
  h.day = 20260930;
  h.epoch = 2;
  h.first_index = 1;
  h.nonce = kNonce;
  h.prev_last_crc = 0xCAFEBABEu;
  h.segment_bytes = std::uint64_t{1} << 30;
  std::array<std::byte, kSegmentHeaderBytes> b{};
  encode_segment_header(b, h);
  const auto head = bytes_of({
      'L', 'L', 'E', 'J', 'R', 'N', 'L', '1',          // magic
      0x01, 0x00, 0x00, 0x00,                          // version 1
      0x00, 0x10, 0x00, 0x00,                          // header bytes 4096
      0x42, 0x28, 0x35, 0x01,                          // day 20260930 (0x01352842)
      0x02, 0x00, 0x00, 0x00,                          // epoch 2
      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // first index 1
      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,  // nonce
      0xbe, 0xba, 0xfe, 0xca,                          // prev last crc
      0x00, 0x00, 0x00, 0x00,                          // reserved
      0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,  // segment bytes 1 GiB
  });
  EXPECT_EQ(std::vector<std::byte>(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(head.size())), head);
  for (std::size_t i = head.size(); i < kSegmentHeaderBytes - 4; ++i) ASSERT_EQ(b[i], std::byte{0}) << i;
  EXPECT_EQ(load_le32(b.data() + kSegmentHeaderBytes - 4), 0x521150BDu);
  const auto d = decode_segment_header(b);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(*d, h);
  EXPECT_EQ(segment_file_name(2, 1), "0002-00000000000000000001.seg");
}

TEST(JournalFormat, SegmentHeaderRejectsDamage) {
  SegmentHeader h;
  h.day = 20260930;
  h.nonce = kNonce;
  h.segment_bytes = kMinSegmentBytes;
  std::array<std::byte, kSegmentHeaderBytes> b{};
  encode_segment_header(b, h);
  ASSERT_TRUE(decode_segment_header(b).has_value());
  for (std::size_t i = 0; i < kSegmentHeaderBytes; i += 7) {
    auto c = b;
    c[i] ^= std::byte{0x10};
    EXPECT_FALSE(decode_segment_header(c).has_value()) << i;
  }
  EXPECT_EQ(decode_segment_header(std::span<const std::byte>(b).first(100)).error(), HeaderError::Truncated);
  h.nonce = 0;
  encode_segment_header(b, h);
  EXPECT_EQ(decode_segment_header(b).error(), HeaderError::BadNonce);
  h.nonce = kNonce;
  h.segment_bytes = kMinSegmentBytes + 8;
  encode_segment_header(b, h);
  EXPECT_EQ(decode_segment_header(b).error(), HeaderError::BadSize);
}

// seal == crc32c_extend(seed, record with crc zeroed) for random records and nonces:
// the mask table reproduces the seeded CRC exactly at every length.
TEST(JournalFormat, SealMatchesSeededCrcAtEveryLength) {
  Prng rng(42);
  std::vector<std::byte> rec(kMaxRecordBytes);
  for (int round = 0; round < 3; ++round) {
    const std::uint64_t nonce = rng.next_u64() | 1;
    const Sealer s(nonce);
    for (std::uint32_t len = kHeaderBytes; len <= kMaxRecordBytes; len += (len < 512 ? 8 : 1016)) {
      for (std::uint32_t i = 0; i < len; ++i) rec[i] = static_cast<std::byte>(rng.next_u64());
      store_le32(rec.data(), len);
      const std::uint32_t content = s.seal(rec.data());
      std::vector<std::byte> z(rec.begin(), rec.begin() + len);
      std::memset(z.data() + hdr::kCrc, 0, 4);
      ASSERT_EQ(content, crc32c(z.data(), len)) << len;
      ASSERT_EQ(load_le32(rec.data() + hdr::kCrc), crc32c_extend(nonce_seed(nonce), z.data(), len)) << len;
      ASSERT_TRUE(s.verify(rec.data()).has_value());
      // Re-sealing for another medium equals sealing from scratch there.
      const Sealer other(nonce ^ 0xFFFF0000FFFFull);
      std::vector<std::byte> copy(rec.begin(), rec.begin() + len);
      EXPECT_EQ(other.reseal(copy.data(), s), content);
      EXPECT_EQ(load_le32(copy.data() + hdr::kCrc), crc32c_extend(other.seed(), z.data(), len));
      EXPECT_FALSE(s.verify(copy.data()).has_value());
      EXPECT_TRUE(other.verify(copy.data()).has_value());
    }
  }
  // Nonce 0 is the canonical form: seal == content crc.
  const Sealer canonical;
  store_le32(rec.data(), 64);
  const std::uint32_t c = canonical.seal(rec.data());
  EXPECT_EQ(load_le32(rec.data() + hdr::kCrc), c);
  EXPECT_FALSE(usable_nonce(0));
}

TEST(JournalFormat, ParseRecordStructuralChecks) {
  const Sealer s(kNonce);
  std::array<std::byte, 64> out{};
  (void)build_record(out.data(), Stamp{1, 1, 0, 0, 0}, SnapshotMark{9}, s);
  EXPECT_TRUE(parse_record(out).has_value());
  EXPECT_EQ(parse_record(std::span<const std::byte>(out).first(39)).error(), ParseError::Truncated);
  EXPECT_EQ(parse_record(std::span<const std::byte>(out).first(47)).error(), ParseError::Truncated);
  auto bad = out;
  store_le32(bad.data(), 44);
  EXPECT_EQ(parse_record(bad).error(), ParseError::BadLength);
  store_le32(bad.data(), 32);
  EXPECT_EQ(parse_record(bad).error(), ParseError::BadLength);
  store_le32(bad.data(), kMaxRecordBytes + 8);
  EXPECT_EQ(parse_record(bad).error(), ParseError::BadLength);
  bad = out;
  store_le16(bad.data() + hdr::kType, 0);
  EXPECT_EQ(parse_record(bad).error(), ParseError::BadType);
  store_le16(bad.data() + hdr::kType, 11);
  EXPECT_EQ(parse_record(bad).error(), ParseError::BadType);
}

template <class P, class D>
void round_trip(const P& p, D decode) {
  const Sealer s(kNonce);
  std::vector<std::byte> buf(record_size(p));
  (void)build_record(buf.data(), Stamp{5, 100, 1, 0x1234, 0}, p, s);
  const auto v = parse_record(buf);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->type(), P::kType);
  EXPECT_EQ(v->len() % 8, 0u);
  const auto d = decode(*v);
  ASSERT_TRUE(d.has_value());
  if constexpr (std::equality_comparable<P>) EXPECT_EQ(*d, p);
  // Wrong type is rejected by every other decoder.
  if (P::kType != RecordType::Timer) EXPECT_EQ(decode_timer(*v).error(), DecodeError::WrongType);
  // Truncated (shorter record length) is rejected.
  if (v->len() > kHeaderBytes) {
    std::vector<std::byte> shorter(buf.begin(), buf.end() - 8);
    store_le32(shorter.data(), static_cast<std::uint32_t>(shorter.size()));
    EXPECT_FALSE(decode(RecordView(shorter)).has_value());
  }
}

TEST(JournalFormat, PayloadRoundTrips) {
  DayStart ds;
  ds.trading_date = 20260930;
  ds.local_midnight_ns = 1'790'740'800'000'000'000;
  ds.build_id = 0xABCDEF;
  std::memcpy(ds.mold_session.data(), "MOLD000001", 10);
  std::memcpy(ds.soup_session.data(), "SOUP000001", 10);
  round_trip(ds, decode_day_start);
  round_trip(SessionEvent{77, 2, SessionEventKind::MirrorAttach, 12345}, decode_session_event);
  round_trip(Timer{9, TimerKind::Cross, 34'200'000'000'000}, decode_timer);
  round_trip(SnapshotMark{10'000'000}, decode_snapshot_mark);
  round_trip(EpochStart{4, 2, 0xFEEDFACECAFEBEEFull}, decode_epoch_start);
  round_trip(DayEnd{1'000'000, 5'000'000, 900'000}, decode_day_end);

  std::vector<std::byte> blob(5000);
  for (std::size_t i = 0; i < blob.size(); ++i) blob[i] = static_cast<std::byte>(i * 7);
  const ConfigChunk cc{ConfigTable::RiskLimits, 1, 3, 15000, blob};
  round_trip(cc, [&](const RecordView& v) {
    auto d = decode_config(v);
    if (d) {
      EXPECT_EQ(d->table, ConfigTable::RiskLimits);
      EXPECT_EQ(d->chunk_index, 1);
      EXPECT_EQ(d->chunk_count, 3);
      EXPECT_EQ(d->table_bytes, 15000u);
      EXPECT_TRUE(std::equal(d->bytes.begin(), d->bytes.end(), blob.begin(), blob.end()));
    }
    return d;
  });
  const Admin a{0x0101, 1, 42, std::span<const std::byte>(blob).first(33)};
  round_trip(a, [&](const RecordView& v) {
    auto d = decode_admin(v);
    if (d) {
      EXPECT_EQ(d->command, 0x0101);
      EXPECT_EQ(d->operator_id, 42u);
      EXPECT_EQ(d->args.size(), 33u);
    }
    return d;
  });
  const OuchInbound o{1, 2, 3, std::span<const std::byte>(blob).first(140)};
  round_trip(o, decode_ouch_inbound);
}

TEST(JournalFormat, DecodersRejectBadFields) {
  const Sealer s(kNonce);
  std::array<std::byte, 56> b{};
  (void)build_record(b.data(), Stamp{1, 1, 0, 0, 0}, Timer{1, TimerKind::DayEnd, 5}, s);
  store_le16(b.data() + kHeaderBytes + 4, 99);
  EXPECT_EQ(decode_timer(RecordView(b)).error(), DecodeError::BadField);
  (void)build_record(b.data(), Stamp{1, 1, 0, 0, 0}, SessionEvent{1, 1, SessionEventKind::Login, 0}, s);
  b[kHeaderBytes + 6] = std::byte{0};
  EXPECT_EQ(decode_session_event(RecordView(b)).error(), DecodeError::BadField);

  std::vector<std::byte> blob(64);
  std::vector<std::byte> c(record_size(ConfigChunk{ConfigTable::Symbols, 0, 1, 64, blob}));
  (void)build_record(c.data(), Stamp{1, 1, 0, 0, 0}, ConfigChunk{ConfigTable::Symbols, 0, 1, 64, blob}, s);
  auto bad = c;
  store_le16(bad.data() + kHeaderBytes + 2, 1);  // chunk_index >= chunk_count
  EXPECT_EQ(decode_config(RecordView(bad)).error(), DecodeError::BadField);
  bad = c;
  store_le32(bad.data() + kHeaderBytes + 12, 9999);  // chunk bytes beyond the record
  EXPECT_EQ(decode_config(RecordView(bad)).error(), DecodeError::BadSize);
  bad = c;
  store_le16(bad.data() + kHeaderBytes, 0);  // table 0
  EXPECT_EQ(decode_config(RecordView(bad)).error(), DecodeError::BadField);

  // Canonical form: padding and reserved bytes must be zero.
  std::array<std::byte, 64> o{};
  (void)build_record(o.data(), Stamp{1, 1, 0, 0, 0}, OuchInbound{1, 2, 3, std::span<const std::byte>(kMsg)}, s);
  ASSERT_TRUE(decode_ouch_inbound(RecordView(o)).has_value());
  auto nc = o;
  nc[63] = std::byte{1};  // padding after the 7-byte message
  EXPECT_EQ(decode_ouch_inbound(RecordView(nc)).error(), DecodeError::NonCanonical);
  nc = o;
  nc[kHeaderBytes + 12] = std::byte{1};  // reserved
  EXPECT_EQ(decode_ouch_inbound(RecordView(nc)).error(), DecodeError::NonCanonical);
}

TEST(JournalFormat, BuilderChainsAndStampsMonotonically) {
  const Sealer s(kNonce);
  RecordBuilder b(s);
  b.set_epoch(1);
  std::array<std::byte, 64> r1{}, r2{}, r3{};
  ASSERT_FALSE(b.append(r1, 1000, SnapshotMark{1}).empty());
  ASSERT_FALSE(b.append(r2, 900, SnapshotMark{2}).empty());  // clock went backwards
  ASSERT_FALSE(b.append(r3, 900, SnapshotMark{3}).empty());
  const RecordView v1(std::span<const std::byte>(r1).first(48));
  const RecordView v2(std::span<const std::byte>(r2).first(48));
  const RecordView v3(std::span<const std::byte>(r3).first(48));
  EXPECT_EQ(v1.index(), 1u);
  EXPECT_EQ(v2.index(), 2u);
  EXPECT_EQ(v3.index(), 3u);
  EXPECT_EQ(v1.ts_ns(), 1000);
  EXPECT_EQ(v2.ts_ns(), 1001);
  EXPECT_EQ(v3.ts_ns(), 1002);
  EXPECT_EQ(v1.prev_crc(), 0u);
  EXPECT_EQ(v2.prev_crc(), v1.content());
  EXPECT_EQ(v3.prev_crc(), v2.content());
  EXPECT_EQ(b.chain().last_crc, v3.content());
  EXPECT_EQ(v3.epoch(), 1u);
  std::array<std::byte, 40> small{};
  EXPECT_TRUE(b.append(small, 5000, SnapshotMark{4}).empty());
  EXPECT_EQ(b.chain().last_index, 3u);
}

TEST(JournalFormat, PadRepeatsChainPosition) {
  const Sealer s(kNonce);
  const ChainState c{41, 0xAABBCCDD, 777, 2};
  std::array<std::byte, 4096> pad{};
  pad.fill(std::byte{0x5A});
  build_pad(pad.data(), 4096, c, s);
  const auto v = parse_record(pad);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->type(), RecordType::Pad);
  EXPECT_EQ(v->index(), 41u);
  EXPECT_EQ(v->prev_crc(), 0xAABBCCDDu);
  EXPECT_TRUE(s.verify(pad.data()).has_value());
  for (std::size_t i = kHeaderBytes; i < pad.size(); ++i) ASSERT_EQ(pad[i], std::byte{0});
  EXPECT_EQ(padded_batch_bytes(0), 0u);
  EXPECT_EQ(padded_batch_bytes(4096), 4096u);
  EXPECT_EQ(padded_batch_bytes(4096 - 40), 4096u);
  EXPECT_EQ(padded_batch_bytes(4096 - 32), 8192u);  // a 32-byte gap cannot hold a Pad
  EXPECT_EQ(padded_batch_bytes(8), 4096u);
}

}  // namespace
}  // namespace lle::journal
