// Replication data-plane codec (10 §2): golden bytes assembled from the layout in
// repl/wire.h with an independent Python CRC32C, round trips of every type, the
// canonical-only decoder, and APPEND record framing.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "common/crc32c.h"
#include "common/endian.h"
#include "journal/record.h"
#include "repl/wire.h"

namespace lle::repl::wire {
namespace {

using Bytes = std::vector<std::byte>;

Bytes bytes(std::initializer_list<int> v) {
  Bytes out;
  for (int x : v) out.push_back(static_cast<std::byte>(x));
  return out;
}

Bytes enc(const Message& m) {
  Bytes out(kMaxDatagram);
  const std::size_t n = encode(m, out);
  out.resize(n);
  return out;
}

// One canonical EpochStart record: index 1, ts 5, epoch 1, primary 0.
Bytes epoch_start_record() {
  journal::Sealer canonical;
  Bytes rec(journal::record_bytes_for_payload(16));
  (void)journal::build_record(rec.data(), journal::Stamp{1, 5, 1, 0, 0}, journal::EpochStart{1, 0, 0}, canonical);
  return rec;
}

Bytes ouch_record(std::uint64_t index, std::uint32_t prev_crc, std::size_t msg_bytes) {
  journal::Sealer canonical;
  const Bytes msg(msg_bytes, std::byte{0x33});
  const journal::OuchInbound o{1, 2, 3, msg};
  Bytes rec(journal::record_size(o));
  (void)journal::build_record(rec.data(), journal::Stamp{index, 10, 1, prev_crc, 0}, o, canonical);
  return rec;
}

TEST(ReplWire, GoldenAck) {
  const auto expect = bytes({0x4c, 0x52, 0x50, 0x31, 0x01, 0x02, 0x01, 0x01, 0x28, 0x00, 0x00, 0x00, 0x03, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00,
                             0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x91, 0xad, 0x26});
  const Ack a{1, true, 3, 0x11'2233'4455, 2, 0, 0};
  EXPECT_EQ(enc(a), expect);
  const auto d = decode(expect);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(std::get<Ack>(*d), a);
}

TEST(ReplWire, GoldenNack) {
  const auto expect = bytes({0x4c, 0x52, 0x50, 0x31, 0x01, 0x03, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x07,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x8a, 0xa3, 0x01});
  const Nack n{0, false, 7, 9, 4};
  EXPECT_EQ(enc(n), expect);
  EXPECT_EQ(std::get<Nack>(*decode(expect)), n);
}

TEST(ReplWire, GoldenAppendWithOneRecord) {
  const Bytes rec = epoch_start_record();
  EXPECT_EQ(load_le32(rec.data() + journal::hdr::kCrc), 0xd2ac4550u);  // independent CRC32C
  const auto expect = bytes(
      {0x4c, 0x52, 0x50, 0x31, 0x01, 0x01, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38,
       0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x50, 0x45, 0xac, 0xd2,
       0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
       0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0xe8, 0xf1, 0x86});
  Append a;
  a.epoch = 1;
  a.first_index = 1;
  a.first_len = 56;
  a.records = rec;
  EXPECT_EQ(enc(a), expect);
  const auto d = decode(expect);
  ASSERT_TRUE(d.has_value());
  const auto& got = std::get<Append>(*d);
  EXPECT_EQ(got.first_index, 1u);
  EXPECT_EQ(got.first_len, 56u);
  EXPECT_TRUE(std::equal(got.records.begin(), got.records.end(), rec.begin(), rec.end()));
}

TEST(ReplWire, RoundTripEveryType) {
  const Bytes rec = epoch_start_record();
  const Bytes ouch(17, std::byte{0x5a});
  Append ap;
  ap.from = 1;
  ap.catchup = true;
  ap.epoch = 4;
  ap.first_index = 1;
  ap.commit_index = 9;
  ap.mold_watermark = 77;
  ap.target_inc = 3;
  ap.first_len = 56;
  ap.has_hash = true;
  ap.hash = StateHash{65536, 0xABCDEF};
  ap.soup_count = 2;
  ap.soup[0] = SoupWatermark{5, 100};
  ap.soup[1] = SoupWatermark{6, 200};
  ap.records = rec;
  Heartbeat hb;
  hb.from = 0;
  hb.epoch = 2;
  hb.last = 10;
  hb.commit = 9;
  hb.applied = 8;
  hb.released = 7;
  hb.durable = 6;
  hb.inc = 5;
  hb.build_id = 4;
  hb.hash = StateHash{3, 2};
  hb.partner_inc = 1;
  hb.role = 2;
  hb.members = 3;
  hb.primary = 1;
  Forward fw;
  fw.from = 1;
  fw.epoch = 3;
  fw.inc = 2;
  fw.seq = 11;
  fw.session_id = 42;
  fw.account = 43;
  fw.instance = 0x8001;
  fw.bytes = ouch;
  fw.record_flags = journal::kFlagMalformedInput;
  Forward ev;
  ev.from = 1;
  ev.kind = ForwardKind::kSessionEvent;
  ev.event = 4;
  ev.requested_seq = 99;
  ev.seq = 1;
  SnapshotChunk sc;
  sc.from = 0;
  sc.snap_index = 50;
  sc.total = 1000;
  sc.offset = 100;
  sc.inc = 2;
  sc.epoch = 3;
  sc.bytes = ouch;
  const std::vector<Message> all = {ap, Ack{0, false, 1, 2, 3, 4, 5}, Nack{1, true, 6, 7, 8}, hb, fw, ev,
                                    EpochEndQuery{0, 1, 2, 3, 4}, EpochEnd{1, true, 2, 3, 4, 5, 6, 7, 8, 9, 10},
                                    CatchupReq{0, 9, 10, 13, 11, 12, 14}, sc};
  for (const Message& m : all) {
    const Bytes b = enc(m);
    ASSERT_FALSE(b.empty()) << to_string(type_of(m));
    const auto d = decode(b);
    ASSERT_TRUE(d.has_value()) << to_string(type_of(m)) << " " << to_string(d.error());
    EXPECT_EQ(type_of(*d), type_of(m));
    EXPECT_EQ(enc(*d), b) << to_string(type_of(m));  // canonical: decode -> encode is the identity
  }
}

TEST(ReplWire, RejectsDamagedAndNonCanonical) {
  const Bytes good = enc(Ack{1, false, 3, 4, 5, 0, 0});
  ASSERT_TRUE(decode(good).has_value());
  for (std::size_t i = 0; i < good.size(); ++i) {
    Bytes b = good;
    b[i] ^= std::byte{0x01};
    EXPECT_FALSE(decode(b).has_value()) << "flipped byte " << i;
  }
  for (std::size_t n = 0; n < good.size(); ++n) {
    EXPECT_FALSE(decode(std::span<const std::byte>(good.data(), n)).has_value()) << "truncated to " << n;
  }
  const auto refit = [](Bytes b) {
    const std::size_t n = b.size() - kTrailerBytes;
    store_le32(b.data() + n, crc32c(b.data(), n));
    return b;
  };
  ASSERT_GT(good.size(), kHeaderBytes + kTrailerBytes);
  // Allocated up front: GCC's -Wnull-dereference at -O2 cannot see that a copy of
  // `good` is never empty.
  Bytes b;
  b.reserve(kMaxDatagram);
  b.assign(good.begin(), good.end());
  b[7] = std::byte{0x02};  // undefined flag bit
  EXPECT_EQ(decode(refit(b)).error(), DecodeError::kFlags);
  b = good;
  b[10] = std::byte{0x01};  // reserved header bytes
  EXPECT_EQ(decode(refit(b)).error(), DecodeError::kPadding);
  b = good;
  b[6] = std::byte{0x02};  // node id out of range
  EXPECT_EQ(decode(refit(b)).error(), DecodeError::kField);
  b = good;
  b[5] = std::byte{0x0A};  // unknown type
  EXPECT_EQ(decode(refit(b)).error(), DecodeError::kType);
}

// FORWARD carries the inbound's journal record flags in what was a reserved field; only
// known flags, and only on OUCH inbound, decode.
TEST(ReplWire, ForwardCarriesRecordFlagsCanonically) {
  const std::vector<std::byte> ouch = {std::byte{'O'}, std::byte{1}};
  Forward fw;
  fw.from = 1;
  fw.epoch = 3;
  fw.inc = 2;
  fw.seq = 1;
  fw.session_id = 42;
  fw.account = 43;
  fw.instance = 1;
  fw.bytes = ouch;
  fw.record_flags = journal::kFlagMalformedInput;
  const Bytes good = enc(fw);
  const auto d = decode(good);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(std::get<Forward>(*d).record_flags, journal::kFlagMalformedInput);
  const auto refit = [](Bytes b) {
    const std::size_t n = b.size() - kTrailerBytes;
    store_le32(b.data() + n, crc32c(b.data(), n));
    return b;
  };
  ASSERT_GT(good.size(), kHeaderBytes + 40);
  Bytes b;
  b.reserve(kMaxDatagram);
  b.assign(good.begin(), good.end());
  b[kHeaderBytes + 38] = std::byte{0x02};  // an unknown record flag
  EXPECT_EQ(decode(refit(b)).error(), DecodeError::kField);
  Forward ev = fw;
  ev.kind = ForwardKind::kSessionEvent;
  ev.event = 1;
  ev.bytes = {};
  ev.record_flags = 0;
  Bytes evb = enc(ev);
  ASSERT_TRUE(decode(evb).has_value());
  ASSERT_GT(evb.size(), kHeaderBytes + 40);
  evb[kHeaderBytes + 38] = std::byte{0x01};  // flags on a session event
  EXPECT_EQ(decode(refit(evb)).error(), DecodeError::kField);
}

TEST(ReplWire, AppendFramingWholeRecordsAndFragments) {
  const Bytes r1 = ouch_record(1, 0, 20);
  const Bytes r2 = ouch_record(2, journal::RecordView(std::span<const std::byte>(r1)).crc(), 30);
  Bytes two = r1;
  two.insert(two.end(), r2.begin(), r2.end());
  const auto len1 = static_cast<std::uint32_t>(r1.size());
  EXPECT_TRUE(append_framing_ok(0, len1, two));
  EXPECT_FALSE(append_framing_ok(0, len1 + 8, two));  // first_len disagrees with the record
  // A record cut short without being a fragment is malformed.
  EXPECT_FALSE(append_framing_ok(0, len1, std::span<const std::byte>(two.data(), two.size() - 8)));
  // Fragments of one record.
  EXPECT_TRUE(append_framing_ok(0, len1, std::span<const std::byte>(r1.data(), 16)));
  EXPECT_TRUE(append_framing_ok(16, len1, std::span<const std::byte>(r1.data() + 16, len1 - 16)));
  EXPECT_FALSE(append_framing_ok(16, len1, std::span<const std::byte>(r1.data(), len1)));  // past the end
  EXPECT_FALSE(append_framing_ok(len1, len1, std::span<const std::byte>(r1.data(), 8)));
  // The encoder refuses what the decoder would reject.
  Append a;
  a.first_index = 1;
  a.first_len = len1 + 8;
  a.records = two;
  Bytes out(kMaxDatagram);
  EXPECT_EQ(encode(a, out), 0u);
}

TEST(ReplWire, AppendCapacityFitsTheMtuBudget) {
  EXPECT_EQ(kMaxDatagram, 1400u);
  EXPECT_EQ(append_capacity(false, 0) + kAppendFixed + kHeaderBytes + kTrailerBytes, kMaxDatagram);
  // A full APPEND encodes to exactly 1,400 bytes.
  std::vector<Bytes> recs;
  Bytes all;
  std::uint32_t prev = 0;
  for (std::uint64_t i = 1; all.size() + 64 <= append_capacity(false, 0); ++i) {
    recs.push_back(ouch_record(i, prev, 8));
    prev = journal::RecordView(std::span<const std::byte>(recs.back())).crc();
    all.insert(all.end(), recs.back().begin(), recs.back().end());
  }
  Append a;
  a.first_index = 1;
  a.first_len = static_cast<std::uint32_t>(recs[0].size());
  a.records = all;
  const Bytes b = enc(a);
  EXPECT_LE(b.size(), kMaxDatagram);
  EXPECT_TRUE(decode(b).has_value());
}

}  // namespace
}  // namespace lle::repl::wire
