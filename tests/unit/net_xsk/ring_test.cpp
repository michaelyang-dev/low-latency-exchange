// AF_XDP ring index arithmetic (no kernel needed): producer/consumer over an in-memory
// ring map, including free-running index wrap-around.
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "net/xsk/ring.h"
#include "net/xsk/socket.h"
#if defined(LLE_XSK_TEST_CLIENT)
#include "client/tx_stamps.h"
#include "net/utcp/wire.h"
#endif

namespace lle::net::xsk {
namespace {

struct FakeRing {
  explicit FakeRing(std::uint32_t size, std::uint32_t start = 0) : desc(size), prod(start), cons(start) {
    m.producer = &prod;
    m.consumer = &cons;
    m.flags = &flags;
    m.desc = desc.data();
    m.size = size;
  }
  std::vector<std::uint64_t> desc;
  std::uint32_t prod;
  std::uint32_t cons;
  std::uint32_t flags = 0;
  RingMap m;
};

TEST(XskRing, ProduceConsumeWrap) {
  FakeRing r(8, 0xFFFFFFFAu);  // indices wrap past 2^32 during the test
  ProducerRing<std::uint64_t> p(r.m);
  ConsumerRing<std::uint64_t> c(r.m);
  std::uint64_t next_in = 0, next_out = 0;
  for (int round = 0; round < 100; ++round) {
    std::uint32_t idx = 0;
    const std::uint32_t got = p.reserve(5, &idx);
    for (std::uint32_t i = 0; i < got; ++i) p.at(idx + i) = next_in++;
    p.submit();
    std::uint32_t cidx = 0;
    const std::uint32_t n = c.peek(3, &cidx);
    for (std::uint32_t i = 0; i < n; ++i) EXPECT_EQ(c.at(cidx + i), next_out++);
    c.release(n);
    EXPECT_LE(next_in - next_out, 8u);
  }
  // Like libxdp's xsk_cons_nb_avail(), peek() re-reads the producer index only once its
  // cached view is empty, so draining takes as many peeks as needed.
  for (int k = 0; k < 4 && next_out != next_in; ++k) {
    std::uint32_t cidx = 0;
    const std::uint32_t n = c.peek(100, &cidx);
    for (std::uint32_t i = 0; i < n; ++i) EXPECT_EQ(c.at(cidx + i), next_out++);
    c.release(n);
  }
  EXPECT_EQ(next_in, next_out);
}

TEST(XskRing, ProducerNeverOverruns) {
  FakeRing r(4);
  ProducerRing<std::uint64_t> p(r.m);
  std::uint32_t idx = 0;
  EXPECT_EQ(p.reserve(10, &idx), 4u);
  p.submit();
  EXPECT_EQ(p.reserve(1, &idx), 0u);
  r.cons += 2;  // the "kernel" consumed two
  EXPECT_EQ(p.reserve(3, &idx), 2u);
  r.flags = XDP_RING_NEED_WAKEUP;
  EXPECT_TRUE(p.needs_wakeup());
}

TEST(XskRing, MetadataLayouts) {
  EXPECT_EQ(sizeof(RxMetaWire), 16u);
  EXPECT_EQ(sizeof(xsk_tx_metadata), 24u);  // tx_metadata_len = 24 (07 §2.3)
}

TEST(XskTxCompletion, OptionsDefaultsKeepOldBehaviour) {
  const TxOptions o;
  EXPECT_EQ(o.cookie, 0u);
  EXPECT_FALSE(o.notify);
  EXPECT_FALSE(o.timestamp);
  const TxCompletion c;
  EXPECT_FALSE(c.valid);
  EXPECT_EQ(c.hw_tx_ns, 0);
}

#if defined(LLE_XSK_TEST_CLIENT)
std::vector<std::byte> tcp(std::uint32_t seq, std::uint8_t flags, std::size_t len) {
  std::vector<std::byte> b(256);
  utcp::TcpHeaderSpec h;
  h.src_port = 40000;
  h.dst_port = 9;
  h.seq = seq;
  h.flags = flags;
  std::vector<std::byte> pl(len, std::byte{1});
  b.resize(utcp::build_tcp(b, utcp::LinkType::Ethernet, h, pl, {}, false));
  return b;
}

// Completions matched by TX cookie: a stamped frame whose completion is never reported
// is skipped (lost) without shifting the stamps of the frames after it.
TEST(XskTxCompletion, TrackerMatchesByIdAndSkipsLost) {
  using namespace utcp::tcp_flag;
  client::FrameStampTracker t;
  t.init(16);
  EXPECT_FALSE(t.on_tx(tcp(100, kSyn, 0)));
  ASSERT_TRUE(t.on_tx(tcp(101, kAck | kPsh, 10)));  // id 1: bytes 0..9
  EXPECT_EQ(t.last_id(), 1u);
  ASSERT_TRUE(t.on_tx(tcp(111, kAck | kPsh, 10)));  // id 2: 10..19 (its completion is lost)
  ASSERT_TRUE(t.on_tx(tcp(121, kAck | kPsh, 10)));  // id 3: 20..29
  EXPECT_EQ(t.last_id(), 3u);
  t.on_completion_for(1, 1000);
  t.on_completion_for(3, 3000);
  t.on_completion_for(9, 9000);  // not in flight
  std::vector<client::FrameStampTracker::Stamped> out;
  t.drain([&](const client::FrameStampTracker::Stamped& s) { out.push_back(s); });
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].id, 1u);
  EXPECT_EQ(out[0].stamp.first, 0u);
  EXPECT_EQ(out[0].stamp.ts.hw_ns, 1000);
  EXPECT_EQ(out[1].id, 3u);
  EXPECT_EQ(out[1].stamp.first, 20u);
  EXPECT_EQ(out[1].stamp.last, 29u);
  EXPECT_EQ(out[1].stamp.ts.hw_ns, 3000);
  EXPECT_EQ(t.lost_completions(), 1u);
  EXPECT_EQ(t.unmatched_completions(), 1u);
  EXPECT_EQ(t.inflight(), 0u);
}
#endif

}  // namespace
}  // namespace lle::net::xsk
