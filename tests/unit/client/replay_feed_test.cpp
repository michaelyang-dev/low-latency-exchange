// mold_replay's publishing core: seeded impairments (LossyLine) and independent
// dual-line packetization (ReplayFeed). 03-protocols §6, §9.
#include <gtest/gtest.h>

#include <map>
#include <set>
#include <vector>

#include "client/lossy_line.h"
#include "client/replay_feed.h"
#include "itch_gen.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::client {
namespace {

struct Sent {
  int line;
  Nanos t;
  std::vector<std::byte> bytes;
};

std::vector<std::byte> packet(std::uint8_t tag) { return std::vector<std::byte>(30, std::byte{tag}); }

TEST(LossyLine, SameSeedSameDecisions) {
  LineImpairment imp{100'000, 50'000, 50'000, 1'000};
  std::vector<int> a, b;
  for (auto* out : {&a, &b}) {
    LossyLine l(imp, 42, 64);
    for (int i = 0; i < 2000; ++i) {
      int copies = 0;
      const auto p = packet(static_cast<std::uint8_t>(i));
      l.offer(p, 1, false, i * 100, [&](std::span<const std::byte>) { ++copies; });
      l.release(i * 100, [&](std::span<const std::byte>) { copies += 10; });
      out->push_back(copies);
    }
  }
  EXPECT_EQ(a, b);
}

TEST(LossyLine, LossPatternIndependentOfDupAndReorderRates) {
  auto losses = [](LineImpairment imp) {
    LossyLine l(imp, 7, 4096);
    std::vector<bool> lost;
    for (int i = 0; i < 5000; ++i) {
      const auto before = l.stats().dropped;
      l.offer(packet(1), 1, false, i, [](std::span<const std::byte>) {});
      lost.push_back(l.stats().dropped != before);
    }
    return lost;
  };
  const auto base = losses({30'000, 0, 0, 100});
  EXPECT_EQ(base, losses({30'000, 200'000, 0, 100}));
  EXPECT_EQ(base, losses({30'000, 0, 300'000, 5'000}));
}

TEST(LossyLine, RatesAreNearTheConfiguredProbabilities) {
  LossyLine l({20'000, 10'000, 0, 100}, 3, 16);
  std::uint64_t sent = 0;
  for (int i = 0; i < 200'000; ++i) l.offer(packet(1), 3, false, i, [&](std::span<const std::byte>) { ++sent; });
  const auto& s = l.stats();
  EXPECT_NEAR(static_cast<double>(s.dropped) / 200'000, 0.02, 0.002);
  EXPECT_NEAR(static_cast<double>(s.duplicated) / 200'000, 0.0098, 0.0015);
  EXPECT_EQ(s.messages_dropped, 3 * s.dropped);
  EXPECT_EQ(sent, s.sent);
  EXPECT_EQ(s.sent, 200'000 - s.dropped + s.duplicated);
}

TEST(LossyLine, DelayedPacketsAreReleasedInDueOrderAndOutagesDrop) {
  LossyLine l({0, 0, 1'000'000, 10'000}, 9, 8);  // every packet delayed
  std::vector<std::uint8_t> got;
  for (std::uint8_t i = 0; i < 8; ++i) l.offer(packet(i), 1, false, 0, [&](std::span<const std::byte> p) { got.push_back(std::to_integer<std::uint8_t>(p[0])); });
  EXPECT_TRUE(got.empty());
  EXPECT_EQ(l.delayed_now(), 8u);
  // Pool full: the ninth goes at once.
  l.offer(packet(99), 1, false, 0, [&](std::span<const std::byte> p) { got.push_back(std::to_integer<std::uint8_t>(p[0])); });
  ASSERT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0], 99);
  EXPECT_EQ(l.stats().pool_full, 1u);
  Nanos last_due = 0;
  while (l.delayed_now() != 0) {
    const Nanos d = l.next_deadline();
    EXPECT_GE(d, last_due);
    last_due = d;
    l.release(d, [&](std::span<const std::byte> p) { got.push_back(std::to_integer<std::uint8_t>(p[0])); });
  }
  EXPECT_EQ(got.size(), 9u);
  std::set<std::uint8_t> all(got.begin(), got.end());
  EXPECT_EQ(all.size(), 9u);
  l.offer(packet(5), 4, true, 0, [&](std::span<const std::byte>) { FAIL() << "outage packet sent"; });
  EXPECT_EQ(l.stats().outage_dropped, 1u);
  EXPECT_EQ(l.stats().messages_dropped, 4u);
}

// Collects what each line sends and reconstructs the message stream per line.
struct Capture {
  std::vector<Sent> sent;
  void operator()(int line, std::span<const std::byte> p) { sent.push_back(Sent{line, 0, {p.begin(), p.end()}}); }
};

std::map<SeqNo, std::vector<std::byte>> messages_of(const std::vector<Sent>& sent, int line,
                                                    std::vector<std::pair<SeqNo, std::uint16_t>>* bounds = nullptr) {
  std::map<SeqNo, std::vector<std::byte>> m;
  for (const auto& s : sent) {
    if (s.line != line) continue;
    const auto pv = mold::PacketView::parse(s.bytes);
    EXPECT_TRUE(pv.has_value());
    if (!pv || pv->message_count() == 0) continue;
    if (bounds) bounds->emplace_back(pv->seq(), pv->message_count());
    pv->for_each([&](SeqNo q, std::span<const std::byte> b) { m[q] = std::vector<std::byte>(b.begin(), b.end()); });
  }
  return m;
}

TEST(ReplayFeed, BothLinesCarryTheStreamWithDifferentBoundaries) {
  const auto msgs = test::ItchGen(11).make(5'000);
  ReplayFeedConfig cfg;
  cfg.seed = 5;
  ReplayFeed f(cfg);
  Capture cap;
  for (const auto& m : msgs) (void)f.append(m, 0, cap);
  f.flush(0, cap);
  f.end_session(0, cap);
  std::vector<std::pair<SeqNo, std::uint16_t>> ba, bb;
  const auto a = messages_of(cap.sent, 0, &ba);
  const auto b = messages_of(cap.sent, 1, &bb);
  ASSERT_EQ(a.size(), msgs.size());
  ASSERT_EQ(b.size(), msgs.size());
  for (SeqNo s = 1; s <= msgs.size(); ++s) {
    EXPECT_EQ(a.at(s), msgs[s - 1]);
    EXPECT_EQ(b.at(s), msgs[s - 1]);
  }
  EXPECT_NE(ba, bb);  // independent packetization
  for (const auto& s : cap.sent) EXPECT_LE(s.bytes.size(), cfg.max_packet[static_cast<std::size_t>(s.line)]);
  // The end of session follows on both lines.
  int eos = 0;
  for (const auto& s : cap.sent) eos += mold::decode_header(s.bytes.data()).is_end_of_session() ? 1 : 0;
  EXPECT_EQ(eos, 2);
}

TEST(ReplayFeed, PacketizationIsAFunctionOfTheSeed) {
  const auto msgs = test::ItchGen(12).make(3'000);
  auto run = [&](std::uint64_t seed) {
    ReplayFeedConfig cfg;
    cfg.seed = seed;
    cfg.impair[0].loss_ppm = 30'000;
    cfg.impair[1].loss_ppm = 10'000;
    ReplayFeed f(cfg);
    Capture cap;
    for (const auto& m : msgs) (void)f.append(m, 0, cap);
    f.flush(0, cap);
    std::vector<std::vector<std::byte>> out;
    for (auto& s : cap.sent) out.push_back(s.bytes);
    return out;
  };
  EXPECT_EQ(run(1), run(1));
  EXPECT_NE(run(1), run(2));
}

TEST(ReplayFeed, OutageDropsEveryPacketTouchingTheRangeOnBothLines) {
  const auto msgs = test::ItchGen(13).make(4'000);
  ReplayFeedConfig cfg;
  cfg.outages = {Outage{1'000, 500}, Outage{3'000, 10}};
  ReplayFeed f(cfg);
  Capture cap;
  for (const auto& m : msgs) (void)f.append(m, 0, cap);
  f.flush(0, cap);
  for (int line = 0; line < 2; ++line) {
    const auto got = messages_of(cap.sent, line);
    for (SeqNo s = 1000; s < 1500; ++s) EXPECT_FALSE(got.contains(s)) << "line " << line << " seq " << s;
    for (SeqNo s = 3000; s < 3010; ++s) EXPECT_FALSE(got.contains(s));
    EXPECT_TRUE(got.contains(1) && got.contains(4'000));
    EXPECT_GT(f.line_stats(static_cast<std::size_t>(line)).outage_dropped, 0u);
  }
  EXPECT_TRUE(f.in_outage(990, 20, false));
  EXPECT_FALSE(f.in_outage(990, 10, false));
  EXPECT_TRUE(f.in_outage(1499, 1, false));
  EXPECT_FALSE(f.in_outage(1500, 1, false));
  EXPECT_TRUE(f.in_outage(1200, 0, true));  // a heartbeat announcing a sequence inside
}

TEST(ReplayFeed, HeartbeatsWhenIdleAndEndOfSessionRepeats) {
  ReplayFeedConfig cfg;
  cfg.heartbeat_interval = 1'000;
  cfg.end_of_session_linger = 5'000;
  ReplayFeed f(cfg);
  Capture cap;
  const auto msgs = test::ItchGen(14).make(10);
  for (const auto& m : msgs) (void)f.append(m, 0, cap);
  f.flush(0, cap);
  Nanos t = 0;
  for (int i = 0; i < 3; ++i) {
    t = f.next_deadline();
    f.on_timer(t, cap);
  }
  f.end_session(t, cap);
  while (!f.done()) {
    t = std::max(t + 1, f.next_deadline());
    f.on_timer(t, cap);
  }
  int hb = 0, eos = 0;
  for (const auto& s : cap.sent) {
    const auto h = mold::decode_header(s.bytes.data());
    if (h.is_heartbeat()) {
      ++hb;
      EXPECT_EQ(h.seq, 11u);
    }
    if (h.is_end_of_session()) ++eos;
  }
  EXPECT_EQ(hb, 6);   // 3 rounds x 2 lines
  EXPECT_GE(eos, 4);  // repeated during the linger on both lines
}

}  // namespace
}  // namespace lle::client
