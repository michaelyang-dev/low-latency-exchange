// loadgen v1 (07 §3): the precomputed open-loop schedule and the response
// accounting, checked against the real sequencer and engine in-process: every
// message of the pre-registered mix gets exactly its expected response.
#include <gtest/gtest.h>

#include <map>
#include <vector>

#include "client/engine_driver.h"
#include "client/loadgen.h"
#include "client/ouch_server.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client {
namespace {

lg::ScheduleConfig small(std::uint64_t seed) {
  lg::ScheduleConfig c;
  c.seed = seed;
  c.sessions = 3;
  c.symbols = 50;
  c.rate = 100'000;
  c.duration = 200'000'000;  // 20,000 measured messages
  c.prefill = 2'000;
  return c;
}

TEST(LoadgenSchedule, MixIsThePreRegisteredOneAndDeterministic) {
  const auto a = lg::build_schedule(small(1));
  const auto b = lg::build_schedule(small(1));
  ASSERT_EQ(a.items.size(), 22'000u);
  ASSERT_EQ(a.items.size(), b.items.size());
  for (std::size_t i = 0; i < a.items.size(); ++i) {
    EXPECT_EQ(a.items[i].t, b.items[i].t);
    EXPECT_EQ(a.items[i].urn, b.items[i].urn);
    EXPECT_EQ(a.items[i].kind, b.items[i].kind);
  }
  EXPECT_NE(lg::build_schedule(small(2)).items[5000].price, a.items[5000].price);
  // Measured part: 45/40/10/5 within sampling error (20,000 draws), Enters include the prefill.
  const double n = 20'000.0;
  const auto& k = a.stats.kinds;
  EXPECT_NEAR(static_cast<double>(k[0] - a.stats.prefill) / n, 0.45, 0.02);
  EXPECT_NEAR(static_cast<double>(k[1]) / n, 0.40, 0.02);
  EXPECT_NEAR(static_cast<double>(k[2]) / n, 0.10, 0.01);
  EXPECT_NEAR(static_cast<double>(k[3]) / n, 0.05, 0.01);
  EXPECT_EQ(a.stats.fallbacks, 0u);
}

TEST(LoadgenSchedule, OpenLoopTimesAndPerSessionUserRefNums) {
  const auto s = lg::build_schedule(small(3));
  Nanos last = 0;
  std::vector<std::uint32_t> last_urn(3, 0);
  std::map<std::uint16_t, std::uint16_t> sym_session;
  for (const auto& it : s.items) {
    EXPECT_GE(it.t, last);
    last = it.t;
    if (it.kind != lg::Kind::Cancel) {
      EXPECT_EQ(it.urn, last_urn[it.session] + 1) << "UserRefNums are consumed in order per session";
      last_urn[it.session] = it.urn;
    }
    // A symbol always trades on one session.
    const auto [pos, fresh] = sym_session.emplace(it.symbol, it.session);
    EXPECT_EQ(pos->second, it.session);
    (void)fresh;
  }
  // Mean inter-arrival = 1/rate (Poisson), within a few percent.
  const double mean = static_cast<double>(last) / static_cast<double>(s.items.size());
  EXPECT_NEAR(mean, 10'000.0, 400.0);
  auto c = small(3);
  c.poisson = false;
  const auto u = lg::build_schedule(c);
  EXPECT_EQ(u.items[1].t - u.items[0].t, 10'000);
}

TEST(LoadgenSchedule, EncodedMessagesAreValidOuch) {
  const auto s = lg::build_schedule(small(4));
  std::array<std::byte, 256> buf{};
  for (std::size_t i = 0; i < s.items.size(); i += 7) {
    const std::size_t n = lg::encode_item(s.items[i], buf);
    ASSERT_GT(n, 0u);
    EXPECT_TRUE(ouch50::validate_inbound(std::span<const std::byte>(buf.data(), n)).has_value()) << i;
  }
}

// The whole schedule through the real sequencer and engine, responses into the
// accounting: no unexpected response, nothing missing, fills as predicted.
TEST(LoadgenAccounting, RealEngineAnswersEveryMessageAsExpected) {
  const auto s = lg::build_schedule(small(5));
  OuchServerConfig sc;
  sc.sessions = 3;
  for (std::uint32_t i = 0; i < 50; ++i) sc.symbols.push_back(lg::symbol_name(i));
  sc.reserve_orders = 1 << 16;
  lg::Accounting acc(s);
  struct Sink {
    lg::Accounting* acc;
    Nanos now = 0;
    std::uint64_t outputs = 0;
    void itch(std::uint64_t, std::span<const std::byte>) {}
    void ouch(std::uint64_t, std::uint32_t session, std::span<const std::byte> b) {
      ++outputs;
      acc->on_response(static_cast<std::uint16_t>(session - 1), b, now);
    }
    void audit(std::uint64_t, const engine::AuditEvent&) {}
  } sink{&acc};
  EngineDriver<Sink> d(ouch_server_day(sc), sink);
  ASSERT_TRUE(d.start(hms_ns(2, 59, 59)));
  d.advance(hms_ns(10, 0, 0));
  std::array<std::byte, 256> buf{};
  const Nanos t0 = 1'000'000;
  for (std::size_t i = 0; i < s.items.size(); ++i) {
    const auto& it = s.items[i];
    acc.on_sent(i, t0, t0 + it.t);
    sink.now = t0 + it.t + 5'000;  // every response 5 us after its scheduled time
    const std::size_t n = lg::encode_item(it, buf);
    ASSERT_TRUE(d.submit_ouch(it.session + 1u, it.session + 1u, std::span<const std::byte>(buf.data(), n)));
  }
  acc.finish();
  const auto& st = acc.stats();
  EXPECT_EQ(st.sent, s.items.size());
  EXPECT_EQ(st.acked, s.items.size());
  EXPECT_EQ(st.missing, 0u);
  EXPECT_EQ(st.unexpected, 0u) << "rejected " << st.rejected << " cancel_rejects " << st.cancel_rejects << " ioc_dead "
                               << st.ioc_dead << " remainder " << st.ioc_remainder << " unknown " << st.unknown_urn
                               << " dup " << st.duplicate_ack << " state " << st.wrong_state << " other " << st.other;
  EXPECT_EQ(st.ioc_shares, s.stats.ioc_shares);
  EXPECT_EQ(st.passive_fills, s.stats.passive_fills);
  EXPECT_EQ(d.engine().live_orders(), s.stats.live_at_end);
  // The latency of the measured part is exactly the injected 5 us.
  EXPECT_EQ(acc.latency().count(), 20'000);
  EXPECT_NEAR(static_cast<double>(acc.latency().percentile(50.0)), 5'000.0, 10.0);
}

TEST(LoadgenAccounting, UnexpectedResponsesAreCounted) {
  const auto s = lg::build_schedule(small(6));
  lg::Accounting acc(s);
  acc.on_sent(0, 0, 0);
  // A Rejected for the first Enter.
  ouch50::out::Rejected j;
  j.user_ref_num = s.items[0].urn;
  j.reason = ouch50::RejectReason::Halted;
  std::array<std::byte, 64> b{};
  const std::size_t n = ouch50::encode(std::span<std::byte>(b), j);
  acc.on_response(s.items[0].session, std::span<const std::byte>(b.data(), n), 10);
  // A Canceled nobody asked for, for an unknown UserRefNum.
  ouch50::out::OrderCanceled c;
  c.user_ref_num = 999'999;
  const std::size_t m = ouch50::encode(std::span<std::byte>(b), c);
  acc.on_response(0, std::span<const std::byte>(b.data(), m), 10);
  acc.finish();
  EXPECT_EQ(acc.stats().rejected, 1u);
  EXPECT_EQ(acc.stats().unknown_urn, 1u);
  EXPECT_EQ(acc.stats().unexpected, 2u);
  EXPECT_EQ(acc.stats().acked, 0u);
}

TEST(OuchServer, UsernamesMapToSessions) {
  EXPECT_EQ(session_of_username("U00001"), 1u);
  EXPECT_EQ(session_of_username("U00099"), 99u);
  EXPECT_EQ(session_of_username("X00001"), 0u);
  EXPECT_EQ(session_of_username("U0001"), 0u);
  EXPECT_EQ(lg::symbol_name(0), Symbol8("S0001"));
  EXPECT_EQ(lg::symbol_name(1999), Symbol8("S2000"));
}

}  // namespace
}  // namespace lle::client
