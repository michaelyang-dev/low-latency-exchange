// Sequencer core (06 §2): stamping, chain, input priority, timers, day start,
// back-pressure, snapshot marks, and the path into L3.
#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "journal/journal_writer.h"
#include "journal/mem_journal_device.h"
#include "journal/reader.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "sequencer_test_env.h"

namespace lle::seq {
namespace {

using journal::RecordType;
using journal::RecordView;
using testing::Rig;

std::vector<RecordType> types(const std::vector<std::vector<std::byte>>& recs) {
  std::vector<RecordType> t;
  for (const auto& r : recs) t.push_back(RecordView(r).type());
  return t;
}

TEST(Sequencer, DayStartJournalsConfigThenEpochStart) {
  Rig rig;
  std::vector<std::byte> symbols(100'000), limits(10);
  for (std::size_t i = 0; i < symbols.size(); ++i) symbols[i] = static_cast<std::byte>(i * 31);
  rig.start({ConfigBlob{journal::ConfigTable::Symbols, symbols}, ConfigBlob{journal::ConfigTable::RiskLimits, limits},
             ConfigBlob{journal::ConfigTable::Schedule, {}}});
  const auto recs = rig.take();
  // DayStart, 4 symbol chunks, 1 risk chunk, 1 (empty) schedule chunk, EpochStart.
  ASSERT_EQ(recs.size(), 8u);
  EXPECT_EQ(RecordView(recs[0]).type(), RecordType::DayStart);
  EXPECT_EQ(RecordView(recs[0]).index(), 1u);
  EXPECT_EQ(RecordView(recs[0]).prev_crc(), 0u);
  std::vector<std::byte> reassembled;
  for (int k = 1; k <= 4; ++k) {
    const auto c = journal::decode_config(RecordView(recs[static_cast<std::size_t>(k)]));
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c->table, journal::ConfigTable::Symbols);
    EXPECT_EQ(c->chunk_index, k - 1);
    EXPECT_EQ(c->chunk_count, 4);
    EXPECT_EQ(c->table_bytes, symbols.size());
    reassembled.insert(reassembled.end(), c->bytes.begin(), c->bytes.end());
  }
  EXPECT_EQ(reassembled, symbols);
  const auto empty = journal::decode_config(RecordView(recs[6]));
  ASSERT_TRUE(empty.has_value());
  EXPECT_EQ(empty->bytes.size(), 0u);
  EXPECT_EQ(empty->chunk_count, 1);
  const auto es = journal::decode_epoch_start(RecordView(recs[7]));
  ASSERT_TRUE(es.has_value());
  EXPECT_EQ(es->epoch, 1u);
  EXPECT_EQ(es->primary_node, 7u);
  EXPECT_EQ(es->config_digest, rig.seq->config_digest());
  EXPECT_NE(es->config_digest, 0u);
}

// seq::config_digest is the digest the day start stamps into EpochStart (a paired node
// restarting on an empty journal joins under it, DST-006).
TEST(Sequencer, ConfigDigestIsTheDayStartsDigest) {
  Rig rig;
  std::vector<std::byte> symbols(5'000), limits(10);
  for (std::size_t i = 0; i < symbols.size(); ++i) symbols[i] = static_cast<std::byte>(i * 7);
  const std::vector<ConfigBlob> cfg{ConfigBlob{journal::ConfigTable::Symbols, symbols},
                                    ConfigBlob{journal::ConfigTable::RiskLimits, limits}};
  rig.start(cfg);
  const auto recs = rig.take();
  const auto es = journal::decode_epoch_start(RecordView(recs.back()));
  ASSERT_TRUE(es.has_value());
  EXPECT_EQ(config_digest(cfg), es->config_digest);
  EXPECT_EQ(config_digest(cfg), rig.seq->config_digest());
  limits[3] = std::byte{1};
  EXPECT_NE(config_digest(cfg), es->config_digest);
}

TEST(Sequencer, StampsIndexEpochTimestampAndChain) {
  Rig rig;
  rig.start();
  (void)rig.take();
  for (std::uint8_t i = 0; i < 20; ++i) ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(i, i)));
  rig.clock.real -= 1'000'000;  // the realtime clock steps backwards (01 §9)
  EXPECT_TRUE(rig.seq->poll());
  const auto recs = rig.take();
  ASSERT_EQ(recs.size(), 20u);
  journal::ChainState prev{2, 0, 0, 1};  // DayStart (1), EpochStart (2)
  Nanos last_ts = 0;
  for (std::size_t k = 0; k < recs.size(); ++k) {
    const RecordView v(recs[k]);
    EXPECT_EQ(v.index(), 3 + k);
    EXPECT_EQ(v.epoch(), 1u);
    EXPECT_TRUE(rig.ring.sealer().verify(v.data()).has_value());
    if (k > 0) {
      EXPECT_EQ(v.prev_crc(), RecordView(recs[k - 1]).content());
      EXPECT_GT(v.ts_ns(), last_ts);  // strictly increasing despite the clock step
    }
    last_ts = v.ts_ns();
    const auto o = journal::decode_ouch_inbound(v);
    ASSERT_TRUE(o.has_value());
    EXPECT_EQ(o->session_id, k);
    EXPECT_EQ(o->account, k * 10);
    EXPECT_EQ(o->instance, 1);
    ASSERT_EQ(o->msg.size(), 47u);
    EXPECT_EQ(o->msg[0], static_cast<std::byte>(k));
  }
  (void)prev;
  EXPECT_EQ(rig.seq->chain().last_index, 22u);
  EXPECT_EQ(rig.seq->chain().last_crc, RecordView(recs.back()).content());
  // ts = max(last + 1, now): with the clock ahead, records take the clock.
  rig.clock.real = last_ts + 5'000;
  ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(1, 1)));
  (void)rig.seq->poll();
  EXPECT_EQ(RecordView(rig.take().at(0)).ts_ns(), last_ts + 5'000);
}

TEST(Sequencer, PollsInputsInFixedPriorityWithoutStarvation) {
  SequencerConfig cfg;
  cfg.ouch_batch = 4;
  cfg.session_batch = 2;
  cfg.admin_batch = 1;
  Rig rig(std::size_t{1} << 20, {}, cfg);
  rig.start();
  (void)rig.take();
  for (std::uint8_t i = 0; i < 10; ++i) ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(i, i)));
  for (std::uint32_t i = 0; i < 3; ++i) {
    ASSERT_TRUE(rig.sessions->try_push(SessionEventMsg{i, 1, journal::SessionEventKind::Disconnect, 0}));
  }
  AdminMsg a;
  a.command = 0x10;
  a.operator_id = 5;
  a.len = 3;
  ASSERT_TRUE(rig.admin->try_push(a));
  ASSERT_TRUE(rig.admin->try_push(a));
  EXPECT_TRUE(rig.seq->poll());
  using enum RecordType;
  EXPECT_EQ(types(rig.take()), (std::vector<RecordType>{OuchInbound, OuchInbound, OuchInbound, OuchInbound,
                                                        SessionEvent, SessionEvent, Admin}));
  EXPECT_TRUE(rig.seq->poll());
  EXPECT_EQ(types(rig.take()),
            (std::vector<RecordType>{OuchInbound, OuchInbound, OuchInbound, OuchInbound, SessionEvent, Admin}));
  EXPECT_TRUE(rig.seq->poll());
  EXPECT_EQ(types(rig.take()), (std::vector<RecordType>{OuchInbound, OuchInbound}));
  EXPECT_FALSE(rig.seq->poll());
  const auto st = rig.seq->stats();
  EXPECT_EQ(st.ouch, 10u);
  EXPECT_EQ(st.session_events, 3u);
  EXPECT_EQ(st.admin, 2u);
}

TEST(Sequencer, SessionAndAdminRecordsCarryTheirFields) {
  Rig rig;
  rig.start();
  (void)rig.take();
  ASSERT_TRUE(rig.sessions->try_push(SessionEventMsg{42, 2, journal::SessionEventKind::MirrorAttach, 777}));
  AdminMsg a;
  a.command = 0x0201;
  a.tlv_version = 3;
  a.operator_id = 9;
  a.len = 5;
  std::memcpy(a.args, "HALT!", 5);
  ASSERT_TRUE(rig.admin->try_push(a));
  InboundMsg bad = Rig::ouch_msg(3, 0, 168);
  bad.flags = journal::kFlagMalformedInput;
  ASSERT_TRUE(rig.ouch->try_push(bad));
  (void)rig.seq->poll();
  const auto recs = rig.take();
  ASSERT_EQ(recs.size(), 3u);
  EXPECT_EQ(RecordView(recs[0]).flags(), journal::kFlagMalformedInput);
  EXPECT_EQ(journal::decode_ouch_inbound(RecordView(recs[0]))->msg.size(), 168u);
  const auto se = journal::decode_session_event(RecordView(recs[1]));
  ASSERT_TRUE(se.has_value());
  EXPECT_EQ(*se, (journal::SessionEvent{42, 2, journal::SessionEventKind::MirrorAttach, 777}));
  const auto ad = journal::decode_admin(RecordView(recs[2]));
  ASSERT_TRUE(ad.has_value());
  EXPECT_EQ(ad->command, 0x0201);
  EXPECT_EQ(ad->tlv_version, 3);
  EXPECT_EQ(ad->operator_id, 9u);
  EXPECT_EQ(std::memcmp(ad->args.data(), "HALT!", 5), 0);
}

// DST-004: session events travel in the OUCH queue, tagged, and are journaled in that
// queue's order, across poll and batch boundaries: a Disconnect after every OUCH its
// producer pushed before it (cancel-on-disconnect covers them), the next Login before
// the orders that follow it. Events from the separate queue still work (after the
// OUCH queue's batch, as before).
TEST(Sequencer, TaggedSessionEventsKeepTheirQueueOrder) {
  SequencerConfig cfg;
  cfg.ouch_batch = 16;  // the queue's 62 entries take four polls
  Rig rig(std::size_t{1} << 20, {}, cfg);
  rig.start();
  (void)rig.take();
  struct Want {
    RecordType type;
    std::uint32_t session;
    std::uint16_t instance;
  };
  std::vector<Want> want;
  for (std::uint8_t i = 0; i < 50; ++i) {
    ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(5, i)));
    want.push_back({RecordType::OuchInbound, 5, 1});
  }
  ASSERT_TRUE(rig.ouch->try_push(session_event_inbound(SessionEventMsg{5, 1, journal::SessionEventKind::Disconnect, 0})));
  want.push_back({RecordType::SessionEvent, 5, 1});
  ASSERT_TRUE(rig.ouch->try_push(session_event_inbound(SessionEventMsg{5, 1, journal::SessionEventKind::Login, 51})));
  want.push_back({RecordType::SessionEvent, 5, 1});
  for (std::uint8_t i = 0; i < 10; ++i) {
    ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(5, static_cast<std::uint8_t>(100 + i))));
    want.push_back({RecordType::OuchInbound, 5, 1});
  }
  ASSERT_TRUE(rig.sessions->try_push(SessionEventMsg{9, 3, journal::SessionEventKind::Logout, 0}));
  for (int i = 0; i < 8 && rig.seq->poll(); ++i) {
  }
  const auto recs = rig.take();
  ASSERT_EQ(recs.size(), want.size() + 1);
  std::size_t k = 0;
  for (std::size_t i = 0; i < recs.size(); ++i) {
    const RecordView v(recs[i]);
    if (v.type() == RecordType::SessionEvent && journal::decode_session_event(v)->session_id == 9) {
      EXPECT_EQ(i, 16u) << "the separate queue's event: after the first poll's OUCH batch";
      continue;
    }
    ASSERT_LT(k, want.size());
    EXPECT_EQ(v.type(), want[k].type) << "record " << i;
    if (v.type() == RecordType::SessionEvent) {
      const auto se = journal::decode_session_event(v);
      ASSERT_TRUE(se.has_value());
      EXPECT_EQ(se->session_id, want[k].session);
      EXPECT_EQ(se->instance, want[k].instance);
      EXPECT_EQ(se->event, k == 50 ? journal::SessionEventKind::Disconnect : journal::SessionEventKind::Login);
      EXPECT_EQ(se->requested_seq, k == 50 ? 0u : 51u);
    } else {
      EXPECT_EQ(journal::decode_ouch_inbound(v)->session_id, want[k].session);
    }
    ++k;
  }
  EXPECT_EQ(k, want.size());
  EXPECT_EQ(rig.seq->stats().session_events, 3u);
  EXPECT_EQ(rig.seq->stats().ouch, 60u);
  // The tag round-trips.
  const InboundMsg t = session_event_inbound(SessionEventMsg{7, 2, journal::SessionEventKind::InstanceDown, 0xABCDEF});
  EXPECT_TRUE(is_session_event(t));
  EXPECT_FALSE(is_session_event(Rig::ouch_msg(7, 0)));
  const SessionEventMsg back = session_event_of(t);
  EXPECT_EQ(back.session_id, 7u);
  EXPECT_EQ(back.instance, 2u);
  EXPECT_EQ(back.event, journal::SessionEventKind::InstanceDown);
  EXPECT_EQ(back.requested_seq, 0xABCDEFu);
}

TEST(Sequencer, TimersAreInjectedWhenTheClockPassesThem) {
  const Nanos t0 = 1'790'000'000'000'000'000;
  std::vector<ScheduleEntry> sched{{t0 + 1000, journal::TimerKind::SystemEvent, 1},
                                   {t0 + 2000, journal::TimerKind::Cross, 2},
                                   {t0 + 2000, journal::TimerKind::StateChange, 3},
                                   {t0 + 9000, journal::TimerKind::DayEnd, 4}};
  Rig rig(std::size_t{1} << 20, sched);
  rig.clock.real = t0;
  rig.start();
  (void)rig.take();
  EXPECT_FALSE(rig.seq->poll());  // nothing due
  // An order arrives after 09:30 (t0 + 2000) but before the sequencer saw the clock
  // pass: the timers come first, so the order is stamped after the cross.
  rig.clock.real = t0 + 2500;
  ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(1, 1)));
  EXPECT_TRUE(rig.seq->poll());
  auto recs = rig.take();
  using enum RecordType;
  ASSERT_EQ(types(recs), (std::vector<RecordType>{Timer, Timer, Timer, OuchInbound}));
  const auto t1 = journal::decode_timer(RecordView(recs[0]));
  ASSERT_TRUE(t1.has_value());
  EXPECT_EQ(*t1, (journal::Timer{1, journal::TimerKind::SystemEvent, t0 + 1000}));
  EXPECT_EQ(journal::decode_timer(RecordView(recs[1]))->timer_id, 2u);
  EXPECT_EQ(journal::decode_timer(RecordView(recs[2]))->timer_id, 3u);
  EXPECT_GE(RecordView(recs[0]).ts_ns(), t0 + 2500);
  // Idle polls fire timers too.
  rig.clock.real = t0 + 9000;
  EXPECT_TRUE(rig.seq->poll());
  recs = rig.take();
  ASSERT_EQ(recs.size(), 1u);
  EXPECT_EQ(journal::decode_timer(RecordView(recs[0]))->kind, journal::TimerKind::DayEnd);
  EXPECT_EQ(rig.seq->next_timer(), 4u);
  EXPECT_FALSE(rig.seq->poll());
}

// A node started late has every 1 Hz timer since 04:00 due at once: timer_batch bounds
// what one poll emits, and an input never overtakes a due timer (it stays staged).
TEST(Sequencer, TimersPerPollAreBoundedAndNeverOvertaken) {
  const Nanos t0 = 1'790'000'000'000'000'000;
  std::vector<ScheduleEntry> sched;
  for (std::uint32_t i = 0; i < 1000; ++i) sched.push_back({t0 + Nanos{1000} * i, journal::TimerKind::SystemEvent, i + 1});
  SequencerConfig cfg;
  cfg.timer_batch = 64;
  Rig rig(std::size_t{4} << 20, sched, cfg);
  rig.clock.real = t0 - 1;
  rig.start();
  (void)rig.take();
  rig.clock.real = t0 + 2'000'000;  // all 1000 due
  ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(7, 1)));
  std::vector<std::vector<std::byte>> all;
  int polls = 0;
  while (rig.seq->stats().ouch == 0 && polls < 100) {
    EXPECT_TRUE(rig.seq->poll());
    const auto recs = rig.take();
    EXPECT_LE(recs.size(), 65u) << "poll " << polls;  // 64 timers (+ the order, once they are out)
    all.insert(all.end(), recs.begin(), recs.end());
    ++polls;
  }
  EXPECT_EQ(polls, 16);  // ceil(1000 / 64)
  ASSERT_EQ(all.size(), 1001u);
  for (std::size_t i = 0; i < 1000; ++i) {
    ASSERT_EQ(RecordView(all[i]).type(), RecordType::Timer) << i;
    EXPECT_EQ(journal::decode_timer(RecordView(all[i]))->timer_id, i + 1);
  }
  EXPECT_EQ(RecordView(all[1000]).type(), RecordType::OuchInbound);
  EXPECT_EQ(rig.seq->stats().backpressure, 0u);
  EXPECT_EQ(rig.seq->stats().timer_bounded, 15u);
  EXPECT_FALSE(rig.seq->poll());
}

// ADR-032: after a restart or a promotion, the InstanceDown records of the dead
// instances are the first records: ahead of every overdue Timer (a cross that came due
// during the outage must not execute a dead connection's cancel-on-disconnect orders)
// and ahead of queued input. Every other input still waits for the due timers.
TEST(Sequencer, FirstEventsGoAheadOfDueTimersAndQueuedInput) {
  const Nanos t0 = 1'790'000'000'000'000'000;
  std::vector<ScheduleEntry> sched{{t0 + 1000, journal::TimerKind::Cross, 1},
                                   {t0 + 2000, journal::TimerKind::StateChange, 2}};
  Rig rig(std::size_t{1} << 20, sched);
  rig.clock.real = t0;
  rig.start();
  (void)rig.take();
  ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(9, 1)));
  ASSERT_TRUE(rig.sessions->try_push(SessionEventMsg{8, 1, journal::SessionEventKind::Disconnect, 0}));
  rig.clock.real = t0 + 5000;  // both timers overdue
  rig.seq->reserve_first(2);
  ASSERT_GE(rig.seq->first_capacity(), 2u);
  EXPECT_TRUE(rig.seq->inject_first(SessionEventMsg{3, 1, journal::SessionEventKind::InstanceDown, 0}));
  EXPECT_TRUE(rig.seq->inject_first(SessionEventMsg{4, 2, journal::SessionEventKind::InstanceDown, 0}));
  EXPECT_EQ(rig.seq->first_pending(), 2u);
  EXPECT_TRUE(rig.seq->poll());
  const auto recs = rig.take();
  using enum RecordType;
  ASSERT_EQ(types(recs), (std::vector<RecordType>{SessionEvent, SessionEvent, Timer, Timer, OuchInbound, SessionEvent}));
  const auto d0 = journal::decode_session_event(RecordView(recs[0]));
  const auto d1 = journal::decode_session_event(RecordView(recs[1]));
  ASSERT_TRUE(d0.has_value() && d1.has_value());
  EXPECT_EQ(d0->session_id, 3u);
  EXPECT_EQ(d0->instance, 1u);
  EXPECT_EQ(d0->event, journal::SessionEventKind::InstanceDown);
  EXPECT_EQ(d1->session_id, 4u);
  EXPECT_EQ(d1->instance, 2u);
  EXPECT_EQ(journal::decode_timer(RecordView(recs[2]))->kind, journal::TimerKind::Cross);
  EXPECT_EQ(journal::decode_session_event(RecordView(recs[5]))->event, journal::SessionEventKind::Disconnect);
  for (std::size_t k = 1; k < recs.size(); ++k) EXPECT_GT(RecordView(recs[k]).ts_ns(), RecordView(recs[k - 1]).ts_ns());
  EXPECT_GE(RecordView(recs[0]).ts_ns(), t0 + 5000);
  EXPECT_EQ(rig.seq->first_pending(), 0u);
  EXPECT_EQ(rig.seq->stats().first, 2u);
  EXPECT_EQ(rig.seq->stats().session_events, 3u);
  EXPECT_EQ(rig.seq->stats().timers, 2u);
  EXPECT_FALSE(rig.seq->poll());
}

// The list is bounded per poll (ouch_batch) and stays first across polls; a full list
// refuses (no allocation), and room freed by emitted entries is reused.
TEST(Sequencer, FirstEventsSpanPollsAndNeverAllocate) {
  const Nanos t0 = 1'790'000'000'000'000'000;
  std::vector<ScheduleEntry> sched{{t0 + 1000, journal::TimerKind::Cross, 1}};
  SequencerConfig cfg;
  cfg.ouch_batch = 2;
  Rig rig(std::size_t{1} << 20, sched, cfg);
  rig.clock.real = t0;
  rig.start();
  (void)rig.take();
  rig.seq->reserve_first(5);
  const std::size_t cap = rig.seq->first_capacity();
  for (std::uint32_t i = 0; i < cap; ++i)
    ASSERT_TRUE(rig.seq->inject_first(SessionEventMsg{i, 1, journal::SessionEventKind::InstanceDown, 0}));
  EXPECT_FALSE(rig.seq->inject_first(SessionEventMsg{99, 1, journal::SessionEventKind::InstanceDown, 0}));
  ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(50, 1)));
  rig.clock.real = t0 + 5000;
  std::vector<std::vector<std::byte>> all;
  EXPECT_TRUE(rig.seq->poll());
  auto recs = rig.take();
  ASSERT_EQ(recs.size(), 2u);  // two of the list, nothing else yet
  all.insert(all.end(), recs.begin(), recs.end());
  // Two emitted: room for two more, appended behind the rest.
  EXPECT_TRUE(rig.seq->inject_first(SessionEventMsg{100, 1, journal::SessionEventKind::InstanceDown, 0}));
  EXPECT_TRUE(rig.seq->inject_first(SessionEventMsg{101, 1, journal::SessionEventKind::InstanceDown, 0}));
  EXPECT_FALSE(rig.seq->inject_first(SessionEventMsg{102, 1, journal::SessionEventKind::InstanceDown, 0}));
  EXPECT_EQ(rig.seq->first_capacity(), cap);
  for (int polls = 0; polls < 10 && rig.seq->stats().ouch == 0; ++polls) {
    (void)rig.seq->poll();
    recs = rig.take();
    all.insert(all.end(), recs.begin(), recs.end());
  }
  ASSERT_EQ(all.size(), cap + 2 + 2);  // the list, the cross, the order
  std::vector<std::uint32_t> sessions;
  for (std::size_t k = 0; k < cap + 2; ++k) {
    ASSERT_EQ(RecordView(all[k]).type(), RecordType::SessionEvent) << k;
    sessions.push_back(journal::decode_session_event(RecordView(all[k]))->session_id);
  }
  std::vector<std::uint32_t> want;
  for (std::uint32_t i = 0; i < cap; ++i) want.push_back(i);
  want.push_back(100);
  want.push_back(101);
  EXPECT_EQ(sessions, want);
  EXPECT_EQ(RecordView(all[cap + 2]).type(), RecordType::Timer);
  EXPECT_EQ(RecordView(all[cap + 3]).type(), RecordType::OuchInbound);
  EXPECT_EQ(rig.seq->first_capacity(), cap);
}

// A full ring holds the list back (back-pressure, nothing lost), and it still goes
// first once there is room, ahead of the order that was staged meanwhile; resume()
// (a promotion's resync) keeps it.
TEST(Sequencer, FirstEventsWaitOutBackpressureAndSurviveResume) {
  const Nanos t0 = 1'790'000'000'000'000'000;
  std::vector<ScheduleEntry> sched{{t0 + 1'000'000'000, journal::TimerKind::Cross, 1}};
  Rig rig(256 * 1024, sched);
  rig.clock.real = t0;
  rig.start();
  (void)rig.take(0);
  (void)rig.take(1);
  // Cursor 1 stalls until the ring is full and an order is staged.
  std::uint32_t pushed = 0;
  for (int round = 0; round < 100 && rig.seq->stats().backpressure == 0; ++round) {
    while (rig.ouch->try_push(Rig::ouch_msg(pushed, 1))) ++pushed;
    (void)rig.seq->poll();
    (void)rig.take(0);
  }
  ASSERT_GT(rig.seq->stats().backpressure, 0u);
  rig.seq->reserve_first(3);
  for (std::uint32_t i = 0; i < 3; ++i)
    ASSERT_TRUE(rig.seq->inject_first(SessionEventMsg{1000 + i, 2, journal::SessionEventKind::InstanceDown, 0}));
  rig.clock.real = t0 + 2'000'000'000;  // the cross is overdue
  const auto bp = rig.seq->stats().backpressure;
  EXPECT_FALSE(rig.seq->poll());
  EXPECT_EQ(rig.seq->stats().backpressure, bp + 1);
  EXPECT_EQ(rig.seq->first_pending(), 3u);
  // A resync (the replica appended nothing here) keeps the list.
  rig.seq->resume(rig.seq->chain(), rig.seq->next_timer(), rig.seq->next_snapshot_id(), rig.seq->config_digest());
  EXPECT_EQ(rig.seq->first_pending(), 3u);
  (void)rig.take(0);
  (void)rig.take(1);
  EXPECT_TRUE(rig.seq->poll());
  const auto recs = rig.take(0);
  ASSERT_GE(recs.size(), 5u);
  for (std::size_t k = 0; k < 3; ++k) {
    ASSERT_EQ(RecordView(recs[k]).type(), RecordType::SessionEvent) << k;
    EXPECT_EQ(journal::decode_session_event(RecordView(recs[k]))->session_id, 1000 + k);
  }
  EXPECT_EQ(RecordView(recs[3]).type(), RecordType::Timer);
  EXPECT_EQ(RecordView(recs[4]).type(), RecordType::OuchInbound);
  EXPECT_EQ(rig.seq->first_pending(), 0u);
}

// A promotion's re-injected input (the backup's pending FORWARDs) goes ahead of the OUCH
// queue, where a gateway may have queued newer input of the same session meanwhile; after
// the session events that go first and after due timers, like all input. A full ring
// holds it back without reordering.
TEST(Sequencer, ReinjectedInputGoesAheadOfTheQueueAfterDueTimers) {
  const Nanos t0 = 1'790'000'000'000'000'000;
  std::vector<ScheduleEntry> sched{{t0 + 1000, journal::TimerKind::Cross, 1}};
  Rig rig(256 * 1024, sched);
  rig.clock.real = t0;
  rig.start();
  (void)rig.take(0);
  (void)rig.take(1);
  ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(4, 0xC0)));  // queued first, but newer
  rig.seq->reserve_ahead(3);
  rig.seq->reserve_first(1);
  ASSERT_TRUE(rig.seq->inject_ahead(Rig::ouch_msg(4, 0xA0)));
  ASSERT_TRUE(rig.seq->inject_ahead(session_event_inbound(SessionEventMsg{4, 1, journal::SessionEventKind::Disconnect, 0})));
  ASSERT_TRUE(rig.seq->inject_ahead(Rig::ouch_msg(4, 0xB0)));
  ASSERT_TRUE(rig.seq->inject_first(SessionEventMsg{9, 0, journal::SessionEventKind::InstanceDown, 0}));
  EXPECT_EQ(rig.seq->ahead_pending(), 3u);
  rig.clock.real = t0 + 5000;  // the cross is due
  EXPECT_TRUE(rig.seq->poll());
  const auto recs = rig.take(0);
  using enum RecordType;
  ASSERT_EQ(types(recs), (std::vector<RecordType>{SessionEvent, Timer, OuchInbound, SessionEvent, OuchInbound, OuchInbound}));
  EXPECT_EQ(journal::decode_session_event(RecordView(recs[0]))->event, journal::SessionEventKind::InstanceDown);
  EXPECT_EQ(journal::decode_ouch_inbound(RecordView(recs[2]))->msg[0], std::byte{0xA0});
  EXPECT_EQ(journal::decode_session_event(RecordView(recs[3]))->event, journal::SessionEventKind::Disconnect);
  EXPECT_EQ(journal::decode_ouch_inbound(RecordView(recs[4]))->msg[0], std::byte{0xB0});
  EXPECT_EQ(journal::decode_ouch_inbound(RecordView(recs[5]))->msg[0], std::byte{0xC0});
  EXPECT_EQ(rig.seq->stats().ahead, 3u);
  EXPECT_EQ(rig.seq->ahead_pending(), 0u);
  EXPECT_GE(rig.seq->ahead_capacity(), 3u);
  // A full ring: the list waits, staged, and keeps its place ahead of the queue.
  std::uint32_t pushed = 0;
  for (int round = 0; round < 100 && rig.seq->stats().backpressure == 0; ++round) {
    while (rig.ouch->try_push(Rig::ouch_msg(pushed % 3, 1))) ++pushed;
    (void)rig.seq->poll();
    (void)rig.take(0);
  }
  ASSERT_GT(rig.seq->stats().backpressure, 0u);
  std::vector<std::vector<std::byte>> drained;
  (void)rig.take(0);
  // Whatever the queue still holds was queued before; the re-injected one goes before it.
  ASSERT_TRUE(rig.seq->inject_ahead(Rig::ouch_msg(7, 0xD0)));
  (void)rig.take(1);
  EXPECT_TRUE(rig.seq->poll());
  const auto after = rig.take(0);
  ASSERT_GE(after.size(), 2u);
  // The order staged when the ring filled is emitted first (it was taken before the
  // re-injection), then the re-injected one, then the rest of the queue.
  EXPECT_EQ(journal::decode_ouch_inbound(RecordView(after[0]))->msg[0], std::byte{1});
  EXPECT_EQ(journal::decode_ouch_inbound(RecordView(after[1]))->msg[0], std::byte{0xD0});
}

// DST-008: a node that takes over, joins or resumes after the close resumes the sequencer
// after the new EpochStart, but the journal already holds DayEnd: day_already_ended()
// keeps it stopped, with queued input, due timers and its lists, and no second DayEnd.
TEST(Sequencer, NothingIsSequencedOnceTheDayAlreadyEnded) {
  const Nanos t0 = 1'790'000'000'000'000'000;
  std::vector<ScheduleEntry> sched{{t0 + 1000, journal::TimerKind::Cross, 1}};
  Rig rig(std::size_t{1} << 20, sched);
  rig.clock.real = t0;
  rig.start();
  ASSERT_TRUE(rig.seq->end_day(0, 0).has_value());
  const auto day = rig.take();
  ASSERT_EQ(RecordView(day.back()).type(), RecordType::DayEnd);
  // The resync of a takeover after the close.
  rig.seq->resume(rig.seq->chain(), rig.seq->next_timer(), rig.seq->next_snapshot_id(), rig.seq->config_digest());
  rig.seq->reserve_first(1);
  rig.seq->reserve_ahead(1);
  ASSERT_TRUE(rig.seq->inject_first(SessionEventMsg{1, 0, journal::SessionEventKind::InstanceDown, 0}));
  ASSERT_TRUE(rig.seq->inject_ahead(Rig::ouch_msg(1, 1)));
  ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(2, 2)));
  rig.seq->day_already_ended();
  EXPECT_FALSE(rig.seq->started());
  EXPECT_EQ(rig.seq->first_pending(), 0u);
  EXPECT_EQ(rig.seq->ahead_pending(), 0u);
  rig.clock.real = t0 + 5000;  // the cross is due
  EXPECT_FALSE(rig.seq->poll());
  EXPECT_TRUE(rig.take().empty());
  EXPECT_FALSE(rig.seq->end_day(0, 0).has_value());
  EXPECT_TRUE(rig.take().empty());
}

TEST(Sequencer, BackpressureStopsPoppingAndLosesNothing) {
  Rig rig(256 * 1024);
  rig.start();
  (void)rig.take(0);
  (void)rig.take(1);
  std::uint32_t pushed = 0;
  std::uint64_t seen = 0;
  std::uint32_t next_session = 0;
  // Cursor 1 (say, the replicator) stalls; cursor 0 keeps up.
  for (int round = 0; round < 200; ++round) {
    while (rig.ouch->try_push(Rig::ouch_msg(pushed, static_cast<std::uint8_t>(pushed)))) ++pushed;
    (void)rig.seq->poll();
    for (const auto& r : rig.take(0)) {
      EXPECT_EQ(journal::decode_ouch_inbound(RecordView(r))->session_id, next_session++);
      ++seen;
    }
  }
  const auto stalls = rig.seq->stats().backpressure;
  EXPECT_GT(stalls, 0u);
  // The queue is full (the sequencer stopped popping) and one message is staged.
  EXPECT_FALSE(rig.ouch->try_push(Rig::ouch_msg(0, 0)));
  EXPECT_EQ(pushed - seen, testing::TestEnv::OuchQueue::capacity() + 1);
  // The stalled cursor catches up: everything flows, in order, nothing lost.
  for (int round = 0; round < 50; ++round) {
    (void)rig.take(1);
    (void)rig.seq->poll();
    for (const auto& r : rig.take(0)) {
      EXPECT_EQ(journal::decode_ouch_inbound(RecordView(r))->session_id, next_session++);
      ++seen;
    }
  }
  EXPECT_EQ(seen, pushed);
}

TEST(Sequencer, SnapshotMarksAtDeterministicPositions) {
  SequencerConfig cfg;
  cfg.snapshot_every = 10;
  Rig rig(std::size_t{1} << 20, {}, cfg);
  rig.start();
  for (std::uint8_t i = 0; i < 30; ++i) ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(i, i)));
  while (rig.seq->poll()) {
  }
  std::vector<std::pair<std::uint64_t, std::uint64_t>> marks;  // (index, snapshot id)
  for (const auto& r : rig.take()) {
    const RecordView v(r);
    if (v.type() == RecordType::SnapshotMark) marks.emplace_back(v.index(), journal::decode_snapshot_mark(v)->snapshot_id);
  }
  ASSERT_EQ(marks.size(), 3u);
  EXPECT_EQ(marks[0], (std::pair<std::uint64_t, std::uint64_t>{11, 1}));
  EXPECT_EQ(marks[1], (std::pair<std::uint64_t, std::uint64_t>{21, 2}));
  EXPECT_EQ(marks[2], (std::pair<std::uint64_t, std::uint64_t>{31, 3}));
}

TEST(Sequencer, ResumeContinuesTheChainAndEpochs) {
  Rig rig;
  rig.start();
  for (std::uint8_t i = 0; i < 5; ++i) ASSERT_TRUE(rig.ouch->try_push(Rig::ouch_msg(i, i)));
  (void)rig.seq->poll();
  const auto before = rig.take();
  const journal::ChainState chain = rig.seq->chain();

  Rig rig2;
  rig2.seq->resume(chain, 0, 1, rig.seq->config_digest());
  ASSERT_TRUE(rig2.seq->start_epoch(2, 9).has_value());
  ASSERT_TRUE(rig2.ouch->try_push(Rig::ouch_msg(1, 1)));
  (void)rig2.seq->poll();
  ASSERT_TRUE(rig2.seq->end_day(1000, 2000).has_value());
  EXPECT_FALSE(rig2.seq->poll());
  const auto after = rig2.take();
  ASSERT_EQ(after.size(), 3u);
  EXPECT_EQ(RecordView(after[0]).index(), chain.last_index + 1);
  EXPECT_EQ(RecordView(after[0]).prev_crc(), RecordView(before.back()).content());
  EXPECT_EQ(RecordView(after[0]).epoch(), 2u);
  EXPECT_EQ(journal::decode_epoch_start(RecordView(after[0]))->config_digest, rig.seq->config_digest());
  EXPECT_EQ(RecordView(after[1]).epoch(), 2u);
  const auto de = journal::decode_day_end(RecordView(after[2]));
  ASSERT_TRUE(de.has_value());
  EXPECT_EQ(de->final_index, RecordView(after[2]).index());
  EXPECT_EQ(de->itch_messages, 1000u);
}

// End to end: sequencer -> L2 ring -> L3 writer (re-sealed per segment) -> recovery.
TEST(Sequencer, RecordsReachL3AndRecoverIdentically) {
  Rig rig;
  journal::MemSegmentDir dir;
  Prng nonces(4);
  journal::SegmentPreparer prep(dir, nonces, 20260930, journal::kSegmentHeaderBytes + 256 * 1024);
  journal::JournalWriterOptions wo;
  wo.day = 20260930;
  journal::JournalWriter<journal::MemJournalDevice> w(wo);
  w.start(journal::ChainState{});
  for (int i = 0; i < 4; ++i) {
    auto p = prep.create();
    ASSERT_TRUE(p.has_value());
    ASSERT_TRUE(w.add_prepared(dir.device(p->handle), p->handle, p->header));
  }
  rig.start();
  std::vector<std::vector<std::byte>> l2;
  for (int round = 0; round < 100; ++round) {
    for (std::uint8_t i = 0; i < 40; ++i) (void)rig.ouch->try_push(Rig::ouch_msg(i, i));
    (void)rig.seq->poll();
    (void)rig.take(1);  // the engine cursor
    // The io stage: drain cursor 0 into the writer (natural group commit).
    for (;;) {
      const RecordView v = rig.ring.peek(0);
      if (v.empty()) break;
      const auto st = w.append(v.bytes(), rig.ring.sealer());
      if (st == journal::JournalWriter<journal::MemJournalDevice>::Status::Busy) break;
      ASSERT_EQ(st, journal::JournalWriter<journal::MemJournalDevice>::Status::Ok);
      l2.emplace_back(v.bytes().begin(), v.bytes().end());
      rig.ring.release(0);
    }
    (void)w.flush();
    (void)w.poll();
  }
  while (w.in_flight() != 0 || w.batch_used() != 0) {
    (void)w.flush();
    (void)w.poll();
  }
  EXPECT_EQ(w.durable_index(), l2.size());
  const journal::RecoveryResult r = journal::recover(dir);
  ASSERT_EQ(r.status, journal::RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, l2.size());
  EXPECT_EQ(r.chain.last_crc, rig.seq->chain().last_crc);
  std::size_t k = 0;
  (void)journal::read_journal(dir, journal::ReadOptions{}, [&](const RecordView& v, const journal::RecordLocation&) {
    EXPECT_TRUE(journal::same_content(v, RecordView(l2[k])));
    ++k;
    return true;
  });
  EXPECT_EQ(k, l2.size());
}

}  // namespace
}  // namespace lle::seq
