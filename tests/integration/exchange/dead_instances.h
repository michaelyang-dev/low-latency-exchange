#pragma once
// ADR-032 checks shared by the restart and HA tests: after a restart, a takeover or a
// RESUME, the InstanceDown records of the dead instances are the first records after the
// recovered prefix (or the new epoch's EpochStart), ahead of every overdue Timer; so an
// opening cross that came due during the outage never executes a dead connection's
// cancel-on-disconnect order.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "common/endian.h"
#include "describe.h"
#include "journal/posix_segment_dir.h"
#include "journal/reader.h"
#include "verify.h"

namespace lle::exch::test {

struct JournalRec {
  std::uint64_t index = 0;
  journal::RecordType type{};
  std::uint32_t epoch = 0;
  std::uint32_t session = 0;  // SessionEvent
  std::uint16_t instance = 0;
  journal::SessionEventKind event{};
  journal::TimerKind timer{};  // Timer
};

inline std::vector<JournalRec> journal_records(const std::string& jdir) {
  std::vector<JournalRec> out;
  auto d = journal::PosixSegmentDir::open(jdir, false, journal::PosixDeviceOptions{.read_only = true});
  EXPECT_TRUE(d.has_value()) << jdir;
  if (!d) return out;
  (void)journal::read_journal(*d, journal::ReadOptions{}, [&](const journal::RecordView& r, const journal::RecordLocation&) {
    JournalRec j;
    j.index = r.index();
    j.type = r.type();
    j.epoch = r.epoch();
    if (j.type == journal::RecordType::SessionEvent) {
      if (const auto e = journal::decode_session_event(r)) {
        j.session = e->session_id;
        j.instance = e->instance;
        j.event = e->event;
      }
    } else if (j.type == journal::RecordType::Timer) {
      if (const auto t = journal::decode_timer(r)) j.timer = t->kind;
    }
    out.push_back(j);
    return true;
  });
  return out;
}

// The index of the last EpochStart (0: none).
inline std::uint64_t last_epoch_start(const std::vector<JournalRec>& recs) {
  std::uint64_t at = 0;
  for (const JournalRec& r : recs)
    if (r.type == journal::RecordType::EpochStart) at = r.index;
  return at;
}

// The records right after index `after` are InstanceDown records of `instance`, the
// cancel-on-disconnect session `cod_session` among them, and the first opening-cross
// Timer after `after` follows all of them (ADR-032).
inline void expect_dead_instances_first(const std::vector<JournalRec>& recs, std::uint64_t after, std::uint16_t instance,
                                        std::uint32_t cod_session) {
  std::size_t k = 0;
  while (k < recs.size() && recs[k].index <= after) ++k;
  ASSERT_LT(k, recs.size()) << "no records after " << after;
  std::size_t downs = 0;
  bool cod = false;
  for (; k < recs.size(); ++k) {
    const JournalRec& r = recs[k];
    if (r.type != journal::RecordType::SessionEvent || r.event != journal::SessionEventKind::InstanceDown) break;
    EXPECT_EQ(r.instance, instance) << "record " << r.index;
    cod = cod || r.session == cod_session;
    ++downs;
  }
  EXPECT_GT(downs, 0u) << "record " << after + 1 << " (type " << static_cast<int>(recs[k < recs.size() ? k : 0].type)
                       << ") is not an InstanceDown";
  EXPECT_TRUE(cod) << "no InstanceDown for session " << cod_session << " in the " << downs << " records after " << after;
  std::uint64_t cross = 0;
  for (const JournalRec& r : recs)
    if (r.index > after && r.type == journal::RecordType::Timer && r.timer == journal::TimerKind::Cross) {
      cross = r.index;
      break;
    }
  EXPECT_GT(cross, after + downs) << "the opening cross (record " << cross << ") is not after the " << downs
                                  << " InstanceDown records after " << after;
}

// The regenerated day: the AAPL opening cross matched nothing (CHARL's held order was
// cancelled at its InstanceDown), nothing executed, and the cancel-on-disconnect
// session's stream shows its order accepted and cancelled.
inline void expect_cod_order_cancelled_before_the_cross(const Regenerated& r, std::uint32_t cod_session,
                                                        std::uint32_t other_session) {
  if (std::getenv("LLE_E2E_DUMP") != nullptr)
    for (const Bytes& m : r.itch)
      if (type_of(m) != 'I') std::printf("%s\n", Itch{m}.str().c_str());
  // Held orders are not displayed: there is no Add Order before the cross.
  bool saw_cross = false;
  for (const Bytes& m : r.itch) {
    if (type_of(m) == 'Q' && load_be16(m.data() + 1) == 1 && !saw_cross) {
      saw_cross = true;
      EXPECT_EQ(load_be64(m.data() + 11), 0u)
          << Itch{m}.str() << ": the overdue cross executed a dead instance's cancel-on-disconnect order";
    }
    EXPECT_NE(type_of(m), 'E') << Itch{m}.str();
  }
  EXPECT_TRUE(saw_cross) << "no AAPL opening cross";
  auto types = [](const Bytes& stream) {
    std::string t;
    for (std::size_t at = 0; at + 2 <= stream.size();) {
      const std::size_t n = load_be16(stream.data() + at);
      if (n != 0 && at + 2 + n <= stream.size()) t += static_cast<char>(stream[at + 2]);
      at += 2 + n;
    }
    return t;
  };
  ASSERT_TRUE(r.ouch.contains(cod_session));
  const std::string c = types(r.ouch.at(cod_session));
  EXPECT_NE(c.find('A'), std::string::npos) << c;
  EXPECT_NE(c.find('C'), std::string::npos) << "the cancel-on-disconnect order was not cancelled: " << c;
  EXPECT_EQ(c.find('E'), std::string::npos) << "the cancel-on-disconnect order executed: " << c;
  ASSERT_TRUE(r.ouch.contains(other_session));
  EXPECT_EQ(types(r.ouch.at(other_session)).find('E'), std::string::npos) << "the other side traded with a dead order";
}

}  // namespace lle::exch::test
