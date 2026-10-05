#pragma once
// Test environment for lle::seq::Sequencer: a fake clock, the real SCQ queues, and the
// L2 ring over heap storage.
#include <cstdint>
#include <memory>
#include <vector>

#include "common/types.h"
#include "concurrent/mpsc_scq.h"
#include "journal/l2_ring.h"
#include "sequencer/sequencer.h"

namespace lle::seq::testing {

// Exchange time is whatever the test says; `step` advances it on every read.
struct FakeClock {
  Nanos real = 1'790'000'000'000'000'000;
  Nanos step = 0;
  Nanos now_mono() noexcept { return 0; }
  Nanos now_real() noexcept {
    const Nanos t = real;
    real += step;
    return t;
  }
  std::uint64_t tsc() noexcept { return 0; }
};

struct TestEnv {
  using Clock = FakeClock;
  using OuchQueue = conc::MpscScqRing<InboundMsg, 64>;
  using SessionQueue = conc::MpscScqRing<SessionEventMsg, 16>;
  using AdminQueue = conc::MpscScqRing<AdminMsg, 16>;
  using Ring = journal::L2Ring<2>;
};
static_assert(SequencerEnv<TestEnv>);

inline constexpr std::uint64_t kRingNonce = 0x0DDBA11CAFEF00D5ull;

struct Rig {
  explicit Rig(std::size_t ring_bytes = std::size_t{1} << 20, std::vector<ScheduleEntry> sched = {},
               SequencerConfig cfg = {})
      : storage(new std::uint64_t[ring_bytes / 8]()), schedule(std::move(sched)),
        ouch(std::make_unique<TestEnv::OuchQueue>()),
        sessions(std::make_unique<TestEnv::SessionQueue>()),
        admin(std::make_unique<TestEnv::AdminQueue>()) {
    ring.init(reinterpret_cast<std::byte*>(storage.get()), ring_bytes, kRingNonce);
    seq = std::make_unique<Sequencer<TestEnv>>(clock, *ouch, *sessions, *admin, ring, schedule, cfg);
  }

  // Records on cursor `c` since the last call (copies).
  std::vector<std::vector<std::byte>> take(std::size_t c = 0) {
    std::vector<std::vector<std::byte>> out;
    while (ring.drain(c, [&](const journal::RecordView& v) { out.emplace_back(v.bytes().begin(), v.bytes().end()); },
                      256) != 0) {
    }
    return out;
  }

  static InboundMsg ouch_msg(std::uint32_t session, std::uint8_t fill, std::uint16_t len = 47) {
    InboundMsg m;
    m.session_id = session;
    m.account = session * 10;
    m.instance = 1;
    m.len = len;
    for (std::uint16_t i = 0; i < len; ++i) m.bytes[i] = static_cast<std::byte>(fill + i);
    return m;
  }

  void start(std::vector<ConfigBlob> cfg = {}) {
    journal::DayStart ds;
    ds.trading_date = 20260930;
    ASSERT_TRUE(seq->start_day(ds, cfg, 1, 7).has_value());
  }

  std::unique_ptr<std::uint64_t[]> storage;
  std::vector<ScheduleEntry> schedule;
  FakeClock clock;
  std::unique_ptr<TestEnv::OuchQueue> ouch;
  std::unique_ptr<TestEnv::SessionQueue> sessions;
  std::unique_ptr<TestEnv::AdminQueue> admin;
  journal::L2Ring<2> ring;
  std::unique_ptr<Sequencer<TestEnv>> seq;
};

}  // namespace lle::seq::testing
