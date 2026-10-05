// DST-001 regression test (seed-independent): the witness must not answer a
// JOIN that names a different joiner incarnation with the grant of an earlier
// JOIN. Found by `exsim --seed=0x340 --world=witness`; see sim/ledger/bugs.yaml.
#include <gtest/gtest.h>

#include <optional>
#include <variant>
#include <vector>

#include "witness/control.h"
#include "witness/witness.h"

namespace lle::witness {
namespace {

constexpr env::Endpoint kA{0x0A000001u, 7400};

struct Rig {
  SlotImage disk[kSlots]{};
  std::optional<Witness> w;
  Rig() {
    State s;
    s.epoch = 1;
    s.primary = 0;
    s.members = 0b11;
    disk[0] = encode_slot(s, 1);
    start();
  }
  void start() { w.emplace(Config{}, *choose(disk[0], disk[1]), 0); }
  Message deliver(const Message& m) {
    w->handle(m, kA, 0);
    while (auto job = w->begin_write()) {
      disk[job->slot] = job->image;
      w->on_persisted(job->generation);
    }
    std::vector<Message> out;
    w->drain([&](const env::Endpoint&, std::span<const std::byte> b) { out.push_back(*decode(b)); });
    EXPECT_EQ(out.size(), 1u);
    return out.at(0);
  }
};

TEST(DST001, JoinForARestartedJoinerIsNotAnsweredWithTheOldGrant) {
  Rig r;
  ASSERT_TRUE(std::holds_alternative<Grant>(r.deliver(Solo{1, 0, 0})));
  ASSERT_TRUE(std::holds_alternative<Grant>(r.deliver(Join{2, 0, 1, 0, 0, 0})));  // GRANT lost
  // The joiner restarted (incarnation 1) and the primary relays JOIN again.
  const Message m = r.deliver(Join{2, 0, 1, 0, 1, 0});
  const auto* g = std::get_if<Grant>(&m);
  EXPECT_EQ(g, nullptr) << "the old grant was returned: W records joiner incarnation "
                        << r.w->state().inc[1] << " while the primary pairs with incarnation 1";
  EXPECT_EQ(r.w->state().inc[1], 0u);
}

}  // namespace
}  // namespace lle::witness
