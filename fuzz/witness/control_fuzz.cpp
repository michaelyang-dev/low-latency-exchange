// Control-plane fuzz target (10 §2, R-03). Arbitrary bytes are cut into
// datagrams. Every datagram that decodes must re-encode to exactly the same
// bytes (one canonical form), and the decoded stream drives a witness core
// whose slot writes complete at once. The core's own assertions (one write in
// flight, valid state) and the checks below must hold for any input.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>

#include "common/assert.h"
#include "witness/control.h"
#include "witness/witness.h"

using namespace lle::witness;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  State init;
  Witness w(Config{1000}, Durable{init, 1, 0}, 0);
  lle::Nanos now = 0;
  std::map<std::uint64_t, Grant> granted;
  std::size_t pos = 0;
  while (pos < size) {
    // First byte: datagram length (0..63); then the datagram; time advances by the length.
    const std::size_t len = data[pos] % kMaxDatagram;
    ++pos;
    if (pos + len > size) break;
    const std::span<const std::byte> dg(reinterpret_cast<const std::byte*>(data + pos), len);
    pos += len;
    now += static_cast<lle::Nanos>(len) * 100;
    const auto m = decode(dg);
    if (!m) continue;
    const Encoded e = encode(*m);
    LLE_ASSERT(e.size == len && std::memcmp(e.bytes.data(), dg.data(), len) == 0, "decode accepted a non-canonical form");
    w.handle(*m, lle::env::Endpoint{1, 2}, now);
    while (auto job = w.begin_write()) {
      LLE_ASSERT(decode_slot(job->image, job->slot).has_value(), "witness wrote an unreadable slot");
      w.on_persisted(job->generation);
    }
    w.drain([&](const lle::env::Endpoint&, std::span<const std::byte> b) {
      const auto r = decode(b);
      LLE_ASSERT(r.has_value(), "witness sent an undecodable reply");
      if (const auto* g = std::get_if<Grant>(&*r)) {
        // One configuration per epoch (a JOIN grant goes to two recipients).
        auto [it, fresh] = granted.emplace(g->epoch, *g);
        const Grant& f = it->second;
        LLE_ASSERT(fresh || (f.primary == g->primary && f.members == g->members && f.request == g->request &&
                             f.from_epoch == g->from_epoch),
                   "two different configurations for one epoch");
      }
    });
    LLE_ASSERT(valid_state(w.state()), "witness reached an invalid state");
  }
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  // One valid datagram of each type that the witness accepts, length-prefixed.
  const Message seeds[] = {
      Heartbeat{0, Role::kPrimary, 0, 1}, Promote{1, 1, 0, 5}, Solo{1, 0, 0}, Join{2, 0, 1, 0, 1, 9}, Resume{2, 0, 1},
  };
  if (index >= sizeof seeds / sizeof seeds[0]) return 0;
  const Encoded e = encode(seeds[index]);
  if (cap < e.size + 1) return 0;
  buf[0] = static_cast<std::uint8_t>(e.size);
  std::memcpy(buf + 1, e.bytes.data(), e.size);
  return e.size + 1;
}
