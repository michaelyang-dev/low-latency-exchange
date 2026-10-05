#pragma once
// Production entropy (never used by deterministic code: the simulator's purity
// audit rejects getentropy). Seeds journal segment and L2 ring nonces (06 §2)
// and production RNGs. In simulation, nonces come from the seeded lle::Prng.
#include <unistd.h>

#include <cstdint>
#include <cstring>

#include "common/assert.h"
#include "common/prng.h"

#if defined(__APPLE__)
#include <sys/random.h>
#endif

namespace lle::env {

// 64 bits from the OS CSPRNG (getentropy: Linux glibc >= 2.25, macOS >= 10.12).
// Aborts if the OS cannot supply entropy, which only happens on a broken host.
[[nodiscard]] inline std::uint64_t os_entropy64() {
  std::uint64_t v = 0;
  unsigned char buf[sizeof v];
  const int rc = ::getentropy(buf, sizeof buf);
  LLE_ASSERT(rc == 0, "getentropy failed");
  std::memcpy(&v, buf, sizeof v);
  return v;
}

// RngLike for production: xoshiro256** seeded once from the OS.
class ProdRng {
 public:
  ProdRng() : rng_(os_entropy64()) {}
  [[nodiscard]] std::uint64_t next_u64() noexcept { return rng_.next_u64(); }

 private:
  Prng rng_;
};

}  // namespace lle::env
