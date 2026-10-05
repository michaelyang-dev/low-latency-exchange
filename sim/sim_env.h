#pragma once
// SimEnv: the simulator's binding of the environment concepts (ADR-003,
// 01-architecture §5). Components written as `template <class Env>` use
// `typename Env::Clock`, `typename Env::DatagramPort`, ... and run unchanged
// in production (ProdEnv) and inside exsim (SimEnv).
#include "env/concepts.h"
#include "sim/clock.h"
#include "sim/disk.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/rng.h"

namespace lle::sim {

struct SimEnv {
  using Clock = sim::Clock;
  using DatagramPort = sim::DatagramPort;
  using StreamPort = sim::StreamPort;
  using DiskFile = sim::DiskFile;
  using Rng = sim::Rng;
};

static_assert(env::ClockLike<SimEnv::Clock>);
static_assert(env::DatagramPortLike<SimEnv::DatagramPort>);
static_assert(env::StreamPortLike<SimEnv::StreamPort>);
static_assert(env::StreamEndpointLike<SimEnv::StreamPort>);
static_assert(env::DiskFileLike<SimEnv::DiskFile>);
static_assert(env::DiskFileReadLike<SimEnv::DiskFile>);
static_assert(env::RngLike<SimEnv::Rng>);

}  // namespace lle::sim
