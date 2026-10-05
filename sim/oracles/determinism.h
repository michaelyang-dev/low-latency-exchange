#pragma once
// O-DETERMINISM (09 §7, §9): the same seed at the same commit must produce
// the same execution. Checked by running a world twice and comparing the
// event count and the trace hash (stronger than FoundationDB's 1-in-100001
// "unseed" sample, R4b §1.6).
#include <cstdint>
#include <string>

#include "sim/oracles/registry.h"
#include "sim/world.h"

namespace lle::sim {

struct DeterminismResult {
  bool ok = false;
  std::uint64_t events[2] = {0, 0};
  std::uint64_t hash[2] = {0, 0};
};

// run_once() builds a fresh world for the seed and returns its RunResult.
template <class F>
DeterminismResult check_determinism(F&& run_once) {
  DeterminismResult r;
  const RunResult a = run_once();
  const RunResult b = run_once();
  r.events[0] = a.events;
  r.events[1] = b.events;
  r.hash[0] = a.trace_hash;
  r.hash[1] = b.trace_hash;
  r.ok = a.events == b.events && a.trace_hash == b.trace_hash;
  return r;
}

inline void record_determinism(OracleRegistry& reg, const DeterminismResult& r) {
  const OracleId h = reg.activate(kODeterminism);
  reg.check(h, r.ok,
            "trace hash differs on re-run: events " + std::to_string(r.events[0]) + " vs " +
                std::to_string(r.events[1]));
}

}  // namespace lle::sim
