#pragma once
// Code-level fault injection and coverage probes for production code (09 §4, §8).
//
//   if (SIM_BUGGIFY("journal.short_write")) len = len / 2;
//   SIM_PROBE("journal.crash_between_write_and_fsync");
//   SIM_PROBE("repl.rejoin_truncates_tail", rare);
//
// Both compile to nothing unless LLE_SIM is defined (the `sim` preset), so
// production binaries carry no trace of them. In sim builds:
//  - SIM_BUGGIFY follows FoundationDB: a site is active for a run with
//    probability 25% (decided by hashing the site's name and file with the
//    buggify seed, so it depends neither on evaluation order nor on line
//    numbers; site names must be unique within a file), and an active site
//    fires with probability 25% per evaluation (draws from the buggify stream).
//  - SIM_PROBE counts hits per name; the must-hit report (09 §8) lists probes
//    that were never hit. `rare` probes must be hit weekly instead of nightly.
//
// This header has no dependencies so any src/ component may include it. The
// implementation lives in lle_sim: in LLE_SIM builds a component that uses
// these macros links it through ${LLE_SIM_HOOKS} (DEPS lle_common ${LLE_SIM_HOOKS}).
#include <cstdint>

#if defined(__FILE_NAME__)
#define LLE_SIM_FILE_NAME __FILE_NAME__
#else
#define LLE_SIM_FILE_NAME __FILE__
#endif

namespace lle::sim::detail {

// Per-call-site static storage. `epoch` caches which world's registry `state`
// points into; a new world (new epoch) re-resolves it.
struct BuggifySiteDecl {
  const char* name;
  const char* file;
  unsigned line;
  std::uint64_t epoch;
  void* state;
};

struct ProbeSiteDecl {
  const char* name;
  bool rare;
  std::uint64_t epoch;
  void* state;
};

bool buggify_eval(BuggifySiteDecl& site) noexcept;
void probe_hit(ProbeSiteDecl& site) noexcept;

}  // namespace lle::sim::detail

#define LLE_SIM_RARE_rare true

#if defined(LLE_SIM) && LLE_SIM

#define SIM_BUGGIFY(site)                                                                       \
  ([]() noexcept -> bool {                                                                      \
    static ::lle::sim::detail::BuggifySiteDecl lle_buggify_site{site, LLE_SIM_FILE_NAME, __LINE__, \
                                                                0, nullptr};                    \
    return ::lle::sim::detail::buggify_eval(lle_buggify_site);                                  \
  }())

#define LLE_SIM_PROBE_IMPL(name, is_rare)                                                     \
  do {                                                                                        \
    static ::lle::sim::detail::ProbeSiteDecl lle_probe_site{name, is_rare, 0, nullptr};       \
    ::lle::sim::detail::probe_hit(lle_probe_site);                                            \
  } while (0)

#else

#define SIM_BUGGIFY(site) (false)
#define LLE_SIM_PROBE_IMPL(name, is_rare) \
  do {                                    \
  } while (0)

#endif

#define LLE_SIM_PROBE1(name) LLE_SIM_PROBE_IMPL(name, false)
#define LLE_SIM_PROBE2(name, r) LLE_SIM_PROBE_IMPL(name, LLE_SIM_RARE_##r)
#define LLE_SIM_PROBE_SEL(a1, a2, macro, ...) macro
#define SIM_PROBE(...) LLE_SIM_PROBE_SEL(__VA_ARGS__, LLE_SIM_PROBE2, LLE_SIM_PROBE1, )(__VA_ARGS__)
