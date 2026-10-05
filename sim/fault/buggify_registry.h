#pragma once
// Per-run SIM_BUGGIFY site state (09 §4).
#include <cstdint>
#include <map>
#include <string>
#include <string_view>

#include "common/prng.h"

namespace lle::sim {

struct BuggifySite {
  std::string name;
  std::string file;
  unsigned line = 0;
  bool active = false;
  std::uint64_t evals = 0;
  std::uint64_t fires = 0;
};

class BuggifyRegistry {
 public:
  BuggifyRegistry(std::uint64_t buggify_seed, bool enabled, std::uint32_t activate_ppm, std::uint32_t fire_ppm);

  // Site identity is (name, file basename); `line` is kept for reports only,
  // so edits that move a site do not change which sites a seed activates.
  // Names must therefore be unique within a file. Activation is a pure hash of
  // the identity with the seed, so it does not depend on evaluation order.
  BuggifySite* site(std::string_view name, std::string_view file, unsigned line);
  bool eval(BuggifySite& s) noexcept;

  // Test hook: force a site on or off for this run regardless of the hash.
  void force(std::string_view name, std::string_view file, unsigned line, bool active);

  [[nodiscard]] bool enabled() const noexcept { return enabled_; }
  [[nodiscard]] std::uint64_t fired() const noexcept { return fired_; }
  template <class F>
  void for_each(F&& f) const {
    for (const auto& [key, s] : sites_) f(s);
  }

 private:
  static std::uint64_t key(std::string_view name, std::string_view file) noexcept;

  std::uint64_t seed_;
  bool enabled_;
  std::uint32_t activate_ppm_;
  std::uint32_t fire_ppm_;
  Prng fire_rng_;
  std::uint64_t fired_ = 0;
  std::map<std::uint64_t, BuggifySite> sites_;
};

}  // namespace lle::sim
