#include "sim/fault/buggify_registry.h"

#include "common/hash.h"
#include "sim/dist.h"

namespace lle::sim {

BuggifyRegistry::BuggifyRegistry(std::uint64_t buggify_seed, bool enabled, std::uint32_t activate_ppm,
                                 std::uint32_t fire_ppm)
    : seed_(buggify_seed),
      enabled_(enabled),
      activate_ppm_(activate_ppm),
      fire_ppm_(fire_ppm),
      fire_rng_(mix64(buggify_seed ^ 0xB0661F7ull)) {}

std::uint64_t BuggifyRegistry::key(std::string_view name, std::string_view file) noexcept {
  Fnv1a64 h;
  h.str(name);
  h.u(std::uint8_t{0});
  h.str(file);
  return h.value();
}

BuggifySite* BuggifyRegistry::site(std::string_view name, std::string_view file, unsigned line) {
  const std::uint64_t k = key(name, file);
  auto it = sites_.find(k);
  if (it == sites_.end()) {
    BuggifySite s;
    s.name = std::string(name);
    s.file = std::string(file);
    s.line = line;
    s.active = enabled_ && (mix64(seed_ ^ k) % kPpm) < activate_ppm_;
    it = sites_.emplace(k, std::move(s)).first;
  }
  return &it->second;
}

bool BuggifyRegistry::eval(BuggifySite& s) noexcept {
  ++s.evals;
  if (!s.active) return false;
  if (!chance_ppm(fire_rng_, fire_ppm_)) return false;
  ++s.fires;
  ++fired_;
  return true;
}

void BuggifyRegistry::force(std::string_view name, std::string_view file, unsigned line, bool active) {
  site(name, file, line)->active = active;
}

}  // namespace lle::sim
