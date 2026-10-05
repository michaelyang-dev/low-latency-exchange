#include "sim/fault/swarm.h"

#include "common/hash.h"
#include "sim/dist.h"
#include "sim/rng.h"

namespace lle::sim {

namespace {

constexpr std::array<std::string_view, static_cast<std::size_t>(FaultClass::kCount)> kClassNames{
    "net", "disk", "crash", "clock", "buggify", "partition", "pause", "sched"};

std::uint64_t name_hash(std::string_view s) noexcept {
  Fnv1a64 h;
  h.str(s);
  return h.value();
}

}  // namespace

std::string_view fault_class_name(FaultClass c) noexcept { return kClassNames[static_cast<std::size_t>(c)]; }

std::string_view mode_name(Mode m) noexcept {
  switch (m) {
    case Mode::Swarm:
      return "swarm";
    case Mode::Lite:
      return "lite";
    case Mode::NoFaults:
      return "no-faults";
  }
  return "?";
}

std::optional<Mode> parse_mode(std::string_view s) noexcept {
  if (s == "swarm") return Mode::Swarm;
  if (s == "lite") return Mode::Lite;
  if (s == "no-faults" || s == "none") return Mode::NoFaults;
  return std::nullopt;
}

std::optional<std::uint32_t> parse_disable_list(std::string_view s) noexcept {
  std::uint32_t mask = 0;
  if (s.empty() || s == "-" || s == "none") return mask;
  while (!s.empty()) {
    const std::size_t comma = s.find(',');
    const std::string_view tok = s.substr(0, comma);
    bool found = false;
    for (std::size_t i = 0; i < kClassNames.size(); ++i) {
      if (kClassNames[i] == tok && static_cast<FaultClass>(i) != FaultClass::Sched) {
        mask |= class_bit(static_cast<FaultClass>(i));
        found = true;
      }
    }
    if (!found) return std::nullopt;
    if (comma == std::string_view::npos) break;
    s.remove_prefix(comma + 1);
  }
  return mask;
}

std::string format_disable_list(std::uint32_t mask) {
  std::string out;
  for (std::size_t i = 0; i < kClassNames.size(); ++i) {
    if ((mask & (1u << i)) == 0) continue;
    if (!out.empty()) out += ',';
    out += kClassNames[i];
  }
  return out.empty() ? std::string("-") : out;
}

std::uint32_t expand_disable_mask(std::uint32_t mask) noexcept {
  if ((mask & class_bit(FaultClass::Net)) != 0) mask |= class_bit(FaultClass::Partition);
  if ((mask & class_bit(FaultClass::Crash)) != 0) mask |= class_bit(FaultClass::Pause);
  return mask;
}

std::uint64_t FaultConfig::digest() const noexcept {
  Fnv1a64 h;
  h.u(static_cast<std::uint8_t>(mode));
  h.u(disabled);
  for (const std::int64_t x : v) h.u(x);
  return h.value();
}

std::string FaultConfig::describe() const {
  std::string out;
  for (std::size_t i = 0; i < kNumParams; ++i) {
    if (!out.empty()) out += ' ';
    out += kSwarmParams[i].name;
    out += '=';
    out += std::to_string(v[i]);
  }
  return out;
}

FaultConfig draw_fault_config(std::uint64_t seed, Mode mode, std::uint32_t disabled_mask) {
  FaultConfig cfg;
  cfg.mode = mode;
  cfg.disabled = expand_disable_mask(disabled_mask);
  for (std::size_t i = 0; i < kNumParams; ++i) {
    const ParamSpec& p = kSwarmParams[i];
    Prng r(derive_seed(seed, Stream::Swarm, name_hash(p.name)));
    // Same draws in every mode and mask, so the value only depends on the
    // seed, the mode's range and whether the class is on.
    const bool off = chance_ppm(r, p.off_ppm);
    const std::int64_t hi = (mode == Mode::Lite && p.lite_hi >= p.lo) ? p.lite_hi : p.hi;
    const std::int64_t drawn = p.shape == Shape::Uniform ? uniform(r, p.lo, hi) : log_uniform(r, p.lo, hi);
    const bool sched = p.cls == FaultClass::Sched;
    const bool class_on = sched || cfg.enabled(p.cls);
    cfg.v[i] = (class_on && !off) ? drawn : p.base;
  }
  return cfg;
}

FaultConfig base_fault_config() {
  FaultConfig cfg;
  cfg.mode = Mode::NoFaults;
  for (std::size_t i = 0; i < kNumParams; ++i) cfg.v[i] = kSwarmParams[i].base;
  return cfg;
}

}  // namespace lle::sim
