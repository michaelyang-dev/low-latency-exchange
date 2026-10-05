#pragma once
// Swarm fault configuration per seed (09 §4).
//
// Every knob is drawn from its own stream derive_seed(seed, Swarm, hash(name)),
// so disabling a class (--disable=net,disk,crash,clock,buggify) only resets
// that class's knobs to their base values and leaves every other draw intact.
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "common/types.h"

namespace lle::sim {

enum class FaultClass : std::uint8_t { Net, Disk, Crash, Clock, Buggify, Partition, Pause, Sched, kCount };

[[nodiscard]] constexpr std::uint32_t class_bit(FaultClass c) noexcept { return 1u << static_cast<unsigned>(c); }

enum class Mode : std::uint8_t { Swarm, Lite, NoFaults };
enum class Shape : std::uint8_t { Uniform, LogUniform };

enum class Param : std::uint16_t {
#define LLE_SWARM_PARAM(id, name, cls, base, lo, hi, lite_hi, shape, off_ppm) id,
#include "sim/fault/swarm_params.def"
#undef LLE_SWARM_PARAM
  kCount
};

inline constexpr std::size_t kNumParams = static_cast<std::size_t>(Param::kCount);

struct ParamSpec {
  std::string_view name;
  FaultClass cls;
  std::int64_t base;
  std::int64_t lo;
  std::int64_t hi;
  std::int64_t lite_hi;
  Shape shape;
  std::uint32_t off_ppm;
};

inline constexpr std::array<ParamSpec, kNumParams> kSwarmParams{{
#define LLE_SWARM_PARAM(id, name, cls, base, lo, hi, lite_hi, shape, off_ppm) \
  {name, FaultClass::cls, base, lo, hi, lite_hi, Shape::shape, off_ppm},
#include "sim/fault/swarm_params.def"
#undef LLE_SWARM_PARAM
}};

[[nodiscard]] std::string_view fault_class_name(FaultClass c) noexcept;
[[nodiscard]] std::string_view mode_name(Mode m) noexcept;
[[nodiscard]] std::optional<Mode> parse_mode(std::string_view s) noexcept;

// Parses "net,disk,crash,clock,buggify,partition,pause" (any subset, "" or "-"
// for none). Returns nullopt on an unknown name.
[[nodiscard]] std::optional<std::uint32_t> parse_disable_list(std::string_view s) noexcept;
[[nodiscard]] std::string format_disable_list(std::uint32_t mask);

// --disable=net implies partition; --disable=crash implies pause.
[[nodiscard]] std::uint32_t expand_disable_mask(std::uint32_t mask) noexcept;

struct FaultConfig {
  Mode mode = Mode::NoFaults;
  std::uint32_t disabled = 0;  // expanded class mask
  std::array<std::int64_t, kNumParams> v{};

  [[nodiscard]] std::int64_t operator[](Param p) const noexcept { return v[static_cast<std::size_t>(p)]; }
  [[nodiscard]] std::uint64_t u(Param p) const noexcept {
    const std::int64_t x = (*this)[p];
    return x < 0 ? 0 : static_cast<std::uint64_t>(x);
  }
  void set(Param p, std::int64_t x) noexcept { v[static_cast<std::size_t>(p)] = x; }
  [[nodiscard]] bool enabled(FaultClass c) const noexcept {
    return mode != Mode::NoFaults && (disabled & class_bit(c)) == 0;
  }

  // FNV-1a over mode, mask and every value: the ledger's swarm_digest.
  [[nodiscard]] std::uint64_t digest() const noexcept;
  // "name=value" pairs separated by spaces, in table order (TB prints every
  // swarm parameter per seed so a failure report is self-describing).
  [[nodiscard]] std::string describe() const;
};

// Draws the swarm configuration for a seed. Pure function of its arguments.
[[nodiscard]] FaultConfig draw_fault_config(std::uint64_t seed, Mode mode, std::uint32_t disabled_mask);

// Base configuration (everything at base values): deterministic timing only.
[[nodiscard]] FaultConfig base_fault_config();

}  // namespace lle::sim
