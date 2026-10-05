#pragma once
// Must-hit coverage probes (09 §8; FoundationDB CODE_PROBE, TigerBeetle marks).
//
// A probe is a named counter. The must-hit manifest (must_hit_probes.def)
// declares which probes the nightly ensemble must hit; worlds may declare more.
// Probes whose component has not landed yet are declared `pending` so the
// report shows them without failing CI.
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace lle::sim {

enum class ProbeStatus : std::uint8_t { Ok, Missing, Pending, Unlisted };

struct ProbeInfo {
  std::string name;
  bool rare = false;
  bool must_hit = false;  // declared in a manifest
  bool pending = false;   // component not landed yet
  std::uint64_t hits = 0;
};

class ProbeRegistry {
 public:
  ProbeRegistry();  // loads the default manifest

  void declare(std::string_view name, bool rare, bool pending = false);
  // Returns a stable pointer (std::map nodes do not move) for call-site caching.
  ProbeInfo* site(std::string_view name, bool rare);
  void hit(std::string_view name, bool rare = false) { ++site(name, rare)->hits; }

  [[nodiscard]] std::uint64_t hits(std::string_view name) const;
  [[nodiscard]] static ProbeStatus status(const ProbeInfo& p) noexcept;
  // Must-hit probes (not pending) with zero hits. Rare ones only if include_rare.
  [[nodiscard]] std::vector<std::string> missing(bool include_rare) const;

  template <class F>
  void for_each(F&& f) const {
    for (const auto& [name, info] : probes_) f(info);
  }
  void merge(const ProbeRegistry& o);

 private:
  std::map<std::string, ProbeInfo, std::less<>> probes_;
};

[[nodiscard]] std::string_view probe_status_name(ProbeStatus s) noexcept;

}  // namespace lle::sim
