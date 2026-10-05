#include "sim/fault/probes.h"

namespace lle::sim {

ProbeRegistry::ProbeRegistry() {
#define LLE_MUST_HIT(name, rare, pending) declare(name, rare, pending);
#include "sim/fault/must_hit_probes.def"
#undef LLE_MUST_HIT
}

void ProbeRegistry::declare(std::string_view name, bool rare, bool pending) {
  ProbeInfo* p = site(name, rare);
  p->rare = rare;
  p->must_hit = true;
  p->pending = pending;
}

ProbeInfo* ProbeRegistry::site(std::string_view name, bool rare) {
  auto it = probes_.find(name);
  if (it == probes_.end()) {
    ProbeInfo info;
    info.name = std::string(name);
    info.rare = rare;
    it = probes_.emplace(info.name, std::move(info)).first;
  }
  return &it->second;
}

std::uint64_t ProbeRegistry::hits(std::string_view name) const {
  const auto it = probes_.find(name);
  return it == probes_.end() ? 0 : it->second.hits;
}

ProbeStatus ProbeRegistry::status(const ProbeInfo& p) noexcept {
  if (!p.must_hit) return ProbeStatus::Unlisted;
  if (p.hits > 0) return ProbeStatus::Ok;
  return p.pending ? ProbeStatus::Pending : ProbeStatus::Missing;
}

std::vector<std::string> ProbeRegistry::missing(bool include_rare) const {
  std::vector<std::string> out;
  for (const auto& [name, p] : probes_) {
    if (status(p) == ProbeStatus::Missing && (include_rare || !p.rare)) out.push_back(name);
  }
  return out;
}

void ProbeRegistry::merge(const ProbeRegistry& o) {
  for (const auto& [name, p] : o.probes_) {
    ProbeInfo* mine = site(name, p.rare);
    mine->hits += p.hits;
    if (p.must_hit) {
      mine->must_hit = true;
      mine->pending = p.pending;
      mine->rare = p.rare;
    }
  }
}

std::string_view probe_status_name(ProbeStatus s) noexcept {
  switch (s) {
    case ProbeStatus::Ok:
      return "OK";
    case ProbeStatus::Missing:
      return "MISSING";
    case ProbeStatus::Pending:
      return "PENDING";
    case ProbeStatus::Unlisted:
      return "UNLISTED";
  }
  return "?";
}

}  // namespace lle::sim
