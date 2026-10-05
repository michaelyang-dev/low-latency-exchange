#include "sim/oracles/registry.h"

#include <cstdio>

#include "common/hash.h"

namespace lle::sim {

std::string Signature::str() const {
  char buf[48];
  std::snprintf(buf, sizeof buf, ":%llu:0x%016llx", static_cast<unsigned long long>(event_index),
                static_cast<unsigned long long>(msg_hash));
  return oracle + buf;
}

OracleRegistry::OracleRegistry() {
  declare(kOSeq, "journal, MoldUDP64 and SoupBinTCP sequences are contiguous");
  declare(kOReplay, "state hash equals a fresh replay of the journal");
  declare(kOPrefix, "every received stream is a prefix of the canonical output");
  declare(kONoLostFill, "every received fill is in the final committed journal output");
  declare(kOExactlyOnce, "<= 1 execution per (account, UserRefNum); no fill seen twice");
  declare(kOOutputCommit, "no output released above the release watermark");
  declare(kOOnePrimary, "at most one node releases outputs per epoch");
  declare(kOLine, "line A and line B bytes identical per sequence number");
  declare(kOArb, "each LineArbiter delivers exactly once, in order, after healing");
  declare(kOBook, "ITCH-reconstructed book equals the engine's displayed book");
  declare(kOConserve, "filled <= ordered; book totals and match quantities balance");
  declare(kORisk, "no accepted order violates an active risk limit");
  declare(kOLive, "convergence within bound B after healing");
  declare(kODeterminism, "trace hash equal on re-run");
}

OracleId OracleRegistry::declare(std::string_view id, std::string_view description) {
  const OracleId existing = find(id);
  if (existing != kNone) {
    if (!description.empty() && oracles_[existing].description.empty()) {
      oracles_[existing].description = std::string(description);
    }
    return existing;
  }
  OracleInfo info;
  info.id = std::string(id);
  info.description = std::string(description);
  oracles_.push_back(std::move(info));
  return static_cast<OracleId>(oracles_.size() - 1);
}

OracleId OracleRegistry::activate(std::string_view id, std::string_view description) {
  const OracleId h = declare(id, description);
  oracles_[h].state = OracleState::Active;
  return h;
}

OracleId OracleRegistry::find(std::string_view id) const {
  for (std::size_t i = 0; i < oracles_.size(); ++i) {
    if (oracles_[i].id == id) return static_cast<OracleId>(i);
  }
  return kNone;
}

void OracleRegistry::fail(OracleId h, std::string_view message) {
  OracleInfo& o = oracles_[h];
  ++o.checks;
  ++o.failures;
  if (failed_) return;
  failed_ = true;
  first_.oracle = o.id;
  first_.event_index = event_index_ != nullptr ? *event_index_ : 0;
  Fnv1a64 fh;
  fh.str(message);
  first_.msg_hash = fh.value();
  first_.message = std::string(message);
}

void OracleRegistry::add_final_check(OracleId h, std::function<void()> fn) { finals_.emplace_back(h, std::move(fn)); }

void OracleRegistry::run_final_checks() {
  for (auto& [h, fn] : finals_) {
    if (failed_) return;
    fn();
  }
}

}  // namespace lle::sim
