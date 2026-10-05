#include "repl/types.h"

namespace lle::repl {

const char* to_string(Role r) noexcept {
  switch (r) {
    case Role::kNone: return "none";
    case Role::kPrimary: return "P";
    case Role::kSoloPrimary: return "SP";
    case Role::kSoloCandidate: return "SC";
    case Role::kBackup: return "B";
    case Role::kCandidate: return "C";
    case Role::kRecovering: return "R";
    case Role::kDeposed: return "deposed";
  }
  return "?";
}

const char* to_string(Alarm a) noexcept {
  switch (a) {
    case Alarm::kBuildMismatch: return "build_mismatch";
    case Alarm::kStateHashMismatch: return "state_hash_mismatch";
    case Alarm::kBadRecord: return "bad_record";
    case Alarm::kDiverged: return "diverged";
    case Alarm::kSnapshotInvalid: return "snapshot_invalid";
    case Alarm::kIncarnationRegressed: return "incarnation_regressed";
    case Alarm::kUnpromotableSuspect: return "unpromotable_suspect";
  }
  return "?";
}

}  // namespace lle::repl
