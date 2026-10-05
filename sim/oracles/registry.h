#pragma once
// Oracle registry (09 §7).
//
// Every oracle ID from 09 §7 is pre-declared as a placeholder. A component (or
// a world) activates the IDs it checks and reports through the returned
// handle. The first failure stops the run and becomes the run's signature:
// (oracle ID, event index, message hash), the triple the bug ledger records
// and verify_bugs.py / shrink.py compare.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace lle::sim {

struct Signature {
  std::string oracle;
  std::uint64_t event_index = 0;
  std::uint64_t msg_hash = 0;
  std::string message;

  // "O-SEQ:1234:0x00ab..." (stable, parsed by tools/ledger).
  [[nodiscard]] std::string str() const;
};

enum class OracleState : std::uint8_t { Placeholder, Active };

struct OracleInfo {
  std::string id;
  std::string description;
  OracleState state = OracleState::Placeholder;
  std::uint64_t checks = 0;
  std::uint64_t failures = 0;
};

using OracleId = std::uint32_t;

// Oracle IDs shared with the TLA+ invariants where they correspond (09 §7).
inline constexpr std::string_view kOSeq = "O-SEQ";
inline constexpr std::string_view kOReplay = "O-REPLAY";
inline constexpr std::string_view kOPrefix = "O-PREFIX";
inline constexpr std::string_view kONoLostFill = "O-NO-LOST-FILL";
inline constexpr std::string_view kOExactlyOnce = "O-EXACTLY-ONCE";
inline constexpr std::string_view kOOutputCommit = "O-OUTPUT-COMMIT";
inline constexpr std::string_view kOOnePrimary = "O-ONE-PRIMARY";
inline constexpr std::string_view kOLine = "O-LINE";
inline constexpr std::string_view kOArb = "O-ARB";
inline constexpr std::string_view kOBook = "O-BOOK";
inline constexpr std::string_view kOConserve = "O-CONSERVE";
inline constexpr std::string_view kORisk = "O-RISK";
inline constexpr std::string_view kOLive = "O-LIVE";
inline constexpr std::string_view kODeterminism = "O-DETERMINISM";

class OracleRegistry {
 public:
  OracleRegistry();

  // Declares (or finds) an oracle; placeholders are listed but not checked.
  OracleId declare(std::string_view id, std::string_view description = {});
  // Marks an oracle as checked by the current world and returns its handle.
  OracleId activate(std::string_view id, std::string_view description = {});
  [[nodiscard]] OracleId find(std::string_view id) const;  // kNone if absent

  void pass(OracleId h) noexcept { ++oracles_[h].checks; }
  void fail(OracleId h, std::string_view message);
  void check(OracleId h, bool ok, std::string_view message) {
    if (ok) {
      pass(h);
    } else {
      fail(h, message);
    }
  }

  // Final checks run once after convergence.
  void add_final_check(OracleId h, std::function<void()> fn);
  void run_final_checks();

  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] const Signature& first_failure() const noexcept { return first_; }
  [[nodiscard]] const std::vector<OracleInfo>& list() const noexcept { return oracles_; }

  // Event index stamped into signatures (the world's current event number).
  void set_event_index_source(const std::uint64_t* src) noexcept { event_index_ = src; }

  static constexpr OracleId kNone = 0xFFFF'FFFFu;

 private:
  std::vector<OracleInfo> oracles_;
  std::vector<std::pair<OracleId, std::function<void()>>> finals_;
  const std::uint64_t* event_index_ = nullptr;
  bool failed_ = false;
  Signature first_;
};

}  // namespace lle::sim
