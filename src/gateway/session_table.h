#pragma once
// The gateway's session table (07 §3, N-17): which SoupBinTCP username logs in to
// which session, with which credential, on which gateway stage. Loaded from the same
// configuration as the journaled engine tables (ADR-028): session id and account
// must equal the journaled Sessions table, which the node checks at start and at
// recovery. Cold path; immutable once built. Lookups are binary searches over sorted
// vectors, so they never allocate.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "gateway/credentials.h"

namespace lle::gw {

inline constexpr std::size_t kMaxUsername = 6;  // SoupBinTCP 3.00 §2.3.1

struct SessionSpec {
  std::uint32_t session_id = 0;
  std::uint32_t account = 0;
  std::string username;  // normalized (trimmed, upper-case), 1..6 characters
  Credential credential;
  std::uint8_t gateway = 0;            // gw0 / gw1
  bool cancel_on_disconnect = false;   // informational: the engine decides (05 §4 step 8)
};

class SessionTable {
 public:
  SessionTable() = default;

  // Validates and sorts: ids >= 1 and unique, usernames 1..6 characters and unique
  // after normalization, credentials valid, gateway < `gateways`.
  [[nodiscard]] static std::expected<SessionTable, std::string> build(std::vector<SessionSpec> specs,
                                                                      std::size_t gateways);

  [[nodiscard]] const SessionSpec* find_user(std::string_view username) const noexcept;
  [[nodiscard]] const SessionSpec* find_id(std::uint32_t session_id) const noexcept;
  // Sorted by session id.
  [[nodiscard]] std::span<const SessionSpec> all() const noexcept { return by_id_; }
  [[nodiscard]] std::size_t size() const noexcept { return by_id_.size(); }

 private:
  std::vector<SessionSpec> by_id_;
  std::vector<std::uint32_t> by_user_;  // positions in by_id_, sorted by username
};

}  // namespace lle::gw
