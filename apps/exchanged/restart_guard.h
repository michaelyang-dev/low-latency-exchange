#pragma once
// The restart-loop guard of a paired node (10 §5). A node that must truncate its journal
// or reload its engine below where it already runs cannot do so under the running stages:
// it exits 5 and the next start repeats the handshake (repl_stage.h). From an unchanged
// journal that can repeat forever (the simulator saw 519 restarts of a node whose journal
// diverged within an epoch, after an operator error). The replica keeps nothing across a
// restart, so exchanged keeps a small record next to the journal (<journal dir>/
// restart-guard): the exit point (what it had to do, the index, and the journal's
// recovered index at that start) and how many starts in a row ended there. A start whose
// journal recovered to the same index after `limit` identical exits is refused with the
// remedy: move the journal's segment files (*.seg) aside, keeping the incarnation file,
// and start again to rejoin from an empty journal. Nothing is truncated automatically.
// A clean stop removes the record; a different exit point starts the count again.
// Cold path.
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace lle::exch {

// Exit code of a start the guard refused (a supervisor should not restart it).
inline constexpr int kExitRestartLoop = 6;

struct RestartRecord {
  std::string what;            // "truncate the journal to" or "reload the engine to"
  std::uint64_t target = 0;    // the index it had to reach
  std::uint64_t recovered = 0; // the journal's recovered index at that start
  std::uint32_t count = 0;     // consecutive starts that exited there
};

// One line: "exit5 <count> <recovered> <target> <what...>".
[[nodiscard]] inline std::string format_restart_record(const RestartRecord& r) {
  return "exit5 " + std::to_string(r.count) + " " + std::to_string(r.recovered) + " " + std::to_string(r.target) + " " +
         r.what + "\n";
}

[[nodiscard]] inline std::optional<RestartRecord> parse_restart_record(std::string_view text) {
  std::istringstream in{std::string(text)};
  std::string tag;
  RestartRecord r;
  if (!(in >> tag >> r.count >> r.recovered >> r.target) || tag != "exit5") return std::nullopt;
  std::getline(in, r.what);
  const auto b = r.what.find_first_not_of(' ');
  r.what = b == std::string::npos ? std::string() : r.what.substr(b);
  if (r.what.empty() || r.count == 0) return std::nullopt;
  return r;
}

// The record after an exit at (what, target) from a start that recovered `recovered`.
[[nodiscard]] inline RestartRecord next_restart_record(const std::optional<RestartRecord>& prev, std::string what,
                                                       std::uint64_t target, std::uint64_t recovered) {
  RestartRecord r{std::move(what), target, recovered, 1};
  if (prev && prev->what == r.what && prev->target == target && prev->recovered == recovered) r.count = prev->count + 1;
  return r;
}

// True if a start whose journal recovered `recovered` must be refused (limit 0: never).
[[nodiscard]] inline bool restart_refused(const std::optional<RestartRecord>& rec, std::uint64_t recovered,
                                          std::uint32_t limit) noexcept {
  return limit != 0 && rec && rec->recovered == recovered && rec->count >= limit;
}

[[nodiscard]] inline std::string restart_refusal(const RestartRecord& r) {
  return "refusing to start: the last " + std::to_string(r.count) + " starts from this journal (recovered to index " +
         std::to_string(r.recovered) + ") each exited 5 because the node had to " + r.what + " " +
         std::to_string(r.target) + " while running. Move the journal's segment files (*.seg) aside, keeping its "
         "incarnation file, and start again to rejoin from an empty journal (nothing is truncated automatically)";
}

[[nodiscard]] inline std::optional<RestartRecord> read_restart_record(const std::string& path) {
  std::ifstream f(path);
  if (!f) return std::nullopt;
  std::stringstream ss;
  ss << f.rdbuf();
  return parse_restart_record(ss.str());
}

// Written to a temporary file and renamed over the record.
inline bool write_restart_record(const std::string& path, const RestartRecord& r) {
  const std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::trunc);
    if (!(f << format_restart_record(r))) return false;
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  return !ec;
}

inline void clear_restart_record(const std::string& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

}  // namespace lle::exch
