#pragma once
// Reports of the client programs: a minimal JSON object writer, the checkpoint
// file format, and the checkpoint comparison behind the T10 evidence.
//
// Checkpoint file (text, one checkpoint per line, '#' comments):
//   seq books_digest live_orders stream_hash bbo_digest tainted splice
// digests in 16-digit hex, the rest decimal. Written by refclient for the feed
// handler (network mode) and for the direct replay (--direct), compared with
// refclient --compare.
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "client/checkpoints.h"
#include "proto/moldudp64/line_arbiter.h"

namespace lle::client {

// Flat JSON object builder (cold path).
class JsonObject {
 public:
  JsonObject& num(std::string_view k, std::uint64_t v);
  JsonObject& inum(std::string_view k, std::int64_t v);
  JsonObject& str(std::string_view k, std::string_view v);
  JsonObject& hex(std::string_view k, std::uint64_t v);
  JsonObject& boolean(std::string_view k, bool v);
  JsonObject& raw(std::string_view k, std::string_view json);  // nested value, already JSON
  [[nodiscard]] std::string done() const;

 private:
  void key(std::string_view k);
  std::string s_;
};

// Reads the top-level members of a JSON object written by JsonObject: numbers and
// booleans as their text, strings unquoted (simple escapes only); nested objects and
// arrays are skipped. Cold path (merging reports). nullopt if the file is unreadable or
// not an object.
[[nodiscard]] std::optional<std::map<std::string, std::string>> read_flat_json(const std::string& path);
[[nodiscard]] std::optional<std::map<std::string, std::string>> parse_flat_json(std::string_view text);

// Arbiter metrics as JSON members (03-protocols §7 "Metrics").
void add_arbiter_metrics(JsonObject& j, const mold::LineArbiterMetrics& m);

bool write_checkpoints(const std::string& path, const std::vector<Checkpoint>& list);
bool read_checkpoints(const std::string& path, std::vector<Checkpoint>& out, std::string* err);

struct CompareResult {
  bool ok = false;
  std::uint64_t compared_books = 0;     // checkpoints present in both, book digests compared
  std::uint64_t compared_streams = 0;   // ... stream hashes compared (untainted on the client side)
  std::uint64_t compared_bbo = 0;       // ... BBO digests compared (before the first splice)
  std::uint64_t missing_in_reference = 0;
  bool reached_end = false;             // the client's last checkpoint is the reference's last (end of stream)
  std::uint64_t mismatches = 0;
  std::vector<std::string> details;     // first mismatches, human readable
};

// `client`: the feed handler's checkpoints; `reference`: the direct replay's,
// which must include every client checkpoint sequence (pass the client's splice
// sequences to the direct replay as extra checkpoints). The client must also have
// reached the end of the stream: its last checkpoint is the reference's last, so a
// client that stopped early never passes on a matching prefix.
[[nodiscard]] CompareResult compare_checkpoints(const std::vector<Checkpoint>& client,
                                                const std::vector<Checkpoint>& reference);

}  // namespace lle::client
