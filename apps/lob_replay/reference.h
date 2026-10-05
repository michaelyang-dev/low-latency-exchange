#pragma once
// Reference digests for the per-run correctness gate (04-order-book §5): the
// day replayed once through fuzz/lob's RefBook, which shares no code with
// src/lob or src/book. Results are cached beside the input, keyed by the
// input's SHA-256 and the record limit.
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "book/itch_adapter.h"

namespace lle::replay {

struct Reference {
  std::string sha256;  // of the replayed bytes
  std::uint64_t max_records = 0;
  std::uint64_t records = 0;
  std::uint64_t bbo_digest = 0;
  std::uint64_t bbo_events = 0;
  std::uint64_t books_digest = 0;
  std::uint64_t live_end = 0;
  std::uint64_t peak_live = 0;
  std::uint64_t bad_status = 0;  // operations RefBook rejected; 0 on NASDAQ files
  std::array<std::uint64_t, book::kItchKinds> kinds{};
};

[[nodiscard]] Reference compute_reference(const std::byte* p, std::size_t n);

[[nodiscard]] std::optional<Reference> load_reference(const std::string& path, const std::string& sha256,
                                                      std::uint64_t max_records);
bool save_reference(const std::string& path, const Reference& r);

}  // namespace lle::replay
