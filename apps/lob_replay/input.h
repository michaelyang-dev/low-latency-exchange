#pragma once
// Replay input (04-order-book §5 "Loading"): the whole BinaryFILE day resident
// in locked anonymous memory, 1 GiB huge pages when the host has them, before
// any clock starts. File-backed mappings would not get huge pages.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>

namespace lle::replay {

enum class HugePolicy : std::uint8_t { kAuto, k1G, k2M, kThp, kNone };

[[nodiscard]] bool parse_huge_policy(const std::string& s, HugePolicy& out) noexcept;

class Input {
 public:
  Input() noexcept = default;
  ~Input();
  Input(Input&& o) noexcept;
  Input& operator=(Input&& o) noexcept;
  Input(const Input&) = delete;
  Input& operator=(const Input&) = delete;

  [[nodiscard]] const std::byte* data() const noexcept { return p_; }
  [[nodiscard]] std::size_t size() const noexcept { return n_; }
  [[nodiscard]] const std::string& pages() const noexcept { return pages_; }  // "1g", "2m", "thp", "4k"
  [[nodiscard]] bool locked() const noexcept { return locked_; }

  // Loads `path` (plain BinaryFILE, or gzip, detected by magic bytes). With
  // max_records != 0 only that many leading records are kept.
  static std::expected<Input, std::string> load(const std::string& path, std::uint64_t max_records, HugePolicy policy);

 private:
  std::expected<void, std::string> allocate(std::size_t n, HugePolicy policy);

  std::byte* p_ = nullptr;
  std::size_t n_ = 0;
  std::size_t mapped_ = 0;
  std::string pages_;
  bool locked_ = false;
};

// Framing scan over a loaded buffer (untimed).
struct FrameScan {
  std::uint64_t records = 0;          // messages (non-empty records)
  std::uint64_t end_of_session = 0;   // zero-length records
  bool truncated = false;
};
[[nodiscard]] FrameScan scan_frames(const std::byte* p, std::size_t n) noexcept;

}  // namespace lle::replay
