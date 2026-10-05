#pragma once
// OutlogDay: the per-day set of output-log writers (06 §8, §10):
//   <root>/<YYYYMMDD>/itch.bin             MoldUDP64 / ITCH stream
//   <root>/<YYYYMMDD>/soup-<NNNNNN>.bin    one per SoupBinTCP session
// (each with its .idx). Sessions come from the journaled config at day start,
// so every file is opened up front and the append path never opens files.
// Rollover to the next day is a close() followed by open() of the new day.
//
// Generic over the storage (outlog/disk.h) like the writers it holds: OutlogDay
// is the POSIX binding; the simulator instantiates BasicOutlogDay on its disk.
#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "outlog/disk.h"
#include "outlog/format.h"
#include "outlog/posix_fs.h"
#include "outlog/writer.h"

namespace lle::outlog {

// The day's file layout (no storage involved).
struct OutlogDayPaths {
  static constexpr std::uint32_t kMaxSessionId = 999'999;  // six decimal digits in the file name

  // `day` is the trading date as YYYYMMDD (e.g. 20260930).
  [[nodiscard]] static std::string day_dir(const std::string& root, std::uint32_t day);
  [[nodiscard]] static std::string itch_path(const std::string& root, std::uint32_t day);
  [[nodiscard]] static std::string soup_path(const std::string& root, std::uint32_t day, std::uint32_t session_id);
};

namespace detail {
// Range checks only: the date itself comes from the journaled DayStart record.
[[nodiscard]] bool plausible_day(std::uint32_t day) noexcept;
}  // namespace detail

template <OutlogFsLike Fs>
class BasicOutlogDay : public OutlogDayPaths {
 public:
  using Writer = BasicOutlogWriter<Fs>;
  static constexpr std::size_t kDefaultSoupBufferBytes = std::size_t{1} << 17;

  BasicOutlogDay() requires std::default_initializable<Fs> = default;
  explicit BasicOutlogDay(Fs fs) : fs_(fs), itch_(std::move(fs)) {}
  ~BasicOutlogDay() { (void)close(); }
  BasicOutlogDay(const BasicOutlogDay&) = delete;
  BasicOutlogDay& operator=(const BasicOutlogDay&) = delete;

  // Creates the day directory and opens (creating or repairing) itch.bin and
  // one soup file per session. Session ids must be unique and <= 999,999.
  std::expected<void, std::string> open(const std::string& root, std::uint32_t day,
                                        std::span<const std::uint32_t> session_ids,
                                        std::size_t itch_buffer_bytes = Writer::kDefaultBufferBytes,
                                        std::size_t soup_buffer_bytes = kDefaultSoupBufferBytes);

  [[nodiscard]] bool is_open() const noexcept { return open_; }
  [[nodiscard]] std::uint32_t day() const noexcept { return day_; }
  // Sorted ascending.
  [[nodiscard]] std::span<const std::uint32_t> sessions() const noexcept { return sessions_; }

  [[nodiscard]] Writer& itch() noexcept { return itch_; }
  // The writer of `session_id`, or nullptr if the session was not configured.
  // Binary search over the sorted ids; never allocates.
  [[nodiscard]] Writer* soup(std::uint32_t session_id) noexcept {
    const auto it = std::lower_bound(sessions_.begin(), sessions_.end(), session_id);
    if (it == sessions_.end() || *it != session_id) return nullptr;
    return soups_[static_cast<std::size_t>(it - sessions_.begin())].get();
  }

  // Flushes every writer; reports the first error but flushes all of them.
  std::expected<void, Error> flush_all() noexcept {
    if (!open_) return std::unexpected(Error::NotOpen);
    std::expected<void, Error> result = itch_.flush();
    for (auto& w : soups_) {
      if (auto r = w->flush(); !r && result) result = r;
    }
    return result;
  }
  // Closes every writer; reports the first error but closes all of them.
  std::expected<void, Error> close() noexcept {
    if (!open_) return {};
    std::expected<void, Error> result = itch_.close();
    for (auto& w : soups_) {
      if (auto r = w->close(); !r && result) result = r;
    }
    soups_.clear();
    sessions_.clear();
    day_ = 0;
    open_ = false;
    return result;
  }

 private:
  Fs fs_{};
  bool open_ = false;
  std::uint32_t day_ = 0;
  Writer itch_;
  std::vector<std::uint32_t> sessions_;
  std::vector<std::unique_ptr<Writer>> soups_;  // parallel to sessions_
};

template <OutlogFsLike Fs>
std::expected<void, std::string> BasicOutlogDay<Fs>::open(const std::string& root, std::uint32_t day,
                                                          std::span<const std::uint32_t> session_ids,
                                                          std::size_t itch_buffer_bytes,
                                                          std::size_t soup_buffer_bytes) {
  (void)close();
  if (!detail::plausible_day(day)) return std::unexpected(std::format("invalid trading day {} (want YYYYMMDD)", day));
  std::vector<std::uint32_t> ids(session_ids.begin(), session_ids.end());
  std::sort(ids.begin(), ids.end());
  if (std::adjacent_find(ids.begin(), ids.end()) != ids.end()) return std::unexpected("duplicate session id");
  if (!ids.empty() && ids.back() > kMaxSessionId) {
    return std::unexpected(std::format("session id {} exceeds {}", ids.back(), kMaxSessionId));
  }

  const std::string dir = day_dir(root, day);
  if (const int e = fs_.make_dirs(dir); e != 0) {
    return std::unexpected("cannot create '" + dir + "': " + std::generic_category().message(e));
  }

  std::vector<std::unique_ptr<Writer>> soups;
  soups.reserve(ids.size());
  for (std::size_t i = 0; i < ids.size(); ++i) soups.push_back(std::make_unique<Writer>(fs_));
  if (auto r = itch_.open(itch_path(root, day), itch_buffer_bytes); !r) return r;
  for (std::size_t i = 0; i < ids.size(); ++i) {
    if (auto r = soups[i]->open(soup_path(root, day, ids[i]), soup_buffer_bytes); !r) {
      (void)itch_.close();
      return r;  // `soups` closes the writers opened so far
    }
  }
  sessions_ = std::move(ids);
  soups_ = std::move(soups);
  day_ = day;
  open_ = true;
  return {};
}

// The production day: POSIX files.
using OutlogDay = BasicOutlogDay<PosixFs>;
extern template class BasicOutlogDay<PosixFs>;

}  // namespace lle::outlog
