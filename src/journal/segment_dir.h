#pragma once
// A journal directory (`journal/<day>/`) as seen by the preparer, recovery and tools:
// a set of named segment files, each a JournalDeviceLike device. Cold-path interface;
// the hot path only touches the devices.
//
//   PosixSegmentDir (posix_segment_dir.h)   a real directory of *.seg files
//   MemSegmentDir                           in memory, with whole-directory crash()
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "journal/journal_device.h"
#include "journal/mem_journal_device.h"

namespace lle::journal {

template <class S>
concept SegmentDirLike = requires(S& s, const S& cs, std::size_t i, std::string_view name, std::uint64_t n) {
  typename S::Device;
  requires JournalDeviceLike<typename S::Device>;
  { cs.count() } -> std::same_as<std::size_t>;                   // segment files (handles 0..count-1)
  { s.device(i) } -> std::same_as<typename S::Device&>;          // stable address while `s` lives
  { cs.name(i) } -> std::convertible_to<std::string_view>;
  { s.create(name, n) } -> std::same_as<std::optional<std::size_t>>;  // new zero-length-or-sized file
  { s.rename(i, name) } -> std::same_as<bool>;
  { s.sync_dir() } -> std::same_as<bool>;                        // make creations/renames durable
};

class MemSegmentDir {
 public:
  using Device = MemJournalDevice;

  MemSegmentDir() = default;
  MemSegmentDir(MemSegmentDir&&) noexcept = default;
  MemSegmentDir& operator=(MemSegmentDir&&) noexcept = default;

  [[nodiscard]] std::size_t count() const noexcept { return files_.size(); }
  [[nodiscard]] Device& device(std::size_t i) noexcept { return *files_[i].dev; }
  [[nodiscard]] const Device& device(std::size_t i) const noexcept { return *files_[i].dev; }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return files_[i].name; }

  std::optional<std::size_t> create(std::string_view name, std::uint64_t size) {
    if (find(name)) return std::nullopt;
    files_.push_back(File{std::string(name), std::make_unique<Device>(size)});
    return files_.size() - 1;
  }
  bool rename(std::size_t i, std::string_view name) {
    if (i >= files_.size() || find(name)) return false;
    files_[i].name = std::string(name);
    return true;
  }
  bool sync_dir() noexcept { return true; }

  [[nodiscard]] std::optional<std::size_t> find(std::string_view name) const noexcept {
    for (std::size_t i = 0; i < files_.size(); ++i) {
      if (files_[i].name == name) return i;
    }
    return std::nullopt;
  }

  // Crashes every device (MemJournalDevice::crash); names and sizes are durable.
  void crash(Prng& rng, const MemCrashOptions& opts = {}) {
    for (auto& f : files_) f.dev->crash(rng, opts);
  }

  // A directory whose devices hold copies of this one's durable (or current) images.
  [[nodiscard]] MemSegmentDir clone(bool durable = true) const {
    MemSegmentDir d;
    for (const auto& f : files_) {
      const auto img = durable ? f.dev->durable_image() : f.dev->image();
      auto dev = std::make_unique<Device>(img.size());
      auto t = dev->tamper();
      if (!img.empty()) std::copy(img.begin(), img.end(), t.begin());
      dev->sync_tamper();
      d.files_.push_back(File{f.name, std::move(dev)});
    }
    return d;
  }

 private:
  struct File {
    std::string name;
    std::unique_ptr<Device> dev;
  };
  std::vector<File> files_;
};

static_assert(SegmentDirLike<MemSegmentDir>);

}  // namespace lle::journal
