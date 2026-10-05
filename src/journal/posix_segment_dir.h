#pragma once
// PosixSegmentDir: a journal day directory on a POSIX file system. Every "*.seg" file
// in it is opened as a PosixJournalDevice (sorted by name, so handles are stable for a
// given listing). Cold path only.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "journal/journal_device.h"
#include "journal/segment_dir.h"

namespace lle::journal {

class PosixSegmentDir {
 public:
  using Device = PosixJournalDevice;

  PosixSegmentDir() = default;
  ~PosixSegmentDir();
  PosixSegmentDir(PosixSegmentDir&& o) noexcept;
  PosixSegmentDir& operator=(PosixSegmentDir&& o) noexcept;
  PosixSegmentDir(const PosixSegmentDir&) = delete;
  PosixSegmentDir& operator=(const PosixSegmentDir&) = delete;

  // Opens (optionally creating) `path` and every *.seg file in it. `dev_opts` applies
  // to every device (create/exclusive are ignored). Returns errno-style text on failure.
  static std::expected<PosixSegmentDir, std::string> open(const std::string& path, bool create_dir = false,
                                                          PosixDeviceOptions dev_opts = {});

  [[nodiscard]] std::size_t count() const noexcept { return files_.size(); }
  // Device references stay valid for the lifetime of the directory object (the writer
  // keeps them across create() calls).
  [[nodiscard]] Device& device(std::size_t i) noexcept { return files_[i]->dev; }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return files_[i]->name; }
  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] std::string file_path(std::size_t i) const { return path_ + "/" + files_[i]->name; }

  std::optional<std::size_t> create(std::string_view name, std::uint64_t size);
  bool rename(std::size_t i, std::string_view name);
  bool sync_dir() noexcept;

 private:
  struct File {
    std::string name;
    Device dev;
  };
  std::string path_;
  int dir_fd_ = -1;
  PosixDeviceOptions opts_{};
  std::vector<std::unique_ptr<File>> files_;
};

static_assert(SegmentDirLike<PosixSegmentDir>);

}  // namespace lle::journal
