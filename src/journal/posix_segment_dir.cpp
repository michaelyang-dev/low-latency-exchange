#include "journal/posix_segment_dir.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace lle::journal {

namespace {

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

std::string errtext(const char* what, const std::string& path, int e) {
  return std::string(what) + " " + path + ": " + std::strerror(e);
}

}  // namespace

PosixSegmentDir::~PosixSegmentDir() {
  if (dir_fd_ >= 0) ::close(dir_fd_);
}

PosixSegmentDir::PosixSegmentDir(PosixSegmentDir&& o) noexcept
    : path_(std::move(o.path_)), dir_fd_(o.dir_fd_), opts_(o.opts_), files_(std::move(o.files_)) {
  o.dir_fd_ = -1;
}

PosixSegmentDir& PosixSegmentDir::operator=(PosixSegmentDir&& o) noexcept {
  if (this != &o) {
    if (dir_fd_ >= 0) ::close(dir_fd_);
    path_ = std::move(o.path_);
    dir_fd_ = o.dir_fd_;
    opts_ = o.opts_;
    files_ = std::move(o.files_);
    o.dir_fd_ = -1;
  }
  return *this;
}

std::expected<PosixSegmentDir, std::string> PosixSegmentDir::open(const std::string& path, bool create_dir,
                                                                  PosixDeviceOptions dev_opts) {
  if (create_dir && ::mkdir(path.c_str(), 0755) != 0 && errno != EEXIST) {
    return std::unexpected(errtext("mkdir", path, errno));
  }
  PosixSegmentDir d;
  d.path_ = path;
  dev_opts.create = false;
  dev_opts.exclusive = false;
  d.opts_ = dev_opts;
  d.dir_fd_ = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (d.dir_fd_ < 0) return std::unexpected(errtext("open", path, errno));

  DIR* dir = ::opendir(path.c_str());
  if (dir == nullptr) return std::unexpected(errtext("opendir", path, errno));
  std::vector<std::string> names;
  while (const dirent* e = ::readdir(dir)) {
    const std::string_view n(e->d_name);
    if (ends_with(n, ".seg")) names.emplace_back(n);
  }
  ::closedir(dir);
  std::sort(names.begin(), names.end());
  for (auto& n : names) {
    auto dev = Device::open(path + "/" + n, dev_opts);
    if (!dev) return std::unexpected(errtext("open", path + "/" + n, dev.error()));
    d.files_.push_back(std::make_unique<File>(File{std::move(n), std::move(*dev)}));
  }
  return d;
}

std::optional<std::size_t> PosixSegmentDir::create(std::string_view name, std::uint64_t size) {
  PosixDeviceOptions o = opts_;
  o.create = true;
  o.exclusive = true;
  o.read_only = false;
  auto dev = Device::open(path_ + "/" + std::string(name), o);
  if (!dev) return std::nullopt;
  if (size != 0 && !dev->resize(size)) return std::nullopt;
  files_.push_back(std::make_unique<File>(File{std::string(name), std::move(*dev)}));
  return files_.size() - 1;
}

bool PosixSegmentDir::rename(std::size_t i, std::string_view name) {
  if (i >= files_.size()) return false;
  const std::string to(name);
  struct stat st {};
  if (::fstatat(dir_fd_, to.c_str(), &st, 0) == 0) return false;  // never clobber a segment
  if (::renameat(dir_fd_, files_[i]->name.c_str(), dir_fd_, to.c_str()) != 0) return false;
  files_[i]->name = to;
  return true;
}

bool PosixSegmentDir::sync_dir() noexcept { return dir_fd_ >= 0 && ::fsync(dir_fd_) == 0; }

}  // namespace lle::journal
