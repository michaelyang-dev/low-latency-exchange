#include "journal/uring_segment_dir.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/resource.h>

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

// ---- UringOrPosixDevice ---------------------------------------------------------------

std::expected<UringOrPosixDevice, int> UringOrPosixDevice::open(const std::string& path, const UringDirOptions& opts,
                                                                std::string* why) {
  UringOrPosixDevice d;
#if LLE_JOURNAL_URING_DIR_HAS_URING
  if (opts.use_io_uring) {
    IoUringOptions o = opts.uring;
    auto u = IoUringJournalDevice::open(path, o);
    if (!u && o.direct && o.allow_fallback) {  // no O_DIRECT on this file system (tmpfs)
      o.direct = false;
      u = IoUringJournalDevice::open(path, o);
    }
    if (u) {
      d.v_.emplace<1>(std::move(*u));
      d.direct_ = o.direct;
      return d;
    }
    if (why != nullptr) *why = std::string("io_uring: ") + std::strerror(-u.error());
  } else if (why != nullptr) {
    *why = "io_uring disabled";
  }
#else
  (void)opts;
  if (why != nullptr) *why = "io_uring not built in (Linux with liburing only)";
#endif
  PosixDeviceOptions p = opts.posix;
  p.create = false;
  p.exclusive = false;
  auto dev = PosixJournalDevice::open(path, p);
  if (!dev) return std::unexpected(-dev.error());
  d.v_.emplace<0>(std::move(*dev));
  return d;
}

int UringOrPosixDevice::register_error() const noexcept {
#if LLE_JOURNAL_URING_DIR_HAS_URING
  if (const auto* u = std::get_if<1>(&v_)) return u->register_error();
#endif
  return 0;
}

bool UringOrPosixDevice::register_buffers(std::span<const std::span<std::byte>> bufs) noexcept {
#if LLE_JOURNAL_URING_DIR_HAS_URING
  if (auto* u = std::get_if<1>(&v_)) return u->register_buffers(bufs);
#else
  (void)bufs;
#endif
  return false;
}

std::string UringOrPosixDevice::describe() const {
#if LLE_JOURNAL_URING_DIR_HAS_URING
  if (const auto* u = std::get_if<1>(&v_)) {
    std::string s = "io_uring (";
    s += u->iopoll_active() ? "iopoll" : "interrupts";
    s += direct_ ? ", O_DIRECT" : ", buffered";
    if (u->fixed_buffers()) s += ", fixed buffers";
    return s + ")";
  }
#endif
  return "posix";
}

// ---- UringSegmentDir -------------------------------------------------------------------

UringSegmentDir::~UringSegmentDir() {
  if (dir_fd_ >= 0) ::close(dir_fd_);
}

UringSegmentDir::UringSegmentDir(UringSegmentDir&& o) noexcept
    : path_(std::move(o.path_)),
      dir_fd_(o.dir_fd_),
      opts_(o.opts_),
      files_(std::move(o.files_)),
      fixed_(std::move(o.fixed_)),
      why_(std::move(o.why_)) {
  o.dir_fd_ = -1;
}

UringSegmentDir& UringSegmentDir::operator=(UringSegmentDir&& o) noexcept {
  if (this != &o) {
    if (dir_fd_ >= 0) ::close(dir_fd_);
    path_ = std::move(o.path_);
    dir_fd_ = o.dir_fd_;
    opts_ = o.opts_;
    files_ = std::move(o.files_);
    fixed_ = std::move(o.fixed_);
    why_ = std::move(o.why_);
    o.dir_fd_ = -1;
  }
  return *this;
}

std::expected<UringOrPosixDevice, int> UringSegmentDir::open_device(const std::string& file) {
  std::string why;
  auto dev = Device::open(file, opts_, &why);
  if (!dev) return dev;
  if (!dev->is_io_uring()) why_ = why;
  if (!fixed_.empty()) register_on(*dev);
  return dev;
}

std::expected<UringSegmentDir, std::string> UringSegmentDir::open(const std::string& path, bool create_dir,
                                                                  UringDirOptions opts) {
  if (create_dir && ::mkdir(path.c_str(), 0755) != 0 && errno != EEXIST) {
    return std::unexpected(errtext("mkdir", path, errno));
  }
  UringSegmentDir d;
  d.path_ = path;
  d.opts_ = opts;
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
    auto dev = d.open_device(path + "/" + n);
    if (!dev) return std::unexpected(errtext("open", path + "/" + n, -dev.error()));
    d.files_.push_back(std::make_unique<File>(File{std::move(n), std::move(*dev)}));
  }
  return d;
}

std::optional<std::size_t> UringSegmentDir::create(std::string_view name, std::uint64_t size) {
  const std::string file = path_ + "/" + std::string(name);
  // Created (exclusive) and sized with a plain fd, then opened as a device.
  const int fd = ::open(file.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0) return std::nullopt;
  const bool sized = size == 0 || ::ftruncate(fd, static_cast<off_t>(size)) == 0;
  ::close(fd);
  if (!sized) return std::nullopt;
  auto dev = open_device(file);
  if (!dev) return std::nullopt;
  files_.push_back(std::make_unique<File>(File{std::string(name), std::move(*dev)}));
  return files_.size() - 1;
}

bool UringSegmentDir::rename(std::size_t i, std::string_view name) {
  if (i >= files_.size()) return false;
  const std::string to(name);
  struct stat st {};
  if (::fstatat(dir_fd_, to.c_str(), &st, 0) == 0) return false;  // never clobber a segment
  if (::renameat(dir_fd_, files_[i]->name.c_str(), dir_fd_, to.c_str()) != 0) return false;
  files_[i]->name = to;
  return true;
}

bool UringSegmentDir::sync_dir() noexcept { return dir_fd_ >= 0 && ::fsync(dir_fd_) == 0; }

void UringSegmentDir::set_fixed_buffers(std::span<const std::span<std::byte>> bufs) {
  fixed_.assign(bufs.begin(), bufs.end());
  for (auto& f : files_) register_on(f->dev);
}

// A refused registration is not fatal (plain writes), but it is reported: the writer
// then runs without WRITE_FIXED, and the usual cause is the locked-memory limit.
void UringSegmentDir::register_on(Device& dev) {
  if (!dev.is_io_uring() || dev.register_buffers(fixed_)) return;
  ++fixed_failures_;
  const int e = -dev.register_error();
  rlimit rl{};
  ::getrlimit(RLIMIT_MEMLOCK, &rl);
  fixed_note_ = std::string("io_uring buffer registration refused: ") + std::strerror(e);
  if (e == ENOMEM || e == EAGAIN) {
    fixed_note_ += rl.rlim_cur == RLIM_INFINITY
                       ? std::string(" (RLIMIT_MEMLOCK unlimited)")
                       : " (RLIMIT_MEMLOCK " + std::to_string(rl.rlim_cur / 1024) +
                             " KiB, shared by every process of this user)";
  }
  fixed_note_ += "; plain writes instead of WRITE_FIXED";
}

std::size_t UringSegmentDir::uring_devices() const noexcept {
  std::size_t n = 0;
  for (const auto& f : files_)
    if (f->dev.is_io_uring()) ++n;
  return n;
}

}  // namespace lle::journal
