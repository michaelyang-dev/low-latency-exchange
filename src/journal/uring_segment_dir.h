#pragma once
// UringSegmentDir: a journal day directory whose segments are written through io_uring
// (IoUringJournalDevice, the production L3 path of 06 §6) wherever the platform allows
// it, and through PosixJournalDevice otherwise. A node uses one directory type on every
// host; the choice is made per segment when its device opens:
//   1. io_uring on an O_DIRECT fd, interrupt-driven by default; IOPOLL only when asked
//      (UringDirOptions::uring.iopoll), for hosts whose NVMe devices have polled queues
//      (nvme.poll_queues): on a virtio disk the device's 4 KiB IOPOLL probe passed but the
//      preparer's 1 MiB writes then failed, so IOPOLL is not inferred from the probe;
//   2. io_uring on a buffered fd (file systems without O_DIRECT, e.g. tmpfs), writes
//      still RWF_DSYNC;
//   3. PosixJournalDevice (pwrite + fdatasync): no liburing in the build, not Linux, or
//      a ring that cannot be created (old kernel, seccomp, locked-memory limit).
// The device is a two-alternative variant; every call dispatches on its index (a
// switch on the write path, no virtual call). Rings are created without SINGLE_ISSUER
// by default because segments are opened and prepared on one thread (start-up, the
// preparer) and written on another (the io stage).
//
// set_fixed_buffers() registers the writer's batch buffers with every io_uring device,
// present and future (IORING_REGISTER_BUFFERS: WRITE_FIXED).
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "journal/journal_device.h"
#include "journal/segment_dir.h"

#if defined(__linux__) && defined(LLE_HAVE_IO_URING)
#include "journal/io_uring_journal_device.h"
#define LLE_JOURNAL_URING_DIR_HAS_URING 1
#else
#define LLE_JOURNAL_URING_DIR_HAS_URING 0
#endif

namespace lle::journal {

#if !LLE_JOURNAL_URING_DIR_HAS_URING
struct IoUringOptions {  // placeholder where io_uring is not built in
  unsigned entries = 32;
  bool iopoll = true;
  bool defer_taskrun = false;
  bool direct = true;
  int iowq_cpu = -1;
  bool allow_fallback = true;
};
#endif

struct UringDirOptions {
  bool use_io_uring = true;  // false: POSIX devices only
  IoUringOptions uring = [] {
    IoUringOptions o;
    o.defer_taskrun = false;  // opened and written on different threads (see above)
    o.iopoll = false;         // opt-in (see above)
    return o;
  }();
  PosixDeviceOptions posix{};
};

class UringOrPosixDevice {
 private:
#if LLE_JOURNAL_URING_DIR_HAS_URING
  using Variant = std::variant<PosixJournalDevice, IoUringJournalDevice>;
#else
  struct NoUring {};
  using Variant = std::variant<PosixJournalDevice, NoUring>;
#endif
  static_assert(std::is_nothrow_move_constructible_v<Variant> && std::is_nothrow_move_assignable_v<Variant>,
                "never valueless: visit() relies on it");

  // The alternatives are moved without throwing, so the variant is never valueless and
  // get_if never returns null here; saying so keeps GCC's -Wnull-dereference quiet at -O2.
  template <std::size_t I, class V>
  static auto* alt(V& v) noexcept {
    auto* p = std::get_if<I>(&v);
    if (p == nullptr) __builtin_unreachable();
    return p;
  }
  template <class F>
  decltype(auto) visit(F&& f) {
#if LLE_JOURNAL_URING_DIR_HAS_URING
    if (v_.index() == 1) return f(*alt<1>(v_));
#endif
    return f(*alt<0>(v_));
  }
  template <class F>
  decltype(auto) cvisit(F&& f) const {
#if LLE_JOURNAL_URING_DIR_HAS_URING
    if (v_.index() == 1) return f(*alt<1>(v_));
#endif
    return f(*alt<0>(v_));
  }

 public:
  UringOrPosixDevice() noexcept = default;
  UringOrPosixDevice(UringOrPosixDevice&&) noexcept = default;
  UringOrPosixDevice& operator=(UringOrPosixDevice&&) noexcept = default;
  UringOrPosixDevice(const UringOrPosixDevice&) = delete;
  UringOrPosixDevice& operator=(const UringOrPosixDevice&) = delete;

  // Opens an existing segment file: io_uring if allowed and possible, else POSIX.
  // `why` (optional) receives the reason io_uring was not used. Returns -errno.
  static std::expected<UringOrPosixDevice, int> open(const std::string& path, const UringDirOptions& opts,
                                                     std::string* why = nullptr);

  // ---- env::DiskFileLike -------------------------------------------------------------
  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept {
    return visit([&](auto& d) { return d.submit_write(off, b, dsync, tag); });
  }
  bool submit_sync(std::uint64_t tag) noexcept {
    return visit([&](auto& d) { return d.submit_sync(tag); });
  }
  template <class F>
  std::size_t poll(F&& f) {
    return visit([&](auto& d) { return d.poll(f); });
  }

  // ---- JournalDeviceLike extras -------------------------------------------------------
  std::int64_t read(std::uint64_t off, std::span<std::byte> out) noexcept {
    return visit([&](auto& d) { return d.read(off, out); });
  }
  [[nodiscard]] std::uint64_t size() const noexcept {
    return cvisit([](const auto& d) { return d.size(); });
  }
  bool resize(std::uint64_t n) noexcept {
    return visit([&](auto& d) { return d.resize(n); });
  }
  [[nodiscard]] std::size_t in_flight() const noexcept {
    return cvisit([](const auto& d) { return d.in_flight(); });
  }

  // io_uring only (false for a POSIX device); register_error(): -errno of a refusal.
  bool register_buffers(std::span<const std::span<std::byte>> bufs) noexcept;
  [[nodiscard]] int register_error() const noexcept;
  [[nodiscard]] bool is_io_uring() const noexcept { return v_.index() == 1; }
  // "io_uring (iopoll, direct, fixed buffers)" or "posix".
  [[nodiscard]] std::string describe() const;

 private:
  Variant v_;
  [[maybe_unused]] bool direct_ = false;  // io_uring on an O_DIRECT fd
};

static_assert(JournalDeviceLike<UringOrPosixDevice>);

class UringSegmentDir {
 public:
  using Device = UringOrPosixDevice;

  UringSegmentDir() = default;
  ~UringSegmentDir();
  UringSegmentDir(UringSegmentDir&& o) noexcept;
  UringSegmentDir& operator=(UringSegmentDir&& o) noexcept;
  UringSegmentDir(const UringSegmentDir&) = delete;
  UringSegmentDir& operator=(const UringSegmentDir&) = delete;

  // Opens (optionally creating) `path` and every *.seg file in it.
  static std::expected<UringSegmentDir, std::string> open(const std::string& path, bool create_dir = false,
                                                          UringDirOptions opts = {});

  [[nodiscard]] std::size_t count() const noexcept { return files_.size(); }
  [[nodiscard]] Device& device(std::size_t i) noexcept { return files_[i]->dev; }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return files_[i]->name; }
  [[nodiscard]] const std::string& path() const noexcept { return path_; }

  std::optional<std::size_t> create(std::string_view name, std::uint64_t size);
  bool rename(std::size_t i, std::string_view name);
  bool sync_dir() noexcept;

  // Registers `bufs` (the writer's batch buffers; they must outlive the directory) with
  // every io_uring device now and with every segment opened or created later.
  void set_fixed_buffers(std::span<const std::span<std::byte>> bufs);

  // io_uring devices whose buffer registration was refused (they use plain writes),
  // and why (e.g. RLIMIT_MEMLOCK, shared by every process of the user). Empty if none.
  [[nodiscard]] std::size_t fixed_buffer_failures() const noexcept { return fixed_failures_; }
  [[nodiscard]] const std::string& fixed_buffer_note() const noexcept { return fixed_note_; }

  // Devices opened on io_uring / on POSIX, and why the last POSIX one was not io_uring.
  [[nodiscard]] std::size_t uring_devices() const noexcept;
  [[nodiscard]] std::size_t posix_devices() const noexcept { return files_.size() - uring_devices(); }
  [[nodiscard]] const std::string& fallback_reason() const noexcept { return why_; }

 private:
  struct File {
    std::string name;
    Device dev;
  };
  std::expected<Device, int> open_device(const std::string& file);

  std::string path_;
  int dir_fd_ = -1;
  UringDirOptions opts_{};
  std::vector<std::unique_ptr<File>> files_;
  std::vector<std::span<std::byte>> fixed_;
  std::string why_;
  std::size_t fixed_failures_ = 0;
  std::string fixed_note_;
  void register_on(Device& dev);
};

static_assert(SegmentDirLike<UringSegmentDir>);

}  // namespace lle::journal
