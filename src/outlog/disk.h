#pragma once
// The storage the output log runs on (06 §8; 09 S-03), so the same writer,
// reader and repair code runs on POSIX files in production (outlog/posix_fs.h)
// and on the simulator's crash-faithful disk (sim/worlds/outlog_fs.h).
//
// A file is an env::DiskFileReadLike (submit_write / submit_sync / poll, read,
// size) that can also be resized and reports read and size errors. The output
// log's I/O is synchronous and off the Output Rule (derived data, written by
// the io stage without fsync gating), so it goes through the helpers below:
// they submit one operation tagged kOutlogSyncTag and poll until it completes.
// A POSIX file completes it inside submit; the simulator applies it at once to
// its page cache, where a crash can still lose or tear it.
//
// A filesystem opens files by path and does the directory operations: rename
// (the index is replaced through a temporary file), remove, make_dirs, and the
// advisory single-writer lock.
#include <cerrno>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include "env/concepts.h"

namespace lle::outlog {

template <class F>
concept OutlogFileLike =
    env::DiskFileReadLike<F> && std::default_initializable<F> && std::movable<F> &&
    requires(F& f, const F& cf, std::uint64_t n, std::uint64_t off, std::span<std::byte> out) {
      { cf.valid() } -> std::same_as<bool>;
      { f.resize(n) } -> std::same_as<bool>;
      // Bytes read (fewer than out.size() only at end of file), or -errno.
      { cf.read_checked(off, out) } -> std::same_as<std::ptrdiff_t>;
      { cf.size_checked() } -> std::same_as<std::expected<std::uint64_t, int>>;
    };

enum class OpenMode : std::uint8_t {
  ReadOnly,
  ReadWrite,        // existing file
  ReadWriteCreate,  // created if missing
  CreateTruncate,   // write-only scratch file, emptied
};

template <class S>
concept OutlogFsLike = requires(S& s, const std::string& p, typename S::File& f) {
  requires OutlogFileLike<typename S::File>;
  { s.open(p, OpenMode::ReadOnly) } -> std::same_as<std::expected<typename S::File, int>>;
  { s.rename(p, p) } -> std::same_as<int>;  // 0 or errno
  { s.remove(p) } -> std::same_as<int>;
  { s.make_dirs(p) } -> std::same_as<int>;
  { s.lock_writer(f) } -> std::same_as<bool>;  // exclusive, non-blocking
};

inline constexpr std::uint64_t kOutlogSyncTag = 0x4F55'544C'4F47'5359ull;  // "OUTLOGSY"

namespace detail {

// Polls until the completion tagged kOutlogSyncTag arrives. A file that never
// completes it (a broken binding) fails with ETIMEDOUT instead of hanging.
template <OutlogFileLike F>
int await_sync_op(F& f) noexcept {
  int result = 0;
  bool done = false;
  for (std::uint32_t spins = 0; !done && spins < (1u << 20); ++spins) {
    f.poll([&](const env::DiskCompletion& c) {
      if (c.tag == kOutlogSyncTag && !done) {
        done = true;
        result = c.result;
      }
    });
  }
  return done ? result : -ETIMEDOUT;
}

}  // namespace detail

// Writes all of `b` at `off`: 0, or the errno of the failure.
template <OutlogFileLike F>
int write_sync(F& f, std::uint64_t off, std::span<const std::byte> b) noexcept {
  if (b.empty()) return 0;
  if (!f.submit_write(off, b, false, kOutlogSyncTag)) return EAGAIN;
  const int r = detail::await_sync_op(f);
  if (r < 0) return -r;
  return static_cast<std::size_t>(r) == b.size() ? 0 : EIO;  // short write: no error code
}

// Makes everything written so far durable (fdatasync): 0, or the errno.
template <OutlogFileLike F>
int sync_file(F& f) noexcept {
  if (!f.submit_sync(kOutlogSyncTag)) return EAGAIN;
  const int r = detail::await_sync_op(f);
  return r < 0 ? -r : 0;
}

}  // namespace lle::outlog
