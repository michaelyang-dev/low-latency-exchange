#pragma once
// Storage for snapshot files other than plain POSIX (06 §9; the simulator,
// 09 S-03, runs snapshot publication and loading on its crash-faithful disk).
//
// Writer's type is part of the engine's API (Engine::snapshot(snap::Writer&)),
// so it cannot become a template over the storage; snapshots are a cold path
// (snapshotd on housekeeping cores), so a virtual interface costs nothing that
// matters. Writer::create(Storage&, ...) publishes through it with the same
// sequence as on POSIX: write temp -> sync(temp) -> close -> rename -> sync(dir).
// find_latest(Storage&, ...) loads through it.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace lle::snap {

class Storage {
 public:
  virtual ~Storage() = default;

  // Creates or truncates `path` for writing: a handle >= 0, or -errno.
  virtual int create(const std::string& path) = 0;
  // Writes all of `data` at `off`: 0, or errno.
  virtual int write_at(int handle, std::uint64_t off, std::span<const std::byte> data) = 0;
  // fdatasync (data_only) or fsync: 0, or errno. Never retried after a failure.
  virtual int sync(int handle, bool data_only) = 0;
  virtual int close(int handle) = 0;
  virtual int rename(const std::string& from, const std::string& to) = 0;
  // Makes the directory's entries durable (fsync of the directory).
  virtual int sync_dir(const std::string& dir) = 0;
  virtual int remove(const std::string& path) = 0;

  // File names (not paths) in `dir`.
  virtual std::vector<std::string> list(const std::string& dir) = 0;
  // The whole file, or errno.
  virtual std::expected<std::vector<std::byte>, int> read_all(const std::string& path) = 0;
};

}  // namespace lle::snap
