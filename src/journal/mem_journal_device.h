#pragma once
// MemJournalDevice: an in-memory JournalDeviceLike for unit and property tests of the
// L3 writer and recovery (06 §6, §12). It models what the simulator's SimJournalDevice
// models at the journal level (09 §4):
//
//   - two images: `image()` is what reads see (every submitted write, like the page
//     cache); `durable_image()` is what survives a crash;
//   - a write with dsync becomes durable when its completion is delivered; a write
//     without dsync becomes durable when a later sync completes;
//   - completions are delivered in FIFO order, or, with a completion PRNG, as a random
//     non-empty subset in random order on each poll() (out-of-order completion);
//   - crash(rng): every write that is not yet durable is independently dropped,
//     persisted whole, or torn (each 512-byte sector persisted or not, independently:
//     out-of-order persistence of in-flight writes), optionally with garbage sectors;
//     then the volatile state is discarded;
//   - fault injection: a chosen future write completes with -EIO or short.
//
// Writes that are in flight (or completed but not yet synced) must not overlap: the
// journal writer never issues overlapping writes, and the model relies on it to keep
// crash semantics exact (asserted).
//
// Allocation: the in-flight table is fixed-size; only non-dsync writes (preparation)
// grow a vector. The writer's dsync-only path never allocates.
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "common/prng.h"
#include "env/concepts.h"
#include "journal/journal_device.h"

namespace lle::journal {

struct MemCrashOptions {
  std::uint32_t sector_bytes = 512;
  // Fate of each non-durable write, as weights.
  std::uint32_t w_drop = 1;
  std::uint32_t w_full = 1;
  std::uint32_t w_torn = 1;
  // Probability (1/garbage_den) that a torn sector receives random bytes instead of
  // old-or-new content; 0 disables garbage.
  std::uint32_t garbage_den = 0;
};

class MemJournalDevice {
 public:
  static constexpr std::size_t kMaxInFlight = 64;

  explicit MemJournalDevice(std::uint64_t size = 0);

  // ---- env::DiskFileLike --------------------------------------------------------
  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept;
  bool submit_sync(std::uint64_t tag) noexcept;

  template <class F>
  std::size_t poll(F&& f) {
    if (n_pending_ == 0) return 0;
    if (only_armed_) {
      only_armed_ = false;
      if (only_ >= n_pending_) return 0;
      const env::DiskCompletion c = complete(only_);
      f(c);
      return 1;
    }
    if (hold_) return 0;
    std::size_t todo = n_pending_;
    if (rng_ != nullptr) todo = 1 + static_cast<std::size_t>(rng_->below(n_pending_));
    std::size_t n = 0;
    while (n < todo && n_pending_ > 0) {
      const std::size_t i = rng_ != nullptr ? static_cast<std::size_t>(rng_->below(n_pending_)) : 0;
      const env::DiskCompletion c = complete(i);
      ++n;
      f(c);
    }
    return n;
  }

  // ---- synchronous extras ---------------------------------------------------------
  std::int64_t read(std::uint64_t off, std::span<std::byte> out) noexcept;
  [[nodiscard]] std::uint64_t size() const noexcept { return cur_.size(); }
  bool resize(std::uint64_t n);
  [[nodiscard]] std::size_t in_flight() const noexcept { return n_pending_; }

  // ---- test controls ----------------------------------------------------------------
  // nullptr: FIFO, every pending operation completes on each poll().
  void set_completion_rng(Prng* rng) noexcept { rng_ = rng; }
  // While held, poll() delivers nothing (operations stay in flight).
  void set_hold(bool h) noexcept { hold_ = h; }
  // The next poll() delivers exactly the i-th oldest pending operation (even while
  // held), then the normal policy resumes.
  void deliver_only(std::size_t i) noexcept {
    only_armed_ = true;
    only_ = i;
  }
  // The `nth` write submitted from now on (0 = the next one) completes with `result`
  // (-EIO, or a short byte count) and does not become durable.
  void inject_write_result(std::uint64_t nth, std::int32_t result) noexcept;

  // Crash: decide the fate of every non-durable write (see the header comment), then
  // drop all volatile state and the hold/deliver/inject controls (the completion PRNG
  // stays). image() equals durable_image() afterwards.
  void crash(Prng& rng, const MemCrashOptions& opts = {});

  [[nodiscard]] std::span<const std::byte> image() const noexcept { return {cur_.data(), cur_.size()}; }
  [[nodiscard]] std::span<const std::byte> durable_image() const noexcept { return {dur_.data(), dur_.size()}; }
  // Direct mutation of both images (test tampering: corruption, stale data).
  [[nodiscard]] std::span<std::byte> tamper() noexcept;
  void sync_tamper() { dur_.copy_from(cur_); }

  [[nodiscard]] std::uint64_t writes_submitted() const noexcept { return writes_; }
  [[nodiscard]] std::uint64_t syncs_submitted() const noexcept { return syncs_; }

 private:
  enum class Kind : std::uint8_t { Write, Sync };
  struct Op {
    Kind kind = Kind::Write;
    bool dsync = false;
    std::uint64_t off = 0;
    std::uint64_t len = 0;
    std::uint64_t tag = 0;
    std::int32_t forced_result = 0;
    bool forced = false;
  };
  struct Range {
    std::uint64_t off = 0;
    std::uint64_t len = 0;
  };
  // A resizable zero-initialized byte buffer (memcpy/memset only: cheap in unoptimized
  // builds, where std::vector<std::byte> constructs element by element).
  class Bytes {
   public:
    explicit Bytes(std::uint64_t n = 0) { resize(n); }
    Bytes(const Bytes& o) : Bytes(o.n_) { copy_from(o); }
    Bytes& operator=(const Bytes& o) {
      if (this != &o) {
        resize(o.n_);
        copy_from(o);
      }
      return *this;
    }
    void resize(std::uint64_t n);
    void copy_from(const Bytes& o) noexcept;
    [[nodiscard]] std::byte* data() noexcept { return p_.get(); }
    [[nodiscard]] const std::byte* data() const noexcept { return p_.get(); }
    [[nodiscard]] std::uint64_t size() const noexcept { return n_; }
    std::byte& operator[](std::uint64_t i) noexcept { return p_[i]; }

   private:
    std::unique_ptr<std::byte[]> p_;
    std::uint64_t n_ = 0;
  };

  env::DiskCompletion complete(std::size_t i) noexcept;
  void persist(std::uint64_t off, std::uint64_t len) noexcept;
  [[nodiscard]] bool overlaps_live(std::uint64_t off, std::uint64_t len) const noexcept;

  Bytes cur_;
  Bytes dur_;
  std::array<Op, kMaxInFlight> pending_{};
  std::size_t n_pending_ = 0;
  std::vector<Range> volatile_;  // completed non-dsync writes awaiting a sync
  Prng* rng_ = nullptr;
  bool hold_ = false;
  bool only_armed_ = false;
  std::size_t only_ = 0;
  bool inject_armed_ = false;
  std::uint64_t inject_at_ = 0;
  std::int32_t inject_result_ = 0;
  std::uint64_t writes_ = 0;
  std::uint64_t syncs_ = 0;
};

static_assert(JournalDeviceLike<MemJournalDevice>);

}  // namespace lle::journal
