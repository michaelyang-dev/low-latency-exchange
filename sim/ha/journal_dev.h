#pragma once
// The HA world's L3 journal media: the journal's own MemJournalDevice (crash
// semantics: every write not yet durable is dropped, persisted whole or torn per
// 512-byte sector at a host crash) behind a virtual-time latency gate driven by the
// world's disk fault parameters (latency, stall spikes, EIO).
//
// Why not sim::DiskFile: SegmentPreparer, recovery's torn-tail repair and the
// rejoin truncation use the journal's synchronous helpers (write_sync, sync_device),
// which spin on poll() until a completion arrives; inside the event loop virtual
// time cannot advance, so an asynchronous sim::Disk completion never would. Here
// those cold-path operations (tag kSyncHelperTag) complete at once, and every
// hot-path write (the JournalWriter's dsync batches) completes, and becomes durable,
// only when its seeded latency has elapsed in virtual time.
//
// The MemSegmentDir lives with the node (it survives process crashes); the gate and
// the HaDevice handles live in the process image.
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "env/concepts.h"
#include "journal/journal_device.h"
#include "journal/mem_journal_device.h"
#include "journal/segment_dir.h"
#include "sim/dist.h"
#include "sim/world.h"

namespace lle::sim::ha {

struct DiskGate {
  const World* world = nullptr;  // virtual time
  Prng rng{1};
  Nanos write_min_ns = 10'000;
  Nanos write_mean_ns = 20'000;
  std::uint32_t stall_ppm = 0;
  Nanos stall_max_ns = 0;
  std::uint32_t eio_ppm = 0;
  bool faults = true;  // EIO and stalls only in the safety phase
  std::function<bool()> may_fail;  // EIO aborts the process: only inside the failure model
  std::uint64_t stalls = 0;
  std::uint64_t eios = 0;

  [[nodiscard]] Nanos now() const { return world->now(); }
  Nanos latency() {
    Nanos l = write_min_ns + exp_ns(rng, write_mean_ns);
    const bool stall = chance_ppm(rng, stall_ppm);
    const Nanos s = log_uniform(rng, kMs, std::max<Nanos>(kMs, stall_max_ns));
    if (stall && faults && world->faults_active()) {
      l += s;
      ++stalls;
    }
    return l;
  }
  // Drawn at submission (one draw per write, whatever the outcome); whether the error
  // is reported is decided at completion, when the failure model is evaluated: the
  // process aborts on it, which is a node failure (01 §9).
  bool eio_candidate() { return chance_ppm(rng, eio_ppm); }
  bool eio_fires() {
    const bool fire = faults && world->faults_active() && (!may_fail || may_fail());
    if (fire) ++eios;
    return fire;
  }
};

class HaDevice {
 public:
  HaDevice(journal::MemJournalDevice& dev, DiskGate& gate) : d_(&dev), g_(&gate) { d_->set_hold(true); }
  HaDevice(const HaDevice&) = delete;
  HaDevice& operator=(const HaDevice&) = delete;

  bool submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept {
    const bool helper = tag == journal::kSyncHelperTag;
    const bool eio = !helper && g_->eio_candidate();
    if (!d_->submit_write(off, b, dsync, tag)) return false;
    pend_.push_back(Op{helper ? g_->now() : g_->now() + g_->latency(), seq_++, eio});
    return true;
  }
  bool submit_sync(std::uint64_t tag) noexcept {
    const bool helper = tag == journal::kSyncHelperTag;
    if (!d_->submit_sync(tag)) return false;
    pend_.push_back(Op{helper ? g_->now() : g_->now() + g_->latency(), seq_++, false});
    return true;
  }

  // Delivers every operation whose latency has elapsed, earliest first; each becomes
  // durable (per MemJournalDevice) at that moment.
  template <class F>
  std::size_t poll(F&& f) {
    const Nanos now = g_->now();
    std::size_t n = 0;
    for (;;) {
      std::size_t best = pend_.size();
      for (std::size_t i = 0; i < pend_.size(); ++i) {
        if (pend_[i].ready > now) continue;
        if (best == pend_.size() || pend_[i].ready < pend_[best].ready ||
            (pend_[i].ready == pend_[best].ready && pend_[i].seq < pend_[best].seq)) {
          best = i;
        }
      }
      if (best == pend_.size()) break;
      d_->deliver_only(best);  // pend_ mirrors the device's pending list, oldest first
      const bool eio = pend_[best].eio && g_->eio_fires();
      std::size_t got = 0;
      d_->poll([&](const env::DiskCompletion& c) {
        ++got;
        // An EIO: the write may or may not have reached the media; the writer must treat
        // it as fatal either way (06 §6, never retry).
        f(eio ? env::DiskCompletion{c.tag, -EIO} : c);
      });
      LLE_ASSERT(got == 1, "gated device lost track of its operations");
      pend_.erase(pend_.begin() + static_cast<std::ptrdiff_t>(best));
      ++n;
    }
    return n;
  }

  std::int64_t read(std::uint64_t off, std::span<std::byte> out) noexcept { return d_->read(off, out); }
  [[nodiscard]] std::uint64_t size() const noexcept { return d_->size(); }
  bool resize(std::uint64_t n) { return d_->resize(n); }
  [[nodiscard]] std::size_t in_flight() const noexcept { return d_->in_flight(); }

  // Makes every operation in flight ready now (a quiesced cold path waits for them).
  void expedite() {
    for (Op& o : pend_) o.ready = std::min(o.ready, g_->now());
  }

  // Completes everything in flight now (the dying process's writes settle before it is
  // gone; a quiesced cold path). Completions are discarded.
  void settle() {
    d_->set_hold(false);
    d_->poll([](const env::DiskCompletion&) {});
    d_->set_hold(true);
    pend_.clear();
  }
  // Completes everything in flight now, delivering the completions to `f`.
  template <class F>
  void settle(F&& f) {
    while (!pend_.empty()) {
      d_->deliver_only(0);
      d_->poll([&](const env::DiskCompletion& c) { f(c); });
      pend_.erase(pend_.begin());
    }
  }

 private:
  struct Op {
    Nanos ready = 0;
    std::uint64_t seq = 0;
    bool eio = false;
  };
  journal::MemJournalDevice* d_;
  DiskGate* g_;
  std::vector<Op> pend_;
  std::uint64_t seq_ = 0;
};
static_assert(journal::JournalDeviceLike<HaDevice>);

// SegmentDirLike over the node's MemSegmentDir, handing out gated devices.
class HaDir {
 public:
  using Device = HaDevice;

  HaDir(journal::MemSegmentDir& dir, DiskGate& gate) : dir_(&dir), gate_(&gate) { sync_handles(); }

  [[nodiscard]] std::size_t count() const noexcept { return dir_->count(); }
  [[nodiscard]] Device& device(std::size_t i) {
    sync_handles();
    return *devs_[i];
  }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return dir_->name(i); }
  std::optional<std::size_t> create(std::string_view name, std::uint64_t size) {
    auto h = dir_->create(name, size);
    sync_handles();
    return h;
  }
  bool rename(std::size_t i, std::string_view name) { return dir_->rename(i, name); }
  bool sync_dir() noexcept { return true; }

  void expedite_all() {
    for (auto& d : devs_) d->expedite();
  }
  void settle_all() {
    for (auto& d : devs_) d->settle();
  }
  template <class F>
  void settle_all(F&& f) {
    for (auto& d : devs_) d->settle(f);
  }

 private:
  void sync_handles() {
    while (devs_.size() < dir_->count()) devs_.push_back(std::make_unique<HaDevice>(dir_->device(devs_.size()), *gate_));
  }
  journal::MemSegmentDir* dir_;
  DiskGate* gate_;
  std::vector<std::unique_ptr<HaDevice>> devs_;
};
static_assert(journal::SegmentDirLike<HaDir>);

}  // namespace lle::sim::ha
