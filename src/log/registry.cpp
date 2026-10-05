// Thread registration and the cold paths of the nlog hot path.
#include "log/registry.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace lle::nlog {
namespace detail {

constinit thread_local conc::SpscByteRing* tl_ring = nullptr;
constinit Registry g_registry;

namespace {

constinit thread_local ThreadBuffer* tl_thread = nullptr;

// Unregisters at thread exit. Only touched by register_thread (cold), so the hot
// path never pays for its TLS destructor registration.
struct ExitGuard {
  bool armed = false;
  ExitGuard() = default;
  ExitGuard(const ExitGuard&) = delete;
  ExitGuard& operator=(const ExitGuard&) = delete;
  ~ExitGuard() {
    if (armed) unregister_thread();
  }
};
thread_local ExitGuard tl_exit_guard;

// Guarantees the section exists (so its start/stop symbols resolve) in every
// image that links the logger, even one without enabled call sites.
constexpr LogSite kAnchorSite{"nlog: section anchor", __FILE__, __LINE__, Level::kDebug, 0, {}};

void free_buffer(ThreadBuffer* b) noexcept {
  std::free(b->storage);
  delete b;
}

}  // namespace

extern const LogSite* const lle_nlog_anchor_slot;
LLE_NLOG_SECTION_ATTR const LogSite* const lle_nlog_anchor_slot = &kAnchorSite;

namespace {

// Slot -> lowest slot with the same site (site.h, canonical_site). Built once.
std::vector<std::uint32_t> build_canonical_table() {
  struct Key {
    std::string_view fmt, file;
    std::uint32_t line;
    Level level;
    std::uint8_t nargs;
    ArgKinds kinds;
    bool operator==(const Key& o) const noexcept {
      return std::tie(fmt, file, line, level, nargs, kinds) == std::tie(o.fmt, o.file, o.line, o.level, o.nargs, o.kinds);
    }
  };
  struct Hash {
    std::size_t operator()(const Key& k) const noexcept {
      return std::hash<std::string_view>{}(k.fmt) ^ (std::hash<std::string_view>{}(k.file) * 31u) ^
             (std::size_t{k.line} << 7);
    }
  };
  const std::uint32_t n = site_count();
  std::vector<std::uint32_t> table(n);
  std::unordered_map<Key, std::uint32_t, Hash> first;
  first.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    table[i] = i;
    const LogSite* s = slot_site(i);
    if (s == nullptr) continue;
    const auto [it, inserted] =
        first.try_emplace(Key{s->fmt, s->file, s->line, s->level, s->nargs, s->kinds}, i);
    table[i] = it->second;
  }
  return table;
}

}  // namespace

std::byte* on_ring_full(std::uint32_t len) noexcept {
  ThreadBuffer* b = tl_thread;
  if (b->policy == FullPolicy::kBlock && len <= b->ring.max_payload()) {
    // Tests only: wait for the consumer (spin briefly, then yield). Without a
    // consumer, waiting would never end.
    for (std::uint32_t spins = 0; g_registry.consumer_active.load(std::memory_order_acquire); ++spins) {
      if (std::byte* p = b->ring.try_reserve(len)) return p;
      if (spins >= 4096) std::this_thread::yield();
    }
  }
  b->drops.store(b->drops.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
  return nullptr;
}

void on_unregistered() noexcept { g_registry.unregistered_drops.fetch_add(1, std::memory_order_relaxed); }

bool acquire_consumer() noexcept {
  bool expected = false;
  if (!g_registry.consumer_active.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return false;
  const std::uint32_t hw = g_registry.high_water.load(std::memory_order_acquire);
  for (std::uint32_t i = 0; i < hw; ++i) {
    if (ThreadBuffer* b = g_registry.slots[i].load(std::memory_order_acquire)) {
      b->announced = false;
      b->drops_reported = 0;
    }
  }
  return true;
}

void release_consumer() noexcept { g_registry.consumer_active.store(false, std::memory_order_release); }

void retire(std::uint32_t slot, ThreadBuffer* b) noexcept {
  g_registry.slots[slot].store(nullptr, std::memory_order_release);
  free_buffer(b);
}

#if defined(LLE_SIM)
namespace {
std::atomic<std::uint64_t> g_sim_tsc{0};
}
std::uint64_t sim_tsc() noexcept { return g_sim_tsc.load(std::memory_order_relaxed); }
#endif

}  // namespace detail

#if defined(LLE_SIM)
void set_sim_tsc(std::uint64_t tsc) noexcept { detail::g_sim_tsc.store(tsc, std::memory_order_relaxed); }
#endif

std::expected<std::uint32_t, RegisterError> register_thread(const ThreadOptions& opts) noexcept {
  using namespace detail;
  if (tl_thread != nullptr) return std::unexpected(RegisterError::kAlreadyRegistered);
  const std::size_t bytes = opts.ring_bytes;
  if (bytes < kMinRingBytes || bytes > kMaxRingBytes || (bytes & (bytes - 1)) != 0) {
    return std::unexpected(RegisterError::kBadRingSize);
  }
  auto* storage = static_cast<std::byte*>(std::aligned_alloc(4096, bytes));
  if (storage == nullptr) return std::unexpected(RegisterError::kOutOfMemory);
  std::memset(storage, 0, bytes);  // pre-fault every page before the hot path runs
  auto* b = new (std::nothrow) ThreadBuffer;
  if (b == nullptr) {
    std::free(storage);
    return std::unexpected(RegisterError::kOutOfMemory);
  }
  b->ring.init(storage, bytes);
  b->storage = storage;
  b->storage_bytes = bytes;
  b->policy = opts.policy;
  const std::size_t name_len = opts.name.size() < kThreadNameBytes - 1 ? opts.name.size() : kThreadNameBytes - 1;
  if (name_len != 0) std::memcpy(b->name, opts.name.data(), name_len);
  b->name[name_len] = '\0';
  {
    std::lock_guard<std::mutex> lk(g_registry.mu);
    std::uint32_t slot = 0;
    while (slot < kMaxThreads && g_registry.slots[slot].load(std::memory_order_acquire) != nullptr) ++slot;
    if (slot == kMaxThreads) {
      free_buffer(b);
      return std::unexpected(RegisterError::kTooManyThreads);
    }
    b->thread_id = g_registry.next_thread_id.fetch_add(1, std::memory_order_relaxed);
    g_registry.slots[slot].store(b, std::memory_order_release);
    if (slot + 1 > g_registry.high_water.load(std::memory_order_relaxed)) {
      g_registry.high_water.store(slot + 1, std::memory_order_release);
    }
  }
  tl_thread = b;
  tl_ring = &b->ring;
  tl_exit_guard.armed = true;
  return b->thread_id;
}

void unregister_thread() noexcept {
  using namespace detail;
  ThreadBuffer* b = tl_thread;
  if (b == nullptr) return;
  tl_ring = nullptr;
  tl_thread = nullptr;
  b->closed.store(true, std::memory_order_release);  // after every commit of this thread
}

std::uint32_t current_thread_id() noexcept {
  const detail::ThreadBuffer* b = detail::tl_thread;
  return b != nullptr ? b->thread_id : 0;
}

std::uint64_t thread_drops() noexcept {
  const detail::ThreadBuffer* b = detail::tl_thread;
  return b != nullptr ? b->drops.load(std::memory_order_relaxed) : 0;
}

std::uint64_t unregistered_drops() noexcept {
  return detail::g_registry.unregistered_drops.load(std::memory_order_relaxed);
}

std::uint32_t canonical_site(std::uint32_t idx) noexcept {
  static const std::vector<std::uint32_t> table = detail::build_canonical_table();
  return idx < table.size() ? table[idx] : idx;
}

}  // namespace lle::nlog
