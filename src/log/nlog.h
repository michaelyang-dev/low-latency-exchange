#pragma once
// nlog: NanoLog-style binary logger (11-logging-observability §1, R6 R4).
//
//   NLOG_INFO("order {} accepted px {} qty {} side {}", ref, px_e4, qty, side);
//   NLOG_EV(ev_tsc, "match {} qty {} px {}", match_no, qty, px_e4);  // caller's timestamp
//   NLOG_DEBUG / NLOG_WARN / NLOG_ERROR                                 // compile-time filtered
//
// Hot path: one TLS load of the thread's ring, a reserve, ~16-40 bytes of raw
// stores, one release store. No formatting, locks, syscalls or allocation; the
// site ID is link-time arithmetic (site.h). A full ring drops the record and bumps
// the thread's drop counter (never blocks) unless the thread registered with
// FullPolicy::kBlock (tests). Calls from threads that never called
// register_thread() are dropped and counted globally.
//
// The format string must be a string literal (or a constexpr const char*); it is
// checked against the argument types at compile time (format_spec.h), even for
// levels compiled out. The recorded line is __LINE__ at the call, which clang
// reports as the line of the closing parenthesis for a call spanning lines.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

#include "concurrent/spsc_byte_ring.h"
#include "env/prod_clock.h"
#include "log/format_spec.h"
#include "log/level.h"
#include "log/record.h"
#include "log/site.h"

namespace lle::nlog {

enum class FullPolicy : std::uint8_t {
  kDrop,   // production: drop and count
  kBlock,  // tests: spin until the consumer frees space (drops only if no consumer runs)
};

inline constexpr std::size_t kMinRingBytes = 4096;
inline constexpr std::size_t kMaxRingBytes = std::size_t{1} << 31;
inline constexpr std::size_t kDefaultRingBytes = std::size_t{1} << 20;  // 1 MiB (1-4 MiB in production)

struct ThreadOptions {
  std::size_t ring_bytes = kDefaultRingBytes;  // power of two in [kMinRingBytes, kMaxRingBytes]
  FullPolicy policy = FullPolicy::kDrop;
  std::string_view name = {};  // up to 31 bytes are kept (THREAD chunk)
};

enum class RegisterError : std::uint8_t { kAlreadyRegistered, kBadRingSize, kOutOfMemory, kTooManyThreads };

// Allocates and pre-faults the calling thread's ring and publishes it to the
// consumer (backend or memory sink). Cold path; call at thread start. Returns the
// thread's log ID (never reused within the process).
[[nodiscard]] std::expected<std::uint32_t, RegisterError> register_thread(const ThreadOptions& opts = {}) noexcept;

// Stops logging on the calling thread; the consumer drains what is left and then
// frees the ring. Also runs automatically at thread exit.
void unregister_thread() noexcept;

[[nodiscard]] std::uint32_t current_thread_id() noexcept;  // 0 if not registered
[[nodiscard]] std::uint64_t thread_drops() noexcept;       // calling thread's drop count
[[nodiscard]] std::uint64_t unregistered_drops() noexcept;  // calls made without a ring

// RAII registration for a scope (tests, short-lived threads).
class ThreadScope {
 public:
  explicit ThreadScope(const ThreadOptions& opts = {}) noexcept : result_(register_thread(opts)) {}
  ~ThreadScope() {
    if (result_) unregister_thread();
  }
  ThreadScope(const ThreadScope&) = delete;
  ThreadScope& operator=(const ThreadScope&) = delete;
  [[nodiscard]] bool ok() const noexcept { return result_.has_value(); }
  [[nodiscard]] std::uint32_t thread_id() const noexcept { return result_ ? *result_ : 0; }

 private:
  std::expected<std::uint32_t, RegisterError> result_;
};

#if defined(LLE_SIM)
// Simulator builds: once a simulator sets this virtual clock, NLOG_INFO & co. stamp
// records with it instead of the CPU counter, keeping its logs deterministic. Until
// then they use the CPU counter, as in other builds.
void set_sim_tsc(std::uint64_t tsc) noexcept;
#endif

namespace detail {

extern constinit thread_local conc::SpscByteRing* tl_ring;

[[gnu::cold]] std::byte* on_ring_full(std::uint32_t len) noexcept;
[[gnu::cold]] void on_unregistered() noexcept;

#if defined(LLE_SIM)
std::uint64_t sim_tsc() noexcept;
[[nodiscard]] inline std::uint64_t now_tsc() noexcept { return sim_tsc(); }
#else
[[nodiscard]] [[gnu::always_inline]] inline std::uint64_t now_tsc() noexcept { return env::read_tsc(); }
#endif

// A function, not an inline comparison in the macro: GCC's -Wtype-limits flags
// `level >= 0` when LLE_NLOG_MIN_LEVEL is 0.
[[nodiscard]] consteval bool level_enabled(Level level, int min_level) noexcept {
  return static_cast<int>(level) >= min_level;
}

template <bool kNow, class... V>
[[gnu::always_inline]] inline bool emit(const LogSite* const* slot, std::uint64_t tsc, const V&... vals) noexcept {
  conc::SpscByteRing* const ring = tl_ring;
  if (ring == nullptr) [[unlikely]] {
    on_unregistered();
    return false;
  }
  const std::uint32_t len = kRecordHeaderBytes + (0u + ... + arg_bytes(vals));
  std::byte* p = ring->try_reserve(len);
  if (p == nullptr) [[unlikely]] {
    p = on_ring_full(len);
    if (p == nullptr) return false;
  }
  if constexpr (kNow) tsc = now_tsc();
  const std::uint16_t flags =
      static_cast<std::uint16_t>((kNow ? 0u : kFlagEventTs) | (0u | ... | arg_flags(vals)));
  const std::uint64_t word0 = std::uint64_t{site_index(slot)} | (std::uint64_t{len} << 32) |
                              (std::uint64_t{flags} << 48);
  std::memcpy(p, &word0, sizeof word0);
  std::memcpy(p + 8, &tsc, sizeof tsc);
  [[maybe_unused]] std::byte* q = p + kRecordHeaderBytes;
  (put_arg(q, vals), ...);
  ring->commit();
  return true;
}

// A distinct type in every translation unit. write() is instantiated with it, so the
// slot of every call site has internal linkage, whatever function the call is in.
// That keeps one kind of variable in the nlog section of a translation unit: GCC
// emits a single section per name and translation unit, rejects a mix of COMDAT and
// internal variables in it ("section type conflict"), and would put all COMDAT ones
// into the group of the first, which the linker may discard with every slot in it.
// A site in an inline function used from several translation units therefore has one
// slot per translation unit; the consumers map them to one site (site.h,
// canonical_site()), so the dictionary still lists it once.
namespace {
struct TuKey {};
}  // namespace

// One instantiation per call site (Tag is a local class of the site) and translation
// unit (TU), so the statics below are per site.
template <class Tag, class TU, Level L, bool kNow, class... A>
[[gnu::always_inline]] inline bool write(std::uint64_t tsc, const A&... args) noexcept {
  using Check = FormatCheck<Tag, TypeList<std::remove_cvref_t<A>...>>;
  static constexpr LogSite kSite{Tag::lle_nlog_fmt(), Tag::lle_nlog_file(), Tag::lle_nlog_line(), L,
                                 static_cast<std::uint8_t>(sizeof...(A)), Check::kKinds};
  LLE_NLOG_SECTION_ATTR static const LogSite* const kSlot = &kSite;
  return emit<kNow>(&kSlot, tsc, normalize(args)...);
}

}  // namespace detail
}  // namespace lle::nlog

// clang-format off
#define LLE_NLOG_CALL(lvl_, now_, tsc_, fmt_, ...)                                               \
  do {                                                                                           \
    struct LleNlogTag_ {                                                                         \
      static consteval const char* lle_nlog_fmt() noexcept { return fmt_; }                      \
      static consteval const char* lle_nlog_file() noexcept { return __FILE__; }                 \
      static consteval std::uint32_t lle_nlog_line() noexcept { return __LINE__; }               \
    };                                                                                           \
    static_assert(::lle::nlog::detail::FormatCheck<                                              \
                  LleNlogTag_, decltype(::lle::nlog::detail::type_list(__VA_ARGS__))>::kOk ||    \
                  true);                                                                         \
    if constexpr (::lle::nlog::detail::level_enabled(lvl_, LLE_NLOG_MIN_LEVEL)) {                \
      ::lle::nlog::detail::write<LleNlogTag_, ::lle::nlog::detail::TuKey, lvl_, now_>(           \
          tsc_ __VA_OPT__(, ) __VA_ARGS__);                                                      \
    }                                                                                            \
  } while (0)
// clang-format on

#define NLOG_DEBUG(fmt_, ...) \
  LLE_NLOG_CALL(::lle::nlog::Level::kDebug, true, std::uint64_t{0}, fmt_ __VA_OPT__(, ) __VA_ARGS__)
#define NLOG_INFO(fmt_, ...) \
  LLE_NLOG_CALL(::lle::nlog::Level::kInfo, true, std::uint64_t{0}, fmt_ __VA_OPT__(, ) __VA_ARGS__)
#define NLOG_WARN(fmt_, ...) \
  LLE_NLOG_CALL(::lle::nlog::Level::kWarn, true, std::uint64_t{0}, fmt_ __VA_OPT__(, ) __VA_ARGS__)
#define NLOG_ERROR(fmt_, ...) \
  LLE_NLOG_CALL(::lle::nlog::Level::kError, true, std::uint64_t{0}, fmt_ __VA_OPT__(, ) __VA_ARGS__)

// INFO record stamped with the caller's timestamp (no counter read in the call).
#define NLOG_EV(ev_tsc_, fmt_, ...)                                                                   \
  LLE_NLOG_CALL(::lle::nlog::Level::kInfo, false, static_cast<std::uint64_t>(ev_tsc_), \
                fmt_ __VA_OPT__(, ) __VA_ARGS__)
// Same with an explicit level.
#define NLOG_EV_AT(level_, ev_tsc_, fmt_, ...) \
  LLE_NLOG_CALL(level_, false, static_cast<std::uint64_t>(ev_tsc_), fmt_ __VA_OPT__(, ) __VA_ARGS__)
