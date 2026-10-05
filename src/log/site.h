#pragma once
// Log-site registry without a run-time registration branch
// (11-logging-observability §1, R6 D3.5).
//
// Every enabled call site owns
//   static constexpr LogSite kSite{...};                      // read-only data
//   static const LogSite* const kSlot = &kSite;               // in the nlog section
// The slots are uniformly sized, naturally aligned pointers, so the linker lays
// them out as a dense array with no padding holes (unlike over-aligned structs in
// a named section). A site's ID is the slot's byte offset from the section start
// divided by the pointer size, computed with integer arithmetic on two link-time
// addresses: PC-relative, no static-initialization order, no first-call branch and
// no pointer subtraction between distinct objects. The backend walks the section
// once at startup to write the site dictionary.
//
// Mach-O: section "__DATA,__lle_nlog", bounds section$start$/section$end$.
// ELF:    section "lle_nlog_sites", bounds __start_/__stop_ (SHF_GNU_RETAIN via
//         `retain` keeps it under --gc-sections). The IDs are per linked image:
//         nlog sites must live in the main executable (static linking), not in
//         several shared objects.
#include <cstddef>
#include <cstdint>

#include "log/format_spec.h"
#include "log/level.h"

namespace lle::nlog {

struct LogSite {
  const char* fmt;
  const char* file;
  std::uint32_t line;
  Level level;
  std::uint8_t nargs;
  ArgKinds kinds;
};

}  // namespace lle::nlog

// AddressSanitizer surrounds instrumented globals with redzones, which would turn
// the dense slot array into slots separated by padding. Clang can exempt the slot
// variables (the section stays dense). GCC cannot exempt a variable, so under
// GCC's ASan the section holds zeroed redzone words between slots: IDs stay
// unique (they are byte offsets / 8) and the readers below skip null words; they
// are compiled without ASan checks because they read the redzones.
#if defined(__clang__) && defined(__has_feature)
#if __has_feature(address_sanitizer)
#define LLE_NLOG_NO_ASAN __attribute__((no_sanitize("address")))
#endif
#endif
#ifndef LLE_NLOG_NO_ASAN
#define LLE_NLOG_NO_ASAN
#endif
#define LLE_NLOG_NO_ASAN_FN __attribute__((no_sanitize_address))

#if defined(__APPLE__) && defined(__MACH__)
// `used` also marks the atom no_dead_strip on Darwin.
#define LLE_NLOG_SECTION_ATTR __attribute__((used, section("__DATA,__lle_nlog"))) LLE_NLOG_NO_ASAN
extern "C" const ::lle::nlog::LogSite* const lle_nlog_section_start __asm("section$start$__DATA$__lle_nlog")
    __attribute__((visibility("hidden")));
extern "C" const ::lle::nlog::LogSite* const lle_nlog_section_stop __asm("section$end$__DATA$__lle_nlog")
    __attribute__((visibility("hidden")));
#define LLE_NLOG_SECTION_START_ADDR (reinterpret_cast<std::uintptr_t>(&lle_nlog_section_start))
#define LLE_NLOG_SECTION_STOP_ADDR (reinterpret_cast<std::uintptr_t>(&lle_nlog_section_stop))
#elif defined(__ELF__)
#if defined(__has_attribute) && __has_attribute(retain)
#define LLE_NLOG_SECTION_ATTR __attribute__((used, retain, section("lle_nlog_sites"))) LLE_NLOG_NO_ASAN
#else
#define LLE_NLOG_SECTION_ATTR __attribute__((used, section("lle_nlog_sites"))) LLE_NLOG_NO_ASAN
#endif
extern "C" const ::lle::nlog::LogSite* const __start_lle_nlog_sites[] __attribute__((visibility("hidden")));
extern "C" const ::lle::nlog::LogSite* const __stop_lle_nlog_sites[] __attribute__((visibility("hidden")));
#define LLE_NLOG_SECTION_START_ADDR (reinterpret_cast<std::uintptr_t>(__start_lle_nlog_sites))
#define LLE_NLOG_SECTION_STOP_ADDR (reinterpret_cast<std::uintptr_t>(__stop_lle_nlog_sites))
#else
#error "nlog: unsupported object format (needs ELF or Mach-O linker sections)"
#endif

namespace lle::nlog {

inline constexpr std::size_t kSlotBytes = sizeof(const LogSite*);

// Site ID of the slot at `slot` (hot path: two PC-relative address materializations,
// a subtract and a shift).
[[nodiscard]] [[gnu::always_inline]] inline std::uint32_t site_index(const LogSite* const* slot) noexcept {
  return static_cast<std::uint32_t>((reinterpret_cast<std::uintptr_t>(slot) - LLE_NLOG_SECTION_START_ADDR) /
                                    kSlotBytes);
}

// Number of slots in the section (including the library's anchor slot).
[[nodiscard]] inline std::uint32_t site_count() noexcept {
  return static_cast<std::uint32_t>((LLE_NLOG_SECTION_STOP_ADDR - LLE_NLOG_SECTION_START_ADDR) / kSlotBytes);
}

// The site in slot `idx` as linked, or nullptr if out of range (or an empty word: the
// anchor never is, but GCC ASan redzones are).
[[nodiscard]] LLE_NLOG_NO_ASAN_FN inline const LogSite* slot_site(std::uint32_t idx) noexcept {
  if (idx >= site_count()) return nullptr;
  const auto* slot = reinterpret_cast<const LogSite* const*>(LLE_NLOG_SECTION_START_ADDR + idx * kSlotBytes);
  return *slot;
}

// Slots are per call site and translation unit (nlog.h, TuKey), so a site in an inline
// function used from several translation units has several slots, and a record carries
// whichever its code was compiled with. canonical_site(idx) is the lowest slot holding
// the same site (format, file, line, level, argument kinds): consumers use it as the
// record's site ID. Cold: the table is built on first use (registry.cpp).
[[nodiscard]] std::uint32_t canonical_site(std::uint32_t idx) noexcept;

// The site with ID `idx`, or nullptr if out of range, an empty word, or a later slot of
// a site that has a lower canonical ID (records naming it are mapped by canonical_site).
[[nodiscard]] inline const LogSite* site_at(std::uint32_t idx) noexcept {
  const LogSite* s = slot_site(idx);
  return s != nullptr && canonical_site(idx) == idx ? s : nullptr;
}

}  // namespace lle::nlog
