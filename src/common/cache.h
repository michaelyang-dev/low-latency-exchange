#pragma once
// False-sharing padding (08-concurrency-runtime §2). Never use
// std::hardware_destructive_interference_size: missing in Apple clang,
// ABI-unstable in GCC, and target-dependent.
#include <cstddef>

#ifndef LLE_FALSE_SHARING_BYTES
#define LLE_FALSE_SHARING_BYTES 128
#endif

namespace lle {
inline constexpr std::size_t kFalseSharingBytes = LLE_FALSE_SHARING_BYTES;
static_assert((kFalseSharingBytes & (kFalseSharingBytes - 1)) == 0 && kFalseSharingBytes >= 64,
              "false-sharing size must be a power of two >= 64");
}  // namespace lle
