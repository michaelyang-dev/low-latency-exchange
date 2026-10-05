#include "net/common/buffer_arena.h"

#include <cstdlib>
#include <cstring>

namespace lle::net {

void BufferArena::FreeDeleter::operator()(std::byte* p) const noexcept { std::free(p); }

Result<void> BufferArena::init(std::uint32_t count, std::uint32_t buf_size, std::size_t align) {
  if (initialized()) return fail("BufferArena::init", EALREADY);
  if (count == 0 || buf_size == 0 || align == 0 || (align & (align - 1)) != 0 || align < alignof(std::max_align_t))
    return fail("BufferArena::init", EINVAL);
  const std::size_t stride = (static_cast<std::size_t>(buf_size) + 63u) & ~std::size_t{63};
  const std::size_t total = stride * count;
  void* p = nullptr;
  if (::posix_memalign(&p, align, total) != 0) return fail("posix_memalign", ENOMEM);
  std::memset(p, 0, total);
  mem_.reset(static_cast<std::byte*>(p));
  base_ = static_cast<std::byte*>(p);
  free_ = std::make_unique<std::uint32_t[]>(count);
  for (std::uint32_t i = 0; i < count; ++i) free_[i] = count - 1 - i;  // acquire() hands out 0 first
  stride_ = stride;
  count_ = count;
  buf_size_ = buf_size;
  nfree_ = count;
  return {};
}

}  // namespace lle::net
