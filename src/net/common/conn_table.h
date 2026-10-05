#pragma once
// Fixed-capacity connection table with generation-checked ConnIds.
//
// ConnId = (generation << 16) | slot. The generation advances every time a slot is
// freed and stays in [1, 0xFFFE], so a stale id (a connection closed and its slot reused)
// is rejected and env::kNoConn (0xFFFFFFFF) is never produced. Capacity ≤ 65,535.
#include <cstdint>
#include <memory>

#include "common/assert.h"
#include "env/concepts.h"

namespace lle::net {

using env::ConnId;
using env::kNoConn;

[[nodiscard]] constexpr ConnId make_conn_id(std::uint32_t slot, std::uint16_t gen) noexcept {
  return (static_cast<ConnId>(gen) << 16) | (slot & 0xFFFFu);
}
[[nodiscard]] constexpr std::uint32_t conn_slot(ConnId c) noexcept { return c & 0xFFFFu; }
[[nodiscard]] constexpr std::uint16_t conn_gen(ConnId c) noexcept { return static_cast<std::uint16_t>(c >> 16); }

template <class Slot>
class ConnTable {
 public:
  static constexpr std::uint32_t kMaxCapacity = 0xFFFF;

  void init(std::uint32_t capacity) {
    LLE_ASSERT(capacity > 0 && capacity <= kMaxCapacity, "ConnTable capacity out of range");
    cap_ = capacity;
    slots_ = std::make_unique<Slot[]>(capacity);
    gen_ = std::make_unique<std::uint16_t[]>(capacity);
    used_ = std::make_unique<bool[]>(capacity);
    free_ = std::make_unique<std::uint32_t[]>(capacity);
    for (std::uint32_t i = 0; i < capacity; ++i) {
      gen_[i] = 1;
      used_[i] = false;
      free_[i] = capacity - 1 - i;
    }
    nfree_ = capacity;
  }

  // Reserves a slot; returns kNoConn when the table is full. The slot's contents are left
  // as the previous owner left them; the caller initializes what it uses.
  [[nodiscard]] ConnId alloc() noexcept {
    if (nfree_ == 0) return kNoConn;
    const std::uint32_t s = free_[--nfree_];
    used_[s] = true;
    return make_conn_id(s, gen_[s]);
  }

  // The slot for `c`, or nullptr if `c` is stale, out of range or free.
  [[nodiscard]] Slot* get(ConnId c) noexcept {
    const std::uint32_t s = conn_slot(c);
    if (c == kNoConn || s >= cap_ || !used_[s] || gen_[s] != conn_gen(c)) return nullptr;
    return &slots_[s];
  }
  [[nodiscard]] const Slot* get(ConnId c) const noexcept { return const_cast<ConnTable*>(this)->get(c); }

  [[nodiscard]] Slot& at(std::uint32_t slot) noexcept {
    LLE_DASSERT(slot < cap_);
    return slots_[slot];
  }
  [[nodiscard]] bool in_use(std::uint32_t slot) const noexcept { return slot < cap_ && used_[slot]; }
  [[nodiscard]] ConnId id_of(std::uint32_t slot) const noexcept { return make_conn_id(slot, gen_[slot]); }

  // Releases the slot and invalidates every outstanding id for it.
  void free(ConnId c) noexcept {
    const std::uint32_t s = conn_slot(c);
    if (get(c) == nullptr) return;
    used_[s] = false;
    gen_[s] = static_cast<std::uint16_t>(gen_[s] >= 0xFFFE ? 1 : gen_[s] + 1);
    free_[nfree_++] = s;
  }

  [[nodiscard]] std::uint32_t capacity() const noexcept { return cap_; }
  [[nodiscard]] std::uint32_t live() const noexcept { return cap_ - nfree_; }

 private:
  std::unique_ptr<Slot[]> slots_;
  std::unique_ptr<std::uint16_t[]> gen_;
  std::unique_ptr<bool[]> used_;
  std::unique_ptr<std::uint32_t[]> free_;
  std::uint32_t cap_ = 0;
  std::uint32_t nfree_ = 0;
};

}  // namespace lle::net
