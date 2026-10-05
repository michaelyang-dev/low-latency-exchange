#pragma once
// Common base of the generated typed message views (ouch50_messages.gen.h).
// A view is a non-owning span; accessors read big-endian fields at fixed
// offsets. Views assume the message passed InboundDecoder/OutboundDecoder (or
// a strict validator), so the fixed part is present.
#include <cstddef>
#include <cstdint>
#include <span>

#include "common/endian.h"
#include "proto/ouch50/spec_types.h"
#include "proto/ouch50/tagvalue.h"

namespace lle::ouch50 {

template <class Msg>
class MessageView {
 public:
  using Message = Msg;

  constexpr MessageView() noexcept = default;
  constexpr explicit MessageView(std::span<const std::byte> b) noexcept : b_(b) {}

  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return b_; }
  [[nodiscard]] static constexpr char type() noexcept { return Msg::kType; }

  [[nodiscard]] bool has_appendage_length() const noexcept {
    if constexpr (Msg::kRule == AppendageRule::None) {
      return false;
    } else {
      return b_.size() >= Msg::kFixedLen;
    }
  }
  [[nodiscard]] std::uint16_t appendage_length() const noexcept {
    return has_appendage_length() ? load_be16(b_.data() + Msg::kBaseLen) : std::uint16_t{0};
  }
  [[nodiscard]] std::span<const std::byte> appendage() const noexcept {
    return has_appendage_length() ? b_.subspan(Msg::kFixedLen) : std::span<const std::byte>{};
  }
  [[nodiscard]] TagValueRange tags() const noexcept { return TagValueRange(appendage()); }

  // Copies the fixed part into the value struct (appendage not included).
  [[nodiscard]] Msg to_struct() const noexcept { return Msg::decode_base(b_.data()); }

 protected:
  [[nodiscard]] const std::byte* p() const noexcept { return b_.data(); }

 private:
  std::span<const std::byte> b_;
};

}  // namespace lle::ouch50
