#pragma once
// Incremental SoupBinTCP packet framer (spec 1.1: logical packets do not map
// onto TCP segments). Complete packets are handed to a callback zero-copy when
// they sit wholly inside the input; a packet straddling calls is reassembled in
// one of two internal buffers. Alternating the buffers keeps every payload span
// delivered during a feed() call valid until the next feed() call, even when
// the same call stores a new trailing partial packet.
//
// Buffers are allocated once at construction; feed() never allocates.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

#include "common/endian.h"
#include "env/buggify.h"
#include "proto/soupbin/packets.h"

namespace lle::soup {

struct Packet {
  char type = 0;
  std::span<const std::byte> payload;
};

class Framer {
 public:
  enum class Status : std::uint8_t {
    Ok,
    ZeroLength,  // Packet Length 0: no type byte
    TooLong,     // Packet Length above the configured maximum
  };

  // `max_packet_length` bounds the Packet Length field (type + payload).
  explicit Framer(std::size_t max_packet_length)
      : max_(std::clamp<std::size_t>(max_packet_length, 1, kMaxPacketLength)),
        bufs_{std::make_unique_for_overwrite<std::byte[]>(kLengthFieldLen + max_),
              std::make_unique_for_overwrite<std::byte[]>(kLengthFieldLen + max_)} {}

  // Feeds bytes. Calls on_packet(const Packet&) -> bool for each complete
  // packet; returning false stops parsing. Returns the number of input bytes
  // consumed: all of them unless the callback stopped early or a framing error
  // occurred (status() then turns sticky and further feeds consume nothing).
  template <class F>
  std::size_t feed(std::span<const std::byte> in, F&& on_packet) {
    if (status_ != Status::Ok) return 0;
    std::size_t pos = 0;
    if (have_ > 0) {
      std::byte* buf = bufs_[cur_].get();
      if (have_ < kLengthFieldLen) {
        const std::size_t take = std::min(kLengthFieldLen - have_, in.size());
        std::memcpy(buf + have_, in.data(), take);
        have_ += take;
        pos += take;
        if (have_ < kLengthFieldLen) return pos;
        if (!check(load_be16(buf))) return pos;
      }
      const std::size_t total = kLengthFieldLen + load_be16(buf);
      const std::size_t take = std::min(total - have_, in.size() - pos);
      std::memcpy(buf + have_, in.data() + pos, take);
      have_ += take;
      pos += take;
      if (have_ < total) return pos;
      have_ = 0;
      cur_ ^= 1u;  // the next partial goes to the other buffer; this payload stays valid
      SIM_PROBE("soup.packet_reassembled_across_reads");
      if (!on_packet(Packet{std::to_integer<char>(buf[2]), std::span<const std::byte>(buf + kHeaderLen, total - kHeaderLen)}))
        return pos;
    }
    while (in.size() - pos >= kLengthFieldLen) {
      const std::size_t len = load_be16(in.data() + pos);
      if (!check(len)) return pos;
      if (in.size() - pos < kLengthFieldLen + len) break;
      const Packet p{std::to_integer<char>(in[pos + 2]), in.subspan(pos + kHeaderLen, len - 1)};
      pos += kLengthFieldLen + len;
      if (!on_packet(p)) return pos;
    }
    const std::size_t rest = in.size() - pos;
    if (rest > 0) {
      std::memcpy(bufs_[cur_].get(), in.data() + pos, rest);  // rest < 2 + len <= buffer size
      have_ = rest;
      pos += rest;
    }
    return pos;
  }

  [[nodiscard]] Status status() const noexcept { return status_; }
  [[nodiscard]] std::size_t buffered() const noexcept { return have_; }
  [[nodiscard]] std::size_t max_packet_length() const noexcept { return max_; }
  void reset() noexcept {
    have_ = 0;
    status_ = Status::Ok;
  }

 private:
  bool check(std::size_t len) noexcept {
    if (len == 0) status_ = Status::ZeroLength;
    else if (len > max_) status_ = Status::TooLong;
    return status_ == Status::Ok;
  }

  std::size_t max_;
  std::unique_ptr<std::byte[]> bufs_[2];
  std::size_t have_ = 0;
  unsigned cur_ = 0;
  Status status_ = Status::Ok;
};

}  // namespace lle::soup
