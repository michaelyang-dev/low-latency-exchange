#pragma once
// MoldUDP64 re-request server core (03-protocols §6; R1b D1, Rec 9), sans-I/O:
// request bytes, source endpoint and time in; at most one reply packet out
// through `reply(const env::Endpoint&, std::span<const std::byte>)`.
//
// Validation (the spec leaves these open; decisions per R1b D1):
//   - exactly 20 bytes, else Malformed;
//   - session equal to ours, else WrongSession;
//   - 1 <= seq <= highest released, else BadSequence;
//   - count >= 1, else ZeroCount;
//   - per-source token bucket (our limits; NASDAQ publishes none), else RateLimited;
//   - seq still held by the store, else Unavailable.
// Invalid requests are dropped and counted; nothing is sent back.
// A reply is one downstream packet with whole messages starting at `seq`, as
// many as fit in max_packet ("one re-request, one packet", R1b D1).
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "common/assert.h"
#include "common/hash.h"
#include "common/types.h"
#include "env/buggify.h"
#include "env/concepts.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::mold {

struct RerequestConfig {
  Session session;
  std::size_t max_packet = kDefaultMaxPacket;
  std::uint32_t bucket_capacity = 200;           // burst size, in requests
  Nanos refill_interval = kNsPerSec / 2000;      // one token per interval (2,000 requests/s sustained)
  std::size_t max_sources = 1024;                // distinct sources with their own bucket
};

enum class RequestOutcome : std::uint8_t {
  Served,
  Malformed,
  WrongSession,
  BadSequence,
  ZeroCount,
  RateLimited,
  Unavailable,
};

struct RerequestStats {
  std::uint64_t requests = 0, served = 0, messages_served = 0, bytes_served = 0;
  std::uint64_t malformed = 0, wrong_session = 0, bad_sequence = 0, zero_count = 0, rate_limited = 0;
  std::uint64_t unavailable = 0, sources_overflowed = 0;
  [[nodiscard]] std::uint64_t invalid() const noexcept { return malformed + wrong_session + bad_sequence + zero_count; }
};

// Integer token bucket: `capacity` tokens, one more every `interval` ns.
struct TokenBucket {
  std::uint32_t tokens = 0;
  Nanos last = 0;

  bool take(Nanos now, std::uint32_t capacity, Nanos interval) noexcept {
    if (now > last) {
      const Nanos add = (now - last) / interval;
      if (add > 0) {
        const auto room = static_cast<Nanos>(capacity - tokens);
        if (add >= room) {
          tokens = capacity;
          last = now;
        } else {
          tokens += static_cast<std::uint32_t>(add);
          last += add * interval;
        }
      }
    }
    if (tokens == 0) return false;
    --tokens;
    return true;
  }
};

template <MessageStoreLike Store>
class RerequestServer {
 public:
  RerequestServer(const RerequestConfig& cfg, const Store& store)
      : cfg_(cfg), store_(store), buf_(std::make_unique<std::byte[]>(cfg.max_packet)) {
    LLE_ASSERT(cfg.max_packet > kHeaderLen && cfg.bucket_capacity > 0 && cfg.refill_interval > 0);
    LLE_ASSERT(cfg.max_sources > 0);
    table_size_ = 1;
    while (table_size_ < 2 * cfg.max_sources) table_size_ <<= 1;
    keys_ = std::make_unique<std::uint64_t[]>(table_size_);
    buckets_ = std::make_unique<TokenBucket[]>(table_size_);
  }

  template <class Reply>
  RequestOutcome on_request(std::span<const std::byte> bytes, const env::Endpoint& src, Nanos now, Reply&& reply) {
    ++stats_.requests;
    const auto req = decode_request(bytes);
    if (!req) return count(RequestOutcome::Malformed, stats_.malformed);
    if (req->session != cfg_.session) return count(RequestOutcome::WrongSession, stats_.wrong_session);
    const SeqNo highest = store_.highest();
    if (req->seq < 1 || req->seq > highest) return count(RequestOutcome::BadSequence, stats_.bad_sequence);
    if (req->count == 0) return count(RequestOutcome::ZeroCount, stats_.zero_count);
    if (!bucket_for(src, now).take(now, cfg_.bucket_capacity, cfg_.refill_interval) ||
        SIM_BUGGIFY("mold.rerequest_refused")) {  // 09 §4: re-request server refusal
      return count(RequestOutcome::RateLimited, stats_.rate_limited);
    }
    if (req->seq < store_.lowest()) return count(RequestOutcome::Unavailable, stats_.unavailable);

    PacketBuilder b(std::span<std::byte>(buf_.get(), cfg_.max_packet), cfg_.session, req->seq);
    const SeqNo last = req->seq + std::min<SeqNo>(req->count - 1, highest - req->seq);
    for (SeqNo s = req->seq; s <= last; ++s) {
      const auto msg = store_.get(s);
      if (!msg || !b.add(*msg)) break;
    }
    if (b.count() == 0) return count(RequestOutcome::Unavailable, stats_.unavailable);
    const std::span<const std::byte> pkt = b.finish();
    ++stats_.served;
    stats_.messages_served += b.count();
    stats_.bytes_served += pkt.size();
    reply(src, pkt);
    return RequestOutcome::Served;
  }

  [[nodiscard]] const RerequestStats& stats() const noexcept { return stats_; }
  [[nodiscard]] const RerequestConfig& config() const noexcept { return cfg_; }

 private:
  RequestOutcome count(RequestOutcome o, std::uint64_t& c) noexcept {
    ++c;
    return o;
  }

  // Open addressing keyed by (ip, port). Once max_sources distinct sources are
  // tracked, newcomers share one overflow bucket (deterministic, bounded memory).
  TokenBucket& bucket_for(const env::Endpoint& e, Nanos now) noexcept {
    const std::uint64_t key = ((std::uint64_t{e.ipv4} << 16) | e.port) + 1;  // 0 = empty slot
    const std::size_t mask = table_size_ - 1;
    for (std::size_t i = static_cast<std::size_t>(mix64(key)) & mask;; i = (i + 1) & mask) {
      if (keys_[i] == key) return buckets_[i];
      if (keys_[i] == 0) {
        if (sources_ >= cfg_.max_sources) {
          ++stats_.sources_overflowed;
          if (!overflow_init_) {
            overflow_ = TokenBucket{cfg_.bucket_capacity, now};
            overflow_init_ = true;
          }
          return overflow_;
        }
        keys_[i] = key;
        buckets_[i] = TokenBucket{cfg_.bucket_capacity, now};
        ++sources_;
        return buckets_[i];
      }
    }
  }

  RerequestConfig cfg_;
  const Store& store_;
  std::unique_ptr<std::byte[]> buf_;
  std::size_t table_size_ = 0;
  std::unique_ptr<std::uint64_t[]> keys_;
  std::unique_ptr<TokenBucket[]> buckets_;
  std::size_t sources_ = 0;
  TokenBucket overflow_;
  bool overflow_init_ = false;
  RerequestStats stats_;
};

}  // namespace lle::mold
