#pragma once
// The admin port's core (sans-I/O): verified admin frames become entries of
// the sequencer's admin queue (seq::AdminMsg), which the sequencer journals as
// Admin records (06 §2 input 3). One FrameAssembler per connection.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "admin/protocol.h"
#include "common/endian.h"
#include "sequencer/sequencer.h"

namespace lle::admin {

struct PortStats {
  std::uint64_t frames = 0;
  std::uint64_t accepted = 0;
  std::uint64_t rejected = 0;
  std::uint64_t busy = 0;
};

// Queue: anything with bool try_push(const seq::AdminMsg&) (the sequencer's
// MPSC admin queue).
template <class Queue>
class AdminPort {
 public:
  AdminPort(Verifier& v, Queue& q) noexcept : v_(&v), q_(&q) {}

  // Bytes received on a connection; appends one response frame per complete
  // request to `out`. False when the stream is unusable and must be closed.
  bool on_bytes(FrameAssembler& conn, std::span<const std::byte> in, std::vector<std::byte>& out) {
    conn.feed(in);
    for (;;) {
      const std::span<const std::byte> f = conn.next();
      if (f.empty()) break;
      ++stats_.frames;
      const auto resp = handle(f);
      out.insert(out.end(), resp.begin(), resp.end());
    }
    return !conn.poisoned();
  }

  // One complete frame: verify, enqueue, respond.
  std::array<std::byte, kResponseBytes> handle(std::span<const std::byte> f) {
    Response r;
    if (f.size() >= 16) {  // echo what can be read
      r.operator_id = load_be32(f.data() + 4);
      r.sequence = load_be64(f.data() + 8);
    }
    const auto req = v_->verify(f);
    if (!req.has_value()) {
      r.reason = req.error();
      ++stats_.rejected;
      return v_->respond(r);
    }
    seq::AdminMsg m;
    m.command = req->command;
    m.tlv_version = req->tlv_version;
    m.operator_id = req->operator_id;
    m.len = static_cast<std::uint32_t>(req->args.size());
    if (!req->args.empty()) std::memcpy(m.args, req->args.data(), req->args.size());
    if (!q_->try_push(m)) {
      r.reason = NackReason::Busy;
      ++stats_.busy;
      return v_->respond(r);
    }
    v_->commit(*req);
    r.accepted = true;
    ++stats_.accepted;
    return v_->respond(r);
  }

  [[nodiscard]] const PortStats& stats() const noexcept { return stats_; }

 private:
  Verifier* v_;
  Queue* q_;
  PortStats stats_{};
};

static_assert(kMaxArgs <= seq::AdminMsg::kMaxArgs);

}  // namespace lle::admin
