#pragma once
// The HA world's replicated state machine: a deterministic toy matching engine
// standing in for the real engine (which another track owns; binding it is exchange
// assembly). It has what the T26 oracles need: a UserRefNum filter in replicated
// state (exactly-once execution, 10 §4 step 6), fills, per-session sequenced output
// streams derived only from the journal, a session/instance table, a state hash, and
// a snapshot in the real container format (src/snapshot).
//
// Toy OUCH message (the bytes inside OuchInbound records), 16 bytes:
//   0 u8 'O'  1 u8 side ('B'|'S')  2 u16 0  4 u32 user_ref_num  8 u32 price  12 u32 qty
// Outputs (one session per account):
//   Accepted  'A' u32 urn  u64 order_ref (journal index)                       13 bytes
//   Executed  'E' u32 urn  u64 match_no  u32 qty  u32 price                    21 bytes
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "common/endian.h"
#include "common/hash.h"
#include "env/buggify.h"
#include "journal/record.h"
#include "snapshot/reader.h"
#include "snapshot/writer.h"

namespace lle::sim::ha {

inline constexpr std::size_t kToyOrderBytes = 16;

struct ToyOrder {
  std::uint32_t urn = 0;
  char side = 'B';
  std::uint32_t px = 0;
  std::uint32_t qty = 0;
};

inline std::array<std::byte, kToyOrderBytes> encode_order(const ToyOrder& o) {
  std::array<std::byte, kToyOrderBytes> b{};
  b[0] = std::byte{'O'};
  b[1] = static_cast<std::byte>(o.side);
  store_le32(b.data() + 4, o.urn);
  store_le32(b.data() + 8, o.px);
  store_le32(b.data() + 12, o.qty);
  return b;
}

inline std::optional<ToyOrder> decode_order(std::span<const std::byte> b) {
  if (b.size() != kToyOrderBytes || b[0] != std::byte{'O'}) return std::nullopt;
  const char side = static_cast<char>(b[1]);
  if (side != 'B' && side != 'S') return std::nullopt;
  ToyOrder o;
  o.side = side;
  o.urn = load_le32(b.data() + 4);
  o.px = load_le32(b.data() + 8);
  o.qty = load_le32(b.data() + 12);
  if (o.qty == 0) return std::nullopt;
  return o;
}

struct Output {
  std::uint64_t source = 0;  // journal index the output derives from (Output Rule)
  std::vector<std::byte> bytes;
};

struct SessionStream {
  std::uint64_t base = 1;  // seq of outputs[0] (> 1 after a snapshot install)
  std::vector<Output> outputs;
  [[nodiscard]] std::uint64_t next_seq() const noexcept { return base + outputs.size(); }
  [[nodiscard]] const Output* at(std::uint64_t seq) const noexcept {
    if (seq < base || seq >= next_seq()) return nullptr;
    return &outputs[static_cast<std::size_t>(seq - base)];
  }
};

class ToyEngine {
 public:
  struct Resting {
    std::uint32_t account = 0;
    std::uint32_t urn = 0;
    std::uint32_t qty = 0;     // remaining
    std::uint32_t filled = 0;  // executed so far: a partially filled resting order
  };

  [[nodiscard]] std::uint64_t applied() const noexcept { return applied_; }
  [[nodiscard]] std::uint64_t hash() const noexcept { return hash_; }
  [[nodiscard]] std::uint64_t executions() const noexcept { return executions_; }
  [[nodiscard]] std::uint64_t duplicates() const noexcept { return duplicates_; }
  [[nodiscard]] bool has_partial_fill() const {
    for (const Side* side : {&bids_, &asks_}) {
      for (const auto& [px, level] : *side) {
        for (const Resting& o : level) {
          if (o.filled != 0) return true;
        }
      }
    }
    return false;
  }
  [[nodiscard]] const std::map<std::uint32_t, SessionStream>& sessions() const noexcept { return sessions_; }
  [[nodiscard]] const SessionStream* session(std::uint32_t s) const {
    const auto it = sessions_.find(s);
    return it == sessions_.end() ? nullptr : &it->second;
  }
  [[nodiscard]] std::uint32_t last_urn(std::uint32_t account) const {
    const auto it = last_urn_.find(account);
    return it == last_urn_.end() ? 0 : it->second;
  }
  // Live session instances whose instance id belongs to `node` (bit 15 = node).
  [[nodiscard]] std::vector<std::pair<std::uint32_t, std::uint16_t>> live_instances(std::uint32_t node) const {
    std::vector<std::pair<std::uint32_t, std::uint16_t>> out;
    for (const auto& [key, alive] : instances_) {
      const auto inst = static_cast<std::uint16_t>(key & 0xFFFF);
      if (alive && (inst >> 15) == node) out.emplace_back(static_cast<std::uint32_t>(key >> 16), inst);
    }
    return out;
  }

  // Applies record applied() + 1. Returns false (and changes nothing) otherwise.
  bool apply(const journal::RecordView& r) {
    if (r.index() != applied_ + 1) return false;
    applied_ = r.index();
    hash_ = combine(hash_, r.content());
    switch (r.type()) {
      case journal::RecordType::OuchInbound:
        if (const auto in = journal::decode_ouch_inbound(r)) on_order(r.index(), *in);
        break;
      case journal::RecordType::SessionEvent:
        if (const auto ev = journal::decode_session_event(r)) on_session(*ev);
        break;
      default:
        break;
    }
    return true;
  }

  // ---- snapshot (06 §9 container; canonical, sorted payload) -----------------------
  [[nodiscard]] std::vector<std::byte> snapshot_image(std::uint32_t epoch) const {
    snap::SnapshotMeta meta;
    meta.day = 20260930;
    meta.epoch = epoch;
    meta.index = applied_;
    meta.state_hash = hash_;
    std::vector<snap::SessionSeq> seqs;
    for (const auto& [s, st] : sessions_) seqs.push_back(snap::SessionSeq{s, st.next_seq()});
    auto w = snap::Writer::create_in_memory(meta, seqs, snap::WriterOptions{4096, false});
    if (!w) return {};
    w->put_u64(match_no_);
    w->put_u64(executions_);
    w->put_u64(duplicates_);
    w->put_u32(static_cast<std::uint32_t>(last_urn_.size()));
    for (const auto& [a, u] : last_urn_) {
      w->put_u32(a);
      w->put_u32(u);
    }
    w->put_u32(static_cast<std::uint32_t>(instances_.size()));
    for (const auto& [k, alive] : instances_) {
      w->put_u64(k);
      w->put_u8(alive ? 1 : 0);
    }
    put_side(*w, bids_);
    put_side(*w, asks_);
    auto img = w->finish_image();
    return img ? std::move(*img) : std::vector<std::byte>{};
  }

  // Loads a validated snapshot image. Output history before the snapshot is not
  // available afterwards (each session stream starts at its snapshot next_seq).
  bool restore(std::span<const std::byte> image) {
    auto r = snap::Reader::open(image);
    if (!r) return false;
    ToyEngine e;
    e.applied_ = r->meta().index;
    e.hash_ = r->meta().state_hash;
    for (const snap::SessionSeq& s : r->sessions()) e.sessions_[s.session_id].base = s.next_seq;
    e.match_no_ = r->get_u64();
    e.executions_ = r->get_u64();
    e.duplicates_ = r->get_u64();
    for (std::uint32_t n = r->get_u32(); n > 0 && r->ok(); --n) {
      const std::uint32_t a = r->get_u32();
      e.last_urn_[a] = r->get_u32();
    }
    for (std::uint32_t n = r->get_u32(); n > 0 && r->ok(); --n) {
      const std::uint64_t k = r->get_u64();
      e.instances_[k] = r->get_u8() != 0;
    }
    if (!get_side(*r, e.bids_) || !get_side(*r, e.asks_) || !r->ok() || r->remaining() != 0) return false;
    *this = std::move(e);
    return true;
  }

 private:
  using Side = std::map<std::uint32_t, std::deque<Resting>>;  // price -> FIFO

  static void put_side(snap::Writer& w, const Side& s) {
    w.put_u32(static_cast<std::uint32_t>(s.size()));
    for (const auto& [px, q] : s) {
      w.put_u32(px);
      w.put_u32(static_cast<std::uint32_t>(q.size()));
      for (const Resting& o : q) {
        w.put_u32(o.account);
        w.put_u32(o.urn);
        w.put_u32(o.qty);
        w.put_u32(o.filled);
      }
    }
  }
  static bool get_side(snap::Reader& r, Side& s) {
    for (std::uint32_t n = r.get_u32(); n > 0 && r.ok(); --n) {
      const std::uint32_t px = r.get_u32();
      auto& q = s[px];
      for (std::uint32_t k = r.get_u32(); k > 0 && r.ok(); --k) {
        Resting o;
        o.account = r.get_u32();
        o.urn = r.get_u32();
        o.qty = r.get_u32();
        o.filled = r.get_u32();
        q.push_back(o);
      }
    }
    return r.ok();
  }

  void emit(std::uint32_t session, std::uint64_t source, std::vector<std::byte> bytes) {
    Fnv1a64 f;
    f.bytes(bytes.data(), bytes.size());
    hash_ = combine(hash_, f.value() ^ session);
    sessions_[session].outputs.push_back(Output{source, std::move(bytes)});
  }

  void accepted(std::uint32_t account, std::uint64_t source, std::uint32_t urn) {
    std::vector<std::byte> b(13);
    b[0] = std::byte{'A'};
    store_le32(b.data() + 1, urn);
    store_le64(b.data() + 5, source);
    emit(account, source, std::move(b));
  }

  void executed(std::uint32_t account, std::uint64_t source, std::uint32_t urn, std::uint32_t qty, std::uint32_t px) {
    std::vector<std::byte> b(21);
    b[0] = std::byte{'E'};
    store_le32(b.data() + 1, urn);
    store_le64(b.data() + 5, match_no_);
    store_le32(b.data() + 13, qty);
    store_le32(b.data() + 17, px);
    emit(account, source, std::move(b));
  }

  void on_order(std::uint64_t index, const journal::OuchInbound& in) {
    const auto o = decode_order(in.msg);
    if (!o) return;
    // The UserRefNum filter (replicated state): a re-sent message is a no-op.
    std::uint32_t& last = last_urn_[in.account];
    if (o->urn <= last) {
      // A client re-sent an order whose acknowledgement it never saw (plan 10 §3).
      SIM_PROBE("client.resend_after_lost_ack");
      ++duplicates_;
      return;
    }
    last = o->urn;
    accepted(in.account, index, o->urn);
    std::uint32_t left = o->qty;
    if (o->side == 'B') {
      while (left > 0 && !asks_.empty() && asks_.begin()->first <= o->px) {
        left = cross(index, in.account, o->urn, left, asks_.begin()->first, asks_.begin()->second);
        if (asks_.begin()->second.empty()) asks_.erase(asks_.begin());
      }
      if (left > 0) bids_[o->px].push_back(Resting{in.account, o->urn, left});
    } else {
      while (left > 0 && !bids_.empty() && bids_.rbegin()->first >= o->px) {
        auto it = std::prev(bids_.end());
        left = cross(index, in.account, o->urn, left, it->first, it->second);
        if (it->second.empty()) bids_.erase(it);
      }
      if (left > 0) asks_[o->px].push_back(Resting{in.account, o->urn, left});
    }
  }

  std::uint32_t cross(std::uint64_t index, std::uint32_t account, std::uint32_t urn, std::uint32_t left,
                      std::uint32_t px, std::deque<Resting>& level) {
    while (left > 0 && !level.empty()) {
      Resting& r = level.front();
      const std::uint32_t q = std::min(left, r.qty);
      ++match_no_;
      ++executions_;
      executed(account, index, urn, q, px);
      executed(r.account, index, r.urn, q, px);
      left -= q;
      r.qty -= q;
      r.filled += q;
      if (r.qty == 0) level.pop_front();
    }
    return left;
  }

  void on_session(const journal::SessionEvent& ev) {
    const std::uint64_t key = (static_cast<std::uint64_t>(ev.session_id) << 16) | ev.instance;
    switch (ev.event) {
      case journal::SessionEventKind::Login:
      case journal::SessionEventKind::MirrorAttach:
        instances_[key] = true;
        break;
      case journal::SessionEventKind::Logout:
      case journal::SessionEventKind::Disconnect:
      case journal::SessionEventKind::InstanceDown:
        instances_[key] = false;
        break;
    }
  }

  std::uint64_t applied_ = 0;
  std::uint64_t hash_ = 0;
  std::uint64_t match_no_ = 0;
  std::uint64_t executions_ = 0;
  std::uint64_t duplicates_ = 0;
  std::map<std::uint32_t, std::uint32_t> last_urn_;
  std::map<std::uint64_t, bool> instances_;
  std::map<std::uint32_t, SessionStream> sessions_;
  Side bids_;
  Side asks_;
};

}  // namespace lle::sim::ha
