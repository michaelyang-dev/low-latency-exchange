#include "witness/witness.h"

#include <cstring>
#include <type_traits>

#include "common/assert.h"
#include "common/crc32c.h"
#include "common/endian.h"
#include "env/buggify.h"

namespace lle::witness {
namespace {

constexpr char kSlotMagic[8] = {'L', 'L', 'E', 'W', 'I', 'T', '0', '1'};
constexpr std::uint32_t kSlotVersion = 1;
constexpr std::size_t kCrcOffset = kSlotBytes - 4;

bool zero(const std::byte* p, std::size_t n) noexcept {
  for (std::size_t i = 0; i < n; ++i)
    if (p[i] != std::byte{0}) return false;
  return true;
}

bool valid_request(MsgType t) noexcept { return t == MsgType::kPromote || t == MsgType::kSolo || t == MsgType::kJoin || t == MsgType::kResume; }

// Whether a request whose key equals last_grant asks for what that grant gave.
// The key (type, sender, from_epoch, sender incarnation) covers every field of
// PROMOTE, SOLO and RESUME that the grant depends on. JOIN also names the
// joiner's incarnation; the grant recorded it in inc[], and since last_grant is
// always the latest grant, the current state still holds it.
template <class Req>
bool repeats_grant(const State&, const Req&) noexcept {
  return true;
}
bool repeats_grant(const State& s, const Join& j) noexcept {
  return is_member(s.members, j.node) && s.inc[j.node] == j.node_incarnation;
}

}  // namespace

bool valid_state(const State& s) noexcept {
  if (s.epoch == 0 || !valid_node(s.primary) || !valid_members(s.members) || !is_member(s.members, s.primary))
    return false;
  if (s.last_grant.valid && (!valid_request(s.last_grant.request) || !valid_node(s.last_grant.node))) return false;
  return true;
}

// Layout (little-endian):
//   0 magic "LLEWIT01" | 8 u32 version | 12 u32 zero | 16 u64 generation
//   24 u64 epoch | 32 u8 primary | 33 u8 members | 34..40 zero
//   40 u64 inc[0] | 48 u64 inc[1]
//   56 u8 last_grant.request (0 = none) | 57 u8 last_grant.node | 58..64 zero
//   64 u64 last_grant.from_epoch | 72 u64 last_grant.incarnation
//   80..4092 zero | 4092 u32 CRC32C over [0, 4092)
SlotImage encode_slot(const State& s, std::uint64_t generation) noexcept {
  SlotImage img{};
  std::byte* p = img.data();
  std::memcpy(p, kSlotMagic, sizeof kSlotMagic);
  store_le32(p + 8, kSlotVersion);
  store_le64(p + 16, generation);
  store_le64(p + 24, s.epoch);
  p[32] = static_cast<std::byte>(s.primary);
  p[33] = static_cast<std::byte>(s.members);
  store_le64(p + 40, s.inc[0]);
  store_le64(p + 48, s.inc[1]);
  if (s.last_grant.valid) {
    p[56] = static_cast<std::byte>(s.last_grant.request);
    p[57] = static_cast<std::byte>(s.last_grant.node);
    store_le64(p + 64, s.last_grant.from_epoch);
    store_le64(p + 72, s.last_grant.incarnation);
  }
  store_le32(p + kCrcOffset, crc32c(p, kCrcOffset));
  return img;
}

std::optional<Durable> decode_slot(std::span<const std::byte> image, std::size_t slot) noexcept {
  if (image.size() != kSlotBytes) return std::nullopt;
  const std::byte* p = image.data();
  if (std::memcmp(p, kSlotMagic, sizeof kSlotMagic) != 0) return std::nullopt;
  if (load_le32(p + kCrcOffset) != crc32c(p, kCrcOffset)) return std::nullopt;
  if (load_le32(p + 8) != kSlotVersion || load_le32(p + 12) != 0) return std::nullopt;
  if (!zero(p + 34, 6) || !zero(p + 58, 6) || !zero(p + 80, kCrcOffset - 80)) return std::nullopt;
  Durable d;
  d.slot = slot;
  d.generation = load_le64(p + 16);
  State& s = d.state;
  s.epoch = load_le64(p + 24);
  s.primary = static_cast<NodeId>(p[32]);
  s.members = static_cast<Members>(p[33]);
  s.inc[0] = load_le64(p + 40);
  s.inc[1] = load_le64(p + 48);
  const auto req = static_cast<std::uint8_t>(p[56]);
  if (req != 0) {
    s.last_grant.valid = true;
    s.last_grant.request = static_cast<MsgType>(req);
    s.last_grant.node = static_cast<NodeId>(p[57]);
    s.last_grant.from_epoch = load_le64(p + 64);
    s.last_grant.incarnation = load_le64(p + 72);
  } else if (p[57] != std::byte{0} || load_le64(p + 64) != 0 || load_le64(p + 72) != 0) {
    return std::nullopt;
  }
  if (d.generation == 0 || !valid_state(s)) return std::nullopt;
  return d;
}

std::optional<Durable> choose(std::span<const std::byte> slot0, std::span<const std::byte> slot1) noexcept {
  const std::optional<Durable> a = decode_slot(slot0, 0);
  const std::optional<Durable> b = decode_slot(slot1, 1);
  if (a && b) return a->generation >= b->generation ? a : b;
  return a ? a : b;
}

Witness::Witness(const Config& cfg, const Durable& durable, Nanos started_at)
    : cfg_(cfg),
      started_at_(started_at),
      state_(durable.state),
      generation_(durable.generation),
      durable_generation_(durable.generation),
      durable_slot_(durable.slot) {
  LLE_ASSERT(valid_state(state_), "witness started from an invalid state");
  LLE_ASSERT(durable_slot_ < kSlots, "bad slot");
}

bool Witness::superseded(NodeId node, std::uint64_t inc) const noexcept {
  const Heard& h = heard_[node];
  return h.any && inc < h.incarnation;
}

bool Witness::hears_primary(Nanos now) const noexcept {
  if (now - started_at_ < cfg_.tie_break_ns) return true;  // too early to judge silence
  const Heard& h = heard_[state_.primary];
  return h.any && h.incarnation == state_.inc[state_.primary] && now - h.at < cfg_.tie_break_ns;
}

void Witness::handle(const Message& m, const env::Endpoint& from, Nanos now) {
  if (failed_) return;
  if (const auto* hb = std::get_if<Heartbeat>(&m)) {
    ++stats_.heartbeats;
    Heard& h = heard_[hb->node];
    // A heartbeat from an older incarnation never replaces a newer one's.
    if (!h.any || hb->incarnation >= h.incarnation) h = Heard{hb->incarnation, now, true, from};
  } else if (const auto* p = std::get_if<Promote>(&m)) {
    on_request(*p, MsgType::kPromote, p->candidate, p->incarnation, from, now);
  } else if (const auto* s = std::get_if<Solo>(&m)) {
    on_request(*s, MsgType::kSolo, s->primary, s->incarnation, from, now);
  } else if (const auto* j = std::get_if<Join>(&m)) {
    on_request(*j, MsgType::kJoin, j->primary, j->primary_incarnation, from, now);
  } else if (const auto* r = std::get_if<Resume>(&m)) {
    on_request(*r, MsgType::kResume, r->node, r->incarnation, from, now);
  }
  // GRANT and REJECT flow only from W; anything else is ignored.
}

template <class Req>
void Witness::on_request(const Req& r, MsgType type, NodeId node, std::uint64_t inc, const env::Endpoint& from,
                         Nanos now) {
  const LastGrant key{type, node, r.from_epoch, inc, true};
  if (state_.last_grant == key && repeats_grant(state_, r)) {
    // A retransmission of the request W last granted (its GRANT was lost):
    // answer with the same grant. last_grant is always the latest grant, so the
    // current configuration is exactly what was granted.
    ++stats_.duplicate_grants;
    SIM_PROBE("witness.retransmission_answered_from_last_grant");
    reply_grant(type, node, inc, r.from_epoch, from);
    if constexpr (std::is_same_v<Req, Join>) notify_joiner(r);
    return;
  }
  // A request from an incarnation older than one W has already heard from that
  // node comes from a dead process: refuse it before it can be granted (for a
  // JOIN this covers the joiner too). Safety-neutral, narrows stale-JOIN windows.
  bool stale = superseded(node, inc);
  if constexpr (std::is_same_v<Req, Join>) stale = stale || superseded(r.node, r.node_incarnation);
  if (stale) {
    ++stats_.rejects;
    SIM_PROBE("witness.request_from_superseded_incarnation");
    reply_reject(type, RejectReason::kWrongIncarnation, node, inc, r.from_epoch, from);
    return;
  }
  if (const std::optional<RejectReason> why = check(r, now)) {
    ++stats_.rejects;
    if (*why == RejectReason::kPrimaryAlive) SIM_PROBE("witness.promote_refused_primary_heard");
    if (*why == RejectReason::kStaleEpoch) SIM_PROBE("witness.request_from_stale_epoch");
    reply_reject(type, *why, node, inc, r.from_epoch, from);
    return;
  }
  apply(r);
  state_.epoch += 1;
  state_.last_grant = key;
  ++generation_;
  ++stats_.grants;
  if (type == MsgType::kPromote) SIM_PROBE("witness.grant_promote");
  if (type == MsgType::kResume) SIM_PROBE("witness.grant_resume");
  reply_grant(type, node, inc, r.from_epoch, from);
  if constexpr (std::is_same_v<Req, Join>) notify_joiner(r);
}

// The joiner learns of its admission directly, addressed to the incarnation W
// recorded for it, in case the primary dies before relaying the grant.
void Witness::notify_joiner(const Join& j) {
  const Heard& h = heard_[j.node];
  if (!h.any) return;  // never heard from it: the primary's relay is the only path
  const Grant g{state_.epoch, state_.primary, state_.members, MsgType::kJoin, j.node, state_.inc[j.node], j.from_epoch};
  outbox_.push_back(Out{generation_, h.from, encode(g)});
}

std::optional<RejectReason> Witness::check(const Promote& r, Nanos now) const noexcept {
  if (r.from_epoch != state_.epoch) return RejectReason::kStaleEpoch;
  if (!is_member(state_.members, r.candidate)) return RejectReason::kNotMember;
  if (r.candidate == state_.primary) return RejectReason::kIsPrimary;
  if (r.incarnation != state_.inc[r.candidate]) return RejectReason::kWrongIncarnation;
  if (hears_primary(now)) return RejectReason::kPrimaryAlive;  // liveness tie-break only
  return std::nullopt;
}

std::optional<RejectReason> Witness::check(const Solo& r, Nanos) const noexcept {
  if (r.from_epoch != state_.epoch) return RejectReason::kStaleEpoch;
  if (r.primary != state_.primary) return RejectReason::kNotPrimary;
  if (r.incarnation != state_.inc[r.primary]) return RejectReason::kWrongIncarnation;
  return std::nullopt;
}

std::optional<RejectReason> Witness::check(const Join& r, Nanos) const noexcept {
  if (r.from_epoch != state_.epoch) return RejectReason::kStaleEpoch;
  if (r.primary != state_.primary) return RejectReason::kNotPrimary;
  if (r.primary_incarnation != state_.inc[r.primary]) return RejectReason::kWrongIncarnation;
  if (is_member(state_.members, r.node)) return RejectReason::kAlreadyMember;
  return std::nullopt;
}

std::optional<RejectReason> Witness::check(const Resume& r, Nanos) const noexcept {
  if (r.from_epoch != state_.epoch) return RejectReason::kStaleEpoch;
  if (r.node != state_.primary) return RejectReason::kNotPrimary;
  if (state_.members != member_bit(r.node)) return RejectReason::kNotSoloOfRecord;
  if (r.incarnation <= state_.inc[r.node]) return RejectReason::kWrongIncarnation;
  return std::nullopt;
}

void Witness::apply(const Promote& r) noexcept {
  state_.primary = r.candidate;
  state_.members = member_bit(r.candidate);
}
void Witness::apply(const Solo& r) noexcept { state_.members = member_bit(r.primary); }
void Witness::apply(const Join& r) noexcept {
  state_.members = static_cast<Members>(state_.members | member_bit(r.node));
  state_.inc[r.node] = r.node_incarnation;
}
void Witness::apply(const Resume& r) noexcept { state_.inc[r.node] = r.incarnation; }

void Witness::reply_grant(MsgType type, NodeId node, std::uint64_t inc, std::uint64_t from_epoch,
                          const env::Endpoint& to) {
  const Grant g{state_.epoch, state_.primary, state_.members, type, node, inc, from_epoch};
  outbox_.push_back(Out{generation_, to, encode(g)});
}

void Witness::reply_reject(MsgType type, RejectReason why, NodeId node, std::uint64_t inc, std::uint64_t from_epoch,
                           const env::Endpoint& to) {
  const Reject r{state_.epoch, state_.primary, state_.members, type, why, node, inc, from_epoch};
  outbox_.push_back(Out{generation_, to, encode(r)});
}

std::optional<SlotWrite> Witness::begin_write() {
  if (failed_ || inflight_ || generation_ == durable_generation_) return std::nullopt;
  const std::size_t slot = 1 - durable_slot_;  // never overwrite the newest durable image
  inflight_ = generation_;
  inflight_slot_ = slot;
  return SlotWrite{generation_, slot, encode_slot(state_, generation_)};
}

void Witness::on_persisted(std::uint64_t generation) {
  LLE_ASSERT(inflight_ && *inflight_ == generation, "on_persisted for a write that is not in flight");
  durable_generation_ = generation;
  durable_slot_ = inflight_slot_;
  inflight_.reset();
}

}  // namespace lle::witness
