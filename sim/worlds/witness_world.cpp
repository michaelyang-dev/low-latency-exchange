// witness world (09 §2 `ha` precursor; 10 §1–§5): the production witness core
// (src/witness) on node W, driven the way witnessd drives it, with its state
// file on the simulated disk, and two scripted data-node actors A and B that
// follow the control-plane rules of 10 §2–§5 over the simulated network:
// HEARTBEAT_W every 1 ms, PROMOTE / SOLO / JOIN / RESUME with retransmission,
// incarnation bumps on restart, deposed primaries exit, rejoin by JOIN.
// The data plane (APPEND / ACK, journals) is abstracted to peer heartbeats: a
// primary counts its backup as acking only while the backup's heartbeat says
// BACKUP, so a frozen candidate (which never thaws, 10 §4) drives it to SOLO.
//
// Oracles (outside process memory, fed by taps on W's sends and writes and by
// the actors' state changes):
//   O-WITNESS-GRANT    one grant per epoch; every announced (epoch, config) is
//                      unique; a grant's epoch is from_epoch + 1
//   O-WITNESS-DURABLE  W always restarts from a valid slot whose epoch is at
//                      least every epoch it ever announced (persist-before-reply,
//                      newest slot never overwritten)
//   O-WITNESS-INC      nodes act only on grants addressed to their incarnation,
//                      and a configuration member runs the incarnation W recorded
//   O-ONE-PRIMARY      at most one node acts as primary per epoch
//   O-WITNESS-CUT      (cut scenario) a cut A–B link with both nodes alive never
//                      yields a takeover, and ends in solo mode on A
//   O-LIVE             after healing: paired, consistent with W, all durable
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "env/buggify.h"
#include "env/concepts.h"
#include "sim/dist.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/worlds/worlds.h"
#include "witness/control.h"
#include "witness/witness.h"

namespace lle::sim::worlds::detail {

namespace {

namespace wit = lle::witness;

constexpr std::uint16_t kWitnessPort = 7300;
constexpr std::uint16_t kNodePort = 7400;
constexpr char kStateFile[] = "witness.state";
constexpr std::size_t kStateBytes = wit::kSlotBytes * wit::kSlots;
constexpr Nanos kHeartbeatNs = kMs;  // HEARTBEAT_W and peer heartbeats (10 §3)
constexpr Nanos kTieBreakNs = 5 * kMs;  // T_w < T_d (10 §4)

// ---- peer heartbeat between A and B (stands in for the data plane) --------
constexpr std::uint32_t kPeerMagic = 0x52454550u;  // "PEER"
constexpr std::size_t kPeerBytes = 40;
struct PeerHb {
  wit::NodeId node = 0;
  wit::Role role = wit::Role::kBackup;
  wit::Members members = 0;
  wit::NodeId primary = 0;
  std::uint64_t epoch = 0;
  std::uint64_t inc = 0;
  // Paired primary: the backup incarnation it paired with. Solo primary with a
  // JOIN in flight: the joiner incarnation it relayed (the handshake marker).
  std::uint64_t joined_inc = 0;
};

std::array<std::byte, kPeerBytes> encode_peer(const PeerHb& h) {
  std::array<std::byte, kPeerBytes> b{};
  store_le32(b.data(), kPeerMagic);
  b[4] = static_cast<std::byte>(h.node);
  b[5] = static_cast<std::byte>(h.role);
  b[6] = static_cast<std::byte>(h.members);
  b[7] = static_cast<std::byte>(h.primary);
  store_le64(b.data() + 8, h.epoch);
  store_le64(b.data() + 16, h.inc);
  store_le64(b.data() + 24, h.joined_inc);
  return b;
}

std::optional<PeerHb> decode_peer(std::span<const std::byte> b) {
  if (b.size() != kPeerBytes || load_le32(b.data()) != kPeerMagic) return std::nullopt;
  PeerHb h;
  h.node = static_cast<wit::NodeId>(b[4]);
  h.role = static_cast<wit::Role>(b[5]);
  h.members = static_cast<wit::Members>(b[6]);
  h.primary = static_cast<wit::NodeId>(b[7]);
  h.epoch = load_le64(b.data() + 8);
  h.inc = load_le64(b.data() + 16);
  h.joined_inc = load_le64(b.data() + 24);
  if (!wit::valid_node(h.node) || !wit::valid_node(h.primary)) return std::nullopt;
  return h;
}

bool is_primary_role(wit::Role r) { return r == wit::Role::kPrimary || r == wit::Role::kSoloPrimary; }

std::string cfg_str(std::uint64_t epoch, wit::NodeId primary, wit::Members members) {
  return "{epoch " + std::to_string(epoch) + " primary " + std::to_string(primary) + " members " +
         std::to_string(members) + "}";
}

struct NodeActor;
struct WitnessProc;

// ---- harness: oracles and the world's view of every process ----------------
struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_grant = 0;
  OracleId o_durable = 0;
  OracleId o_inc = 0;
  OracleId o_one = 0;
  OracleId o_cut = 0;
  bool cut = false;
  bool verbose = false;
  NodeId w_node = 2;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  struct Announced {
    wit::NodeId primary = 0;
    wit::Members members = 0;
    std::optional<wit::Grant> grant;   // the first copy: the epoch's decree
    std::vector<wit::Grant> copies;     // every GRANT W sent for the epoch (a JOIN grant has two)
  };
  std::map<std::uint64_t, Announced> announced;   // epoch -> what W told the world
  std::uint64_t max_announced = 0;
  std::map<std::uint64_t, wit::State> persisted;  // epoch -> state W made durable
  std::map<std::uint64_t, wit::NodeId> primary_of_epoch;
  std::array<NodeActor*, wit::kNodes> actors{};
  WitnessProc* witness = nullptr;

  std::uint64_t w_starts = 0;
  std::uint64_t takeovers = 0;
  std::uint64_t solos = 0;
  std::uint64_t joins = 0;
  std::uint64_t resumes = 0;
  std::uint64_t deposed = 0;

  void announce_config(std::uint64_t epoch, wit::NodeId primary, wit::Members members, const char* what) {
    auto [it, fresh] = announced.try_emplace(epoch, Announced{primary, members, std::nullopt, {}});
    if (!fresh && (it->second.primary != primary || it->second.members != members)) {
      o->fail(o_grant, std::string(what) + " announces " + cfg_str(epoch, primary, members) + " but W announced " +
                           cfg_str(epoch, it->second.primary, it->second.members) + " before");
      return;
    }
    if (epoch > max_announced) max_announced = epoch;
  }

  void on_w_send(std::span<const std::byte> bytes) {
    const auto m = wit::decode(bytes);
    LLE_ASSERT(m.has_value(), "W sent an undecodable datagram");
    if (const auto* g = std::get_if<wit::Grant>(&*m)) {
      log("W sends GRANT %s %s to n%u inc %llu from_epoch %llu", wit::to_string(g->request),
          cfg_str(g->epoch, g->primary, g->members).c_str(), g->to_node, static_cast<unsigned long long>(g->incarnation), static_cast<unsigned long long>(g->from_epoch));
      if (g->epoch != g->from_epoch + 1) {
        o->fail(o_grant, "grant epoch " + std::to_string(g->epoch) + " != from_epoch + 1");
        return;
      }
      announce_config(g->epoch, g->primary, g->members, "GRANT");
      Announced& a = announced[g->epoch];
      // One decree per epoch. A JOIN grant goes to two recipients (the primary and
      // the joiner, each at its own incarnation), so recipient fields may differ.
      if (a.grant && !(a.grant->primary == g->primary && a.grant->members == g->members &&
                       a.grant->request == g->request && a.grant->from_epoch == g->from_epoch)) {
        o->fail(o_grant, "two different grants for epoch " + std::to_string(g->epoch));
        return;
      }
      if (std::find(a.copies.begin(), a.copies.end(), *g) == a.copies.end()) a.copies.push_back(*g);
      if (!a.grant) {
        a.grant = *g;
        o->pass(o_grant);
        if (g->request == wit::MsgType::kPromote) {
          ++takeovers;
          if (cut) o->fail(o_cut, "takeover (PROMOTE granted) while the A-B link is cut and both nodes are alive");
        }
      }
    } else if (const auto* r = std::get_if<wit::Reject>(&*m)) {
      log("W sends REJECT %s (%s) %s to n%u inc %llu from_epoch %llu", wit::to_string(r->request),
          wit::to_string(r->reason), cfg_str(r->epoch, r->primary, r->members).c_str(), r->to_node,
          static_cast<unsigned long long>(r->incarnation), static_cast<unsigned long long>(r->from_epoch));
      announce_config(r->epoch, r->primary, r->members, "REJECT");
    }
  }

  void on_persisted(const wit::State& s) {
    log("W persisted %s inc [%llu, %llu]", cfg_str(s.epoch, s.primary, s.members).c_str(), static_cast<unsigned long long>(s.inc[0]),
        static_cast<unsigned long long>(s.inc[1]));
    auto [it, fresh] = persisted.try_emplace(s.epoch, s);
    if (!fresh && !(it->second == s)) o->fail(o_durable, "two different states made durable for epoch " +
                                                             std::to_string(s.epoch));
  }

  void on_w_start(const std::optional<wit::Durable>& d) {
    ++w_starts;
    if (d) {
      log("W starts from slot %zu gen %llu %s inc [%llu, %llu]", d->slot, static_cast<unsigned long long>(d->generation),
          cfg_str(d->state.epoch, d->state.primary, d->state.members).c_str(), static_cast<unsigned long long>(d->state.inc[0]),
          static_cast<unsigned long long>(d->state.inc[1]));
    }
    if (!d) {
      o->fail(o_durable, "no valid state slot: W refuses to start");
      return;
    }
    const wit::State& s = d->state;
    if (s.epoch < max_announced) {
      o->fail(o_durable, "W restarted at epoch " + std::to_string(s.epoch) + " below announced epoch " +
                             std::to_string(max_announced));
      return;
    }
    if (const auto it = announced.find(s.epoch);
        it != announced.end() && (it->second.primary != s.primary || it->second.members != s.members)) {
      o->fail(o_durable, "W restarted with " + cfg_str(s.epoch, s.primary, s.members) + " but announced " +
                             cfg_str(s.epoch, it->second.primary, it->second.members));
      return;
    }
    o->pass(o_durable);
  }

  // A node acts on a grant: it must be the one W announced, for this incarnation.
  void on_grant_applied(wit::NodeId node, std::uint64_t inc, const wit::Grant& g) {
    const auto it = announced.find(g.epoch);
    if (g.to_node != node || g.incarnation != inc) {
      o->fail(o_inc, "node " + std::to_string(node) + " (inc " + std::to_string(inc) +
                         ") acted on a grant for node " + std::to_string(g.to_node) + " inc " +
                         std::to_string(g.incarnation));
    } else if (it == announced.end() ||
               std::find(it->second.copies.begin(), it->second.copies.end(), g) == it->second.copies.end()) {
      o->fail(o_inc, "node " + std::to_string(node) + " acted on a grant W never sent (epoch " +
                         std::to_string(g.epoch) + ")");
    } else {
      o->pass(o_inc);
    }
  }

  // A configuration member must run the incarnation W recorded for it.
  void check_member_inc(wit::NodeId node, std::uint64_t inc, std::uint64_t epoch, const char* when) {
    const auto it = persisted.find(epoch);
    if (it == persisted.end()) return;  // durable but its completion was never observed (process crash)
    if (it->second.inc[node] != inc) {
      o->fail(o_inc, std::string(when) + ": node " + std::to_string(node) + " is a member at epoch " +
                         std::to_string(epoch) + " running incarnation " + std::to_string(inc) +
                         " but W recorded incarnation " + std::to_string(it->second.inc[node]));
    } else {
      o->pass(o_inc);
    }
  }

  void on_role(wit::NodeId node, wit::Role role, std::uint64_t epoch) {
    if (!is_primary_role(role)) return;
    auto [it, fresh] = primary_of_epoch.try_emplace(epoch, node);
    if (!fresh && it->second != node) {
      o->fail(o_one, "nodes " + std::to_string(it->second) + " and " + std::to_string(node) +
                         " both act as primary in epoch " + std::to_string(epoch));
    } else {
      o->pass(o_one);
    }
  }
};

// ---- W: the production core driven like apps/witnessd ----------------------
struct WitnessProc : Process {
  struct Stage {
    WitnessProc* p;
    bool poll() { return p->poll(); }
  };

  WitnessProc(Node& n, Harness& h) : node_(n), h_(h), port(n, kWitnessPort), file(n, kStateFile), stage{this} {
    std::array<std::byte, kStateBytes> img{};
    (void)file.read(0, img);
    const auto d = wit::choose(std::span<const std::byte>(img).first(wit::kSlotBytes),
                               std::span<const std::byte>(img).subspan(wit::kSlotBytes));
    h_.on_w_start(d);
    if (!d) return;  // W refuses to start (the oracle has already failed the run)
    if (!wit::decode_slot(std::span<const std::byte>(img).first(wit::kSlotBytes), 0) ||
        !wit::decode_slot(std::span<const std::byte>(img).subspan(wit::kSlotBytes), 1)) {
      SIM_PROBE("witness.start_with_one_invalid_slot");
    }
    core.emplace(wit::Config{kTieBreakNs}, *d, n.clock().now_mono());
    h_.witness = this;
    n.add_stage(stage, "witness");
  }
  ~WitnessProc() override {
    if (h_.witness == this) h_.witness = nullptr;
  }

  bool poll() {
    bool did = false;
    file.poll([&](const env::DiskCompletion& c) {
      did = true;
      writing_ = false;
      if (failed_) return;
      if (c.result < 0) {
        // witnessd: a failed state write stops W; the operator restarts it.
        core->on_write_failed();
        failed_ = true;
        SIM_PROBE("witness.write_failed_restart");
        node_.request_crash();
        return;
      }
      core->on_persisted(c.tag);
      h_.on_persisted(writing_state_);
    });
    if (failed_) return did;
    const Nanos now = node_.clock().now_mono();
    port.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      const auto m = wit::decode(d.data);
      if (m) core->handle(*m, d.src, now);  // not ours or damaged: dropped, as witnessd does
    });
    if (!writing_) {
      if (auto job = core->begin_write()) {
        writing_state_ = wit::decode_slot(job->image, job->slot)->state;
        // O_DSYNC pwrite to the slot that does not hold the newest durable image.
        LLE_ASSERT(file.submit_write(job->slot * wit::kSlotBytes, job->image, /*dsync=*/true, job->generation));
        writing_ = true;
        did = true;
      }
    }
    if (writing_ && core->pending_replies() > 0) SIM_PROBE("witness.reply_waits_for_persist");
    core->drain([&](const env::Endpoint& to, std::span<const std::byte> b) {
      h_.on_w_send(b);
      port.send(to, b);
      did = true;
    });
    return did;
  }

  [[nodiscard]] bool settled() const { return core && !failed_ && core->generation() == core->durable_generation(); }

  Node& node_;
  Harness& h_;
  DatagramPort port;
  DiskFile file;
  std::optional<wit::Witness> core;
  bool writing_ = false;
  bool failed_ = false;
  wit::State writing_state_{};
  Stage stage;
};

// ---- data-node actor: control plane of 10 §2–§5 ----------------------------
struct ActorTiming {
  Nanos t_d = 15 * kMs;    // backup suspects the primary
  Nanos t_ack = 8 * kMs;   // primary suspects the backup (< T_d)
  Nanos retry = 3 * kMs;   // request retransmission
  Nanos catchup = 5 * kMs; // rejoin catch-up before JOIN
};

struct NodeActor {
  struct Pending {
    wit::Message msg;
    wit::MsgType type = wit::MsgType::kPromote;
    std::uint64_t from_epoch = 0;
    std::uint64_t joiner_inc = 0;
    Nanos next_send = 0;
    std::uint32_t sends = 0;
    std::uint32_t unanswered = 0;  // sends since W last answered this request
  };

  NodeActor(Node& n, Harness& h, DatagramPort& port, wit::NodeId me, const ActorTiming& t, env::Endpoint w_ep,
            env::Endpoint peer_ep)
      : node_(n), h_(h), port_(port), me_(me), peer_(static_cast<wit::NodeId>(1 - me)), t_(t), w_ep_(w_ep),
        peer_ep_(peer_ep), inc_(n.incarnation()) {
    const Nanos now = n.clock().now_mono();
    last_primary_seen_ = last_backup_seen_ = now;
    h_.log("n%u boots inc %llu", me_, static_cast<unsigned long long>(inc_));
    if (n.incarnation() == 0) {
      // As initialized by `witnessd --init --primary 0`: epoch 1, members {A, B}.
      epoch_ = 1;
      primary_ = 0;
      members_ = 0b11;
      backup_inc_ = 0;
      role_ = me_ == 0 ? wit::Role::kPrimary : wit::Role::kBackup;
      h_.on_role(me_, role_, epoch_);
    } else {
      // Restart: local recovery, then RECOVERING with a new incarnation (10 §5).
      role_ = wit::Role::kRecovering;
      request(wit::Resume{epoch_, me_, inc_}, wit::MsgType::kResume, epoch_, now);
    }
    h_.actors[me_] = this;
  }
  ~NodeActor() {
    if (h_.actors[me_] == this) h_.actors[me_] = nullptr;
  }

  bool poll() {
    bool did = false;
    const Nanos now = node_.clock().now_mono();
    port_.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      if (const auto hb = decode_peer(d.data)) {
        on_peer(*hb, now);
        return;
      }
      const auto m = wit::decode(d.data);
      if (!m) return;
      if (const auto* g = std::get_if<wit::Grant>(&*m)) on_grant(*g, now);
      if (const auto* r = std::get_if<wit::Reject>(&*m)) on_reject(*r, now);
    });
    if (exiting_) return did;
    if (now >= next_hb_) {
      next_hb_ = now + kHeartbeatNs;
      send_w(wit::Heartbeat{me_, role_, inc_, epoch_});
      const bool joining = role_ == wit::Role::kSoloPrimary && pending_ && pending_->type == wit::MsgType::kJoin;
      const auto hb =
          encode_peer(PeerHb{me_, role_, members_, primary_, epoch_, inc_, joining ? pending_->joiner_inc : backup_inc_});
      port_.send(peer_ep_, hb);
      did = true;
    }
    did = drive(now) || did;
    if (pending_ && now >= pending_->next_send) {
      if (pending_->sends > 0) SIM_PROBE("witness_world.request_retransmitted");
      if (pending_->type == wit::MsgType::kPromote && pending_->unanswered == 20) {
        SIM_PROBE("ha.witness_unreachable_during_promotion", rare);
      }
      send_w(pending_->msg);
      ++pending_->sends;
      ++pending_->unanswered;
      pending_->next_send = now + t_.retry;
      did = true;
    }
    return did;
  }

  // Role timers.
  bool drive(Nanos now) {
    switch (role_) {
      case wit::Role::kBackup:
        if (!pending_ && now - last_primary_seen_ > t_.t_d) {
          // Freeze, flush to L3, then PROMOTE (10 §4 steps 1-2).
          role_ = wit::Role::kCandidate;
          request(wit::Promote{epoch_, me_, inc_, 0}, wit::MsgType::kPromote, epoch_, now);
          return true;
        }
        return false;
      case wit::Role::kPrimary:
        if (!pending_ && now - last_backup_seen_ > t_.t_ack) {
          // Backup loss: stop releasing, flush to L3, SOLO.
          request(wit::Solo{epoch_, me_, inc_}, wit::MsgType::kSolo, epoch_, now);
          return true;
        }
        return false;
      case wit::Role::kSoloPrimary: {
        const bool peer_recovering = have_peer_ && peer_hb_.role == wit::Role::kRecovering && now - peer_at_ < 3 * kMs;
        if (!peer_recovering) {
          recovering_since_ = -1;
          return false;
        }
        if (recovering_since_ < 0) recovering_since_ = now;
        // A JOIN in flight is retransmitted unchanged until W answers, even if
        // the joiner restarts meanwhile: a GRANT does not name the joiner's
        // incarnation, so a second JOIN at the same epoch would be ambiguous.
        // A grant for a dead incarnation is undone by the T_ack -> SOLO path.
        if (!pending_ && now - recovering_since_ >= t_.catchup) {
          // Zero lag reached with release paused (10 §5): relay JOIN.
          request(wit::Join{epoch_, me_, peer_, inc_, peer_hb_.inc, 0}, wit::MsgType::kJoin, epoch_, now, peer_hb_.inc);
          return true;
        }
        return false;
      }
      case wit::Role::kRecovering:
        // Proposed resolution (reported): a joiner that saw the primary relay
        // JOIN for its incarnation and then loses the primary asks W to
        // promote it. W's membership, incarnation and tie-break checks decide;
        // the joiner was at zero lag with the primary's release paused.
        if (!pending_ && handshake_epoch_ != 0 && now - peer_at_ > t_.t_d) {
          SIM_PROBE("witness_world.joiner_promotes_after_handshake");
          request(wit::Promote{handshake_epoch_ + 1, me_, inc_, 0}, wit::MsgType::kPromote, handshake_epoch_ + 1, now);
          return true;
        }
        return false;
      case wit::Role::kCandidate:
        return false;
    }
    return false;
  }

  void on_peer(const PeerHb& hb, Nanos now) {
    if (hb.node != peer_) return;
    have_peer_ = true;
    peer_hb_ = hb;
    peer_at_ = now;
    if (role_ == wit::Role::kBackup && hb.role == wit::Role::kPrimary && hb.epoch == epoch_ && hb.node == primary_) {
      last_primary_seen_ = now;
    }
    if (role_ == wit::Role::kPrimary && hb.role == wit::Role::kBackup && hb.epoch == epoch_ && hb.inc == backup_inc_) {
      last_backup_seen_ = now;
    }
    if (role_ == wit::Role::kRecovering && hb.role == wit::Role::kSoloPrimary && hb.joined_inc == inc_) {
      handshake_epoch_ = hb.epoch;  // the primary relays JOIN for this incarnation
    }
    if (hb.epoch > epoch_ && is_primary_role(hb.role)) {
      if (is_primary_role(role_)) {
        deposed("peer leads a newer epoch");
        return;
      }
      if (pending_ && pending_->type == wit::MsgType::kPromote) {
        // A PROMOTE in flight may still be granted: wait for W's verdict
        // rather than adopt a configuration W may already have superseded.
      } else if (wit::is_member(hb.members, me_) && hb.joined_inc == inc_) {
        // The primary's JOIN for this incarnation was granted: paired as backup.
        if (role_ == wit::Role::kRecovering) SIM_PROBE("witness_world.rejoined");
        h_.check_member_inc(me_, inc_, hb.epoch, "joiner adopts the configuration");
        adopt(hb.epoch, hb.primary, hb.members, wit::Role::kBackup, now);
      } else if (role_ != wit::Role::kRecovering) {
        set_role(wit::Role::kRecovering);
        epoch_ = hb.epoch;
        pending_.reset();
      }
    }
  }

  void on_grant(const wit::Grant& g, Nanos now) {
    if (g.to_node != me_ || g.incarnation != inc_) {
      SIM_PROBE("witness_world.stale_grant_ignored");  // e.g. addressed to my previous incarnation
      return;
    }
    if (g.epoch <= epoch_) return;  // duplicate of a grant already acted on
    const bool matches = pending_ && g.request == pending_->type && g.from_epoch == pending_->from_epoch;
    if (!matches) {
      // As RecvGrant in HotStandby.tla: a grant for this incarnation and a newer
      // epoch is acted on in a compatible role even if the request that earned it
      // is no longer pending (an earlier copy was rejected, a later one granted).
      // A JOIN grant needs the relayed joiner incarnation, so only a pending one.
      const bool ok = (g.request == wit::MsgType::kPromote &&
                       (role_ == wit::Role::kCandidate || role_ == wit::Role::kRecovering || role_ == wit::Role::kBackup)) ||
                      (g.request == wit::MsgType::kSolo && is_primary_role(role_)) ||
                      (g.request == wit::MsgType::kResume && role_ == wit::Role::kRecovering) ||
                      // W also sends a JOIN grant to the joiner itself, in case the
                      // primary dies before relaying it (10 §5). A joiner whose own
                      // PROMOTE is in flight waits for W's verdict on it instead, as
                      // in on_peer: a later copy may still be granted, and a node
                      // that adopted BACKUP meanwhile would never ask again.
                      (g.request == wit::MsgType::kJoin && role_ == wit::Role::kRecovering && g.primary != me_ &&
                       wit::is_member(g.members, me_) && !(pending_ && pending_->type == wit::MsgType::kPromote));
      if (!ok) return;
      if (g.request != wit::MsgType::kJoin) SIM_PROBE("witness_world.grant_for_an_earlier_copy");
    }
    h_.on_grant_applied(me_, inc_, g);
    const Pending p = matches ? *pending_ : Pending{};
    pending_.reset();
    switch (g.request) {
      case wit::MsgType::kPromote:
        adopt(g.epoch, g.primary, g.members, wit::Role::kSoloPrimary, now);
        break;
      case wit::MsgType::kSolo:
        ++h_.solos;
        adopt(g.epoch, g.primary, g.members, wit::Role::kSoloPrimary, now);
        break;
      case wit::MsgType::kResume:
        ++h_.resumes;
        adopt(g.epoch, g.primary, g.members, wit::Role::kSoloPrimary, now);
        break;
      case wit::MsgType::kJoin:
        if (g.primary != me_) {
          // The joiner's own copy: it is a member, so it becomes the backup.
          SIM_PROBE("witness_world.joiner_adopts_join_grant");
          h_.check_member_inc(me_, inc_, g.epoch, "joiner applies JOIN grant");
          adopt(g.epoch, g.primary, g.members, wit::Role::kBackup, now);
          break;
        }
        ++h_.joins;
        backup_inc_ = p.joiner_inc;
        h_.check_member_inc(peer_, p.joiner_inc, g.epoch, "primary applies JOIN grant");
        adopt(g.epoch, g.primary, g.members, wit::Role::kPrimary, now);
        break;
      default:
        break;
    }
  }

  void on_reject(const wit::Reject& r, Nanos now) {
    if (r.to_node != me_ || r.incarnation != inc_) return;
    if (!pending_ || r.request != pending_->type || r.from_epoch != pending_->from_epoch) return;
    if (r.request == wit::MsgType::kPromote && r.reason == wit::RejectReason::kPrimaryAlive &&
        wit::is_member(r.members, me_) && r.primary != me_) {
      // 10 §4: a candidate froze before asking and never thaws, and W may still
      // grant a later copy of this PROMOTE once it stops hearing the primary.
      // So keep asking until the epoch moves: the primary, no longer acked,
      // goes SOLO, and exactly one of the two requests is granted.
      SIM_PROBE("witness_world.promote_rejected_primary_alive");
      pending_->unanswered = 0;
      return;
    }
    pending_.reset();
    if (role_ == wit::Role::kRecovering && r.request == wit::MsgType::kPromote) {
      // Handshake takeover attempt: W knows whether the JOIN made us a member.
      if (!wit::is_member(r.members, me_) || r.primary == me_) {
        handshake_epoch_ = 0;  // the JOIN was not granted: wait to be joined
      } else if (r.reason == wit::RejectReason::kStaleEpoch) {
        request(wit::Promote{r.epoch, me_, inc_, 0}, wit::MsgType::kPromote, r.epoch, now);
      }
      return;
    }
    if (is_primary_role(role_)) {
      if (r.primary != me_) {
        deposed("request rejected");  // 10 §4: a deposed primary exits
        return;
      }
      if (r.epoch > epoch_) {
        // W still names me primary, at an epoch whose grant (to one of my own
        // requests) never reached me. Only my own grants keep me primary, so
        // take W's epoch and shrink to solo before anything else.
        SIM_PROBE("witness_world.primary_resyncs_to_witness_epoch");
        h_.log("n%u inc %llu resyncs to W %s", me_, static_cast<unsigned long long>(inc_), cfg_str(r.epoch, r.primary, r.members).c_str());
        adopt(r.epoch, r.primary, r.members, wit::Role::kSoloPrimary, now);
        request(wit::Solo{epoch_, me_, inc_}, wit::MsgType::kSolo, epoch_, now);
        return;
      }
      deposed("request rejected at the current epoch");
      return;
    }
    if (role_ == wit::Role::kRecovering) {
      if (r.primary == me_ && r.members == wit::member_bit(me_) && r.reason == wit::RejectReason::kStaleEpoch) {
        // Solo primary of record whose last grant never reached it: resume at
        // W's epoch (safe: solo mode released only L3-durable records).
        request(wit::Resume{r.epoch, me_, inc_}, wit::MsgType::kResume, r.epoch, now);
      }
      return;
    }
    // A candidate or backup that is no longer a member must rejoin; one that
    // still is stays a backup (it learns the epoch from the primary).
    if (!wit::is_member(r.members, me_)) {
      epoch_ = std::max(epoch_, r.epoch);
      set_role(wit::Role::kRecovering);
    } else if (role_ == wit::Role::kCandidate) {
      set_role(wit::Role::kBackup);
      last_primary_seen_ = now;
    }
  }

  void request(const wit::Message& m, wit::MsgType type, std::uint64_t from_epoch, Nanos now,
               std::uint64_t joiner_inc = 0) {
    h_.log("n%u inc %llu requests %s from_epoch %llu (joiner inc %llu)", me_, static_cast<unsigned long long>(inc_), wit::to_string(type),
           static_cast<unsigned long long>(from_epoch), static_cast<unsigned long long>(joiner_inc));
    pending_ = Pending{m, type, from_epoch, joiner_inc, now, 0, 0};
  }

  void adopt(std::uint64_t epoch, wit::NodeId primary, wit::Members members, wit::Role role, Nanos now) {
    pending_.reset();  // a new configuration supersedes any request still in flight
    handshake_epoch_ = 0;
    epoch_ = epoch;
    primary_ = primary;
    members_ = members;
    last_primary_seen_ = last_backup_seen_ = now;
    recovering_since_ = -1;
    set_role(role);
  }

  void set_role(wit::Role r) {
    h_.log("n%u inc %llu role %u epoch %llu", me_, static_cast<unsigned long long>(inc_), static_cast<unsigned>(r), static_cast<unsigned long long>(epoch_));
    role_ = r;
    h_.on_role(me_, role_, epoch_);
  }

  void deposed(const char* why) {
    h_.log("n%u inc %llu deposed (%s): exits", me_, static_cast<unsigned long long>(inc_), why);
    ++h_.deposed;
    SIM_PROBE("witness_world.deposed_primary_exits");
    exiting_ = true;
    pending_.reset();
    node_.request_crash();
  }

  void send_w(const wit::Message& m) {
    const wit::Encoded e = wit::encode(m);
    port_.send(w_ep_, e.span());
  }

  Node& node_;
  Harness& h_;
  DatagramPort& port_;
  wit::NodeId me_;
  wit::NodeId peer_;
  ActorTiming t_;
  env::Endpoint w_ep_;
  env::Endpoint peer_ep_;
  std::uint64_t inc_;
  wit::Role role_ = wit::Role::kRecovering;
  std::uint64_t epoch_ = 0;
  wit::NodeId primary_ = 0;
  wit::Members members_ = 0;
  std::uint64_t backup_inc_ = 0;
  std::optional<Pending> pending_;
  Nanos next_hb_ = 0;
  Nanos last_primary_seen_ = 0;
  Nanos last_backup_seen_ = 0;
  Nanos recovering_since_ = -1;
  std::uint64_t handshake_epoch_ = 0;  // recovering: epoch at which the primary relayed JOIN for us
  bool have_peer_ = false;
  PeerHb peer_hb_{};
  Nanos peer_at_ = 0;
  bool exiting_ = false;
};

struct NodeProc : Process {
  struct Stage {
    NodeActor* a;
    bool poll() { return a->poll(); }
  };
  NodeProc(Node& n, Harness& h, wit::NodeId me, const ActorTiming& t, env::Endpoint w_ep, env::Endpoint peer_ep)
      : port(n, kNodePort), actor(n, h, port, me, t, w_ep, peer_ep), stage{&actor} {
    n.add_stage(stage, "ctl");
  }
  DatagramPort port;
  NodeActor actor;
  Stage stage;
};

}  // namespace

Report run_witness(const Options& o) {
  // The harness outlives the world: process destructors still report to it.
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x3171);
  h->w = &w;
  h->o = &w.oracles();
  h->o_grant = w.oracles().activate("O-WITNESS-GRANT", "one grant per epoch; announced configurations unique");
  h->o_durable = w.oracles().activate("O-WITNESS-DURABLE", "W restarts from a valid slot at or above every announced epoch");
  h->o_inc = w.oracles().activate("O-WITNESS-INC", "act only on own-incarnation grants; members run W's recorded incarnation");
  h->o_one = w.oracles().activate(kOOnePrimary);
  h->verbose = o.verbose;
  h->cut = wl.below(4) == 0;  // a quarter of seeds: the cut-link scenario
  if (h->cut) h->o_cut = w.oracles().activate("O-WITNESS-CUT", "a cut A-B link with both nodes alive never yields a takeover");

  ActorTiming t;
  t.t_d = 10 * kMs + static_cast<Nanos>(wl.below(10 * kMs + 1));
  t.t_ack = 5 * kMs + static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(t.t_d - 8 * kMs)));
  t.retry = 2 * kMs + static_cast<Nanos>(wl.below(3 * kMs + 1));
  t.catchup = kMs + static_cast<Nanos>(wl.below(20 * kMs));

  Node& a = w.add_node("A", NodeOptions{true, true});
  Node& b = w.add_node("B", NodeOptions{true, true});
  Node& wn = w.add_node("W", NodeOptions{true, h->cut ? false : true});
  h->w_node = wn.id();
  const env::Endpoint w_ep{wn.ip(), kWitnessPort};
  const env::Endpoint a_ep{a.ip(), kNodePort};
  const env::Endpoint b_ep{b.ip(), kNodePort};

  // `witnessd --init --primary 0`: slot 0 = generation 1, slot 1 zeroed.
  {
    wit::State s;
    s.epoch = 1;
    s.primary = 0;
    s.members = 0b11;
    std::array<std::byte, kStateBytes> img{};
    const wit::SlotImage s0 = wit::encode_slot(s, 1);
    std::memcpy(img.data(), s0.data(), s0.size());
    wn.disk().install(kStateFile, img);
    h->persisted.emplace(1, s);
  }
  Harness* hp = h.get();
  wn.set_boot([hp](Node& n, BootReason) { n.emplace_process<WitnessProc>(n, *hp); });
  a.set_boot([=](Node& n, BootReason) { n.emplace_process<NodeProc>(n, *hp, wit::NodeId{0}, t, w_ep, b_ep); });
  b.set_boot([=](Node& n, BootReason) { n.emplace_process<NodeProc>(n, *hp, wit::NodeId{1}, t, w_ep, a_ep); });

  // Stay inside the failure model (01 §9): never take down a data node while
  // the other is not a working member, which would need a manual --reinit.
  w.injector().set_crash_guard([hp, &w](NodeId id) {
    if (id >= wit::kNodes) return true;  // W may always crash
    const NodeActor* self = hp->actors[id];
    const NodeActor* other = hp->actors[1 - id];
    const WitnessProc* wp = hp->witness;
    if (wp != nullptr && wp->settled() && self != nullptr && !self->pending_) {
      // The solo primary of record can come back with RESUME, provided no
      // request of its own (a JOIN in flight) can still change W's state.
      const wit::State& s = wp->core->state();
      if (s.members == wit::member_bit(static_cast<wit::NodeId>(id)) && s.primary == id) return true;
    }
    if (other == nullptr || !w.node(1 - id).alive()) return false;
    const bool working = other->role_ == wit::Role::kPrimary || other->role_ == wit::Role::kSoloPrimary ||
                         other->role_ == wit::Role::kBackup;
    if (!working || wp == nullptr || !wp->core) return false;
    const wit::State& s = wp->core->state();
    return wit::is_member(s.members, other->me_) && s.inc[other->me_] == other->inc_;
  });

  if (h->cut) {
    // No W disk stalls or EIO: "solo on A by the end of the cut" is a timing
    // (liveness) property, and a 5 s state-write stall would postpone it.
    wn.disk().set_params(DiskParams{});
    // Clean control network: the property assumes T_w < T_d holds in practice.
    for (NodeId x = 0; x < 3; ++x) {
      for (NodeId y = 0; y < 3; ++y) {
        if (x == y) continue;
        LinkParams& lp = w.net().link_params(x, y);
        lp = LinkParams{};
        lp.delay_min = 20 * kUs;
      }
    }
  }
  for (NodeId i = 0; i < w.node_count(); ++i) w.node(i).boot();

  const auto shape = [&](FaultSchedule& s) {
    if (!h->cut) return;
    // Only the A-B cut: no crashes, pauses or other partitions, so both data
    // nodes stay alive and W stays reachable for the whole cut.
    s.events.clear();
    const Nanos at = 50 * kMs + static_cast<Nanos>(wl.below(100 * kMs));
    s.events.push_back(FaultEvent{at, FaultKind::Partition, 1, std::uint64_t{1} << a.id(), std::uint64_t{1} << b.id(),
                                  o.plan.safety_ns});
  };
  if (h->cut) {
    w.on_heal([hp, &w] {
      const WitnessProc* wp = hp->witness;
      if (wp == nullptr || !wp->core) return;
      const wit::State& s = wp->core->state();
      // CutLinkLeadsToSolo: by the end of the cut, A is the solo primary.
      w.oracles().check(hp->o_cut, s.primary == 0 && s.members == wit::member_bit(0),
                        "after the A-B cut W is at " + cfg_str(s.epoch, s.primary, s.members) + ", not solo on A");
    });
  }

  const auto converged = [hp, &w] {
    const WitnessProc* wp = hp->witness;
    if (wp == nullptr || !wp->settled()) return false;
    const wit::State& s = wp->core->state();
    if (s.members != 0b11) return false;
    for (wit::NodeId n = 0; n < wit::kNodes; ++n) {
      const NodeActor* a2 = hp->actors[n];
      if (a2 == nullptr || !w.node(n).alive() || w.node(n).paused()) return false;
      const wit::Role want = n == s.primary ? wit::Role::kPrimary : wit::Role::kBackup;
      if (a2->role_ != want || a2->epoch_ != s.epoch || a2->inc_ != s.inc[n] || a2->pending_) return false;
    }
    return true;
  };
  return finish(
      w, WorldKind::Witness, o, converged,
      [hp] {
        return std::string(hp->cut ? "scenario=cut" : "scenario=swarm") + " epoch=" +
               std::to_string(hp->max_announced) + " takeovers=" + std::to_string(hp->takeovers) +
               " solos=" + std::to_string(hp->solos) + " joins=" + std::to_string(hp->joins) +
               " resumes=" + std::to_string(hp->resumes) + " deposed=" + std::to_string(hp->deposed) +
               " w_starts=" + std::to_string(hp->w_starts);
      },
      shape);
}

}  // namespace lle::sim::worlds::detail
