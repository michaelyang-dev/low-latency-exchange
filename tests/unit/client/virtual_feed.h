#pragma once
// An in-process, virtual-time version of the T10 setup for unit tests:
//   ReplayFeed (two lossy lines) -> FeedHandler (LineArbiter + book)
//   MessageRing -> RerequestServer A/B <- re-requests
//   ReplayBookState -> SnapshotSpinSession <-> soup::ClientSession (GLIMPSE join)
// Packets travel with per-line latency; requests, replies and the snapshot
// stream with their own. Deterministic for a seed. Test-support code: allocates.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <span>
#include <vector>

#include "book/itch_adapter.h"
#include "book/digested_book.h"
#include "book/variants.h"
#include "client/feed_handler.h"
#include "client/glimpse_service.h"
#include "client/replay_feed.h"
#include "client/replay_state.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/rerequest_server.h"
#include "proto/soupbin/client_session.h"

namespace lle::client::test {

struct VirtualFeedConfig {
  ReplayFeedConfig feed{};
  FeedConfig client{};
  Nanos msg_interval = 1'000;  // publisher: one message per interval
  Nanos delay_a = 5'000, delay_b = 9'000;
  Nanos rtt = 30'000;
  Nanos snapshot_chunk_interval = 20'000;  // one TCP "read" of the spin per interval
  std::size_t snapshot_chunk = 4096;       // bytes per read
  bool rerequest_servers = true;
  bool snapshot_service = true;
  Nanos time_limit = 600 * kNsPerSec;
};

struct VirtualFeedResult {
  bool ended = false;
  std::uint64_t delivered = 0;
  std::uint64_t snapshots = 0;
  std::uint64_t spins_served = 0;
  std::uint64_t requests_served = 0;
  std::uint64_t direct_digest = 0;
  std::uint64_t client_digest = 0;
  std::vector<Checkpoint> client_checkpoints;
  std::vector<SeqNo> order;  // delivered sequences (first 1M), for exactly-once checks
  mold::LineArbiterMetrics metrics;
};

class VirtualFeed {
 public:
  using Msgs = std::vector<std::vector<std::byte>>;

  VirtualFeed(const VirtualFeedConfig& cfg, const Msgs& msgs) : cfg_(cfg), msgs_(msgs) {}

  VirtualFeedResult run() {
    VirtualFeedResult res;
    ReplayFeed feed(cfg_.feed);
    mold::MessageRing ring(msgs_.size() + 16, msgs_.size() * 64 + 1024);
    mold::RerequestConfig rc;
    rc.session = cfg_.feed.session;
    rc.bucket_capacity = 1'000'000;
    rc.refill_interval = 1;
    mold::RerequestServer<mold::MessageRing> srv_a(rc, ring), srv_b(rc, ring);
    ReplayBookState state;
    FeedHandler<book::BboRecorder> fh(cfg_.client);

    struct Down {
      VirtualFeed* self;
      VirtualFeedResult* res;
      void on_book_message(SeqNo seq, std::span<const std::byte>) {
        ++res->delivered;
        if (res->order.size() < 1'000'000) res->order.push_back(seq);
      }
      void on_snapshot_message(std::span<const std::byte>) {}
      void send_request(mold::Server s, std::span<const std::byte> req) {
        self->push(self->now_ + self->cfg_.rtt / 2, s == mold::Server::A ? Kind::RequestA : Kind::RequestB, req);
      }
      void on_snapshot_needed(SeqNo, SeqNo) { self->snap_wanted_ = true; }
      void on_end_of_session(SeqNo) { res->ended = true; }
    } down{this, &res};

    auto send = [&](int line, std::span<const std::byte> p) {
      push(now_ + (line == 0 ? cfg_.delay_a : cfg_.delay_b), line == 0 ? Kind::LineA : Kind::LineB, p);
    };

    std::size_t next_msg = 0;
    Nanos next_pub = 0;
    bool ended_pub = false;
    std::unique_ptr<SnapshotSpinSession> spin;
    std::optional<soup::ClientSession> sc;
    std::vector<std::byte> to_server, to_client;  // in-flight TCP bytes
    Nanos next_chunk = 0;

    while (now_ < cfg_.time_limit && !(res.ended && feed.done())) {
      // Publisher.
      if (!ended_pub && now_ >= next_pub) {
        const auto& m = msgs_[next_msg];
        (void)ring.append(m);
        state.apply(feed.next_seq(), m);
        (void)feed.append(m, now_, send);
        ++next_msg;
        next_pub = now_ + cfg_.msg_interval;
        if (next_msg == msgs_.size()) {
          feed.flush(now_, send);
          feed.end_session(now_, send);
          ended_pub = true;
        }
      }
      if (now_ >= feed.next_deadline()) feed.on_timer(now_, send);
      // Network events due.
      while (!q_.empty() && q_.top().t <= now_) {
        Ev e = q_.top();
        q_.pop();
        switch (e.kind) {
          case Kind::LineA: fh.on_packet(mold::Source::LineA, e.bytes, now_, down); break;
          case Kind::LineB: fh.on_packet(mold::Source::LineB, e.bytes, now_, down); break;
          case Kind::ReplyA: fh.on_packet(mold::Source::RerequestA, e.bytes, now_, down); break;
          case Kind::ReplyB: fh.on_packet(mold::Source::RerequestB, e.bytes, now_, down); break;
          case Kind::RequestA:
          case Kind::RequestB: {
            if (!cfg_.rerequest_servers) break;
            auto& srv = e.kind == Kind::RequestA ? srv_a : srv_b;
            const Kind back = e.kind == Kind::RequestA ? Kind::ReplyA : Kind::ReplyB;
            if (srv.on_request(e.bytes, env::Endpoint{1, 1}, now_, [&](const env::Endpoint&, std::span<const std::byte> p) {
                  push(now_ + cfg_.rtt / 2, back, p);
                }) == mold::RequestOutcome::Served)
              ++res.requests_served;
            break;
          }
        }
      }
      if (now_ >= fh.next_deadline()) fh.on_timer(now_, down);
      // Snapshot join over an in-process SoupBinTCP pair.
      if (snap_wanted_ && !spin && cfg_.snapshot_service) {
        snap_wanted_ = false;
        soup::ServerConfig scfg;
        scfg.session = soup::SessionId::from("GLIMPSE");
        scfg.tx_capacity = 1 << 16;
        spin = std::make_unique<SnapshotSpinSession>(state, state.live_orders() + 5 * 65536 + 64, now_, scfg);
        ++res.spins_served;
        soup::ClientConfig ccfg;
        ccfg.sequence = 1;
        sc.emplace(ccfg);
        const auto& a = sc->connect(now_);
        to_server.insert(to_server.end(), a.write.begin(), a.write.end());
        sc->consume_tx(a.write.size());
        next_chunk = now_;
      }
      if (spin && now_ >= next_chunk) {
        next_chunk = now_ + cfg_.snapshot_chunk_interval;
        if (!to_server.empty()) {
          (void)spin->on_bytes(to_server, now_);
          to_server.clear();
        }
        if (spin->actions().deadline <= now_) (void)spin->on_timer(now_);
        for (int k = 0; k < 4; ++k) {
          const auto w = spin->actions().write;
          if (w.empty()) break;
          to_client.insert(to_client.end(), w.begin(), w.end());
          if (spin->consume_tx(w.size())) (void)spin->on_timer(now_);
        }
        const std::size_t n = std::min(to_client.size(), cfg_.snapshot_chunk);
        std::span<const std::byte> in(to_client.data(), n);
        bool done = false;
        while (!in.empty() && sc) {
          const soup::Actions& a = sc->on_bytes(in, now_);
          for (const soup::Delivered& d : a.delivered) {
            if (d.seq == 0 || done) continue;
            const auto r = fh.on_snapshot_payload(d.data, now_, down);
            if (r != FeedHandler<book::BboRecorder>::SpinResult::Applied) done = true;
          }
          if (a.consumed == 0) break;
          in = in.subspan(a.consumed);
        }
        to_client.erase(to_client.begin(), to_client.begin() + static_cast<std::ptrdiff_t>(n));
        if (done || (sc && sc->state() == soup::ClientSession::State::Closed)) {
          if (!done) fh.abort_snapshot();
          spin.reset();
          sc.reset();
          to_client.clear();
          to_server.clear();
        }
      }
      // Advance to the next event.
      Nanos t = cfg_.time_limit;
      if (!ended_pub) t = std::min(t, next_pub);
      if (!q_.empty()) t = std::min(t, q_.top().t);
      t = std::min({t, feed.next_deadline(), fh.next_deadline()});
      if (spin) t = std::min(t, next_chunk);
      if (snap_wanted_ && cfg_.snapshot_service) t = std::min(t, now_ + 1);
      now_ = std::max(now_ + 1, t);
    }
    fh.finish();
    res.snapshots = fh.stats().snapshots_applied;
    res.client_digest = fh.book().books_digest();
    res.client_checkpoints = fh.checkpoints().list();
    res.metrics = fh.arbiter().metrics();
    // Direct replay.
    book::OptBook<> direct;
    for (const auto& m : msgs_) (void)book::apply_itch(direct, m.data(), m.size());
    res.direct_digest = direct.books_digest();
    return res;
  }

  // Direct replay checkpoints at the given sequences (plus every `every`).
  static std::vector<Checkpoint> direct_checkpoints(const Msgs& msgs, CheckpointConfig cfg) {
    book::DigestedBook<book::VarOpt> db;
    CheckpointRecorder ck(cfg);
    SeqNo seq = 0;
    for (const auto& m : msgs) {
      ++seq;
      (void)book::apply_itch(db.book(), m.data(), m.size());
      ck.on_message(seq, m, db.book(), db.recorder().digest.value);
    }
    ck.finish(seq, db.book(), db.recorder().digest.value);
    return ck.list();
  }

 private:
  enum class Kind : std::uint8_t { LineA, LineB, RequestA, RequestB, ReplyA, ReplyB };
  struct Ev {
    Nanos t;
    std::uint64_t order;
    Kind kind;
    std::vector<std::byte> bytes;
    friend bool operator>(const Ev& a, const Ev& b) { return a.t != b.t ? a.t > b.t : a.order > b.order; }
  };
  void push(Nanos t, Kind k, std::span<const std::byte> b) {
    q_.push(Ev{t, order_++, k, std::vector<std::byte>(b.begin(), b.end())});
  }

  VirtualFeedConfig cfg_;
  const Msgs& msgs_;
  std::priority_queue<Ev, std::vector<Ev>, std::greater<>> q_;
  std::uint64_t order_ = 0;
  Nanos now_ = 0;
  bool snap_wanted_ = false;
};

}  // namespace lle::client::test
