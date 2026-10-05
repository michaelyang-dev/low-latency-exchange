#pragma once
// One GLIMPSE-style snapshot session of mold_replay (03-protocols §8): a
// SoupBinTCP server session whose sequenced stream is a spin of the replay
// state taken when the connection was accepted (journal position P = the last
// message published), ending with End of Snapshot G(S(P)+1), then End of
// Session. The client logs in with sequence 1 (any credentials are accepted;
// this is a test service).
//
// Sans-I/O: bytes and time in, Actions out (soup::ServerSession). The spin is
// built into a store sized for it at accept time (a cold path: one allocation
// per snapshot session).
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "common/types.h"
#include "proto/glimpse/snapshot_server.h"
#include "proto/soupbin/sequenced_store.h"
#include "proto/soupbin/server_session.h"

namespace lle::client {

struct AcceptAllLogins {
  soup::LoginDecision authorize(const soup::LoginRequest&) noexcept { return soup::LoginDecision::Accept; }
};

class SnapshotSpinSession {
 public:
  using Session = soup::ServerSession<soup::MemorySequencedStore, AcceptAllLogins>;

  template <glimpse::SnapshotStateLike State>
  SnapshotSpinSession(const State& state, std::size_t max_messages, Nanos now, const soup::ServerConfig& cfg)
      : store_(std::make_unique<soup::MemorySequencedStore>(max_messages, max_messages * 40 + 64)) {
    stats_ = glimpse::SnapshotServer{}.emit(state, [&](std::span<const std::byte> m) {
      if (!store_->append(m)) overflow_ = true;
    });
    session_ = std::make_unique<Session>(cfg, *store_, policy_, now);
  }

  const soup::Actions& on_bytes(std::span<const std::byte> in, Nanos now) { return after(session_->on_bytes(in, now), now); }
  const soup::Actions& on_timer(Nanos now) { return after(session_->on_timer(now), now); }
  // True when replay is pending and on_timer() should run again.
  bool consume_tx(std::size_t n) noexcept { return session_->consume_tx(n); }
  [[nodiscard]] const soup::Actions& actions() const noexcept { return session_->actions(); }
  [[nodiscard]] bool closed() const noexcept { return session_->state() == Session::State::Closed; }
  [[nodiscard]] const glimpse::SpinStats& spin() const noexcept { return stats_; }
  [[nodiscard]] bool overflow() const noexcept { return overflow_; }

 private:
  const soup::Actions& after(const soup::Actions& a, Nanos now) {
    for (const soup::Event& e : a.events) {
      // Deliver the spin, then 'Z' and close (spec 2.2.5).
      if (e.kind == soup::EventKind::LoggedIn) return session_->end_session(now);
    }
    return a;
  }

  std::unique_ptr<soup::MemorySequencedStore> store_;
  AcceptAllLogins policy_;
  std::unique_ptr<Session> session_;
  glimpse::SpinStats stats_;
  bool overflow_ = false;
};

}  // namespace lle::client
