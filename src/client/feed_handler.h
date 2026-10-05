#pragma once
// refclient's feed handler (07 §3 steps 1-3; 03-protocols §7-§8; T10): MoldUDP64
// packets from line A, line B and the re-request servers go through the
// LineArbiter; every message it delivers, exactly once and in sequence order, is
// applied to the ITCH book (the optimized LOB variant) and then handed
// downstream (the strategy). On a large gap the arbiter asks for a snapshot:
// the downstream opens the GLIMPSE session, the spin is applied to a fresh
// book, and End of Snapshot G(S(P)+1) splices the buffered live stream back in.
//
// Downstream (any type with these members, called synchronously):
//   void on_book_message(SeqNo seq, std::span<const std::byte> itch);  // after the book applied it
//   void on_snapshot_message(std::span<const std::byte> itch);           // a spin message, applied
//   void send_request(mold::Server server, std::span<const std::byte> request);
//   void on_snapshot_needed(SeqNo next_expected, SeqNo known_end);
//   void on_end_of_session(SeqNo end_seq);
//
// Sans-I/O and single-threaded. The book, the arbiter's reorder buffer and the
// checkpoint list are allocated at construction; nothing allocates afterwards
// (the book's pools are sized by BookConfig; overflowing them grows them).
//
// A snapshot join starts from a fresh book: the old one is destroyed and a new
// one constructed (about 10 ms for a full-day book of 3.7M orders, against
// several hundred ms to remove the orders one by one; that stall made the
// kernel drop line packets, which opened the next large gap). This allocates,
// on the recovery path only. A spin that ends without End of Snapshot is
// abandoned with abort_snapshot(); the next spin starts from a fresh book again.

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

#include "book/itch_adapter.h"
#include "book/listener.h"
#include "book/variants.h"
#include "client/checkpoints.h"
#include "common/types.h"
#include "proto/glimpse/glimpse.h"
#include "proto/itch50/itch50.h"
#include "proto/moldudp64/line_arbiter.h"

namespace lle::client {

struct FeedConfig {
  mold::LineArbiterConfig arbiter{};
  book::BookConfig book{};
  CheckpointConfig checkpoints{};
};

struct FeedStats {
  std::uint64_t delivered = 0;
  std::array<std::uint64_t, book::kItchKinds> kinds{};
  std::array<std::uint64_t, 7> book_status{};  // by book::Status
  std::uint64_t snapshots_requested = 0;
  std::uint64_t snapshots_applied = 0;
  std::uint64_t snapshots_rejected = 0;   // G below what was already delivered, or bad G
  std::uint64_t snapshots_aborted = 0;    // the session ended before End of Snapshot
  std::uint64_t snapshot_messages = 0;    // spin messages applied
  std::uint64_t snapshot_rejected_messages = 0;
  std::uint64_t snapshot_covered = 0;     // live messages skipped by splices
  SeqNo last_seq = 0;   // last message delivered
  SeqNo book_seq = 0;   // the book holds the state after this message (delivery or splice)
  bool ended = false;
  SeqNo end_seq = 0;
};

template <class Listener = book::NullListener>
class FeedHandler {
 public:
  using Book = book::OptBook<Listener>;
  enum class SpinResult : std::uint8_t { Applied, Spliced, Rejected };

  explicit FeedHandler(const FeedConfig& cfg)
      : cfg_(cfg),
        arb_(cfg.arbiter),
        book_(std::make_unique<Book>(cfg.book)),
        ckpt_(cfg.checkpoints) {}
  FeedHandler(const FeedHandler&) = delete;
  FeedHandler& operator=(const FeedHandler&) = delete;

  template <class Down>
  void on_packet(mold::Source src, std::span<const std::byte> pkt, Nanos now, Down& down) {
    ArbSink<Down> sink{this, &down};
    arb_.on_packet(src, pkt, now, sink);
  }

  template <class Down>
  void on_timer(Nanos now, Down& down) {
    ArbSink<Down> sink{this, &down};
    arb_.on_timer(now, sink);
  }

  [[nodiscard]] Nanos next_deadline() const noexcept { return arb_.next_deadline(); }

  // --- snapshot join (03-protocols §8) -----------------------------------------
  // A spin is starting: the book is replaced by an empty one (the spin carries
  // the whole state). Called by the snapshot session at login, or implicitly by
  // the first payload.
  void begin_snapshot() {
    book_.reset();  // free the old pools before allocating the new ones
    book_ = std::make_unique<Book>(cfg_.book);
    in_spin_ = true;
  }

  // The snapshot session ended without End of Snapshot: the partial book is
  // discarded by the next begin_snapshot(); the arbiter keeps buffering.
  void abort_snapshot() noexcept {
    if (in_spin_) ++st_.snapshots_aborted;
    in_spin_ = false;
  }

  // One spin payload: S/R/H/Y/h/A/F are applied, G(N) splices the live stream at N.
  template <class Down>
  SpinResult on_snapshot_payload(std::span<const std::byte> payload, Nanos now, Down& down) {
    if (!in_spin_) begin_snapshot();
    if (!payload.empty() && static_cast<char>(payload[0]) == glimpse::kEndOfSnapshotType) {
      const auto n = glimpse::decode_end_of_snapshot(payload);
      in_spin_ = false;
      if (!n || *n == 0 || arb_.state() != mold::LineArbiter::State::AwaitingSnapshot || *n < arb_.next_expected()) {
        // Unusable: the book was replaced by the spin, so a fresh snapshot is required.
        ++st_.snapshots_rejected;
        down.on_snapshot_needed(arb_.next_expected(), arb_.known_end());
        return SpinResult::Rejected;
      }
      const SeqNo from = arb_.next_expected();
      st_.snapshot_covered += *n - from;
      ++st_.snapshots_applied;
      st_.book_seq = *n - 1;
      ckpt_.on_splice(from, *n, book(), bbo_value());
      ArbSink<Down> sink{this, &down};
      arb_.resume_from_snapshot(*n, now, sink);
      return SpinResult::Spliced;
    }
    if (payload.empty() || payload.size() != itch50::kMsgLen[static_cast<unsigned char>(payload[0])] ||
        !glimpse::is_snapshot_type(static_cast<char>(payload[0]))) {
      ++st_.snapshot_rejected_messages;
      return SpinResult::Rejected;
    }
    ++st_.snapshot_messages;
    const book::ItchResult r = book::apply_itch(book(), payload.data(), payload.size());
    ++st_.book_status[static_cast<std::size_t>(r.status)];
    down.on_snapshot_message(payload);
    return SpinResult::Applied;
  }

  // Records the final checkpoint (call once the stream has ended).
  void finish() { ckpt_.finish(st_.book_seq, book(), bbo_value()); }

  [[nodiscard]] const Book& book() const noexcept { return *book_; }
  [[nodiscard]] Book& book() noexcept { return *book_; }
  [[nodiscard]] const mold::LineArbiter& arbiter() const noexcept { return arb_; }
  [[nodiscard]] mold::LineArbiter& arbiter() noexcept { return arb_; }
  [[nodiscard]] const FeedStats& stats() const noexcept { return st_; }
  [[nodiscard]] const CheckpointRecorder& checkpoints() const noexcept { return ckpt_; }
  [[nodiscard]] bool in_spin() const noexcept { return in_spin_; }
  [[nodiscard]] std::uint64_t bbo_value() const noexcept {
    if constexpr (std::is_same_v<Listener, book::BboRecorder>) {
      return book().listener().digest.value;
    } else {
      return 0;
    }
  }

 private:
  template <class Down>
  struct ArbSink {
    FeedHandler* self;
    Down* down;
    void on_message(SeqNo seq, std::span<const std::byte> msg) { self->deliver(seq, msg, *down); }
    void send_request(mold::Server s, std::span<const std::byte> req) { down->send_request(s, req); }
    void on_snapshot_needed(SeqNo next, SeqNo end) {
      ++self->st_.snapshots_requested;
      down->on_snapshot_needed(next, end);
    }
    void on_end_of_session(SeqNo end) {
      self->st_.ended = true;
      self->st_.end_seq = end;
      down->on_end_of_session(end);
    }
  };

  template <class Down>
  void deliver(SeqNo seq, std::span<const std::byte> msg, Down& down) {
    ++st_.delivered;
    st_.last_seq = seq;
    st_.book_seq = seq;
    Book& b = book();
    const book::ItchResult r = book::apply_itch(b, msg.data(), msg.size());
    ++st_.kinds[static_cast<std::size_t>(r.kind)];
    ++st_.book_status[static_cast<std::size_t>(r.status)];
    if (ckpt_.enabled()) ckpt_.on_message(seq, msg, b, bbo_value());
    down.on_book_message(seq, msg);
  }

  FeedConfig cfg_;
  mold::LineArbiter arb_;
  std::unique_ptr<Book> book_;
  CheckpointRecorder ckpt_;
  FeedStats st_;
  bool in_spin_ = false;
};

}  // namespace lle::client
