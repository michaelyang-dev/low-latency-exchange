#pragma once
// A variant's book wired to a BboRecorder, for harnesses that compare
// digests and per-operation BBO events (lobdiff, lobfuzz, tests, benchmarks,
// and later lob_replay's correctness gate). B0 reports through its virtual
// BookListener; every other variant through the template listener.
#include "book/itch_book.h"
#include "book/listener.h"

namespace lle::book {

template <class V, bool kVirtual = V::kVirtualListener>
class DigestedBook;

template <class V>
class DigestedBook<V, false> {
 public:
  using Book = ItchBook<typename V::Policies, BboRecorder>;
  explicit DigestedBook(const BookConfig& cfg = {}) : book_(cfg) {}
  [[nodiscard]] Book& book() noexcept { return book_; }
  [[nodiscard]] const Book& book() const noexcept { return book_; }
  [[nodiscard]] BboRecorder& recorder() noexcept { return book_.listener(); }
  [[nodiscard]] const BboRecorder& recorder() const noexcept { return book_.listener(); }

 private:
  Book book_;
};

template <class V>
class DigestedBook<V, true> {
 public:
  using Book = ItchBook<typename V::Policies, VirtualListener>;
  explicit DigestedBook(const BookConfig& cfg = {}) : book_(cfg, VirtualListener{&listener_}) {}
  DigestedBook(const DigestedBook&) = delete;
  DigestedBook& operator=(const DigestedBook&) = delete;
  [[nodiscard]] Book& book() noexcept { return book_; }
  [[nodiscard]] const Book& book() const noexcept { return book_; }
  [[nodiscard]] BboRecorder& recorder() noexcept { return listener_.rec; }
  [[nodiscard]] const BboRecorder& recorder() const noexcept { return listener_.rec; }

 private:
  RecordingBookListener listener_;  // declared first: outlives book_
  Book book_;
};

}  // namespace lle::book
