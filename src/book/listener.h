#pragma once
// BBO-change listeners. ItchBook calls `listener.on_bbo_change(locate, bbo)`
// once per operation whose effect changed that locate's cached BBO.
//
// B0 uses the textbook virtual BookListener (04-order-book §4) through
// VirtualListener; optimized variants take any type with that member function
// as a template parameter, so the call is static and inlinable.
#include <cstdint>

#include "book/digest.h"
#include "common/types.h"
#include "lob/types.h"

namespace lle::book {

class BookListener {
 public:
  virtual ~BookListener() = default;
  virtual void on_bbo_change(Locate loc, const lob::Bbo& bbo) = 0;
};

class NullBookListener final : public BookListener {
 public:
  void on_bbo_change(Locate, const lob::Bbo&) override {}
};

inline NullBookListener& null_book_listener() noexcept {
  static NullBookListener l;
  return l;
}

// Adapter: forwards to a BookListener through a virtual call (B0).
struct VirtualListener {
  BookListener* target = &null_book_listener();
  void on_bbo_change(Locate loc, const lob::Bbo& bbo) { target->on_bbo_change(loc, bbo); }
};

struct NullListener {
  void on_bbo_change(Locate, const lob::Bbo&) noexcept {}
};

// Folds every event into the stream digest and remembers the latest one, so
// a differential harness can compare per-operation events.
struct BboRecorder {
  BboDigest digest;
  bool fired = false;  // reset by the harness before each operation
  Locate loc = 0;
  lob::Bbo bbo{};
  void on_bbo_change(Locate l, const lob::Bbo& b) noexcept {
    digest.add(l, b);
    fired = true;
    loc = l;
    bbo = b;
  }
};

// BboRecorder behind the virtual interface (for B0).
class RecordingBookListener final : public BookListener {
 public:
  void on_bbo_change(Locate l, const lob::Bbo& b) override { rec.on_bbo_change(l, b); }
  BboRecorder rec;
};

}  // namespace lle::book
