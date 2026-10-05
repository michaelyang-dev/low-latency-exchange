#pragma once
// FIFO-per-level policies (04-order-book §3, X07).
//
// A FIFO policy defines the per-level Queue and the per-order Link, both
// parameterized on the store's handle type H (u32 pool handle or record
// pointer). Operations take the store so they can resolve handles:
// `st.rec(h).link` must name the order's Link.
//
//   ListFifo      std::list<H> per level; the order keeps its list iterator.
//                 The B0 design: one node allocation per order.
//   IntrusiveFifo doubly linked list threaded through the order records by
//                 handle; a level holds head and tail. No allocation.
#include <cstddef>
#include <iterator>
#include <list>
#include <string>

#include "lob/types.h"

namespace lle::lob {

struct IntrusiveFifo {
  template <class H>
  struct Link {
    H prev = nil_handle<H>();
    H next = nil_handle<H>();
  };
  template <class H>
  struct Queue {
    H head = nil_handle<H>();
    H tail = nil_handle<H>();
  };

  template <class Store, class H>
  static void push_back(Store& st, Queue<H>& q, H h) noexcept {
    constexpr H kNil = nil_handle<H>();
    auto& l = st.rec(h).link;
    l.prev = q.tail;
    l.next = kNil;
    if (q.tail != kNil) {
      st.rec(q.tail).link.next = h;
    } else {
      q.head = h;
    }
    q.tail = h;
  }

  template <class Store, class H>
  static void unlink(Store& st, Queue<H>& q, H h) noexcept {
    constexpr H kNil = nil_handle<H>();
    const auto& l = st.rec(h).link;
    if (l.prev != kNil) {
      st.rec(l.prev).link.next = l.next;
    } else {
      q.head = l.next;
    }
    if (l.next != kNil) {
      st.rec(l.next).link.prev = l.prev;
    } else {
      q.tail = l.prev;
    }
  }

  template <class H>
  [[nodiscard]] static bool empty(const Queue<H>& q) noexcept {
    return q.head == nil_handle<H>();
  }

  template <class Store, class H>
  [[nodiscard]] static H front(const Store&, const Queue<H>& q) noexcept {
    return q.head;
  }

  // f(H) in priority order (front first).
  template <class Store, class H, class F>
  static void for_each(const Store& st, const Queue<H>& q, F&& f) {
    for (H h = q.head; h != nil_handle<H>(); h = st.rec(h).link.next) f(h);
  }

  // Link consistency: head/tail ends, prev/next symmetry, length == expect.
  template <class Store, class H>
  [[nodiscard]] static bool check(const Store& st, const Queue<H>& q, std::size_t expect, std::string* err) {
    constexpr H kNil = nil_handle<H>();
    std::size_t n = 0;
    H prev = kNil;
    for (H h = q.head; h != kNil; h = st.rec(h).link.next) {
      if (st.rec(h).link.prev != prev) {
        if (err) *err = "fifo: prev link mismatch";
        return false;
      }
      prev = h;
      if (++n > expect) {
        if (err) *err = "fifo: longer than level count (cycle?)";
        return false;
      }
    }
    if (prev != q.tail) {
      if (err) *err = "fifo: tail mismatch";
      return false;
    }
    if (n != expect) {
      if (err) *err = "fifo: length != level count";
      return false;
    }
    return true;
  }
};

struct ListFifo {
  template <class H>
  struct Link {
    typename std::list<H>::iterator it{};
  };
  template <class H>
  using Queue = std::list<H>;

  template <class Store, class H>
  static void push_back(Store& st, Queue<H>& q, H h) {
    q.push_back(h);
    st.rec(h).link.it = std::prev(q.end());
  }

  template <class Store, class H>
  static void unlink(Store& st, Queue<H>& q, H h) noexcept {
    q.erase(st.rec(h).link.it);
  }

  template <class H>
  [[nodiscard]] static bool empty(const Queue<H>& q) noexcept {
    return q.empty();
  }

  template <class Store, class H>
  [[nodiscard]] static H front(const Store&, const Queue<H>& q) noexcept {
    return q.empty() ? nil_handle<H>() : q.front();
  }

  template <class Store, class H, class F>
  static void for_each(const Store&, const Queue<H>& q, F&& f) {
    for (H h : q) f(h);
  }

  template <class Store, class H>
  [[nodiscard]] static bool check(const Store& st, const Queue<H>& q, std::size_t expect, std::string* err) {
    std::size_t n = 0;
    for (auto it = q.begin(); it != q.end(); ++it) {
      if (&*st.rec(*it).link.it != &*it) {
        if (err) *err = "fifo: stored list iterator does not point at the order";
        return false;
      }
      ++n;
    }
    if (n != expect) {
      if (err) *err = "fifo: length != level count";
      return false;
    }
    return true;
  }
};

}  // namespace lle::lob
