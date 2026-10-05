#include <gtest/gtest.h>

#include <cstdint>
#include <list>
#include <string>
#include <vector>

#include "common/prng.h"
#include "lob/fifo.h"
#include "lob/slab_pool.h"

namespace lle::lob {
namespace {

// Pooled records with u32 handles.
template <class Fifo>
struct PoolStoreT {
  using H = Handle32;
  struct Node {
    int id = 0;
    typename Fifo::template Link<H> link;
  };
  SlabPool<Node> pool;
  Node& rec(H h) { return pool[h]; }
  const Node& rec(H h) const { return pool[h]; }
  H make(int id) {
    const H h = pool.alloc();
    pool[h].id = id;
    return h;
  }
};

// Node-based records with pointer handles.
template <class Fifo>
struct PtrStoreT {
  struct Node;
  using H = Node*;
  struct Node {
    int id = 0;
    typename Fifo::template Link<H> link;
  };
  std::list<Node> nodes;  // stable addresses
  Node& rec(H h) { return *h; }
  const Node& rec(H h) const { return *h; }
  H make(int id) {
    nodes.emplace_back();
    nodes.back().id = id;
    return &nodes.back();
  }
};

template <class Fifo, template <class> class StoreT>
struct Case {
  using F = Fifo;
  using Store = StoreT<Fifo>;
};

template <class C>
struct FifoContract : ::testing::Test {
  using F = typename C::F;
  using Store = typename C::Store;
  using H = typename Store::H;
  Store st;
  typename F::template Queue<H> q{};

  std::vector<int> ids() const {
    std::vector<int> v;
    F::for_each(st, q, [&](H h) { v.push_back(st.rec(h).id); });
    return v;
  }
};

using Cases = ::testing::Types<Case<IntrusiveFifo, PoolStoreT>, Case<IntrusiveFifo, PtrStoreT>,
                               Case<ListFifo, PoolStoreT>, Case<ListFifo, PtrStoreT>>;
TYPED_TEST_SUITE(FifoContract, Cases);

TYPED_TEST(FifoContract, PushBackKeepsArrivalOrder) {
  using F = typename TestFixture::F;
  EXPECT_TRUE(F::empty(this->q));
  for (int i = 1; i <= 4; ++i) F::push_back(this->st, this->q, this->st.make(i));
  EXPECT_FALSE(F::empty(this->q));
  EXPECT_EQ(this->ids(), (std::vector<int>{1, 2, 3, 4}));
  EXPECT_EQ(this->st.rec(F::front(this->st, this->q)).id, 1);
  std::string err;
  EXPECT_TRUE(F::check(this->st, this->q, 4, &err)) << err;
  EXPECT_FALSE(F::check(this->st, this->q, 3, &err));
}

TYPED_TEST(FifoContract, UnlinkHeadMiddleTail) {
  using F = typename TestFixture::F;
  using H = typename TestFixture::H;
  std::vector<H> h;
  for (int i = 1; i <= 5; ++i) {
    h.push_back(this->st.make(i));
    F::push_back(this->st, this->q, h.back());
  }
  F::unlink(this->st, this->q, h[2]);  // middle
  EXPECT_EQ(this->ids(), (std::vector<int>{1, 2, 4, 5}));
  F::unlink(this->st, this->q, h[0]);  // head
  EXPECT_EQ(this->ids(), (std::vector<int>{2, 4, 5}));
  F::unlink(this->st, this->q, h[4]);  // tail
  EXPECT_EQ(this->ids(), (std::vector<int>{2, 4}));
  F::push_back(this->st, this->q, h[0]);  // re-queued at the back: new priority
  EXPECT_EQ(this->ids(), (std::vector<int>{2, 4, 1}));
  std::string err;
  EXPECT_TRUE(F::check(this->st, this->q, 3, &err)) << err;
  F::unlink(this->st, this->q, h[1]);
  F::unlink(this->st, this->q, h[3]);
  F::unlink(this->st, this->q, h[0]);
  EXPECT_TRUE(F::empty(this->q));
  EXPECT_TRUE(F::check(this->st, this->q, 0, &err)) << err;
}

TYPED_TEST(FifoContract, RandomAgainstStdList) {
  using F = typename TestFixture::F;
  using H = typename TestFixture::H;
  Prng rng(99);
  std::vector<H> in;  // reference order
  int next = 0;
  for (int i = 0; i < 5'000; ++i) {
    if (in.empty() || rng.chance(1, 2)) {
      H h = this->st.make(next++);
      F::push_back(this->st, this->q, h);
      in.push_back(h);
    } else {
      const std::size_t k = static_cast<std::size_t>(rng.below(in.size()));
      F::unlink(this->st, this->q, in[k]);
      in.erase(in.begin() + static_cast<std::ptrdiff_t>(k));
    }
    if (i % 250 == 0) {
      std::vector<int> want;
      for (H h : in) want.push_back(this->st.rec(h).id);
      ASSERT_EQ(this->ids(), want);
      std::string err;
      ASSERT_TRUE(F::check(this->st, this->q, in.size(), &err)) << err;
    }
  }
}

TEST(IntrusiveFifo, CheckDetectsBrokenLinks) {
  PoolStoreT<IntrusiveFifo> st;
  IntrusiveFifo::Queue<Handle32> q;
  const auto a = st.make(1), b = st.make(2), c = st.make(3);
  IntrusiveFifo::push_back(st, q, a);
  IntrusiveFifo::push_back(st, q, b);
  IntrusiveFifo::push_back(st, q, c);
  st.rec(c).link.prev = a;  // corrupt
  std::string err;
  EXPECT_FALSE(IntrusiveFifo::check(st, q, 3, &err));
  EXPECT_NE(err.find("prev"), std::string::npos);
}

}  // namespace
}  // namespace lle::lob
