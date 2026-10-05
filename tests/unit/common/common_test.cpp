#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "common/alpha.h"
#include "common/crc32c.h"
#include "common/endian.h"
#include "common/hash.h"
#include "common/prng.h"
#include "common/sha256.h"
#include "env/concepts.h"
#include "env/entropy.h"
#include "runtime/stage.h"

namespace lle {
namespace {

TEST(Endian, BigEndianRoundTrip) {
  unsigned char buf[8]{};
  store_be16(buf, 0x1234);
  EXPECT_EQ(buf[0], 0x12);
  EXPECT_EQ(buf[1], 0x34);
  EXPECT_EQ(load_be16(buf), 0x1234);
  store_be32(buf, 0xA1B2C3D4u);
  EXPECT_EQ(buf[0], 0xA1);
  EXPECT_EQ(load_be32(buf), 0xA1B2C3D4u);
  store_be64(buf, 0x0102030405060708ull);
  EXPECT_EQ(buf[7], 0x08);
  EXPECT_EQ(load_be64(buf), 0x0102030405060708ull);
}

TEST(Endian, Timestamp48) {
  unsigned char buf[6]{};
  const std::uint64_t ns = 0x0000'7FFF'1234'5678ull;  // < 2^48
  store_be48(buf, ns);
  EXPECT_EQ(load_be48(buf), ns);
  // Bytes from a real ITCH 'S' message: 0a 0a 60 aa db 93 = 03:03:59.687760787
  const unsigned char real[6] = {0x0a, 0x0a, 0x60, 0xaa, 0xdb, 0x93};
  EXPECT_EQ(load_be48(real), 11039687760787ull);
}

TEST(Alpha, PadAndView) {
  Symbol8 s("AAPL");
  EXPECT_EQ(s.raw(), "AAPL    ");
  EXPECT_EQ(s.view(), "AAPL");
  char wire[8];
  s.to_wire(wire);
  EXPECT_EQ(Symbol8::from_wire(wire), s);
  EXPECT_TRUE(Symbol8().blank());
}

TEST(Alpha, PaddedDecimal) {
  std::uint64_t v = 0;
  EXPECT_TRUE(parse_padded_decimal("   42", v));
  EXPECT_EQ(v, 42u);
  EXPECT_TRUE(parse_padded_decimal("42   ", v));
  EXPECT_EQ(v, 42u);
  EXPECT_FALSE(parse_padded_decimal("4x2", v));
  EXPECT_FALSE(parse_padded_decimal("     ", v));                 // blank is not a number
  EXPECT_FALSE(parse_padded_decimal("18446744073709551616", v));  // 2^64 overflows
  EXPECT_TRUE(parse_padded_decimal("18446744073709551615", v));
  EXPECT_EQ(v, UINT64_MAX);
  char f[20];
  format_padded_decimal(f, 12345);
  EXPECT_EQ(std::string(f, 20), std::string(15, ' ') + "12345");
}

TEST(Crc32c, KnownVector) {
  const char* s = "123456789";
  EXPECT_EQ(crc32c(s, 9), 0xE3069283u);
  EXPECT_EQ(crc32c_extend_sw(0, s, 9), 0xE3069283u);
}

TEST(Crc32c, HardwareMatchesSoftwareAndChains) {
  Prng r(7);
  std::vector<unsigned char> buf(4096 + 13);
  for (auto& b : buf) b = static_cast<unsigned char>(r.next_u64());
  for (std::size_t n : {0u, 1u, 7u, 8u, 9u, 63u, 64u, 1000u, 4109u}) {
    EXPECT_EQ(crc32c(buf.data(), n), crc32c_extend_sw(0, buf.data(), n)) << n;
    const std::size_t half = n / 2;
    EXPECT_EQ(crc32c_extend(crc32c(buf.data(), half), buf.data() + half, n - half), crc32c(buf.data(), n)) << n;
  }
}

TEST(Sha256, Fips180Vectors) {
  EXPECT_EQ(Sha256::hex(Sha256::of("", 0)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(Sha256::hex(Sha256::of("abc", 3)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const char* two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";  // 56 bytes: padding spills a block
  EXPECT_EQ(Sha256::hex(Sha256::of(two, std::strlen(two))),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  Sha256 m;  // one million 'a', fed in uneven pieces
  const std::string chunk(997, 'a');
  std::size_t left = 1'000'000;
  while (left > 0) {
    const std::size_t n = std::min(left, chunk.size());
    m.update(chunk.data(), n);
    left -= n;
  }
  EXPECT_EQ(Sha256::hex(m.finish()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(Env, OsEntropyAndProdRng) {
  static_assert(env::RngLike<env::ProdRng>);
  // Two 64-bit draws collide with probability 2^-64.
  EXPECT_NE(env::os_entropy64(), env::os_entropy64());
  env::ProdRng a, b;
  EXPECT_NE(a.next_u64(), b.next_u64());
}

TEST(Prng, DeterministicAndBounded) {
  Prng a(123), b(123);
  for (int i = 0; i < 1000; ++i) EXPECT_EQ(a.next_u64(), b.next_u64());
  Prng r(1);
  std::set<std::uint64_t> seen;
  for (int i = 0; i < 10'000; ++i) {
    const auto v = r.below(10);
    ASSERT_LT(v, 10u);
    seen.insert(v);
  }
  EXPECT_EQ(seen.size(), 10u);
  for (int i = 0; i < 1000; ++i) {
    const auto v = r.range(-5, 5);
    ASSERT_GE(v, -5);
    ASSERT_LE(v, 5);
  }
}

TEST(Prng, ForkedStreamsDiffer) {
  Prng root(99);
  auto s1 = root.fork(1);
  Prng root2(99);
  auto s2 = root2.fork(2);
  EXPECT_NE(s1.next_u64(), s2.next_u64());
}

TEST(Hash, Fnv1aStable) {
  Fnv1a64 h;
  h.str("a");
  EXPECT_EQ(h.value(), 0xaf63dc4c8601ec8cull);  // FNV-1a 64 of "a"
  Fnv1a64 x, y;
  x.u(std::uint32_t{0x01020304});
  const unsigned char le[4] = {4, 3, 2, 1};
  y.bytes(le, 4);
  EXPECT_EQ(x.value(), y.value());
}

struct CountStage {
  int left;
  int polled = 0;
  bool poll() {
    ++polled;
    if (left == 0) return false;
    --left;
    return true;
  }
};

TEST(Runtime, InlineRunnerPollsUntilIdle) {
  CountStage a{3}, b{5};
  rt::InlineRunner runner(a, b);
  runner.run_until([] { return false; }, 2);
  EXPECT_EQ(a.left, 0);
  EXPECT_EQ(b.left, 0);
  rt::StageRef ref(a);
  EXPECT_FALSE(ref.poll());
}

}  // namespace
}  // namespace lle
