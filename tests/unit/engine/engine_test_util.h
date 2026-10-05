#pragma once
// Shared fixture for engine unit and golden tests: a standard day
// configuration, a sink that validates every emitted message (ITCH strict
// validator, OUCH validate_outbound), and decoding helpers.
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "engine/engine.h"
#include "engine/scenario.h"
#include "proto/itch50/itch50.h"
#include "proto/itch50/validator.h"
#include "proto/ouch50/ouch50.h"

namespace lle::engine::testing {

struct Msg {
  Dest dest;
  std::uint32_t session;
  std::vector<std::byte> bytes;
  AuditEvent audit{};
  [[nodiscard]] char type() const { return bytes.empty() ? '\0' : static_cast<char>(bytes[0]); }
};

// Records outputs per apply() and checks each message against the codecs.
class CheckingSink {
 public:
  void itch(std::uint64_t, std::span<const std::byte> b) {
    if (itch_validator_.check(b) != 0) ++bad_;
    out_.push_back(Msg{Dest::Itch, 0, {b.begin(), b.end()}});
  }
  void ouch(std::uint64_t, std::uint32_t s, std::span<const std::byte> b) {
    if (!ouch50::validate_outbound(b)) ++bad_;
    out_.push_back(Msg{Dest::Ouch, s, {b.begin(), b.end()}});
  }
  void audit(std::uint64_t, const AuditEvent& a) { out_.push_back(Msg{Dest::Audit, a.session_id, {}, a}); }

  std::vector<Msg> take() { return std::exchange(out_, {}); }
  [[nodiscard]] std::uint64_t bad() const { return bad_; }
  [[nodiscard]] const itch50::Validator& itch_validator() const { return itch_validator_; }

 private:
  std::vector<Msg> out_;
  itch50::Validator itch_validator_{true};
  std::uint64_t bad_ = 0;
};

inline constexpr std::uint32_t kAcctA = 100;  // firms FIRM (default), FRM2
inline constexpr std::uint32_t kAcctB = 200;  // firm OTHR
inline constexpr std::uint32_t kSessA = 1;    // account A
inline constexpr std::uint32_t kSessB = 2;    // account B
inline constexpr std::uint32_t kSessA2 = 3;   // account A, second port (post-only cancels, no market orders)
inline constexpr Locate kAAPL = 1;            // tick $0.01
inline constexpr Locate kMSFT = 2;            // tick $0.01
inline constexpr Locate kHALF = 3;            // tick $0.005

class EngineFixture : public ::testing::Test {
 protected:
  void SetUp() override {
    sc_.day_start();
    std::array<SymbolEntry, 3> syms{};
    syms[0].symbol = Symbol8("AAPL");
    syms[1].symbol = Symbol8("MSFT");
    syms[2].symbol = Symbol8("HALF");
    syms[2].tick = 50;
    std::array<AccountEntry, 2> accts{};
    accts[0].account_id = kAcctA;
    accts[0].firms[0] = Mpid4("FIRM");
    accts[0].firms[1] = Mpid4("FRM2");
    accts[1].account_id = kAcctB;
    accts[1].firms[0] = Mpid4("OTHR");
    std::array<SessionEntry, 3> sess{};
    sess[0] = SessionEntry{kSessA, kAcctA, SessionEntry::kCancelOnDisconnect | SessionEntry::kMarketOrders, 'N'};
    sess[1] = SessionEntry{kSessB, kAcctB, SessionEntry::kCancelOnDisconnect | SessionEntry::kMarketOrders, 'N'};
    sess[2] = SessionEntry{kSessA2, kAcctA, SessionEntry::kPostOnlyCancel, 'N'};
    sc_.symbols(syms);
    sc_.accounts(accts);
    sc_.sessions(sess);
    for (std::size_t i = 0; i < sc_.size(); ++i) eng_.apply(sc_[i], sink_);
    setup_out_ = sink_.take();
  }

  void TearDown() override {
    EXPECT_EQ(sink_.bad(), 0u) << "an emitted message failed ITCH strict or OUCH outbound validation";
    std::string err;
    EXPECT_TRUE(eng_.check(&err)) << err;
  }

  std::vector<Msg> run(const InputRecord& r) {
    eng_.apply(r, sink_);
    return sink_.take();
  }
  std::vector<Msg> ouch(std::uint32_t session, std::span<const std::byte> m) {
    const std::uint32_t acct = session == kSessB ? kAcctB : kAcctA;
    return run(sc_.ouch(session, acct, m));
  }
  std::vector<Msg> a(std::span<const std::byte> m) { return ouch(kSessA, m); }
  std::vector<Msg> b(std::span<const std::byte> m) { return ouch(kSessB, m); }

  // Wire timestamp the next record will carry.
  [[nodiscard]] std::uint64_t ts() const { return static_cast<std::uint64_t>(sc_.now()); }

  Scenario sc_;
  Engine eng_;
  CheckingSink sink_;
  std::vector<Msg> setup_out_;
};

// ---- expected-message builders: the fixed parts written field by field.

template <class M>
std::vector<std::byte> itch_bytes(M m, Locate l, std::uint64_t ts) {
  m.stock_locate = l;
  m.tracking_number = 0;
  m.timestamp = ts;
  std::vector<std::byte> b(M::kLen);
  (void)itch50::encode(std::span<std::byte>(b), m);
  return b;
}

template <class M>
std::vector<std::byte> ouch_out(M m, std::uint64_t ts, const ouch50::TagSet& tags = {}) {
  m.timestamp = ts;
  std::vector<std::byte> b(ouch50::kMaxOutboundOuchLen);
  ouch50::MessageWriter<M> w(std::span<std::byte>(b), m);
  if constexpr (M::kRule != ouch50::AppendageRule::None) ouch50::put_tags(w.tags(), tags);
  b.resize(w.finish());
  return b;
}

inline std::string hex(std::span<const std::byte> b) {
  static constexpr char k[] = "0123456789abcdef";
  std::string s;
  for (std::byte x : b) {
    s += k[std::to_integer<unsigned>(x) >> 4];
    s += k[std::to_integer<unsigned>(x) & 15];
  }
  return s;
}

inline std::string describe(const std::vector<Msg>& v) {
  std::string s;
  for (const Msg& m : v) {
    s += m.dest == Dest::Itch ? "ITCH " : (m.dest == Dest::Ouch ? "OUCH(" + std::to_string(m.session) + ") " : "AUDIT ");
    if (m.dest == Dest::Audit) {
      s += std::to_string(static_cast<int>(m.audit.code));
    } else {
      s += m.type();
      s += ' ';
      s += hex(m.bytes);
    }
    s += '\n';
  }
  return s;
}

// Expected output entry.
struct Exp {
  Dest dest;
  std::uint32_t session;
  std::vector<std::byte> bytes;
};
inline Exp I(std::vector<std::byte> b) { return Exp{Dest::Itch, 0, std::move(b)}; }
inline Exp O(std::uint32_t s, std::vector<std::byte> b) { return Exp{Dest::Ouch, s, std::move(b)}; }

// Compares the client-visible outputs (audit events excluded) in order.
inline ::testing::AssertionResult same(const std::vector<Msg>& got, const std::vector<Exp>& want) {
  std::vector<const Msg*> vis;
  for (const Msg& m : got)
    if (m.dest != Dest::Audit) vis.push_back(&m);
  std::string w;
  for (const Exp& e : want) {
    w += e.dest == Dest::Itch ? "ITCH " : "OUCH(" + std::to_string(e.session) + ") ";
    w += e.bytes.empty() ? '?' : static_cast<char>(e.bytes[0]);
    w += ' ' + hex(e.bytes) + '\n';
  }
  if (vis.size() != want.size())
    return ::testing::AssertionFailure() << "count " << vis.size() << " != " << want.size() << "\n got:\n"
                                         << describe(got) << " want:\n"
                                         << w;
  for (std::size_t i = 0; i < want.size(); ++i) {
    const Msg& g = *vis[i];
    if (g.dest != want[i].dest || g.session != want[i].session || g.bytes != want[i].bytes)
      return ::testing::AssertionFailure() << "message " << i << " differs\n got:\n"
                                           << describe(got) << " want:\n"
                                           << w;
  }
  return ::testing::AssertionSuccess();
}

inline bool has_audit(const std::vector<Msg>& v, AuditCode c) {
  for (const Msg& m : v)
    if (m.dest == Dest::Audit && m.audit.code == c) return true;
  return false;
}

inline ouch50::TagSet tags_idx(std::uint8_t idx) {
  ouch50::TagSet t;
  t.set_user_ref_idx(idx);
  return t;
}

}  // namespace lle::engine::testing
