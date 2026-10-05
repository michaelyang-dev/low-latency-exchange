#pragma once
// itch2ouch (07 §3, WP N-19): converts a NASDAQ ITCH 5.0 day into an OUCH 5.0
// order-flow script, and reads and writes the script format.
//
// Mapping (the source order reference identifies the order through its life):
//   A, F  -> Enter Order: same side, shares, price and symbol; TIF System Hours
//            (GTX, so pre- and post-market adds rest as on NASDAQ and nothing
//            expires before 20:00); displayed; ClOrdID = the ITCH reference.
//   E, C  -> a marketable IOC Enter Order on the opposite side at the resting
//            order's price for the executed shares, from the same session
//            (self-match prevention off). ClOrdID = the resting order's reference.
//   X     -> Cancel Order with the reduced total quantity: OUCH 5.0 §2.3
//            Quantity is "the new intended order size", and the engine reads it
//            as the total over the replace chain including executions
//            (matching-rules §13.1, §16 #3), so Quantity = executed + remaining.
//   D     -> Cancel Order with Quantity 0.
//   U     -> Replace Order: new UserRefNum, Quantity = executed over the chain +
//            the new shares (OUCH 5.0 §2.2: "inclusive of previous executions"),
//            the new price; ClOrdID = the new ITCH reference.
//   P, Q, every other type -> nothing (non-displayed trades and crosses cannot be
//            reproduced from the displayed book; they are counted).
// Sessions: a symbol's whole flow goes to session (locate mod K) + 1, so the
// per-symbol order survives K independent connections; each session has its
// own strictly increasing UserRefNums (one account per session).
//
// Script file ("LLE order-flow script", big-endian, optionally gzip):
//   header  "LLEOFS1\n" | u32 version=1 | u32 date YYYYMMDD | u16 sessions |
//           u16 flags (bit 0: synthetic source) | u32 symbol count N |
//           u64 source messages | N x { symbol[8] | u32 round lot | u16 source
//           locate | char LULD tier | char ETP flag }
//   records [u16 len][u64 scheduled time, ns since midnight][u16 session][OUCH bytes]
//           with len = 10 + OUCH length; a zero length ends the script.
// Scheduled time = the timestamp of the ITCH message the record comes from.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/alpha.h"
#include "common/assert.h"
#include "common/endian.h"
#include "common/types.h"
#include "proto/itch50/itch50.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client::i2o {

inline constexpr std::array<char, 8> kMagic{'L', 'L', 'E', 'O', 'F', 'S', '1', '\n'};
inline constexpr std::uint32_t kVersion = 1;

struct SymbolInfo {
  Symbol8 symbol;
  std::uint32_t round_lot = 100;
  Locate locate = 0;  // in the source day
  char luld_tier = '2';
  char etp = 'N';
};

struct ScriptHeader {
  std::uint32_t date = 20190130;
  std::uint16_t sessions = 4;
  std::uint16_t flags = 0;
  std::uint64_t source_messages = 0;
  std::vector<SymbolInfo> symbols;  // in source locate order
};

enum class Op : std::uint8_t { Enter = 0, Cancel = 1, Replace = 2, Ioc = 3 };
inline constexpr std::size_t kOps = 4;

// Where a script record came from (the divergence report correlates by it).
struct Origin {
  Op op = Op::Enter;
  char itch_type = 0;      // A F E C X D U
  SeqNo itch_seq = 0;      // record index in the source day, from 1
  OrderRef ref = 0;        // the source order (for U: the original)
  OrderRef new_ref = 0;    // U: the new reference
  Locate locate = 0;
  Side side = Side::Buy;   // of the source (resting) order
  PxE4 price = 0;          // of the resting order (E/C) or the new price (A/F/U)
  PxE4 exec_price = 0;     // C: the execution price
  Qty shares = 0;          // A/F/U: shares; E/C/X: shares executed or cancelled
  Qty open_before = 0;     // E/C/X/D/U: the source order's open shares before
  bool printable = true;   // C
  UserRefNum urn = 0;      // the UserRefNum the record consumes (Enter, Replace, IOC) or names (Cancel)
  UserRefNum orig_urn = 0; // Replace: the original's
  std::uint16_t session = 0;
};

struct ConvertStats {
  std::uint64_t source = 0;
  std::array<std::uint64_t, 256> by_type{};
  std::array<std::uint64_t, kOps> ops{};
  std::uint64_t partial_cancels = 0, full_cancels = 0;
  std::uint64_t ioc_from_e = 0, ioc_from_c = 0;
  std::uint64_t c_nonprintable = 0, c_price_differs = 0;
  std::uint64_t hidden_trades = 0, hidden_shares = 0;   // P
  std::uint64_t cross_prints = 0, cross_shares = 0;     // Q
  std::uint64_t unknown_ref = 0, duplicate_ref = 0, bad_length = 0;
  std::uint64_t live_at_end = 0;
};

struct ConvertConfig {
  std::uint16_t sessions = 4;
  ouch50::TimeInForce tif = ouch50::TimeInForce::Gtx;
};

class Converter {
 public:
  explicit Converter(const ConvertConfig& cfg);

  // Converts message `seq` of the source. out(Nanos t, std::uint16_t session,
  // std::span<const std::byte> ouch, const Origin&) receives 0 or 1 records.
  template <class Out>
  void on_itch(SeqNo seq, std::span<const std::byte> msg, Out&& out);

  [[nodiscard]] const ConvertStats& stats() const noexcept { return st_; }
  [[nodiscard]] std::size_t live() const noexcept { return orders_.size(); }
  [[nodiscard]] UserRefNum last_urn(std::uint16_t session) const noexcept { return urn_[session]; }

 private:
  struct OState {
    UserRefNum urn = 0;
    std::uint32_t open = 0;
    std::uint32_t exec = 0;  // executed over the replace chain
    PxE4 price = 0;
    Locate locate = 0;
    std::uint16_t session = 0;
    Side side = Side::Buy;
  };
  std::size_t encode_enter(const OState& o, Qty qty, PxE4 px, ouch50::Side side, ouch50::TimeInForce tif, OrderRef cl);

  ConvertConfig cfg_;
  std::unordered_map<OrderRef, OState> orders_;  // looked up only; never iterated
  std::vector<UserRefNum> urn_;                  // per session (1-based)
  std::unique_ptr<Symbol8[]> sym_;               // per locate, from R and A/F
  std::array<std::byte, 160> buf_{};
  ConvertStats st_;
};

// --- script I/O -----------------------------------------------------------------------
class ScriptWriter {
 public:
  ScriptWriter() = default;
  ~ScriptWriter();
  ScriptWriter(const ScriptWriter&) = delete;
  ScriptWriter& operator=(const ScriptWriter&) = delete;
  // A path ending in ".gz" is written gzip-compressed.
  bool open(const std::string& path, const ScriptHeader& h, std::string* err);
  bool write(Nanos t, std::uint16_t session, std::span<const std::byte> ouch);
  bool close();  // writes the end marker
  [[nodiscard]] std::uint64_t records() const noexcept { return records_; }

 private:
  void* gz_ = nullptr;
  std::uint64_t records_ = 0;
};

struct ScriptRecord {
  Nanos t = 0;
  std::uint16_t session = 0;
  std::span<const std::byte> ouch;  // valid until the next read
};

class ScriptReader {
 public:
  ScriptReader() = default;
  ~ScriptReader();
  ScriptReader(const ScriptReader&) = delete;
  ScriptReader& operator=(const ScriptReader&) = delete;
  bool open(const std::string& path, std::string* err);  // plain or gzip
  [[nodiscard]] const ScriptHeader& header() const noexcept { return h_; }
  // False at the end marker (or an error: see error()).
  bool next(ScriptRecord& r);
  [[nodiscard]] const std::string& error() const noexcept { return err_; }

 private:
  void* gz_ = nullptr;
  ScriptHeader h_;
  std::array<std::byte, 65536> buf_{};
  std::string err_;
};

// Symbols of a day: every R message among the first `max_messages` records (0: all).
bool scan_symbols(const std::string& itch_path, std::uint64_t max_messages, std::vector<SymbolInfo>& out,
                  std::string* err);

// --- template implementation ------------------------------------------------------------
template <class Out>
void Converter::on_itch(SeqNo seq, std::span<const std::byte> msg, Out&& out) {
  ++st_.source;
  if (msg.empty()) return;
  const auto* p = msg.data();
  const auto t = static_cast<unsigned char>(p[0]);
  ++st_.by_type[t];
  if (msg.size() != itch50::kMsgLen[t]) {
    ++st_.bad_length;
    return;
  }
  const Nanos ts = static_cast<Nanos>(itch50::MessageHeaderView(p).timestamp());
  Origin og;
  og.itch_type = static_cast<char>(t);
  og.itch_seq = seq;
  auto lookup = [&](OrderRef ref) -> OState* {
    const auto it = orders_.find(ref);
    if (it == orders_.end()) {
      ++st_.unknown_ref;
      return nullptr;
    }
    return &it->second;
  };
  switch (static_cast<char>(t)) {
    case 'A':
    case 'F': {
      const itch50::AddOrderView v(p);  // F shares A's layout up to the price
      if (orders_.contains(v.order_ref())) {
        ++st_.duplicate_ref;
        return;
      }
      OState o;
      o.locate = v.stock_locate();
      sym_[o.locate] = v.stock();
      o.session = static_cast<std::uint16_t>(o.locate % cfg_.sessions + 1);
      o.urn = ++urn_[o.session];
      o.open = v.shares();
      o.price = v.price();
      o.side = v.side();
      orders_.emplace(v.order_ref(), o);
      og.op = Op::Enter;
      og.ref = v.order_ref();
      og.locate = o.locate;
      og.side = o.side;
      og.price = o.price;
      og.shares = o.open;
      og.urn = o.urn;
      og.session = o.session;
      const std::size_t n = encode_enter(o, o.open, o.price, static_cast<ouch50::Side>(static_cast<char>(o.side)),
                                         cfg_.tif, v.order_ref());
      ++st_.ops[static_cast<std::size_t>(Op::Enter)];
      out(ts, o.session, std::span<const std::byte>(buf_.data(), n), og);
      return;
    }
    case 'E':
    case 'C': {
      const bool with_price = t == 'C';
      const OrderRef ref = itch50::OrderExecutedView(p).order_ref();
      const Qty q = itch50::OrderExecutedView(p).executed_shares();
      OState* o = lookup(ref);
      if (o == nullptr) return;
      og.op = Op::Ioc;
      og.ref = ref;
      og.locate = o->locate;
      og.side = o->side;
      og.price = o->price;
      og.shares = q;
      og.open_before = o->open;
      og.session = o->session;
      if (with_price) {
        const itch50::OrderExecutedWithPriceView c(p);
        og.exec_price = c.execution_price();
        og.printable = static_cast<char>(c.printable()) == 'Y';
        if (!og.printable) ++st_.c_nonprintable;
        if (og.exec_price != o->price) ++st_.c_price_differs;
        ++st_.ioc_from_c;
      } else {
        og.exec_price = o->price;
        ++st_.ioc_from_e;
      }
      og.urn = ++urn_[o->session];
      const ouch50::Side side = o->side == Side::Buy ? ouch50::Side::Sell : ouch50::Side::Buy;
      const std::size_t n = encode_enter(*o, q, o->price, side, ouch50::TimeInForce::Ioc, ref);
      // Rewrite the UserRefNum the encoder took from the resting order.
      store_be32(buf_.data() + 1, og.urn);
      const std::uint16_t session = o->session;
      o->exec += q;
      o->open = o->open > q ? o->open - q : 0;
      if (o->open == 0) orders_.erase(ref);
      ++st_.ops[static_cast<std::size_t>(Op::Ioc)];
      out(ts, session, std::span<const std::byte>(buf_.data(), n), og);
      return;
    }
    case 'X':
    case 'D': {
      const bool del = t == 'D';
      const OrderRef ref = del ? itch50::OrderDeleteView(p).order_ref() : itch50::OrderCancelView(p).order_ref();
      OState* o = lookup(ref);
      if (o == nullptr) return;
      const Qty q = del ? o->open : itch50::OrderCancelView(p).cancelled_shares();
      og.op = Op::Cancel;
      og.ref = ref;
      og.locate = o->locate;
      og.side = o->side;
      og.price = o->price;
      og.shares = q;
      og.open_before = o->open;
      og.urn = o->urn;
      og.session = o->session;
      const std::uint32_t remaining = o->open > q ? o->open - q : 0;
      ouch50::in::CancelOrder c;
      c.user_ref_num = o->urn;
      c.quantity = remaining == 0 ? 0 : o->exec + remaining;  // the new total over the chain (§2.3)
      const std::size_t n = ouch50::encode(std::span<std::byte>(buf_), c);
      const std::uint16_t session = o->session;
      if (remaining == 0) {
        ++st_.full_cancels;
        orders_.erase(ref);
      } else {
        ++st_.partial_cancels;
        o->open = remaining;
      }
      ++st_.ops[static_cast<std::size_t>(Op::Cancel)];
      out(ts, session, std::span<const std::byte>(buf_.data(), n), og);
      return;
    }
    case 'U': {
      const itch50::OrderReplaceView v(p);
      OState* o = lookup(v.original_order_ref());
      if (o == nullptr) return;
      if (orders_.contains(v.new_order_ref())) {
        ++st_.duplicate_ref;
        return;
      }
      OState nw = *o;
      nw.urn = ++urn_[o->session];
      nw.open = v.shares();
      nw.price = v.price();
      og.op = Op::Replace;
      og.ref = v.original_order_ref();
      og.new_ref = v.new_order_ref();
      og.locate = o->locate;
      og.side = o->side;
      og.price = nw.price;
      og.shares = nw.open;
      og.open_before = o->open;
      og.urn = nw.urn;
      og.orig_urn = o->urn;
      og.session = o->session;
      ouch50::in::ReplaceOrder r;
      r.orig_user_ref_num = o->urn;
      r.user_ref_num = nw.urn;
      r.quantity = o->exec + nw.open;  // inclusive of previous executions (§2.2)
      r.price = static_cast<std::uint64_t>(nw.price);
      r.time_in_force = cfg_.tif;
      r.display = ouch50::Display::Visible;
      r.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
      char id[24];
      const int k = std::snprintf(id, sizeof id, "%llu", static_cast<unsigned long long>(v.new_order_ref()));
      r.cl_ord_id = Alpha<14>(std::string_view(id, static_cast<std::size_t>(k > 14 ? 14 : k)));
      const std::size_t n = ouch50::encode(std::span<std::byte>(buf_), r);
      orders_.erase(v.original_order_ref());
      orders_.emplace(v.new_order_ref(), nw);
      ++st_.ops[static_cast<std::size_t>(Op::Replace)];
      out(ts, nw.session, std::span<const std::byte>(buf_.data(), n), og);
      return;
    }
    case 'R':
      sym_[itch50::MessageHeaderView(p).stock_locate()] = itch50::StockDirectoryView(p).stock();
      return;
    case 'P':
      ++st_.hidden_trades;
      st_.hidden_shares += itch50::TradeView(p).shares();
      return;
    case 'Q':
      ++st_.cross_prints;
      st_.cross_shares += itch50::CrossTradeView(p).shares();
      return;
    default: return;
  }
}

}  // namespace lle::client::i2o
