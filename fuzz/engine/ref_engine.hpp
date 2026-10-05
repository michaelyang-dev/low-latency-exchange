#pragma once
// RefEngine: a naive, obviously-correct reference for the matching engine
// (05-matching-engine §9, E-05/E-14), written from the rules in
// docs/design/matching-rules.md independently of src/engine's code:
// std::map price levels holding two std::list queues, std::list off-book
// lists, std::map order and UserRefNum tables, linear scans, totals
// recomputed by summation, brute-force crosses (cross_bruteforce.hpp), and
// matching outputs buffered so an order's state is decided after the fact
// ("no execution and nothing rests" = dead) rather than by a dry run. Only
// the wire codecs (src/proto), the record payload layouts (engine/records.h)
// and the cross I/O structs are shared.
#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "common/alpha.h"
#include "common/endian.h"
#include "common/hash.h"
#include "common/int128.h"
#include "common/time.h"
#include "common/types.h"
#include "cross_bruteforce.hpp"
#include "engine/records.h"
#include "proto/itch50/itch50.h"
#include "proto/ouch50/ouch50.h"

namespace lle::engine::ref {

struct ROut {
  bool itch = false;
  std::uint32_t session = 0;
  std::vector<std::byte> bytes;
  friend bool operator==(const ROut&, const ROut&) = default;
};

class RefEngine {
 public:
  RefEngine() { day_reset(); }

  void apply(const InputRecord& rec, std::vector<ROut>& out) {
    out_ = &out;
    ts_ = rec.ts_ns - midnight_;
    if (ts_ < 0) ts_ = 0;
    if (ts_ > kNsPerDay - 1) ts_ = kNsPerDay - 1;
    index_ = rec.index;
    switch (rec.type) {
      case 1: day_start(rec.payload); break;
      case 2: config(rec.payload); break;
      case 3: session_event(rec.payload); break;
      case 4: ouch_in(rec.payload, (rec.flags & 1) != 0); break;
      case 5: timer(rec.payload); break;
      case 6: admin(rec.payload); break;
      default: break;
    }
    risk_after_record();
  }

  [[nodiscard]] std::vector<std::byte> canonical() const;
  [[nodiscard]] std::uint64_t state_hash() const {
    Fnv1a64 h;
    const auto c = canonical();
    h.bytes(c);
    return h.value();
  }
  [[nodiscard]] std::size_t live_orders() const { return orders_.size(); }

 private:
  // ---------------------------------------------------------------- model
  enum : std::uint16_t {
    fPostOnly = 1, fHasExpire = 2, fHeld = 4, fIO = 8, fMarket = 16, fCxlPending = 32, fPendSent = 64, fRejSent = 128,
    fMidPeg = 256, fChild = 512, fLocated = 1024,
  };
  enum : std::uint8_t { mOpenFreeze = 1, mMooCut = 2, mLooCut = 4, mCloseFreeze = 8, mMocCut = 16, mLocCut = 32 };
  struct Sym {
    Symbol8 symbol;
    std::uint32_t lot = 0, tick = 0, adv = 0;
    PxE4 prior_close = 0;
    char mc = ' ', luld = ' ';
    std::uint8_t flags = 0;
    bool opened = false, closed = false;
    char regsho = '0';
    std::uint8_t halt = 0;  // 0 none, 1 halted, 2 quote, 3 paused, 4 ipo quote, 5 ipo prelaunch
    std::uint8_t kind = 0;  // 0 none, 1 news, 2 luld, 3 mwcb, 4 ipo
    Alpha<4> reason;
    std::uint32_t ticks = 0, period = 0, ext = 0;
    PxE4 arp = 0, clo = 0, chi = 0, cstep = 0, blo = 0, bhi = 0;
    std::int32_t limit = -1;
    PxE4 last = 0;
    Nanos last_ns = 0;
    PxE4 oref2 = 0, cref1 = 0, cref2 = 0, ipo_px = 0, ipo_band = 0, ipo_exp = 0;
    std::uint32_t peg_pulled = 0;
    std::list<std::uint64_t> pending;
    std::list<std::uint64_t> pegs[2];
  };
  struct Acct {
    std::uint32_t id = 0;
    std::vector<Mpid4> firms;
    std::uint8_t disabled = 0;
    bool permit = false;
    std::map<std::uint8_t, std::uint32_t> last;
  };
  struct Sess {
    std::uint32_t id = 0, acct = 0;
    std::uint8_t flags = 0;
    char aiq = 'N';
    std::uint8_t late = 1;
    std::uint64_t live = 0, outs = 0;
  };
  struct Ord {
    std::uint64_t ref = 0, itch_ref = 0, prio = 0;
    std::uint16_t locate = 0;
    char side = 'B';
    std::uint8_t where = 0;  // 0 book, 1 pending, 2 peg
    char marking = 'B', display = 'Y', tif = '0', capacity = 'A', iso = 'N', cross = 'N', aiq = 'N';
    PxE4 px = 0;
    PxE4 rpx = 0;  // risk price: open notional = (leaves + reserve) x rpx
    std::uint32_t reserve = 0;  // reserve shares (an entry ref|kRes in the hidden queue)
    std::uint64_t rprio = 0;    // the reserve part's time priority (the order's entry)
    bool off = false;           // display used up, out of its queue until the refresh
    bool queued = false;        // in rq_ (refresh queue)
    std::uint32_t leaves = 0, done = 0, minq = 0, maxf = 0, urn = 0, acct = 0, sess = 0, expire = 0;
    Mpid4 firm;
    std::uint16_t group = 0, flags = 0;
    Alpha<2> aiq_group;
    std::uint8_t idx = 0;
    [[nodiscard]] int cls() const { return display == 'N' ? 1 : 0; }
    [[nodiscard]] bool has(std::uint16_t f) const { return (flags & f) != 0; }
  };
  struct Level {
    std::list<std::uint64_t> q[2];
  };
  struct Book {
    std::map<PxE4, Level> bids, asks;
  };
  struct Params {
    std::int64_t thr_bps = 1000, thr_min = 5000, pt_bps = 1000, pt_min = 5000, pt_mask = 7, halt = 300, luld = 300,
                 mwcb = 900, limit = 15, ext = 300;
  };

  // ---------------------------------------------------------------- writer
  struct W {
    std::vector<std::byte> b;
    void n(std::uint64_t v, int k) {
      for (int i = 0; i < k; ++i) b.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xFF));
    }
    void u8(std::uint8_t v) { n(v, 1); }
    void u16(std::uint16_t v) { n(v, 2); }
    void u32(std::uint32_t v) { n(v, 4); }
    void u64(std::uint64_t v) { n(v, 8); }
  };
  static std::uint64_t pack(const char* c, int k) {
    std::uint64_t v = 0;
    for (int i = 0; i < k; ++i) v |= std::uint64_t{static_cast<unsigned char>(c[i])} << (8 * i);
    return v;
  }
  void walk_order(W& w, const Ord& o) const;

  void day_reset() {
    syms_.clear();
    books_.clear();
    accts_.clear();
    sess_.clear();
    orders_.clear();
    urns_.clear();
    sched_.clear();
    prm_ = Params{};
    cfg_next_ = 0;
    cfg_total_ = 0;
    cfg_buf_.clear();
    midnight_ = 0;
    date_ = 0;
    started_ = false;
    session_ = 'R';
    init_session_ = 'R';
    miles_ = 0;
    next_ref_ = 1;
    next_match_ = 1;
    itch_n_ = 0;
    mwcb_ = {0, 0, 0};
    mwcb_breach_ = 0;
    risk_reset();
  }

  // ---------------------------------------------------------------- output
  std::vector<ROut>& sink() { return buffer_ != nullptr ? *buffer_ : *out_; }
  template <class M>
  void itch(M m, std::uint16_t locate) {
    m.stock_locate = locate;
    m.tracking_number = 0;
    m.timestamp = static_cast<std::uint64_t>(ts_);
    ROut r;
    r.itch = true;
    r.bytes.resize(M::kLen);
    (void)itch50::encode(std::span<std::byte>(r.bytes), m);
    ++itch_n_;
    sink().push_back(std::move(r));
  }
  template <class M>
  void ouch(std::uint32_t si, M m, const ouch50::TagSet& tags) {
    m.timestamp = static_cast<std::uint64_t>(ts_);
    ROut r;
    r.session = sess_[si].id;
    r.bytes.resize(200);
    ouch50::MessageWriter<M> w(std::span<std::byte>(r.bytes), m);
    if constexpr (M::kRule != ouch50::AppendageRule::None) ouch50::put_tags(w.tags(), tags);
    r.bytes.resize(w.finish());
    ++sess_[si].outs;
    sink().push_back(std::move(r));
  }
  static ouch50::TagSet idx_tag(std::uint8_t idx) {
    ouch50::TagSet t;
    if (idx != 0) t.set_user_ref_idx(idx);
    return t;
  }
  void o_canceled(std::uint32_t s, std::uint32_t urn, std::uint8_t idx, std::uint32_t q, char why) {
    ouch50::out::OrderCanceled m;
    m.user_ref_num = urn;
    m.quantity = q;
    m.reason = static_cast<ouch50::CancelReason>(why);
    ouch(s, m, idx_tag(idx));
  }
  void o_reject(std::uint32_t s, std::uint32_t urn, std::uint8_t idx, std::uint16_t why, const Alpha<14>& clid) {
    ouch50::out::Rejected m;
    m.user_ref_num = urn;
    m.reason = static_cast<ouch50::RejectReason>(why);
    m.cl_ord_id = clid;
    ouch(s, m, idx_tag(idx));
  }
  void o_exec(std::uint32_t s, std::uint32_t urn, std::uint8_t idx, std::uint32_t q, PxE4 px, char flag,
              std::uint64_t mn) {
    ouch50::out::OrderExecuted e;
    e.user_ref_num = urn;
    e.quantity = q;
    e.price = static_cast<std::uint64_t>(px);
    e.liquidity_flag = static_cast<ouch50::LiquidityFlag>(flag);
    e.match_number = mn;
    ouch(s, e, idx_tag(idx));
    RAcct& ra = rk_.accts[sess_[s].acct];
    ra.executed += i128{q} * px;
    ra.touched = true;
  }
  void i_delete(std::uint16_t l, std::uint64_t ref) {
    itch50::OrderDelete d;
    d.order_ref = ref;
    itch(d, l);
  }
  void i_action(std::uint16_t l, char state, const Alpha<4>& reason) {
    itch50::StockTradingAction m;
    m.stock = syms_[l - 1u].symbol;
    m.trading_state = static_cast<itch50::TradingState>(state);
    m.reserved = ' ';
    m.reason = reason;
    itch(m, l);
  }

  // ---------------------------------------------------------------- helpers
  Sym& sym(std::uint16_t l) { return syms_[l - 1u]; }
  const Sym& sym(std::uint16_t l) const { return syms_[l - 1u]; }
  Book& book(std::uint16_t l) { return books_[l - 1u]; }
  std::map<PxE4, Level>& side_map(std::uint16_t l, char side) { return side == 'B' ? book(l).bids : book(l).asks; }
  int find_sess(std::uint32_t id) const {
    for (std::size_t i = 0; i < sess_.size(); ++i)
      if (sess_[i].id == id) return static_cast<int>(i);
    return -1;
  }
  int find_sym(const Symbol8& s) const {
    for (std::size_t i = 0; i < syms_.size(); ++i)
      if (syms_[i].symbol == s) return static_cast<int>(i + 1);
    return 0;
  }
  // Ascending reference (= entry) order, by account in table order.
  std::vector<std::uint64_t> refs_of_acct(std::uint32_t a) const {
    std::vector<std::uint64_t> v;
    for (const auto& [ref, o] : orders_)
      if (o.acct == a) v.push_back(ref);
    return v;
  }
  // Queue entries: an order ref, or ref|kRes for the reserve part of a reserve order.
  static constexpr std::uint64_t kRes = std::uint64_t{1} << 63;
  static bool is_res(std::uint64_t x) { return (x & kRes) != 0; }
  static std::uint64_t base(std::uint64_t x) { return x & ~kRes; }
  std::uint32_t part_leaves(std::uint64_t x) const {
    const Ord& o = orders_.at(base(x));
    return is_res(x) ? o.reserve : o.leaves;
  }
  std::uint64_t part_prio(std::uint64_t x) const {
    const Ord& o = orders_.at(base(x));
    return is_res(x) ? o.rprio : o.prio;
  }
  // The displayed part of an order on the book.
  bool shown(std::uint64_t x) const {
    const Ord& o = orders_.at(base(x));
    return !is_res(x) && o.where == 0 && o.cls() == 0;
  }
  std::uint64_t level_qty(const Level& lv, int c) const {
    std::uint64_t q = 0;
    for (std::uint64_t r : lv.q[c]) q += part_leaves(r);
    return q;
  }
  // Removes one queue entry; an empty level goes.
  void unqueue(std::uint16_t l, char side, PxE4 px, int c, std::uint64_t entry) {
    auto& m = side_map(l, side);
    const auto it = m.find(px);
    if (it == m.end()) return;
    it->second.q[c].remove(entry);
    if (it->second.q[0].empty() && it->second.q[1].empty()) m.erase(it);
  }
  // Best displayed price of a side (a level with displayed shares); 0 if none.
  PxE4 disp_best(std::uint16_t l, char side) {
    auto& m = side_map(l, side);
    if (side == 'B') {
      for (auto it = m.rbegin(); it != m.rend(); ++it)
        if (level_qty(it->second, 0) > 0) return it->first;
    } else {
      for (auto& [px, lv] : m)
        if (level_qty(lv, 0) > 0) return px;
    }
    return 0;
  }
  // Best level (any class) of a side; nullptr if empty.
  Level* best_level(std::uint16_t l, char side, PxE4* px) {
    auto& m = side_map(l, side);
    if (m.empty()) return nullptr;
    if (side == 'B') {
      *px = m.rbegin()->first;
      return &m.rbegin()->second;
    }
    *px = m.begin()->first;
    return &m.begin()->second;
  }
  PxE4 tick_at(std::uint16_t l, PxE4 px) const { return px >= 10000 ? static_cast<PxE4>(sym(l).tick) : 1; }
  PxE4 round_px(std::uint16_t l, PxE4 p, char dir) const {
    if (p <= 0) return 0;
    const PxE4 t = tick_at(l, p);
    const PxE4 lo = p - p % t;
    if (lo == p) return p;
    if (dir == 'U') return lo + t;
    if (dir == 'D') return lo;
    return 2 * (p - lo) >= t ? lo + t : lo;
  }
  static bool crosses(char side, PxE4 resting, PxE4 limit) { return side == 'B' ? resting <= limit : resting >= limit; }
  static bool aiq_ok(char c) { return c != '\0' && std::string_view("NYDOW0124").find(c) != std::string_view::npos; }
  static bool aiq_firm(char c) { return std::string_view("YDOW").find(c) != std::string_view::npos; }
  static char aiq_act(char c) {
    switch (c) {
      case 'Y': case 'D': case '0': case '1': return 'B';
      case 'O': case '2': return 'O';
      case 'W': case '4': return 'W';
      default: return 0;
    }
  }
  static bool aiq_details(char c) { return c == 'D' || c == '1'; }

  // Removes an order record from wherever it lives (no output).
  void erase_order(std::uint64_t ref) {
    Ord& o = orders_.at(ref);
    if (o.queued) std::erase(rq_, ref);
    if (o.where == 0) {
      if (!o.off) unqueue(o.locate, o.side, o.px, o.cls(), ref);
      if (o.reserve > 0) unqueue(o.locate, o.side, o.px, 1, ref | kRes);
    } else if (o.where == 1) {
      sym(o.locate).pending.remove(ref);
    } else {
      sym(o.locate).pegs[o.side == 'B' ? 0 : 1].remove(ref);
    }
    urns_.erase(std::make_tuple(o.acct, o.idx, o.urn));
    orders_.erase(ref);
  }
  // Full cancel: OUCH C, ITCH D if displayed on the book.
  void kill(std::uint64_t ref, char why) {
    ref = base(ref);
    const Ord o = orders_.at(ref);
    o_canceled(o.sess, o.urn, o.idx, o.leaves + o.reserve, why);
    if (o.where == 0 && o.display != 'N' && !o.off) i_delete(o.locate, o.itch_ref);
    erase_order(ref);
  }
  // d shares leave an order; ITCH as the caller decides.
  void shrink(std::uint64_t ref, std::uint32_t d) {
    Ord& o = orders_.at(ref);
    o.leaves -= d;
    if (o.leaves == 0) erase_order(ref);
  }
  void i_reduce(const Ord& o, std::uint32_t d) {
    if (d == o.leaves) {
      i_delete(o.locate, o.itch_ref);
    } else {
      itch50::OrderCancel x;
      x.order_ref = o.itch_ref;
      x.cancelled_shares = d;
      itch(x, o.locate);
    }
  }
  void i_add(const Ord& o) {
    if (o.display == 'Y') {
      itch50::AddOrder m;
      m.order_ref = o.itch_ref;
      m.side = o.side == 'B' ? Side::Buy : Side::Sell;
      m.shares = o.leaves;
      m.stock = sym(o.locate).symbol;
      m.price = o.px;
      itch(m, o.locate);
    } else if (o.display == 'A') {
      itch50::AddOrderMpid m;
      m.order_ref = o.itch_ref;
      m.side = o.side == 'B' ? Side::Buy : Side::Sell;
      m.shares = o.leaves;
      m.stock = sym(o.locate).symbol;
      m.price = o.px;
      m.attribution = o.firm;
      itch(m, o.locate);
    }
  }
  void to_book(std::uint64_t ref) {  // append at the back of its FIFO
    Ord& o = orders_.at(ref);
    o.where = 0;
    side_map(o.locate, o.side)[o.px].q[o.cls()].push_back(ref);
  }
  void to_book_by_prio(std::uint64_t ref) {  // by time priority among its FIFO
    Ord& o = orders_.at(ref);
    o.where = 0;
    auto& q = side_map(o.locate, o.side)[o.px].q[o.cls()];
    auto it = q.begin();
    while (it != q.end() && part_prio(*it) <= o.prio) ++it;
    q.insert(it, ref);
  }
  // Last sale; Rule 201: at or below 90% of the prior close the short sale
  // price test turns on for the day (ITCH 'Y' '1').
  void last_sale(std::uint16_t l, PxE4 px) {
    Sym& y = sym(l);
    y.last = px;
    y.last_ns = ts_;
    if (y.regsho == '0' && y.prior_close > 0 && px * 10 <= y.prior_close * 9) {
      y.regsho = '1';
      itch50::RegShoRestriction m;
      m.stock = y.symbol;
      m.reg_sho_action = static_cast<itch50::RegShoAction>('1');
      itch(m, l);
    }
  }
  // floor((NBB + NBO) / 2) of the displayed best bid and offer; active when both exist and NBB < NBO.
  PxE4 mid(std::uint16_t l, bool* active) {
    const PxE4 b = disp_best(l, 'B'), a = disp_best(l, 'S');
    *active = b > 0 && a > 0 && b < a;
    return *active ? (b + a) / 2 : 0;
  }
  void consume_part(std::uint64_t part, std::uint32_t q);
  void refresh_all();
  void reduce_user(std::uint64_t ref, std::uint32_t d);

  bool frozen(const Ord& o) const {
    if (o.where != 1) return false;
    const Sym& y = sym(o.locate);
    if (o.cross == 'O' || o.has(fHeld)) return (miles_ & mOpenFreeze) && !y.opened;
    if (o.cross == 'C') return (miles_ & mCloseFreeze) && !y.closed && ((miles_ & mLocCut) || !accts_[o.acct].permit);
    return false;
  }

  // ---------------------------------------------------------------- records
  void day_start(std::span<const std::byte> p) {
    if (p.size() < 48 || load_le32(p.data()) != 1) return;
    day_reset();
    date_ = load_le32(p.data() + 4);
    midnight_ = static_cast<Nanos>(load_le64(p.data() + 8));
  }
  void config(std::span<const std::byte> p);
  bool load(std::uint16_t table, std::span<const std::byte> t);
  void directory();
  void session_event(std::span<const std::byte> p);
  void timer(std::span<const std::byte> p);
  void milestone(std::uint16_t arg);
  void admin(std::span<const std::byte> p);

  // ---------------------------------------------------------------- OUCH
  void ouch_in(std::span<const std::byte> p, bool malformed);
  struct Req {
    char side = 'B', marking = 'B';
    std::uint32_t qty = 0;
    PxE4 px = 0;
    bool market = false;
    char tif = '0', display = 'Y', capacity = 'A', iso = 'N', cross = 'N', aiq = 'N', peg = 'L';
    bool post_only = false, io = false, has_expire = false, located = false;
    Mpid4 firm;
    std::uint16_t group = 0;
    Alpha<2> aiq_group;
    std::uint32_t expire = 0, minq = 0, maxf = 0, urn = 0;
    std::uint8_t idx = 0;
    PxE4 rpx = 0;
  };
  enum class Route { Match, RestOnly, Held, Cross, Peg };
  void rest(const Req& q, std::uint16_t l, std::uint32_t a, std::uint32_t s, std::uint64_t ref, PxE4 px,
            std::uint32_t leaves, std::uint32_t done);
  std::uint16_t checks(Req& q, const ouch50::TagSet& t, const Sess& s, std::uint16_t l, bool replace, Route& route);
  void enter(std::uint32_t s, std::uint32_t a, const ouch50::in::EnterOrderView& v, std::uint32_t urn, std::uint8_t idx);
  void replace(std::uint32_t s, std::uint32_t a, std::span<const std::byte> msg, bool valid, std::uint32_t nurn,
               std::uint8_t idx);
  void cancel(std::uint32_t a, const ouch50::in::CancelOrderView& v, std::uint8_t idx);
  void modify(std::uint32_t a, const ouch50::in::ModifyOrderView& v, std::uint8_t idx);
  void mass_cancel(std::uint32_t s, std::uint32_t a, const ouch50::in::MassCancelView& v, std::uint32_t urn,
                   std::uint8_t idx);
  void entry_switch(std::uint32_t s, std::uint32_t a, std::span<const std::byte> msg, std::uint32_t urn,
                    std::uint8_t idx, bool disable);
  bool frozen_request(std::uint64_t ref, bool full);

  // Matching
  struct Taker {
    std::uint16_t l = 0;
    char side = 'B';
    bool peg = false;
    std::uint32_t minq = 0;
    PxE4 limit = 0;
    std::uint32_t rem = 0, done = 0, acct = 0, sess = 0, urn = 0;
    std::uint8_t idx = 0;
    Mpid4 firm;
    char aiq = 'N';
    Alpha<2> aiq_group;
    PxE4 blo = 0, bhi = 0;
    int fills = 0, touches = 0;
  };
  bool is_self(const Taker& t, const Ord& r) const {
    if (aiq_act(t.aiq) == 0 || r.aiq == 'N' || !(r.aiq_group == t.aiq_group)) return false;
    return aiq_firm(t.aiq) ? r.firm == t.firm : r.acct == t.acct;
  }
  void aiq_notice(std::uint32_t s, std::uint32_t urn, std::uint8_t idx, std::uint32_t d, PxE4 px, char flag, char aiq);
  bool walk(Taker& t);  // true: stopped at a price outside the limit
  char post_only(std::uint16_t l, char side, PxE4* px, const Sess& s);
  Ord make(const Req& q, std::uint16_t l, std::uint32_t a, std::uint32_t s, std::uint64_t ref, PxE4 px,
           std::uint32_t leaves, std::uint32_t done) const;
  void place(const Req& q, Route route, Taker& tk, std::uint64_t ref, PxE4 px, char po,
             std::vector<ROut>& buf, bool collar_stop, bool dead);
  void uncross(std::uint16_t l);

  // Crosses
  void interest(std::uint16_t l, char kind, bool cross_only, std::vector<CrossInterest>& v, std::vector<std::uint64_t>& refs);
  CrossResult cross_at(std::uint16_t l, char kind, bool cross_only, bool crp);
  bool price_tests(std::uint16_t l, PxE4 p);
  void execute(std::uint16_t l, char kind, const CrossResult& r, bool ipo);
  void cancel_pending(std::uint16_t l, char which, char why, bool held);
  void post_held(std::uint16_t l);
  void open_cross(std::uint16_t l);
  void close_cross(std::uint16_t l);
  void noii(std::uint16_t l, char kind, bool eoii);
  void halt(std::uint16_t l, std::uint8_t phase, std::uint8_t kind, const Alpha<4>& reason);
  void display_period(std::uint16_t l, std::uint8_t kind, PxE4 arp);
  void collars(std::uint16_t l, std::uint8_t kind, PxE4 arp);
  void widen(std::uint16_t l, char side);
  static void clamp_collars(Sym& y);
  void collar_msg(std::uint16_t l);
  void tick_symbol(std::uint16_t l);
  void release(std::uint16_t l, const CrossResult& r);
  void clock(Nanos scheduled);
  void sweep(char kind);

  // ---------------------------------------------------------------- risk (05 §7)
  struct RLim {
    std::uint32_t perms = 0;
    std::int64_t max_qty = 0, max_notional = 0, ff_bps = 0, ff_abs = 0, lop = 1, dup = 0, port = 0, symrate = 0,
                 gross = 0, symnot = 0, adv = 0, kill = 0;
  };
  struct RAcct {
    RLim lim;
    i128 executed = 0;
    bool killed = false, track_sym = false, touched = false;
  };
  struct RRule {
    bool restricted = false, htb = false;
    std::int64_t notional = -1;
  };
  struct RBucket {
    std::int64_t level = 0, last = INT64_MIN;
  };
  struct RDup {
    std::int64_t last = -1;
    std::map<std::int64_t, std::deque<std::uint64_t>> secs;
  };
  struct RiskState {
    std::vector<RAcct> accts;
    std::map<std::pair<std::uint32_t, std::uint16_t>, RRule> rules;
    std::vector<RBucket> port;
    std::map<std::pair<std::uint32_t, std::uint16_t>, RBucket> sym;
    std::map<std::uint32_t, RDup> dup;
  };
  void risk_reset() {
    rk_ = RiskState{};
    rk_.accts.assign(accts_.size(), RAcct{});
    rk_.port.assign(sess_.size(), RBucket{});
  }
  static bool risk_set(RiskState& st, std::uint32_t a, std::uint16_t kind, std::int64_t v, std::uint16_t l);
  static bool bucket_take(RBucket& b, std::int64_t rate, std::int64_t now);
  i128 open_notional(std::uint32_t a, std::uint16_t l) const;  // l = 0: all symbols
  std::uint16_t risk_check(std::uint32_t a, std::uint32_t s, std::uint16_t l, const Req& q, std::uint64_t price_field,
                           bool replace, const Ord* old, PxE4* rpx);
  void kill_acct(std::uint32_t a);
  void risk_after_record();

  // ---------------------------------------------------------------- state
  RiskState rk_;
  std::vector<std::uint64_t> rq_;  // reserve orders to refresh after the current taker
  std::vector<ROut>* out_ = nullptr;
  std::vector<ROut>* buffer_ = nullptr;
  std::vector<std::size_t> taker_msgs_;  // positions in the walk buffer of the aggressor's own notices
  Nanos ts_ = 0;
  std::uint64_t index_ = 0;
  std::vector<Sym> syms_;
  std::vector<Book> books_;
  std::vector<Acct> accts_;
  std::vector<Sess> sess_;
  std::map<std::uint64_t, Ord> orders_;
  std::map<std::tuple<std::uint32_t, std::uint8_t, std::uint32_t>, std::uint64_t> urns_;
  std::vector<ScheduleEntry> sched_;
  Params prm_;
  std::uint16_t cfg_table_ = 0, cfg_next_ = 0;
  std::uint32_t cfg_total_ = 0;
  std::vector<std::byte> cfg_buf_;
  Nanos midnight_ = 0;
  std::uint32_t date_ = 0;
  bool started_ = false;
  char session_ = 'R', init_session_ = 'R';
  std::uint8_t miles_ = 0;
  std::uint64_t next_ref_ = 1, next_match_ = 1, itch_n_ = 0;
  std::array<std::int64_t, 3> mwcb_{};
  std::uint8_t mwcb_breach_ = 0;
};

}  // namespace lle::engine::ref

#include "ref_engine_impl.hpp"
