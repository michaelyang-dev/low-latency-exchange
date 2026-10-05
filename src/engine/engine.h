#pragma once
// The deterministic matching engine (05-matching-engine; ADR-004, -010, -025,
// -027, -028). Semantics, output order and documented choices:
// src/engine/README.md and docs/design/matching-rules.md.
//
// Engine::apply(record, sink) is a pure function of (state, record): no
// clocks, no RNG, no I/O, no iteration over unordered containers, no floating
// point, and no allocation once the day's configuration is loaded (pools,
// level vectors, indexes and scratch buffers are pre-sized; only overflowing a
// reserve allocates). Every output is tagged with the record's journal index,
// and every wire timestamp is record.ts_ns minus the day's local midnight.
//
// Only the sink is a template parameter (no virtual dispatch); the emitting
// member templates are defined in engine/detail/*.h, everything else in
// engine.cpp.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/alpha.h"
#include "common/types.h"
#include "engine/canonical.h"
#include "engine/cross.h"
#include "engine/matching_book.h"
#include "engine/order.h"
#include "engine/output.h"
#include "engine/records.h"
#include "engine/risk/risk_gate.h"
#include "engine/state.h"
#include "lob/index.h"
#include "proto/itch50/itch50.h"
#include "proto/ouch50/ouch50.h"

namespace lle::engine {

struct EngineConfig {
  BookConfig book{};
  std::size_t urn_capacity = std::size_t{1} << 17;  // live (account, UserRefIdx, UserRefNum) keys
  std::size_t scratch = std::size_t{1} << 12;       // cross interest / allocation buffers
};

// ---------------------------------------------------------------------------- self-match prevention (tag 29)
enum class SmpAction : std::uint8_t { None, DecrementBoth, CancelOldest, CancelNewest };
struct Smp {
  SmpAction action = SmpAction::None;
  bool firm_level = true;  // Firm level (same MPID) vs Match-Any level (same account)
  bool details = false;    // report with AIQ Canceled 'D' instead of Canceled 'C' reason 'Q'
};

// Supported: Disabled, the Firm level and the Match-Any level with decrement
// both (with or without details), cancel oldest and cancel newest. The
// Organization and Affiliate levels and "use remover" reject with 0x0040.
[[nodiscard]] constexpr Smp smp_of(AiqMode m) noexcept {
  switch (m) {
    case AiqMode::FirmDecrementBothNoDetails: return {SmpAction::DecrementBoth, true, false};
    case AiqMode::FirmDecrementBoth: return {SmpAction::DecrementBoth, true, true};
    case AiqMode::FirmCancelOldest: return {SmpAction::CancelOldest, true, false};
    case AiqMode::FirmCancelNewest: return {SmpAction::CancelNewest, true, false};
    case AiqMode::AnyDecrementBothNoDetails: return {SmpAction::DecrementBoth, false, false};
    case AiqMode::AnyDecrementBoth: return {SmpAction::DecrementBoth, false, true};
    case AiqMode::AnyCancelOldest: return {SmpAction::CancelOldest, false, false};
    case AiqMode::AnyCancelNewest: return {SmpAction::CancelNewest, false, false};
    default: return {};
  }
}
[[nodiscard]] constexpr bool aiq_supported(AiqMode m) noexcept {
  return m == AiqMode::Disabled || smp_of(m).action != SmpAction::None;
}

// Market collar (05 §3): max($0.25, 5%) beyond the reference, which is the
// best opposite price when the market order arrives.
[[nodiscard]] constexpr PxE4 collar_band(PxE4 ref) noexcept { return ref / 20 > 2'500 ? ref / 20 : 2'500; }

// NOII Price Variation Indicator (R2 D2.6): band of 100 * |Near - CRP| / max(Near, CRP).
[[nodiscard]] constexpr char price_variation(PxE4 near, PxE4 crp) noexcept {
  if (near <= 0 || crp <= 0) return ' ';
  const PxE4 d = near > crp ? near - crp : crp - near;
  const PxE4 m = near > crp ? near : crp;
  const PxE4 pct = d * 100 / m;  // integer percent, floored
  if (pct < 1) return 'L';
  if (pct < 10) return static_cast<char>('0' + pct);
  if (pct < 20) return 'A';
  if (pct < 30) return 'B';
  return 'C';
}

namespace detail {
template <class S>
struct Out {
  S& sink;
  std::uint64_t idx;  // journal index of the record
  std::uint64_t ts;   // wire timestamp (ns since local midnight)
};
}  // namespace detail

class Engine {
 public:
  static constexpr std::uint64_t kMagic = 0x3153474E45454C4Cull;  // "LLEENGS1"
  static constexpr std::uint32_t kVersion = 1;
  static constexpr std::uint32_t kMaxAccounts = std::uint32_t{1} << 24;  // account index bits in urn_key()

  explicit Engine(const EngineConfig& c = {});
  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  // Applies one journal record, appending its outputs to `sink`.
  template <OutputSink S>
  void apply(const InputRecord& rec, S& sink);

  // FNV-1a 64 over the canonical state encoding (== over the snapshot payload).
  [[nodiscard]] std::uint64_t state_hash() const;
  // Canonical state payload (cold path; allocates).
  void snapshot(std::vector<std::byte>& out) const;
  // Replaces all state with a snapshot payload; false (and a reset engine) on malformed input.
  bool restore(std::span<const std::byte> in);
  // Book, list, index and account-list consistency (tests and harnesses).
  [[nodiscard]] bool check(std::string* err) const;

  // ---- introspection (tests, harnesses, benchmarks, recovery)
  [[nodiscard]] std::size_t live_orders() const noexcept { return live_; }
  [[nodiscard]] OrderRef next_ref() const noexcept { return next_ref_; }
  [[nodiscard]] MatchNo next_match() const noexcept { return next_match_; }
  [[nodiscard]] std::size_t symbols() const noexcept { return symbols_.size() - 1; }
  [[nodiscard]] const SymbolInfo& symbol(Locate l) const noexcept { return symbols_[l]; }
  [[nodiscard]] Locate find_symbol(const Symbol8& s) const noexcept;
  [[nodiscard]] const MatchingBook& book() const noexcept { return book_; }
  [[nodiscard]] std::size_t slabs() const noexcept { return book_.order_slabs() + book_.level_slabs(); }
  [[nodiscard]] Session session() const noexcept { return session_; }
  [[nodiscard]] std::uint8_t milestones() const noexcept { return milestones_; }
  [[nodiscard]] std::uint32_t date() const noexcept { return date_; }
  // ITCH messages emitted today: the MoldUDP64 output sequence S(P) after the last record.
  [[nodiscard]] std::uint64_t itch_count() const noexcept { return itch_count_; }
  // (session id, OUCH messages sent today) in session-table order.
  [[nodiscard]] std::vector<std::pair<std::uint32_t, std::uint64_t>> session_outputs() const;
  [[nodiscard]] const RiskGate& risk() const noexcept { return risk_; }
  [[nodiscard]] const MarketParams& params() const noexcept { return params_; }

 private:
  template <class S>
  using Out = detail::Out<S>;
  using RR = ouch50::RejectReason;
  using CR = ouch50::CancelReason;
  using LF = ouch50::LiquidityFlag;
  using Tag = ouch50::Tag;
  using TagSet = ouch50::TagSet;
  static constexpr std::uint16_t code(RR r) noexcept { return static_cast<std::uint16_t>(r); }

  enum class Stop : std::uint8_t { Filled, Exhausted, Limit, SmpNewest };
  enum class Dry : std::uint8_t { Exec, Left, Gone };
  // How an accepted order proceeds (state gate, 05 §4 step 3).
  enum class Route : std::uint8_t { Match, RestOnly, Held, Cross, Peg };

  struct Taker {
    Locate locate = 0;
    Side side = Side::Buy;
    PxE4 limit = 0;
    Qty rem = 0;
    Qty done = 0;
    Qty min_qty = 0;
    std::uint32_t account = 0;
    std::uint32_t session = 0;
    UserRefNum urn = 0;
    std::uint8_t idx = 0;
    Firm firm{};
    AiqMode aiq = AiqMode::Disabled;
    AiqGroup aiq_group{};
    Smp smp{};
    bool peg = false;  // a midpoint peg aggressor (needs an active midpoint; liquidity 'm')
    // Accepted with Order State Dead: the 'A'/'U' was its last message (OUCH 5.0
    // §3.2, §3.3), so nothing more is sent for it; resting orders it meets still
    // get theirs.
    bool dead = false;
    PxE4 band_lo = 0, band_hi = 0;  // LULD execution window (0 = none)
  };

  struct PostOnlyResult {
    enum Kind : std::uint8_t { None, Slid, Cancel } kind = None;
    PxE4 px = 0;
    CR reason = CR::PostOnlyContra;
  };

  // One allocated cross fill.
  struct Fill {
    Handle h;
    Qty qty;
  };
  // A cross participant eligible at the cross price (allocate()).
  struct Cand {
    Handle h;
    PxE4 px;
    Qty qty;
    std::uint8_t rank;     // open/close class; halt: market 0, else 1
    std::uint8_t display;  // halt secondary key
    std::uint64_t prio;
    OrderRef ref;
    bool io;
    bool market;
  };

  // NOII field values (R2 D2.6).
  struct NoiiValues {
    std::uint64_t paired = 0;
    std::uint64_t imbalance = 0;
    char direction = 'O';
    PxE4 far = 0, near = 0, crp = 0;
  };

  // ======================================================================== records (detail/records.h)
  template <class S> void on_day_start(Out<S>& o, std::span<const std::byte> p);
  template <class S> void on_config(Out<S>& o, std::span<const std::byte> p);
  template <class S> void emit_directory(Out<S>& o);
  template <class S> void on_session_event(Out<S>& o, std::span<const std::byte> p);
  template <class S> void on_timer(Out<S>& o, std::span<const std::byte> p);
  template <class S> void on_admin(Out<S>& o, std::span<const std::byte> p);
  template <class S> void state_change(Out<S>& o, Milestone m);
  template <class S> void run_crosses(Out<S>& o, CrossKind k);
  template <class S> void expiry_sweep(Out<S>& o, char kind);
  template <class S> void clock_tick(Out<S>& o, Nanos scheduled);
  template <class S> void noii_tick(Out<S>& o, CrossKind k, bool eoii);

  // ======================================================================== OUCH (detail/inbound.h)
  template <class S> void on_ouch(Out<S>& o, std::span<const std::byte> p, bool malformed);
  template <class S>
  void on_consuming(Out<S>& o, std::uint32_t s, std::uint32_t a, char type, std::span<const std::byte> msg,
                    bool malformed);
  template <class S>
  void on_referencing(Out<S>& o, std::uint32_t s, std::uint32_t a, char type, std::span<const std::byte> msg,
                      bool malformed);
  template <class S>
  void on_enter(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::EnterOrderView& v, UserRefNum urn,
                std::uint8_t idx);
  template <class S>
  void on_replace(Out<S>& o, std::uint32_t s, std::uint32_t a, std::span<const std::byte> msg,
                  const std::expected<ouch50::InboundView, RR>& v, UserRefNum nurn, std::uint8_t idx);
  template <class S>
  void do_replace(Out<S>& o, std::uint32_t s, std::uint32_t a, Handle oh, OrderSpec sp, Route route,
                  const ouch50::in::ReplaceOrderView& rv, const TagSet& tags);
  template <class S>
  void on_cancel(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::CancelOrderView& v, std::uint8_t idx);
  template <class S>
  void on_modify(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::ModifyOrderView& v, std::uint8_t idx);
  template <class S>
  void on_mass_cancel(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::MassCancelView& v,
                      UserRefNum urn, std::uint8_t idx);
  template <class S, class View>
  void on_entry_switch(Out<S>& o, std::uint32_t s, std::uint32_t a, const View& v, UserRefNum urn, std::uint8_t idx,
                       bool disable);
  template <class S> void cancel_session_orders(Out<S>& o, std::uint32_t s);
  // Freeze handling of a cancel/modify aimed at a frozen order; true if handled.
  template <class S> bool frozen_change(Out<S>& o, Handle h, bool full_cancel);

  // ======================================================================== placement and matching (detail/matching.h)
  // The accepted order's path after its 'A'/'U' has been emitted.
  template <class S>
  void place(Out<S>& o, const OrderSpec& sp, Route route, Taker& t, OrderRef ref, PxE4 px, PostOnlyResult po);
  template <class S> Stop match(Out<S>& o, Taker& t);
  template <class S> void finish(Out<S>& o, Taker& t, const OrderSpec& sp, OrderRef ref, PxE4 px, Stop st);
  template <class S> void fill(Out<S>& o, Taker& t, Handle h, Qty f, PxE4 px, LF rflag);
  template <class S> bool smp_event(Out<S>& o, Taker& t, Handle h, LF rflag, PxE4 px);
  template <class S> Handle rest_on_book(Out<S>& o, const OrderSpec& sp, const Taker& t, OrderRef ref, PxE4 px);
  void consume(Handle h, Qty q);
  template <class S> void run_refreshes(Out<S>& o);
  template <class S> void reduce_total(Out<S>& o, Handle h, Qty d);
  template <class S> void peg_tick(Out<S>& o, Locate l);
  template <class F> void scan(const Taker& t, F&& f) const;
  // Contra shares a MinQty taker could execute against (self-match orders excluded), up to its MinQty.
  [[nodiscard]] Qty available(const Taker& t) const noexcept;
  [[nodiscard]] static bool in_band(const Taker& t, PxE4 px) noexcept {
    return t.band_hi == 0 || (px >= t.band_lo && px <= t.band_hi);
  }
  // Resting price `px` is worse for the taker than `mid`.
  [[nodiscard]] static bool worse(Side taker, PxE4 px, PxE4 mid) noexcept {
    return taker == Side::Buy ? px > mid : px < mid;
  }
  [[nodiscard]] static LF resting_flag(const Order& r) noexcept {
    if (r.has(Order::kReserveChild)) return LF::ReserveAddedNonDisplayed;
    return r.cls() == kDisplayed ? LF::Added : LF::NonDisplayedAdded;
  }
  template <class S> void uncross(Out<S>& o, Locate l);
  template <class S> void cancel_whole(Out<S>& o, Handle h, CR why);
  template <class S> void reduce_order(Out<S>& o, Handle h, Qty d);
  template <class S> void after_execution(Out<S>& o, Locate l, PxE4 px);
  template <class S> void cancel_pegs(Out<S>& o, Locate l, CR why);

  // ======================================================================== risk (engine.cpp, detail/records.h)
  // Sizes the gate for the loaded tables (clears its limits).
  void risk_configure();
  // The risk gate's view of a symbol for an order of `side` (only the near side's quote is read).
  [[nodiscard]] RiskQuote risk_quote(Locate l, Side side) const noexcept;
  // Adds the open orders of an account whose per-symbol table was just created.
  void risk_rebuild(std::uint32_t a);
  // Kill switch: latch and cancel every order of the account ('C' reason 'S'), frozen ones included.
  template <class S> void kill_account(Out<S>& o, std::uint32_t a);
  template <class S> void run_kills(Out<S>& o);

  // ======================================================================== auctions and halts (detail/auction.h)
  template <class S> void opening_cross(Out<S>& o, Locate l);
  template <class S> void closing_cross(Out<S>& o, Locate l);
  template <class S>
  void execute_cross(Out<S>& o, Locate l, CrossKind kind, const CrossResult& r, bool halt_ipo);
  template <class S> void cancel_pending(Out<S>& o, Locate l, CrossType which, CR why, bool held);
  template <class S> void post_held(Out<S>& o, Locate l);
  template <class S> void emit_noii(Out<S>& o, Locate l, CrossKind k, bool eoii);
  template <class S> void enter_halt(Out<S>& o, Locate l, HaltPhase phase, HaltKind kind, const Alpha<4>& reason);
  template <class S> void start_display_period(Out<S>& o, Locate l, HaltKind kind, PxE4 arp);
  template <class S> void symbol_tick(Out<S>& o, Locate l);
  template <class S> void resume(Out<S>& o, Locate l, const CrossResult& r);
  template <class S> void emit_collars(Out<S>& o, Locate l);

  // ======================================================================== emission (detail/emit.h)
  template <class S, class M> void itch(Out<S>& o, M m, Locate l);
  template <class S> void itch_delete(Out<S>& o, Locate l, OrderRef ref);
  template <class S> void itch_reduce(Out<S>& o, const Order& r, Qty d);
  template <class S> void itch_add(Out<S>& o, const Order& r);
  template <class S> void itch_trading_action(Out<S>& o, Locate l, char state, const Alpha<4>& reason);
  template <class S, class Msg> void ouch(Out<S>& o, std::uint32_t s, Msg m, std::uint8_t idx);
  template <class S, class Msg> void ouch_tags(Out<S>& o, std::uint32_t s, Msg m, const TagSet& tags);
  template <class S>
  void reject(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, std::uint16_t why, const ClOrdId& id);
  template <class S> void canceled(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, Qty q, CR why);
  template <class S>
  void executed(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, Qty q, PxE4 px, LF flag, MatchNo mn);
  template <class S>
  void smp_notice(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, Qty d, PxE4 px, LF flag,
                  const Taker& t);
  template <class S> void audit(Out<S>& o, AuditCode c, std::uint32_t session_id, std::uint64_t detail);

  // ======================================================================== non-emitting helpers (engine.cpp)
  void reset_day();
  [[nodiscard]] std::uint64_t wire_ts(Nanos ts) const noexcept;
  bool load_table(ConfigTable t, std::span<const std::byte> body);
  bool load_symbols(std::span<const std::byte> body);
  bool load_accounts(std::span<const std::byte> body);
  bool load_sessions(std::span<const std::byte> body);
  bool load_risk(std::span<const std::byte> body);
  bool load_schedule(std::span<const std::byte> body);
  [[nodiscard]] const ScheduleEntry* find_timer(std::uint32_t id) const noexcept;

  [[nodiscard]] bool authorized(std::uint32_t a, const Firm& f) const noexcept;
  [[nodiscard]] bool disabled(std::uint32_t a, const Firm& f) const noexcept;
  [[nodiscard]] static AiqMode resolve_aiq(AiqMode m, const SessionInfo& si) noexcept;
  // Feature matrix, price and state checks shared by Enter and Replace (05 §3-§4); 0 = pass.
  [[nodiscard]] std::uint16_t check_order(OrderSpec& sp, const TagSet& tags, const SessionInfo& si, Locate l,
                                          bool replace, Route& route) const noexcept;
  [[nodiscard]] std::uint16_t check_cross_order(OrderSpec& sp, const SessionInfo& si, Locate l, bool replace,
                                                Route& route) const noexcept;
  [[nodiscard]] bool can_match(Locate l) const noexcept;
  [[nodiscard]] PxE4 tick_of(Locate l, PxE4 px) const noexcept;
  [[nodiscard]] bool on_tick(Locate l, PxE4 px) const noexcept;
  [[nodiscard]] PxE4 tick_below(Locate l, PxE4 p) const noexcept;
  [[nodiscard]] PxE4 tick_above(Locate l, PxE4 p) const noexcept;
  [[nodiscard]] PxE4 round_tick(Locate l, PxE4 p, char dir) const noexcept;
  [[nodiscard]] static bool crosses(Side side, PxE4 resting, PxE4 limit) noexcept;
  [[nodiscard]] PxE4 collar_limit(Locate l, Side side) const noexcept;
  [[nodiscard]] PostOnlyResult post_only_check(Locate l, Side side, PxE4 px, const SessionInfo& si) const noexcept;
  [[nodiscard]] Taker make_taker(const OrderSpec& sp, Locate l, std::uint32_t a, std::uint32_t s) const noexcept;
  [[nodiscard]] static bool self_match(const Taker& t, const Order& r) noexcept;
  [[nodiscard]] Dry dry_run(const Taker& t) const noexcept;
  [[nodiscard]] bool dead_on_arrival(const Taker& t, bool immediate) const noexcept;
  // floor((NBB + NBO) / 2) of the displayed best bid and offer; active when both exist and NBB < NBO.
  [[nodiscard]] PxE4 midpoint(Locate l, bool& active) const noexcept;
  // A peg taker's limit: its cap, bounded by the midpoint when there is one.
  [[nodiscard]] PxE4 peg_limit(Locate l, Side side, PxE4 cap) const noexcept;
  [[nodiscard]] bool peg_eligible(const Order& r, PxE4 mid) const noexcept;

  // Cross interest (crosses, NOII); handles_ is parallel to interest_.
  void gather_interest(Locate l, CrossKind k, bool cross_only);
  [[nodiscard]] CrossResult compute_cross(Locate l, CrossKind k, bool cross_only, bool crp);
  [[nodiscard]] NoiiValues noii_values(Locate l, CrossKind k, bool eoii);
  void threshold_window(Locate l, CrossKind k, PxE4 ref, CrossParams& p) const noexcept;
  [[nodiscard]] bool price_tests_pass(Locate l, PxE4 p) const noexcept;
  // Allocation at the cross price; fills both sides in priority order.
  void allocate(Locate l, CrossKind k, const CrossResult& r);
  void set_collars(Locate l, HaltKind kind, PxE4 arp);
  void widen_collars(Locate l, char side);
  static void clamp_collars(SymbolInfo& y) noexcept;
  [[nodiscard]] PxE4 late_reference(Locate l, bool buy, CrossType ct) const noexcept;
  [[nodiscard]] bool frozen(const Order& r) const noexcept;

  [[nodiscard]] static std::uint64_t urn_key(std::uint32_t a, std::uint8_t idx, UserRefNum urn) noexcept {
    return (std::uint64_t{a} << 40) | (std::uint64_t{idx} << 32) | urn;
  }
  // Record bookkeeping. new_order() allocates and indexes an order (not yet placed).
  Handle new_order(const OrderSpec& sp, const Taker& t, OrderRef ref, PxE4 px, std::uint64_t prio);
  void acct_append(Handle h) noexcept;
  void acct_unlink(Handle h) noexcept;
  void list_append(Handle& head, Handle& tail, Handle h) noexcept;
  void list_unlink(Handle& head, Handle& tail, Handle h) noexcept;
  void detach(Handle h) noexcept;        // out of its book level or list
  void remove_order(Handle h) noexcept;  // detach, unindex, free (and its reserve child)
  void take_leaves(Handle h, Qty d) noexcept;  // d < leaves shares leave the order (keeps priority)
  [[nodiscard]] Qty total_leaves(Handle h) const noexcept;

  template <class V>
  void walk(V& v) const;
  template <class V>
  static void walk_order(V& v, const Order& r);
  bool restore_impl(std::span<const std::byte> in);

  // ======================================================================== state
  EngineConfig cfg_;
  MatchingBook book_;
  RiskGate risk_;
  CrossCalculator calc_;
  std::vector<SymbolInfo> symbols_;  // index = locate; [0] unused
  std::vector<AccountInfo> accounts_;
  std::vector<SessionInfo> sessions_;
  std::vector<std::array<UserRefNum, 256>> trackers_;  // last consumed per (account, UserRefIdx)
  std::vector<ScheduleEntry> schedule_;                // the Schedule table (timers and parameters)
  std::vector<ScheduleEntry> timers_;                  // timer entries sorted by id
  std::unique_ptr<lob::FlatIndex<>> sym_index_;        // packed symbol -> locate
  std::unique_ptr<lob::FlatIndex<>> acct_index_;       // account id -> index
  std::unique_ptr<lob::FlatIndex<>> sess_index_;       // session id -> index
  std::unique_ptr<lob::FlatIndex<>> urn_;              // (account, UserRefIdx, UserRefNum) -> live order
  MarketParams params_;
  // Config chunk reassembly
  ConfigTable cfg_table_ = ConfigTable::Symbols;
  std::uint16_t cfg_next_ = 0;
  std::uint32_t cfg_total_ = 0;
  std::vector<std::byte> cfg_buf_;
  // the day
  Nanos midnight_ = 0;
  std::uint32_t date_ = 0;
  bool started_ = false;  // an OuchInbound has been applied: configuration is frozen
  Session session_ = Session::Regular;
  Session initial_session_ = Session::Regular;
  std::uint8_t milestones_ = 0;
  OrderRef next_ref_ = 1;
  MatchNo next_match_ = 1;
  std::uint64_t itch_count_ = 0;
  std::size_t live_ = 0;  // live orders (reserve children not counted)
  std::array<std::int64_t, 3> mwcb_levels_{};
  std::uint8_t mwcb_breached_ = 0;
  // scratch (reused; never part of the state)
  std::vector<CrossInterest> interest_;
  std::vector<Handle> handles_;
  std::vector<Fill> buys_, sells_;
  std::vector<Cand> bcand_, scand_;
  std::vector<Handle> scratch_;
  std::vector<std::uint32_t> kills_;
  std::vector<Handle> refresh_;  // reserve parents to refresh after the current taker
};

}  // namespace lle::engine

#include "engine/detail/emit.h"
#include "engine/detail/records.h"
#include "engine/detail/inbound.h"
#include "engine/detail/matching.h"
#include "engine/detail/auction.h"

namespace lle::engine {

template <OutputSink S>
void Engine::apply(const InputRecord& rec, S& sink) {
  Out<S> o{sink, rec.index, wire_ts(rec.ts_ns)};
  switch (static_cast<RecordType>(rec.type)) {
    case RecordType::DayStart: on_day_start(o, rec.payload); break;
    case RecordType::Config: on_config(o, rec.payload); break;
    case RecordType::SessionEvent: on_session_event(o, rec.payload); break;
    case RecordType::OuchInbound: on_ouch(o, rec.payload, (rec.flags & kFlagMalformedInput) != 0); break;
    case RecordType::Timer: on_timer(o, rec.payload); break;
    case RecordType::Admin: on_admin(o, rec.payload); break;
    case RecordType::SnapshotMark:
    case RecordType::EpochStart:
    case RecordType::DayEnd:
    case RecordType::Pad: break;
    default: audit(o, AuditCode::UnhandledRecord, 0, rec.type); break;
  }
  if (risk_.kills_pending()) run_kills(o);  // KillExposure breaches latch after the record
}

}  // namespace lle::engine
