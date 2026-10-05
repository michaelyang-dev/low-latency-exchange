#include "client/divergence.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <map>
#include <memory>
#include <unordered_map>

#include "book/itch_adapter.h"
#include "book/variants.h"
#include "client/engine_driver.h"
#include "client/report.h"
#include "common/endian.h"
#include "proto/itch50/binary_file.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client::i2o {
namespace {

namespace lo = ouch50::layout::out;

struct Capture {
  bool accepted = false, replaced = false, rejected = false, canceled = false;
  char state = 0;
  std::uint16_t reason = 0;
  std::uint64_t aggressor_shares = 0;
  std::uint64_t itch_adds = 0;
  std::uint64_t target_reduced = 0;  // shares that left the source's target order (executions, cancels, removal)
  std::uint64_t exec_on_target = 0, exec_on_others = 0;
};

class Run {
 public:
  struct Sink {
    Run* r;
    void itch(std::uint64_t, std::span<const std::byte> b) { r->on_engine_itch(b); }
    void ouch(std::uint64_t, std::uint32_t session, std::span<const std::byte> b) { r->on_engine_ouch(session, b); }
    void audit(std::uint64_t, const engine::AuditEvent&) {}
  };

  Run(const DivergenceConfig& cfg, const std::vector<SymbolInfo>& syms, DivergenceReport& rep)
      : cfg_(cfg), rep_(rep), sink_{this}, conv_(ConvertConfig{cfg.sessions, ouch50::TimeInForce::Gtx}) {
    book::BookConfig bc;
    bc.reserve_orders = cfg.reserve_orders;
    bc.reserve_levels = std::size_t{1} << 20;
    src_ = std::make_unique<book::OptBook<>>(bc);
    eng_ = std::make_unique<book::OptBook<>>(bc);
    e2o_.reserve(cfg.reserve_orders);
    eloc_.assign(syms.size() + 1, 0);
    EngineDayConfig d;
    d.date = cfg.date;
    for (std::size_t i = 0; i < syms.size(); ++i) {
      engine::SymbolEntry e;
      e.symbol = syms[i].symbol;
      e.round_lot = syms[i].round_lot;
      e.luld_tier = syms[i].luld_tier == '1' ? '1' : '2';
      if (syms[i].etp == 'Y') e.flags |= engine::SymbolEntry::kFlagEtp;
      d.symbols.push_back(e);
      eloc_[i + 1] = syms[i].locate;
    }
    for (std::uint32_t n = 1; n <= cfg.sessions; ++n) {
      engine::AccountEntry a;
      a.account_id = n;
      a.firms[0] = Mpid4("LLEC");
      d.accounts.push_back(a);
      engine::SessionEntry s;
      s.session_id = n;
      s.account_id = n;
      s.flags = engine::SessionEntry::kMarketOrders;  // no session events here: no cancel-on-disconnect
      d.sessions.push_back(s);
      engine::RiskEntry r;  // Limit Order Protection is on unless turned off (matching-rules §5.1)
      r.account_id = n;
      r.kind = engine::RiskKind::Lop;
      r.value = 0;
      d.risk.push_back(r);
    }
    d.engine.book.reserve_orders = cfg.reserve_orders;
    d.engine.book.reserve_levels = std::size_t{1} << 20;
    d.engine.urn_capacity = cfg.reserve_orders;
    driver_ = std::make_unique<EngineDriver<Sink>>(d, sink_);
    halted_.fill(0);
  }

  bool run(std::string* err) {
    ScriptWriter writer;
    const bool write = !cfg_.script_out.empty();
    if (write) {
      ScriptHeader h;
      h.date = cfg_.date;
      h.sessions = cfg_.sessions;
      h.flags = cfg_.synthetic ? 1 : 0;
      h.symbols = syms_copy_;
      if (!writer.open(cfg_.script_out, h, err)) return false;
    }
    if (!driver_->start(hms_ns(2, 59, 59))) {
      if (err) *err = "engine day start failed";
      return false;
    }
    itch50::BinaryFileReader rd;
    if (auto r = rd.open(cfg_.itch_path); !r) {
      if (err) *err = r.error();
      return false;
    }
    std::vector<Nanos> cps = cfg_.checkpoint_times;
    std::sort(cps.begin(), cps.end());
    std::size_t next_cp = 0;
    SeqNo seq = 0;
    Nanos last_ts = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (;;) {
      const itch50::Record r = rd.next();
      if (r.status != itch50::RecordStatus::Message) {
        if (r.status == itch50::RecordStatus::IoError || r.status == itch50::RecordStatus::Truncated) {
          if (err) *err = "read error: " + rd.error();
          return false;
        }
        break;
      }
      const std::span<const std::byte> m = r.data;
      const Nanos ts = m.size() >= 11 ? static_cast<Nanos>(itch50::MessageHeaderView(m.data()).timestamp()) : last_ts;
      while (next_cp < cps.size() && ts >= cps[next_cp]) {
        driver_->advance(cps[next_cp]);
        compare(seq, cps[next_cp]);
        ++next_cp;
      }
      ++seq;
      if (cfg_.checkpoint_every != 0 && seq % cfg_.checkpoint_every == 0) pending_cp_ = true;
      // The source message: halt state, then the record (if any), then the source book.
      if (!m.empty() && static_cast<char>(m[0]) == 'H' && m.size() == itch50::StockTradingActionView::kLen) {
        const itch50::StockTradingActionView h(m.data());
        halted_[h.stock_locate()] = static_cast<char>(h.trading_state());
      }
      bool emitted = false;
      conv_.on_itch(seq, m, [&](Nanos t, std::uint16_t session, std::span<const std::byte> ouch, const Origin& og) {
        emitted = true;
        if (write) (void)writer.write(t, session, ouch);
        process(t, session, ouch, og, m);
      });
      if (!emitted) (void)book::apply_itch(*src_, m.data(), m.size());
      last_ts = ts;
      if (pending_cp_) {
        compare(seq, last_ts);
        pending_cp_ = false;
      }
      if (cfg_.progress_every != 0 && seq % cfg_.progress_every == 0) {
        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        std::fprintf(stderr, "itch2ouch: %" PRIu64 " source messages, %.0f s, src %zu eng %zu live\n", seq, s,
                     src_->live_orders(), eng_->live_orders());
      }
      if (cfg_.max_messages != 0 && seq >= cfg_.max_messages) break;
    }
    // The end of the source (or slice): the engine's clock catches up first, so its
    // own timer events up to the last source time (crosses, sweeps) are in.
    driver_->advance(last_ts);
    if (rep_.checkpoints.empty() || rep_.checkpoints.back().seq != seq) compare(seq, last_ts);
    if (write && !writer.close()) {
      if (err) *err = "script write failed";
      return false;
    }
    rep_.convert = conv_.stats();
    rep_.convert.live_at_end = conv_.live();
    rep_.engine_records = driver_->records();
    rep_.engine_timers = driver_->timer_records();
    rep_.elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - t0).count();
    return true;
  }

  std::vector<SymbolInfo> syms_copy_;

 private:
  // --- one script record -------------------------------------------------------------------
  void process(Nanos t, std::uint16_t session, std::span<const std::byte> ouch, const Origin& og,
               std::span<const std::byte> source_msg) {
    ++rep_.records;
    // Facts before the record: is the target in the engine's book; did the source
    // add lock or cross the source book.
    const bool target_in_engine = og.op != Op::Enter && eng_->find_order(og.ref).has_value();
    bool source_locked = false;
    if (og.op == Op::Enter) {
      const lob::Bbo b = src_->bbo(og.locate);
      if (og.side == Side::Buy) source_locked = b.ask.qty != 0 && b.ask.px <= og.price;
      else source_locked = b.bid.qty != 0 && b.bid.px >= og.price;
    }
    (void)book::apply_itch(*src_, source_msg.data(), source_msg.size());
    driver_->advance(t);
    cap_ = Capture{};
    og_ = og;
    rec_session_ = session;
    in_record_ = true;
    (void)driver_->submit_ouch(session, session, ouch);
    in_record_ = false;
    classify(target_in_engine, source_locked);
  }

  void classify(bool target_in_engine, bool source_locked) {
    const Capture& c = cap_;
    if (c.rejected) ++rep_.reject_reasons[c.reason & 0xFF];
    switch (og_.op) {
      case Op::Enter:
        if (c.rejected) {
          ++rep_.enter_rejected;
        } else if (c.aggressor_shares > 0) {
          ++rep_.enter_crossed;
          rep_.enter_crossed_shares += c.aggressor_shares;
          const char h = halted_[og_.locate];
          if (source_locked) ++rep_.enter_crossed_source_locked;
          else if (h != 0 && h != 'T') ++rep_.enter_crossed_source_halted;
          else ++rep_.enter_crossed_cascade;
        } else if (c.itch_adds == 0) {
          ++rep_.enter_not_displayed;
        } else {
          ++rep_.enter_ok;
        }
        return;
      case Op::Cancel: {
        const std::uint64_t expected = og_.shares;
        if (!target_in_engine) ++rep_.cancel_no_order;
        else if (c.target_reduced == expected) ++rep_.cancel_ok;
        else ++rep_.cancel_shares_differ;
        return;
      }
      case Op::Replace:
        if (!target_in_engine) ++rep_.replace_no_order;
        else if (c.rejected) ++rep_.replace_rejected;
        else if (c.canceled && !c.replaced) ++rep_.replace_original_cancelled;
        else if (c.aggressor_shares > 0) {
          ++rep_.replace_crossed;
          rep_.replace_crossed_shares += c.aggressor_shares;
        } else {
          ++rep_.replace_ok;
        }
        return;
      case Op::Ioc:
        rep_.ioc_shares_expected += og_.shares;
        rep_.ioc_shares_executed += c.aggressor_shares;
        rep_.ioc_shares_on_target += c.exec_on_target;
        if (!target_in_engine) ++rep_.ioc_target_absent;
        if (c.rejected) ++rep_.ioc_rejected;
        else if (c.aggressor_shares == 0) ++rep_.ioc_none;
        else if (c.aggressor_shares < og_.shares) ++rep_.ioc_short;
        else if (c.exec_on_target == og_.shares) ++rep_.ioc_exact;
        else ++rep_.ioc_other_orders;
        return;
    }
  }

  // --- engine outputs -------------------------------------------------------------------------
  void on_engine_ouch(std::uint32_t session, std::span<const std::byte> b) {
    if (!in_record_ || session != rec_session_ || b.size() < 13) return;
    const char t = static_cast<char>(b[0]);
    const UserRefNum u9 = load_be32(b.data() + 9);
    switch (t) {
      case 'A':
        if (u9 != og_.urn) return;
        cap_.accepted = true;
        cap_.state = b.size() > lo::OrderAccepted::kOrderStateOff ? static_cast<char>(b[lo::OrderAccepted::kOrderStateOff]) : 0;
        if (og_.op == Op::Enter && cap_.state == 'L' && b.size() >= lo::OrderAccepted::kOrderReferenceNumberOff + 8)
          e2o_[load_be64(b.data() + lo::OrderAccepted::kOrderReferenceNumberOff)] = og_.ref;
        return;
      case 'U': {
        if (b.size() < lo::OrderReplaced::kOrderReferenceNumberOff + 8) return;
        if (load_be32(b.data() + lo::OrderReplaced::kUserRefNumOff) != og_.urn) return;
        cap_.replaced = true;
        e2o_[load_be64(b.data() + lo::OrderReplaced::kOrderReferenceNumberOff)] = og_.new_ref;
        return;
      }
      case 'J':
        if (u9 != og_.urn) return;
        cap_.rejected = true;
        cap_.reason = b.size() >= lo::Rejected::kReasonOff + 2 ? load_be16(b.data() + lo::Rejected::kReasonOff) : 0;
        return;
      case 'C':
        if (u9 == og_.urn || (og_.op == Op::Replace && u9 == og_.orig_urn)) cap_.canceled = true;
        return;
      case 'E':
        if (u9 == og_.urn && b.size() >= lo::OrderExecuted::kQuantityOff + 4)
          cap_.aggressor_shares += load_be32(b.data() + lo::OrderExecuted::kQuantityOff);
        return;
      default: return;
    }
  }

  // Engine reference -> source reference (0 when unknown).
  OrderRef src_of(OrderRef e) {
    const auto it = e2o_.find(e);
    if (it == e2o_.end()) {
      ++rep_.unmapped_engine_orders;
      return 0;
    }
    return it->second;
  }

  void forget_if_gone(OrderRef e, OrderRef s) {
    if (!eng_->find_order(s)) e2o_.erase(e);
  }

  void on_engine_itch(std::span<const std::byte> b) {
    if (b.empty() || b.size() != itch50::kMsgLen[static_cast<unsigned char>(b[0])]) return;
    const auto* p = b.data();
    switch (static_cast<char>(p[0])) {
      case 'A':
      case 'F': {
        const itch50::AddOrderView v(p);
        const OrderRef s = src_of(v.order_ref());
        if (s == 0) return;
        const Locate el = v.stock_locate();
        (void)eng_->add(s, el < eloc_.size() ? eloc_[el] : el, v.side(), v.price(), v.shares());
        if (in_record_) ++cap_.itch_adds;
        return;
      }
      case 'E':
      case 'C': {
        const itch50::OrderExecutedView v(p);
        const OrderRef s = src_of(v.order_ref());
        const Qty q = v.executed_shares();
        if (!in_record_) ++rep_.engine_executions_unsolicited;
        if (s == 0) return;
        (void)eng_->reduce(s, q);
        forget_if_gone(v.order_ref(), s);
        if (in_record_) {
          if (s == og_.ref) {
            cap_.exec_on_target += q;
            cap_.target_reduced += q;
          } else {
            cap_.exec_on_others += q;
          }
        }
        return;
      }
      case 'X': {
        const itch50::OrderCancelView v(p);
        const OrderRef s = src_of(v.order_ref());
        if (!in_record_) ++rep_.engine_cancels_unsolicited;
        if (s == 0) return;
        (void)eng_->reduce(s, v.cancelled_shares());
        forget_if_gone(v.order_ref(), s);
        if (in_record_ && s == og_.ref) cap_.target_reduced += v.cancelled_shares();
        return;
      }
      case 'D': {
        const itch50::OrderDeleteView v(p);
        const OrderRef s = src_of(v.order_ref());
        if (!in_record_) ++rep_.engine_cancels_unsolicited;
        if (s == 0) return;
        const auto o = eng_->find_order(s);
        (void)eng_->remove(s);
        e2o_.erase(v.order_ref());
        if (in_record_ && s == og_.ref && o) cap_.target_reduced += o->qty;
        return;
      }
      case 'U': {
        const itch50::OrderReplaceView v(p);
        const OrderRef so = src_of(v.original_order_ref());
        const OrderRef sn = src_of(v.new_order_ref());
        if (so == 0 || sn == 0) return;
        (void)eng_->replace(so, sn, v.price(), v.shares());
        e2o_.erase(v.original_order_ref());
        return;
      }
      case 'P': ++rep_.engine_hidden_executions; return;
      case 'Q': ++rep_.engine_cross_prints; return;
      default: return;
    }
  }

  // --- books ------------------------------------------------------------------------------------
  void compare(SeqNo seq, Nanos t) {
    BookDiff d;
    d.seq = seq;
    d.time = t;
    d.source_orders = src_->live_orders();
    d.engine_orders = eng_->live_orders();
    d.source_digest = src_->books_digest();
    d.engine_digest = eng_->books_digest();
    struct O {
      OrderRef ref;
      PxE4 px;
      Qty qty;
    };
    std::vector<O> a, e;
    std::unordered_map<OrderRef, std::size_t> idx;
    const std::size_t nloc = std::max(src_->locates(), eng_->locates());
    for (std::size_t l = 0; l < nloc; ++l) {
      for (Side s : {Side::Buy, Side::Sell}) {
        a.clear();
        e.clear();
        src_->for_each_order(static_cast<Locate>(l), s, [&](PxE4 px, OrderRef r, Qty q) { a.push_back(O{r, px, q}); });
        eng_->for_each_order(static_cast<Locate>(l), s, [&](PxE4 px, OrderRef r, Qty q) { e.push_back(O{r, px, q}); });
        if (a.empty() && e.empty()) continue;
        idx.clear();
        for (std::size_t i = 0; i < e.size(); ++i) idx.emplace(e[i].ref, i);
        std::vector<char> matched(e.size(), 0);
        for (const O& o : a) {
          const auto it = idx.find(o.ref);
          if (it == idx.end()) {
            ++d.missing_in_engine;
            continue;
          }
          matched[it->second] = 1;
          const O& x = e[it->second];
          if (x.px != o.px) ++d.price_differs;
          else if (x.qty != o.qty) ++d.shares_differ;
          else ++d.identical;
        }
        for (char m : matched) d.extra_in_engine += m ? 0 : 1;
        // Queue order per price level over the orders both books hold.
        std::map<PxE4, std::vector<OrderRef>> la, le;
        for (const O& o : a)
          if (idx.contains(o.ref)) la[o.px].push_back(o.ref);
        std::unordered_map<OrderRef, char> in_a;
        for (const O& o : a) in_a.emplace(o.ref, 1);
        for (const O& o : e)
          if (in_a.contains(o.ref)) le[o.px].push_back(o.ref);
        for (const auto& [px, refs] : la) {
          ++d.levels_compared;
          const auto it = le.find(px);
          if (it == le.end() || it->second != refs) ++d.levels_queue_order_differs;
        }
      }
    }
    rep_.checkpoints.push_back(d);
  }

  const DivergenceConfig& cfg_;
  DivergenceReport& rep_;
  Sink sink_;
  Converter conv_;
  std::unique_ptr<EngineDriver<Sink>> driver_;
  std::unique_ptr<book::OptBook<>> src_, eng_;
  std::unordered_map<OrderRef, OrderRef> e2o_;  // live engine orders -> source references; never iterated
  std::vector<Locate> eloc_;
  std::array<char, 65536> halted_{};
  bool in_record_ = false, pending_cp_ = false;
  std::uint16_t rec_session_ = 0;
  Origin og_;
  Capture cap_;
};

}  // namespace

bool run_divergence(const DivergenceConfig& cfg, DivergenceReport& out, std::string* err) {
  std::vector<SymbolInfo> syms;
  if (!scan_symbols(cfg.itch_path, cfg.max_messages, syms, err)) return false;
  if (syms.empty()) {
    if (err) *err = "no stock directory (R) messages in the source";
    return false;
  }
  auto r = std::make_unique<Run>(cfg, syms, out);
  r->syms_copy_ = syms;
  return r->run(err);
}

std::string divergence_json(const DivergenceConfig& cfg, const DivergenceReport& r) {
  JsonObject j;
  j.str("mode", "divergence").str("file", cfg.itch_path).num("max_messages", cfg.max_messages);
  j.num("sessions", cfg.sessions).num("elapsed_ns", static_cast<std::uint64_t>(r.elapsed_ns));
  const ConvertStats& c = r.convert;
  j.num("source_messages", c.source).num("script_records", r.records);
  j.num("script_enter", c.ops[0]).num("script_cancel", c.ops[1]).num("script_replace", c.ops[2]).num("script_ioc", c.ops[3]);
  j.num("script_partial_cancels", c.partial_cancels).num("script_full_cancels", c.full_cancels);
  j.num("script_ioc_from_e", c.ioc_from_e).num("script_ioc_from_c", c.ioc_from_c);
  j.num("source_c_nonprintable", c.c_nonprintable).num("source_c_price_differs", c.c_price_differs);
  j.num("source_hidden_trades_P", c.hidden_trades).num("source_hidden_shares_P", c.hidden_shares);
  j.num("source_cross_prints_Q", c.cross_prints).num("source_cross_shares_Q", c.cross_shares);
  j.num("source_unknown_ref", c.unknown_ref).num("source_duplicate_ref", c.duplicate_ref).num("source_bad_length", c.bad_length);
  j.num("engine_records", r.engine_records).num("engine_timers", r.engine_timers);
  j.num("enter_ok", r.enter_ok).num("enter_rejected", r.enter_rejected).num("enter_not_displayed", r.enter_not_displayed);
  j.num("enter_crossed", r.enter_crossed).num("enter_crossed_shares", r.enter_crossed_shares);
  j.num("enter_crossed_source_locked", r.enter_crossed_source_locked);
  j.num("enter_crossed_source_halted", r.enter_crossed_source_halted);
  j.num("enter_crossed_cascade", r.enter_crossed_cascade);
  j.num("cancel_ok", r.cancel_ok).num("cancel_no_order", r.cancel_no_order).num("cancel_shares_differ", r.cancel_shares_differ);
  j.num("replace_ok", r.replace_ok).num("replace_no_order", r.replace_no_order).num("replace_rejected", r.replace_rejected);
  j.num("replace_original_cancelled", r.replace_original_cancelled);
  j.num("replace_crossed", r.replace_crossed).num("replace_crossed_shares", r.replace_crossed_shares);
  j.num("ioc_exact", r.ioc_exact).num("ioc_other_orders", r.ioc_other_orders).num("ioc_short", r.ioc_short);
  j.num("ioc_none", r.ioc_none).num("ioc_rejected", r.ioc_rejected).num("ioc_target_absent", r.ioc_target_absent);
  j.num("ioc_shares_expected", r.ioc_shares_expected).num("ioc_shares_executed", r.ioc_shares_executed);
  j.num("ioc_shares_on_target", r.ioc_shares_on_target);
  std::string reasons;
  for (std::size_t i = 0; i < r.reject_reasons.size(); ++i) {
    if (r.reject_reasons[i] == 0) continue;
    char b[32];
    std::snprintf(b, sizeof b, "%s0x%04zx:%" PRIu64, reasons.empty() ? "" : ",", i, r.reject_reasons[i]);
    reasons += b;
  }
  j.str("reject_reasons", reasons);
  j.num("engine_executions_unsolicited", r.engine_executions_unsolicited);
  j.num("engine_cancels_unsolicited", r.engine_cancels_unsolicited).num("engine_cross_prints", r.engine_cross_prints);
  j.num("engine_hidden_executions", r.engine_hidden_executions).num("unmapped_engine_orders", r.unmapped_engine_orders);
  std::string cps = "[";
  for (std::size_t i = 0; i < r.checkpoints.size(); ++i) {
    const BookDiff& d = r.checkpoints[i];
    char b[640];
    std::snprintf(b, sizeof b,
                  "%s\n    {\"seq\": %" PRIu64 ", \"time_ns\": %lld, \"source_orders\": %" PRIu64 ", \"engine_orders\": %" PRIu64
                  ", \"identical\": %" PRIu64 ", \"shares_differ\": %" PRIu64 ", \"price_differs\": %" PRIu64
                  ", \"missing_in_engine\": %" PRIu64 ", \"extra_in_engine\": %" PRIu64 ", \"levels_compared\": %" PRIu64
                  ", \"levels_queue_order_differs\": %" PRIu64 ", \"digests_equal\": %s}",
                  i == 0 ? "" : ",", d.seq, static_cast<long long>(d.time), d.source_orders, d.engine_orders, d.identical,
                  d.shares_differ, d.price_differs, d.missing_in_engine, d.extra_in_engine, d.levels_compared,
                  d.levels_queue_order_differs, d.source_digest == d.engine_digest ? "true" : "false");
    cps += b;
  }
  cps += "\n  ]";
  j.raw("checkpoints", cps);
  return j.done();
}

}  // namespace lle::client::i2o
