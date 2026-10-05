#pragma once
// RefEngine member definitions (see ref_engine.hpp). Header-only.

namespace lle::engine::ref {

// ============================================================================ canonical state

inline void RefEngine::walk_order(W& w, const Ord& o) const {
  w.u16(o.locate);
  w.u8(static_cast<std::uint8_t>(o.side));
  w.u8(o.where);
  w.u8(static_cast<std::uint8_t>(o.cls()));
  w.u64(o.ref);
  w.u64(o.itch_ref);
  w.u64(o.prio);
  w.u64(static_cast<std::uint64_t>(o.px));
  w.u64(static_cast<std::uint64_t>(o.rpx));
  for (std::uint32_t x : {o.leaves, o.done, o.minq, o.maxf, o.urn, o.acct, o.sess, o.expire}) w.u32(x);
  w.u32(static_cast<std::uint32_t>(pack(o.firm.c.data(), 4)));
  w.u16(o.group);
  w.u16(o.flags);
  w.u16(static_cast<std::uint16_t>(pack(o.aiq_group.c.data(), 2)));
  w.u8(o.idx);
  for (char c : {o.marking, o.display, o.tif, o.capacity, o.iso, o.cross, o.aiq}) w.u8(static_cast<std::uint8_t>(c));
}

inline std::vector<std::byte> RefEngine::canonical() const {
  W w;
  w.u64(0x3153474E45454C4Cull);
  w.u32(1);
  w.u64(static_cast<std::uint64_t>(midnight_));
  w.u32(date_);
  w.u8(started_ ? 1 : 0);
  w.u8(static_cast<std::uint8_t>(session_));
  w.u8(static_cast<std::uint8_t>(init_session_));
  w.u8(miles_);
  w.u64(next_ref_);
  w.u64(next_match_);
  w.u64(itch_n_);
  w.u8(mwcb_breach_);
  for (std::int64_t x : mwcb_) w.u64(static_cast<std::uint64_t>(x));
  for (std::int64_t x : {prm_.thr_bps, prm_.thr_min, prm_.pt_bps, prm_.pt_min, prm_.pt_mask, prm_.halt, prm_.luld,
                         prm_.mwcb, prm_.limit, prm_.ext})
    w.u64(static_cast<std::uint64_t>(x));
  w.u32(static_cast<std::uint32_t>(sched_.size()));
  for (const ScheduleEntry& e : sched_) {
    w.u32(e.timer_id);
    w.u16(static_cast<std::uint16_t>(e.kind));
    w.u16(e.arg);
    w.u64(static_cast<std::uint64_t>(e.time_ns));
  }
  w.u32(static_cast<std::uint32_t>(syms_.size()));
  for (const Sym& y : syms_) {
    w.u64(pack(y.symbol.c.data(), 8));
    w.u32(y.lot);
    w.u32(y.tick);
    w.u64(static_cast<std::uint64_t>(y.prior_close));
    w.u8(static_cast<std::uint8_t>(y.mc));
    w.u8(static_cast<std::uint8_t>(y.luld));
    w.u8(y.flags);
    w.u32(y.adv);
    w.u8(y.opened ? 1 : 0);
    w.u8(y.closed ? 1 : 0);
    w.u8(static_cast<std::uint8_t>(y.regsho));
    w.u8(y.halt);
    w.u8(y.kind);
    w.u32(static_cast<std::uint32_t>(pack(y.reason.c.data(), 4)));
    w.u32(y.ticks);
    w.u32(y.period);
    w.u32(y.ext);
    for (PxE4 x : {y.arp, y.clo, y.chi, y.cstep, y.blo, y.bhi}) w.u64(static_cast<std::uint64_t>(x));
    w.u32(static_cast<std::uint32_t>(y.limit));
    for (PxE4 x : {y.last, y.last_ns, y.oref2, y.cref1, y.cref2, y.ipo_px, y.ipo_band, y.ipo_exp})
      w.u64(static_cast<std::uint64_t>(x));
    w.u32(y.peg_pulled);
  }
  w.u32(static_cast<std::uint32_t>(accts_.size()));
  for (const Acct& a : accts_) {
    w.u32(a.id);
    for (std::size_t i = 0; i < 4; ++i) {
      const Mpid4 f = i < a.firms.size() ? a.firms[i] : Mpid4{};
      w.u32(static_cast<std::uint32_t>(pack(f.c.data(), 4)));
    }
    w.u8(static_cast<std::uint8_t>(a.firms.size()));
    w.u8(a.disabled);
    w.u8(a.permit ? 1 : 0);
    w.u16(static_cast<std::uint16_t>(a.last.size()));
    for (const auto& [idx, last] : a.last) {
      w.u8(idx);
      w.u32(last);
    }
  }
  w.u32(static_cast<std::uint32_t>(sess_.size()));
  for (const Sess& s : sess_) {
    w.u32(s.id);
    w.u32(s.acct);
    w.u8(s.flags);
    w.u8(static_cast<std::uint8_t>(s.aiq));
    w.u8(s.late);
    w.u64(s.live);
    w.u64(s.outs);
  }
  // Records: a reserve order is two (the display and the reserve part).
  std::uint64_t records = 0;
  for (const auto& [ref, o] : orders_) records += o.reserve > 0 ? 2u : 1u;
  w.u64(records);
  auto walk_part = [&](std::uint64_t e) {
    const Ord& o = orders_.at(base(e));
    if (!is_res(e)) return walk_order(w, o);
    Ord c = o;  // the reserve record: hidden, its own priority, no ITCH reference
    c.display = 'N';
    c.flags = static_cast<std::uint16_t>(c.flags | fChild);
    c.leaves = o.reserve;
    c.done = 0;
    c.itch_ref = 0;
    c.prio = o.rprio;
    walk_order(w, c);
  };
  for (std::size_t l = 0; l < books_.size(); ++l) {
    const Book& b = books_[l];
    for (auto it = b.bids.rbegin(); it != b.bids.rend(); ++it)
      for (int c = 0; c < 2; ++c)
        for (std::uint64_t r : it->second.q[c]) walk_part(r);
    for (const auto& [px, lv] : b.asks)
      for (int c = 0; c < 2; ++c)
        for (std::uint64_t r : lv.q[c]) walk_part(r);
    const Sym& y = syms_[l];
    for (std::uint64_t r : y.pending) walk_order(w, orders_.at(r));
    for (int sd = 0; sd < 2; ++sd)
      for (std::uint64_t r : y.pegs[sd]) walk_order(w, orders_.at(r));
  }
  // Risk gate.
  auto w128 = [&](i128 x) {
    const auto u = static_cast<u128>(x);
    w.u64(static_cast<std::uint64_t>(u));
    w.u64(static_cast<std::uint64_t>(u >> 64));
  };
  w.u32(static_cast<std::uint32_t>(rk_.accts.size()));
  for (std::uint32_t a = 0; a < rk_.accts.size(); ++a) {
    const RAcct& ra = rk_.accts[a];
    const RLim& m = ra.lim;
    w.u32(m.perms);
    for (std::int64_t x : {m.max_qty, m.max_notional, m.ff_bps, m.ff_abs, m.lop, m.dup, m.port, m.symrate, m.gross,
                           m.symnot, m.adv, m.kill})
      w.u64(static_cast<std::uint64_t>(x));
    w128(open_notional(a, 0));
    w128(ra.executed);
    w.u8(ra.killed ? 1 : 0);
    w.u8(ra.track_sym ? 1 : 0);
  }
  w.u32(static_cast<std::uint32_t>(rk_.rules.size()));
  for (const auto& [k, r] : rk_.rules) {
    w.u32(k.first);
    w.u16(k.second);
    w.u8(r.restricted ? 1 : 0);
    w.u8(r.htb ? 1 : 0);
    w.u64(static_cast<std::uint64_t>(r.notional));
  }
  w.u32(static_cast<std::uint32_t>(rk_.port.size()));
  for (const RBucket& b : rk_.port) {
    w.u64(static_cast<std::uint64_t>(b.level));
    w.u64(static_cast<std::uint64_t>(b.last));
  }
  w.u32(static_cast<std::uint32_t>(rk_.sym.size()));
  for (const auto& [k, b] : rk_.sym) {
    w.u32(k.first);
    w.u16(k.second);
    w.u64(static_cast<std::uint64_t>(b.level));
    w.u64(static_cast<std::uint64_t>(b.last));
  }
  w.u32(static_cast<std::uint32_t>(rk_.dup.size()));
  for (const auto& [a, f] : rk_.dup) {
    w.u32(a);
    w.u64(static_cast<std::uint64_t>(f.last));
    w.u32(static_cast<std::uint32_t>(f.secs.size()));
    for (const auto& [sec, dq] : f.secs) {
      w.u64(static_cast<std::uint64_t>(sec));
      w.u32(static_cast<std::uint32_t>(dq.size()));
      for (std::uint64_t h : dq) w.u64(h);
    }
  }
  return w.b;
}

// ============================================================================ risk gate (05 §7)

inline bool RefEngine::bucket_take(RBucket& b, std::int64_t rate, std::int64_t now) {
  const std::int64_t unit = 1'000'000'000;
  const std::int64_t cap = rate * unit;
  std::int64_t lvl = cap;
  if (b.last != INT64_MIN) lvl = std::min(cap, b.level + std::clamp<std::int64_t>(now - b.last, 0, unit) * rate);
  b.last = now;
  if (lvl < unit) {
    b.level = lvl;
    return false;
  }
  b.level = lvl - unit;
  return true;
}

inline bool RefEngine::risk_set(RiskState& st, std::uint32_t a, std::uint16_t kind, std::int64_t v, std::uint16_t l) {
  if (a >= st.accts.size() || v < 0) return false;
  if (l != 0 && kind != 11 && kind != 13 && kind != 14) return false;
  RLim& m = st.accts[a].lim;
  switch (kind) {
    case 1:
      if ((v & ~std::int64_t{127}) != 0) return false;
      m.perms = static_cast<std::uint32_t>(v);
      return true;
    case 2: m.max_qty = v; return true;
    case 3: m.max_notional = v; return true;
    case 4: m.ff_bps = v; return true;
    case 5: m.ff_abs = v; return true;
    case 6:
      if (v > 1) return false;
      m.lop = v;
      return true;
    case 7:
      if (v > 30) return false;
      m.dup = v;
      (void)st.dup[a];
      return true;
    case 8:
      if (v > 1'000'000) return false;
      m.port = v;
      return true;
    case 9:
      if (v > 1'000'000) return false;
      m.symrate = v;
      return true;
    case 10: m.gross = v; return true;
    case 11:
      st.accts[a].track_sym = true;
      if (l == 0) {
        m.symnot = v;
      } else {
        st.rules[{a, l}].notional = v;
      }
      return true;
    case 12: m.adv = v; return true;
    case 13:
    case 14:
      if (l == 0 || v > 1) return false;
      (kind == 13 ? st.rules[{a, l}].restricted : st.rules[{a, l}].htb) = v == 1;
      return true;
    case 15: m.kill = v; return true;
    default: return false;
  }
}

inline i128 RefEngine::open_notional(std::uint32_t a, std::uint16_t l) const {
  i128 s = 0;
  for (const auto& [ref, o] : orders_)
    if (o.acct == a && (l == 0 || o.locate == l)) s += i128{std::uint64_t{o.leaves} + o.reserve} * o.rpx;
  return s;
}

inline std::uint16_t RefEngine::risk_check(std::uint32_t a, std::uint32_t s, std::uint16_t l, const Req& q,
                                           std::uint64_t price_field, bool replace, const Ord* old, PxE4* rpx) {
  RAcct& ra = rk_.accts[a];
  const RLim& m = ra.lim;
  const std::int64_t now = ts_;
  if (m.port > 0 && !bucket_take(rk_.port[s], m.port, now)) return 0x0029;
  if (m.symrate > 0 && !bucket_take(rk_.sym[{s, l}], m.symrate, now)) return 0x0028;
  const bool buy = q.marking == 'B';
  const Sym& y = sym(l);
  if ((m.perms & 1) && session_ == 'P') return 0x002D;
  if ((m.perms & 2) && session_ == 'A') return 0x002E;
  if ((m.perms & 4) && q.marking == 'T') return 0x002B;
  if ((m.perms & 8) && q.marking == 'E') return 0x002F;
  if ((m.perms & 16) && q.market) return 0x002C;
  if ((m.perms & 32) && q.market && buy && (y.halt == 4 || y.halt == 5)) return 0x0033;
  const auto ri = rk_.rules.find({a, l});
  const RRule* rule = ri == rk_.rules.end() ? nullptr : &ri->second;
  if (rule && rule->restricted) return 0x0022;
  if (rule && rule->htb && (q.marking == 'T' || q.marking == 'E') && !q.located) return 0x0027;
  if (m.max_qty > 0 && q.qty > m.max_qty) return 0x0031;
  if (m.adv > 0 && y.adv > 0 && i128{q.qty} * 100 > i128{y.adv} * m.adv) return 0x0025;
  const PxE4 bid = disp_best(l, 'B'), ask = disp_best(l, 'S');
  const PxE4 nb = buy ? ask : bid;
  const PxE4 ref = nb > 0 ? nb : y.last;
  const PxE4 rp = q.market ? (ref > 0 ? ref : y.prior_close) : q.px;
  *rpx = rp;
  if (m.max_notional > 0 && i128{q.qty} * rp > m.max_notional) return 0x0030;
  if (!q.market && q.cross == 'N' && y.halt == 0) {
    if (ref > 0) {
      const PxE4 thr = buy ? q.px - ref : ref - q.px;
      if (m.lop != 0 && thr > std::max<PxE4>(ref / 10, 5000)) return 0x0006;
      if (m.ff_bps > 0 && i128{thr} * 10000 > i128{ref} * m.ff_bps) return 0x0026;
      if (m.ff_abs > 0 && thr > m.ff_abs) return 0x0026;
    }
    if ((m.perms & 64) && y.bhi > 0 && (buy ? q.px > y.bhi : q.px < y.blo)) return 0x0021;
  }
  const std::uint32_t open = replace ? (q.qty > old->done ? q.qty - old->done : 0) : q.qty;
  const i128 add = i128{open} * rp;
  const i128 old_open = replace ? i128{std::uint64_t{old->leaves} + old->reserve} * old->rpx : 0;
  const std::int64_t symlim = rule && rule->notional >= 0 ? rule->notional : m.symnot;
  if (symlim > 0 && open_notional(a, l) - old_open + add > symlim) return 0x001F;
  if (m.gross > 0 && open_notional(a, 0) - old_open + add + ra.executed > m.gross) return 0x0020;
  if (!replace && m.dup > 0) {
    const auto fi = rk_.dup.find(a);
    if (fi != rk_.dup.end()) {
      Fnv1a64 h;
      h.u(l);
      h.u(static_cast<std::uint8_t>(q.marking));
      h.u(q.qty);
      h.u(price_field);
      h.u(static_cast<std::uint8_t>(q.tif));
      h.u(static_cast<std::uint8_t>(q.display));
      h.u(static_cast<std::uint8_t>(q.cross));
      const std::uint64_t key = h.value();
      RDup& f = fi->second;
      const std::int64_t sec = now / 1'000'000'000;
      for (std::int64_t x = sec - m.dup + 1; x <= sec; ++x) {
        const auto it = f.secs.find(x);
        if (it != f.secs.end() && std::find(it->second.begin(), it->second.end(), key) != it->second.end())
          return 0x002A;
      }
      std::erase_if(f.secs, [&](const auto& e) { return e.first <= sec - 32; });
      auto& dq = f.secs[sec];
      dq.push_back(key);
      if (dq.size() > 8) dq.pop_front();
      f.last = sec;
    }
  }
  return 0;
}

inline void RefEngine::kill_acct(std::uint32_t a) {
  rk_.accts[a].killed = true;
  for (std::uint64_t r : refs_of_acct(a)) kill(r, 'S');
}

inline void RefEngine::risk_after_record() {
  for (std::uint32_t a = 0; a < rk_.accts.size(); ++a) {
    RAcct& ra = rk_.accts[a];
    if (!ra.touched) continue;
    ra.touched = false;
    if (ra.lim.kill > 0 && ra.executed > ra.lim.kill && !ra.killed) kill_acct(a);
  }
}

// ============================================================================ configuration

inline void RefEngine::config(std::span<const std::byte> p) {
  auto reset = [&] {
    cfg_next_ = 0;
    cfg_buf_.clear();
  };
  if (p.size() < 16) return reset();
  const std::uint16_t table = load_le16(p.data());
  const std::uint16_t index = load_le16(p.data() + 2);
  const std::uint16_t count = load_le16(p.data() + 4);
  const std::uint32_t total = load_le32(p.data() + 8);
  const std::uint32_t n = load_le32(p.data() + 12);
  if (p.size() - 16 < n || count == 0 || index >= count || started_) return reset();
  if (index == 0) {
    cfg_table_ = table;
    cfg_total_ = total;
    reset();
  }
  if (table != cfg_table_ || index != cfg_next_ || total != cfg_total_ || cfg_buf_.size() + n > cfg_total_)
    return reset();
  cfg_buf_.insert(cfg_buf_.end(), p.begin() + 16, p.begin() + 16 + n);
  ++cfg_next_;
  if (cfg_next_ < count) return;
  const std::vector<std::byte> body = cfg_buf_;
  reset();
  if (body.size() == cfg_total_ && load(table, body) && table == 1) directory();
}

inline bool RefEngine::load(std::uint16_t table, std::span<const std::byte> t) {
  if (t.size() < 8 || load_le16(t.data()) != 1 || load_le16(t.data() + 2) != 0) return false;
  const std::uint32_t n = load_le32(t.data() + 4);
  const std::span<const std::byte> body = t.subspan(8);
  const std::size_t esz = table == 1 ? 32 : table == 3 ? 20 : table == 4 ? 16 : table == 5 ? 24 : table == 6 ? 16 : 0;
  if (esz == 0 || body.size() != std::size_t{n} * esz) return false;
  if (table == 1) {
    if (n > 0xFFFE) return false;
    std::vector<Sym> ys;
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::byte* e = body.data() + std::size_t{i} * 32;
      Sym y;
      y.symbol = Symbol8::from_wire(e);
      y.lot = load_le32(e + 8);
      y.tick = load_le32(e + 12);
      y.prior_close = static_cast<PxE4>(load_le64(e + 16));
      y.mc = static_cast<char>(e[24]);
      y.luld = static_cast<char>(e[25]);
      y.flags = static_cast<std::uint8_t>(e[26]);
      y.regsho = static_cast<char>(e[27]);
      y.adv = load_le32(e + 28);
      if (y.symbol.blank() || y.tick == 0 || 10000 % y.tick != 0 || y.lot == 0 || y.prior_close < 0 ||
          y.prior_close > 0xFFFFFFFFll)
        return false;
      for (const Sym& z : ys)
        if (z.symbol == y.symbol) return false;
      if (y.mc == '\0' || std::string_view("QGSNAPZVM ").find(y.mc) == std::string_view::npos) y.mc = ' ';
      if (y.luld != '1' && y.luld != '2') y.luld = ' ';
      if (y.regsho != '0' && y.regsho != '2') y.regsho = ' ';
      ys.push_back(y);
    }
    syms_ = ys;
    books_.assign(syms_.size(), Book{});
    risk_reset();
    return true;
  }
  if (table == 3) {
    if (n > (1u << 24)) return false;
    std::vector<Acct> as;
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::byte* e = body.data() + std::size_t{i} * 20;
      Acct a;
      a.id = load_le32(e);
      for (const Acct& b : as)
        if (b.id == a.id) return false;
      for (int k = 0; k < 4; ++k) {
        const Mpid4 f = Mpid4::from_wire(e + 4 + 4 * k);
        if (!f.blank() && std::find(a.firms.begin(), a.firms.end(), f) == a.firms.end()) a.firms.push_back(f);
      }
      as.push_back(a);
    }
    accts_ = as;
    sess_.clear();
    risk_reset();
    return true;
  }
  if (table == 4) {
    std::vector<Sess> ss;
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::byte* e = body.data() + std::size_t{i} * 16;
      Sess s;
      s.id = load_le32(e);
      const std::uint32_t acct_id = load_le32(e + 4);
      s.flags = static_cast<std::uint8_t>(e[8]);
      s.aiq = static_cast<char>(e[9]);
      s.late = static_cast<std::uint8_t>(e[10]);
      bool found = false;
      for (std::size_t k = 0; k < accts_.size(); ++k) {
        if (accts_[k].id == acct_id) {
          s.acct = static_cast<std::uint32_t>(k);
          found = true;
        }
      }
      if (!found || s.late > 2) return false;
      for (const Sess& u : ss)
        if (u.id == s.id) return false;
      if (!aiq_ok(s.aiq)) s.aiq = 'N';
      ss.push_back(s);
    }
    sess_ = ss;
    risk_reset();
    return true;
  }
  if (table == 5) {
    RiskState st;
    st.accts.assign(accts_.size(), RAcct{});
    st.port.assign(sess_.size(), RBucket{});
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::byte* e = body.data() + std::size_t{i} * 24;
      const std::uint32_t id = load_le32(e);
      const std::uint16_t kind = load_le16(e + 4);
      const auto v = static_cast<std::int64_t>(load_le64(e + 8));
      const Symbol8 sy = Symbol8::from_wire(e + 16);
      int ai = -1;
      for (std::size_t k = 0; k < accts_.size(); ++k)
        if (accts_[k].id == id) ai = static_cast<int>(k);
      const int li = sy.blank() ? 0 : find_sym(sy);
      if (ai < 0 || (!sy.blank() && li == 0) ||
          !risk_set(st, static_cast<std::uint32_t>(ai), kind, v, static_cast<std::uint16_t>(li)))
        return false;
    }
    rk_ = st;
    return true;
  }
  // Schedule
  std::vector<ScheduleEntry> all;
  Params pr = prm_;
  char init = init_session_;
  std::vector<std::uint32_t> ids;
  for (std::uint32_t i = 0; i < n; ++i) {
    const std::byte* e = body.data() + std::size_t{i} * 16;
    ScheduleEntry x;
    x.timer_id = load_le32(e);
    x.kind = static_cast<TimerKind>(load_le16(e + 4));
    x.arg = load_le16(e + 6);
    x.time_ns = static_cast<Nanos>(load_le64(e + 8));
    all.push_back(x);
    if (x.timer_id != 0) {
      const auto k = static_cast<std::uint16_t>(x.kind);
      if (k < 1 || k > 7) return false;
      if (std::find(ids.begin(), ids.end(), x.timer_id) != ids.end()) return false;
      ids.push_back(x.timer_id);
      continue;
    }
    const std::int64_t v = x.time_ns;
    switch (x.arg) {
      case 1:
        if (v != 'C' && v != 'P' && v != 'R' && v != 'A') return false;
        init = static_cast<char>(v);
        break;
      case 2: pr.thr_bps = v; break;
      case 3: pr.thr_min = v; break;
      case 4: pr.pt_bps = v; break;
      case 5: pr.pt_min = v; break;
      case 6: pr.pt_mask = v; break;
      case 7: pr.halt = v; break;
      case 8: pr.luld = v; break;
      case 9: pr.mwcb = v; break;
      case 10: pr.limit = v; break;
      case 11: pr.ext = v; break;
      default: return false;
    }
    if (v < 0) return false;
  }
  // Bounds (05 §4 Schedule): bps <= 100000, minimums <= the OUCH maximum price,
  // mask <= 7, periods <= 86400 s.
  if (pr.thr_bps > 100'000 || pr.pt_bps > 100'000 || pr.thr_min > kPxMaxLimit || pr.pt_min > kPxMaxLimit ||
      pr.pt_mask > 7 || pr.halt > 86'400 || pr.luld > 86'400 || pr.mwcb > 86'400 || pr.limit > 86'400 ||
      pr.ext > 86'400)
    return false;
  sched_ = all;
  prm_ = pr;
  init_session_ = init;
  session_ = init;
  return true;
}

inline void RefEngine::directory() {
  for (std::size_t i = 0; i < syms_.size(); ++i) {
    const Sym& y = syms_[i];
    itch50::StockDirectory m;
    m.stock = y.symbol;
    m.market_category = static_cast<itch50::MarketCategory>(y.mc);
    m.financial_status = itch50::FinancialStatus::Normal;
    m.round_lot_size = y.lot;
    m.round_lots_only = itch50::YesNo::No;
    m.issue_classification = itch50::IssueClassification::CommonStock;
    m.issue_sub_type = Alpha<2>("Z ");
    m.authenticity = (y.flags & 1) ? itch50::Authenticity::Test : itch50::Authenticity::LiveProduction;
    m.short_sale_threshold = itch50::YesNoBlank::No;
    m.ipo_flag = itch50::IpoFlag::NotNewIpo;
    m.luld_tier = static_cast<itch50::LuldTier>(y.luld);
    m.etp_flag = (y.flags & 2) ? itch50::YesNoBlank::Yes : itch50::YesNoBlank::No;
    m.etp_leverage_factor = 0;
    m.inverse_indicator = itch50::YesNo::No;
    itch(m, static_cast<std::uint16_t>(i + 1));
  }
  for (std::size_t i = 0; i < syms_.size(); ++i) {
    if (syms_[i].regsho != '0' && syms_[i].regsho != '2') continue;
    itch50::RegShoRestriction y;
    y.stock = syms_[i].symbol;
    y.reg_sho_action = static_cast<itch50::RegShoAction>(syms_[i].regsho);
    itch(y, static_cast<std::uint16_t>(i + 1));
  }
}

inline void RefEngine::session_event(std::span<const std::byte> p) {
  if (p.size() < 16) return;
  const int s = find_sess(load_le32(p.data()));
  if (s < 0) return;
  Sess& ss = sess_[static_cast<std::size_t>(s)];
  const std::uint64_t bit = std::uint64_t{1} << (load_le16(p.data() + 4) % 64);
  const auto ev = static_cast<std::uint8_t>(p[6]);
  if (ev == 1 || ev == 4) ss.live |= bit;
  if (ev == 2) ss.live &= ~bit;
  if (ev == 3 || ev == 5) {
    const bool was = (ss.live & bit) != 0;
    ss.live &= ~bit;
    if (was && ss.live == 0 && (ss.flags & 1)) {
      for (const std::uint64_t ref : refs_of_acct(ss.acct)) {
        const Ord& o = orders_.at(ref);
        if (o.sess != static_cast<std::uint32_t>(s)) continue;
        if ((ss.flags & 2) && o.cross != 'N') continue;
        if (frozen(o)) continue;
        kill(ref, 'Z');
      }
    }
  }
}

// ============================================================================ timers

inline void RefEngine::timer(std::span<const std::byte> p) {
  if (p.size() < 16) return;
  const std::uint32_t id = load_le32(p.data());
  const std::uint16_t kind = load_le16(p.data() + 4);
  const Nanos scheduled = static_cast<Nanos>(load_le64(p.data() + 8));
  const ScheduleEntry* e = nullptr;
  for (const ScheduleEntry& x : sched_)
    if (x.timer_id != 0 && x.timer_id == id) e = &x;
  if (e == nullptr || static_cast<std::uint16_t>(e->kind) != kind) return;
  const std::uint16_t arg = e->arg;
  switch (kind) {
    case 1: {
      if (arg > 0x7F || arg == 0 || std::string_view("OSQMEC").find(static_cast<char>(arg)) == std::string_view::npos)
        return;
      itch50::SystemEvent m;
      m.event_code = static_cast<itch50::EventCode>(arg);
      itch(m, 0);
      if (arg == 'O' || arg == 'C') {
        for (std::size_t s = 0; s < sess_.size(); ++s) {
          ouch50::out::SystemEvent se;
          se.event_code = arg == 'O' ? ouch50::EventCode::StartOfDay : ouch50::EventCode::EndOfDay;
          ouch(static_cast<std::uint32_t>(s), se, {});
        }
      }
      return;
    }
    case 5: milestone(arg); return;
    case 2:
    case 3:
      if (arg == 'O' || arg == 'C') {
        const bool open = arg == 'O';
        if (open ? session_ != 'P' : session_ != 'R') return;
        for (std::uint16_t l = 1; l <= syms_.size(); ++l) {
          const Sym& y = sym(l);
          if (y.halt != 0 || (open ? y.opened : y.closed)) continue;
          noii(l, static_cast<char>(arg), kind == 2);
        }
      } else if (arg == 'H' && kind == 3) {
        clock(scheduled);
      }
      return;
    case 4:
      if (arg != 'O' && arg != 'C') return;
      for (std::uint16_t l = 1; l <= syms_.size(); ++l) {
        if (arg == 'O' && !sym(l).opened) open_cross(l);
        if (arg == 'C' && !sym(l).closed) close_cross(l);
      }
      session_ = arg == 'O' ? 'R' : 'A';
      return;
    case 6:
      if (arg == 'D' || arg == 'X') sweep(static_cast<char>(arg));
      return;
    default: return;
  }
}

inline void RefEngine::milestone(std::uint16_t arg) {
  auto record = [&](char kind, PxE4 Sym::*f) {
    for (std::uint16_t l = 1; l <= syms_.size(); ++l) {
      Sym& y = sym(l);
      if (y.halt != 0 || (kind == 'O' ? y.opened : y.closed)) continue;
      const CrossResult r = cross_at(l, kind, false, true);
      sym(l).*f = (r.valid && r.price > 0) ? round_px(l, r.price, r.side == 'B' ? 'U' : (r.side == 'S' ? 'D' : 'N')) : 0;
    }
  };
  switch (arg) {
    case 'P': session_ = 'P'; break;
    case 'F': miles_ |= mOpenFreeze; break;
    case 'M':
      miles_ |= mMooCut;
      record('O', &Sym::oref2);
      break;
    case 'L': miles_ |= mLooCut; break;
    case 'f':
      miles_ |= mCloseFreeze;
      record('C', &Sym::cref1);
      break;
    case 'm':
      miles_ |= mMocCut;
      record('C', &Sym::cref2);
      break;
    case 'l':
      miles_ |= mLocCut;
      for (Acct& a : accts_) a.permit = false;
      break;
    case 'X': session_ = 'C'; break;
    default: break;
  }
}

inline void RefEngine::sweep(char kind) {
  for (std::uint32_t a = 0; a < accts_.size(); ++a) {
    for (const std::uint64_t ref : refs_of_acct(a)) {
      if (!orders_.count(ref)) continue;
      if (kind == 'X' || orders_.at(ref).tif == '0') kill(ref, 'E');
    }
  }
}

inline void RefEngine::clock(Nanos scheduled) {
  for (std::uint16_t l = 1; l <= syms_.size(); ++l) tick_symbol(l);
  // Midpoint pegs with no valid midpoint at two consecutive ticks are cancelled ('Z').
  for (std::uint16_t l = 1; l <= syms_.size(); ++l) {
    Sym& y = sym(l);
    if (y.pegs[0].empty() && y.pegs[1].empty()) {
      y.peg_pulled = 0;
      continue;
    }
    bool act = false;
    (void)mid(l, &act);
    if (act) {
      y.peg_pulled = 0;
    } else if (y.peg_pulled == 0) {
      y.peg_pulled = 1;
    } else {
      for (int sd = 0; sd < 2; ++sd) {
        const std::list<std::uint64_t> pegs = y.pegs[sd];
        for (std::uint64_t r : pegs) kill(r, 'Z');
      }
      y.peg_pulled = 0;
    }
  }
  const Nanos since = scheduled - midnight_;
  const std::uint64_t now_s = since > 0 ? static_cast<std::uint64_t>(since / kNsPerSec) : 0;
  for (std::uint32_t a = 0; a < accts_.size(); ++a) {
    for (const std::uint64_t ref : refs_of_acct(a)) {
      if (!orders_.count(ref)) continue;
      const Ord& o = orders_.at(ref);
      if (o.tif == '6' && o.has(fHasExpire) && o.expire <= now_s && !frozen(o)) kill(ref, 'T');
    }
  }
}

// ============================================================================ admin

inline void RefEngine::admin(std::span<const std::byte> p) {
  const auto rec = parse_admin(p);
  if (!rec) return;
  const auto args = parse_admin_args(rec->args, rec->hdr.tlv_version);
  if (!args) return;
  const AdminArgs& a = *args;
  const std::uint16_t l = a.has(AdminTag::Symbol) ? static_cast<std::uint16_t>(find_sym(a.symbol)) : 0;
  switch (rec->hdr.command) {
    case 1:  // Halt
      if (l == 0) return;
      halt(l, 1, 1, a.has(AdminTag::Reason) ? a.reason : Alpha<4>("T1"));
      return;
    case 2: {  // QuoteOnly
      if (l == 0 || (a.has(AdminTag::Price) && a.price > 0xFFFFFFFFll)) return;
      Sym& y = sym(l);
      y.reason = a.has(AdminTag::Reason) ? a.reason : Alpha<4>("T3");
      const PxE4 arp = a.has(AdminTag::Price) && a.price > 0 ? a.price : (y.last > 0 ? y.last : y.prior_close);
      display_period(l, 1, arp);
      return;
    }
    case 3:  // Resume
      if (l == 0 || sym(l).halt == 0) return;
      release(l, cross_at(l, 'H', false, false));
      return;
    case 4: {  // IpoSchedule
      if (l == 0 || !a.has(AdminTag::Price) || a.price <= 0 || a.price > 0xFFFFFFFFll) return;
      const char q = a.has(AdminTag::Qualifier) ? static_cast<char>(a.qualifier) : 'A';
      if (q != 'A' && q != 'C') return;
      sym(l).ipo_px = q == 'A' ? a.price : 0;
      itch50::IpoQuotingPeriodUpdate k;
      k.stock = sym(l).symbol;
      k.release_time = a.time;
      k.release_qualifier = static_cast<itch50::IpoReleaseQualifier>(q);
      k.ipo_price = a.price;
      itch(k, 0);
      return;
    }
    case 5:  // IpoQuote
      if (l == 0) return;
      halt(l, 4, 4, Alpha<4>("IPOQ"));
      return;
    case 6: {  // IpoRelease
      if (l == 0 || sym(l).halt != 4 || (a.has(AdminTag::Band) && a.band > 0xFFFFFFFFll)) return;
      const CrossResult r = cross_at(l, 'H', false, false);
      Sym& y = sym(l);
      y.ipo_band = a.has(AdminTag::Band) && a.band > 0 ? a.band : 0;
      y.ipo_exp = r.valid ? r.price : y.ipo_px;
      y.halt = 5;
      return;
    }
    case 7:  // LuldBands
      if (l == 0 || a.lower <= 0 || a.upper <= a.lower || a.upper > 0xFFFFFFFFll) return;
      sym(l).blo = a.lower;
      sym(l).bhi = a.upper;
      return;
    case 8: {  // MwcbLevels
      mwcb_ = {a.level1, a.level2, a.level3};
      itch50::MwcbDeclineLevel v;
      v.level1 = a.level1;
      v.level2 = a.level2;
      v.level3 = a.level3;
      itch(v, 0);
      return;
    }
    case 9: {  // MwcbBreach
      if (a.level < 1 || a.level > 3) return;
      mwcb_breach_ = a.level;
      itch50::MwcbStatus w;
      w.breached_level = static_cast<itch50::BreachedLevel>('0' + a.level);
      itch(w, 0);
      for (std::uint16_t s = 1; s <= syms_.size(); ++s) {
        Sym& y = sym(s);
        if (a.level == 3) {
          halt(s, 1, 3, Alpha<4>("MWC3"));
        } else if (y.halt == 0) {
          halt(s, 1, 3, Alpha<4>(a.level == 1 ? "MWC1" : "MWC2"));
          y.period = static_cast<std::uint32_t>(prm_.mwcb);
        }
      }
      return;
    }
    case 10:    // KillSwitch
    case 11: {  // KillReset
      int ai = -1;
      for (std::size_t k = 0; k < accts_.size(); ++k)
        if (a.has(AdminTag::Account) && accts_[k].id == a.account) ai = static_cast<int>(k);
      if (ai < 0) return;
      if (rec->hdr.command == 10) {
        kill_acct(static_cast<std::uint32_t>(ai));
      } else {
        rk_.accts[static_cast<std::size_t>(ai)].killed = false;
      }
      return;
    }
    case 12: {  // RiskLimit
      int ai = -1;
      for (std::size_t k = 0; k < accts_.size(); ++k)
        if (a.has(AdminTag::Account) && accts_[k].id == a.account) ai = static_cast<int>(k);
      if (ai < 0 || !a.has(AdminTag::Kind) || !a.has(AdminTag::Value) || (a.has(AdminTag::Symbol) && l == 0)) return;
      (void)risk_set(rk_, static_cast<std::uint32_t>(ai), a.kind, a.value, l);
      return;
    }
    case 13: {  // CrossCancelPermit
      if (!a.has(AdminTag::Account) || (miles_ & mLocCut)) return;
      for (Acct& x : accts_)
        if (x.id == a.account) x.permit = true;
      return;
    }
    case 14: {  // RegSho
      if (l == 0 || (a.action != '0' && a.action != '1' && a.action != '2')) return;
      sym(l).regsho = static_cast<char>(a.action);
      itch50::RegShoRestriction y;
      y.stock = sym(l).symbol;
      y.reg_sho_action = static_cast<itch50::RegShoAction>(a.action);
      itch(y, l);
      return;
    }
    default: return;
  }
}

// ============================================================================ halts

inline void RefEngine::halt(std::uint16_t l, std::uint8_t phase, std::uint8_t kind, const Alpha<4>& reason) {
  Sym& y = sym(l);
  y.halt = phase;
  y.kind = kind;
  y.reason = reason;
  y.ticks = y.period = y.ext = 0;
  y.arp = y.clo = y.chi = y.cstep = 0;
  y.limit = -1;
  i_action(l, phase == 1 ? 'H' : (phase == 3 ? 'P' : 'Q'), reason);
  for (int sd = 0; sd < 2; ++sd) {
    const std::list<std::uint64_t> pegs = y.pegs[sd];
    for (std::uint64_t r : pegs) kill(r, 'H');
  }
  y.peg_pulled = 0;
}

inline void RefEngine::display_period(std::uint16_t l, std::uint8_t kind, PxE4 arp) {
  const Alpha<4> reason = kind == 2 ? Alpha<4>("LUDP") : sym(l).reason;
  halt(l, kind == 2 ? 3 : 2, kind, reason);
  sym(l).period = static_cast<std::uint32_t>(kind == 2 ? prm_.luld : prm_.halt);
  collars(l, kind, arp);
  if ((kind == 1 || kind == 2) && sym(l).chi > 0) collar_msg(l);
}

inline void RefEngine::collars(std::uint16_t l, std::uint8_t kind, PxE4 arp) {
  Sym& y = sym(l);
  y.arp = arp;
  y.ext = 0;
  y.clo = y.chi = y.cstep = 0;
  if (arp <= 0) return;
  if (kind == 1) {
    const PxE4 d = arp > 10000 ? std::max<PxE4>(10000, arp / 10) : std::max<PxE4>(5000, arp / 10);
    y.clo = round_px(l, arp - d, 'N');
    y.chi = round_px(l, arp + d, 'N');
  } else if (kind == 2) {
    y.cstep = arp <= 30000 ? 1500 : round_px(l, arp / 20, 'N');
    if (arp == y.blo) {
      y.clo = arp - y.cstep;
      y.chi = y.bhi;
    } else {
      y.chi = arp + y.cstep;
      y.clo = y.blo;
    }
  } else if (kind == 3) {
    y.cstep = arp <= 50000 ? 5000 : round_px(l, arp / 10, 'N');
    y.clo = arp - y.cstep;
    y.chi = arp + y.cstep;
  } else {
    return;
  }
  clamp_collars(y);
}

// Collars at most $429,496.00 (inside ITCH Price(4)); lower >= 1 and <= upper.
inline void RefEngine::clamp_collars(Sym& y) {
  if (y.chi > 4'294'960'000) y.chi = 4'294'960'000;
  if (y.clo < 1) y.clo = 1;
  if (y.chi > 0 && y.clo > y.chi) y.clo = y.chi;
}

inline void RefEngine::widen(std::uint16_t l, char side) {
  Sym& y = sym(l);
  if (y.chi == 0) return;
  if (y.kind == 1) {
    const PxE4 pct = y.ext <= 1 ? y.arp / 10 : y.arp / 5;
    const PxE4 d = y.arp > 10000 ? std::max<PxE4>(10000, pct) : std::max<PxE4>(5000, pct);
    y.clo = round_px(l, y.clo - d, 'N');
    y.chi = round_px(l, y.chi + d, 'N');
  } else {
    if (side != 'S') y.chi += y.cstep;
    if (side != 'B') y.clo -= y.cstep;
  }
  clamp_collars(y);
}

inline void RefEngine::collar_msg(std::uint16_t l) {
  const Sym& y = sym(l);
  itch50::LuldAuctionCollar j;
  j.stock = y.symbol;
  j.reference_price = y.arp;
  j.upper_price = y.chi;
  j.lower_price = y.clo;
  j.extension = y.ext;
  itch(j, l);
}

inline void RefEngine::tick_symbol(std::uint16_t l) {
  Sym& y = sym(l);
  if (y.halt == 1 && y.kind == 3 && mwcb_breach_ < 3) {
    if (++y.ticks >= y.period) {
      y.reason = Alpha<4>("MWCQ");
      display_period(l, 3, y.last > 0 ? y.last : y.prior_close);
    }
    return;
  }
  if (y.halt >= 2) {
    ++y.ticks;
    noii(l, 'H', false);
    if (y.halt == 4) return;
    const CrossResult r = cross_at(l, 'H', false, false);
    if (y.halt == 5) {
      const PxE4 d = r.price > y.ipo_exp ? r.price - y.ipo_exp : y.ipo_exp - r.price;
      if (!r.valid || (!r.market_unexecuted && d <= y.ipo_band)) release(l, r);
      return;
    }
    const bool inside = y.chi == 0 || (r.price >= y.clo && r.price <= y.chi);
    const bool ok = !r.valid || (!r.market_unexecuted && inside);
    if (y.ticks >= y.period) {
      if (ok) return release(l, r);
      ++y.ext;
      widen(l, r.side);
      y.ticks = 0;
      y.period = static_cast<std::uint32_t>(prm_.ext);
      if (y.kind == 1 || y.kind == 2) collar_msg(l);
    } else if (y.ext >= 2 && ok && r.imbalance == 0) {
      release(l, r);
    }
    return;
  }
  if (y.halt == 0 && session_ == 'R' && y.bhi > 0) {
    const PxE4 ask = disp_best(l, 'S');
    const PxE4 bid = disp_best(l, 'B');
    char side = 0;
    if (ask > 0 && ask <= y.blo) {
      side = 'S';
    } else if (bid > 0 && bid >= y.bhi) {
      side = 'B';
    }
    if (side == 0) {
      y.limit = -1;
    } else {
      ++y.limit;
      if (y.limit >= prm_.limit) display_period(l, 2, side == 'S' ? y.blo : y.bhi);
    }
  }
}

inline void RefEngine::release(std::uint16_t l, const CrossResult& r) {
  execute(l, 'H', r, sym(l).kind == 4);
  i_action(l, 'T', Alpha<4>{});
  Sym& y = sym(l);
  y.halt = 0;
  y.kind = 0;
  y.reason = Alpha<4>{};
  y.ticks = y.period = y.ext = 0;
  y.arp = y.clo = y.chi = y.cstep = 0;
  y.ipo_band = y.ipo_exp = 0;
  cancel_pending(l, 'H', 'I', false);
  uncross(l);
}

// ============================================================================ crosses

inline void RefEngine::interest(std::uint16_t l, char kind, bool cross_only, std::vector<CrossInterest>& v,
                                std::vector<std::uint64_t>& refs) {
  v.clear();
  refs.clear();
  const PxE4 bid = disp_best(l, 'B'), ask = disp_best(l, 'S');
  for (std::uint64_t ref : sym(l).pending) {
    const Ord& o = orders_.at(ref);
    const bool in = (kind == 'O' && (o.cross == 'O' || o.has(fHeld))) || (kind == 'C' && o.cross == 'C') ||
                    (kind == 'H' && o.cross == 'H');
    if (!in || o.minq != 0) continue;
    CrossInterest c;
    c.qty = o.leaves;
    c.buy = o.side == 'B';
    c.market = o.has(fMarket);
    c.imbalance_only = o.has(fIO);
    c.cross_order = !c.imbalance_only;
    c.px = o.px;
    if (c.imbalance_only) {
      if (c.buy && bid > 0) c.px = std::min(o.px, bid);
      if (!c.buy && ask > 0) c.px = std::max(o.px, ask);
    }
    v.push_back(c);
    refs.push_back(ref);
  }
  if (cross_only) return;
  const Book& b = book(l);
  auto add = [&](const Level& lv, bool buy) {
    for (int c = 0; c < 2; ++c) {
      for (std::uint64_t e : lv.q[c]) {
        const Ord& o = orders_.at(base(e));
        if (o.minq != 0) continue;
        CrossInterest ci;
        ci.px = o.px;
        ci.qty = part_leaves(e);
        ci.buy = buy;
        v.push_back(ci);
        refs.push_back(e);
      }
    }
  };
  for (auto it = b.bids.rbegin(); it != b.bids.rend(); ++it) add(it->second, true);
  for (const auto& [px, lv] : b.asks) add(lv, false);
}

inline CrossResult RefEngine::cross_at(std::uint16_t l, char kind, bool cross_only, bool crp) {
  std::vector<CrossInterest> v;
  std::vector<std::uint64_t> refs;
  interest(l, kind, cross_only, v, refs);
  const Sym& y = sym(l);
  const PxE4 bid = disp_best(l, 'B'), ask = disp_best(l, 'S');
  CrossParams prm;
  prm.kind = static_cast<CrossKind>(kind);
  if (kind == 'H') {
    prm.ref = y.kind == 4 && y.ipo_px > 0 ? y.ipo_px : (y.last > 0 ? y.last : y.prior_close);
  } else if (bid > 0 && ask > 0) {
    prm.ref = (bid + ask) / 2;
  } else {
    prm.ref = kind == 'O' ? y.prior_close : (y.last > 0 ? y.last : y.prior_close);
  }
  if (crp) {
    if (bid > 0 && ask > 0 && bid <= ask) {
      prm.lo = bid;
      prm.hi = ask;
      prm.hard = true;
    }
  } else if (kind != 'H' && !cross_only && (bid > 0 || ask > 0)) {
    const PxE4 mid = bid > 0 && ask > 0 ? (bid + ask) / 2 : (bid > 0 ? bid : ask);
    PxE4 thr;
    if (y.flags & 2) {
      thr = kind == 'C' && mid > 500100 ? mid * 3 / 100 : std::max<PxE4>(mid * 5 / 100, 5000);
    } else {
      thr = std::max<PxE4>(mid * prm_.thr_bps / 10000, prm_.thr_min);
    }
    PxE4 lo = (bid > 0 ? bid : ask) - thr;
    PxE4 hi = (ask > 0 ? ask : bid) + thr;
    lo = lo < 1 ? 1 : round_px(l, lo, 'U');
    hi = round_px(l, hi, 'D');
    if (hi < lo) hi = lo;
    prm.lo = lo;
    prm.hi = hi;
  }
  return brute_cross(v, prm);
}

inline bool RefEngine::price_tests(std::uint16_t l, PxE4 p) {
  if (prm_.pt_mask == 0) return true;
  const Sym& y = sym(l);
  auto within = [&](PxE4 ref) {
    const PxE4 t = std::max<PxE4>(ref * prm_.pt_bps / 10000, prm_.pt_min);
    return (p > ref ? p - ref : ref - p) <= t;
  };
  bool any = false;
  if ((prm_.pt_mask & 1) && y.prior_close > 0) {
    any = true;
    if (within(y.prior_close)) return true;
  }
  if ((prm_.pt_mask & 2) && y.last > 0 && y.last_ns >= hms_ns(9, 15, 0)) {
    any = true;
    if (within(y.last)) return true;
  }
  if (prm_.pt_mask & 4) {
    const PxE4 bid = disp_best(l, 'B'), ask = disp_best(l, 'S');
    if (bid > 0 || ask > 0) any = true;
    if (bid > 0 && within(bid)) return true;
    if (ask > 0 && within(ask)) return true;
  }
  return !any;
}

inline void RefEngine::execute(std::uint16_t l, char kind, const CrossResult& r, bool ipo) {
  std::uint64_t volume = 0;
  const PxE4 p = r.price;
  if (r.valid && r.volume > 0) {
    std::vector<CrossInterest> v;
    std::vector<std::uint64_t> refs;
    interest(l, kind, false, v, refs);
    struct C {
      std::uint64_t ref;
      PxE4 px;
      std::uint32_t qty;
      int rank, disp;
      std::uint64_t prio;
      bool io, market;
    };
    std::vector<C> bc, sc;
    std::uint64_t rb = 0, rs = 0;
    for (std::size_t i = 0; i < v.size(); ++i) {
      const CrossInterest& c = v[i];
      if (!(c.market || (c.buy ? c.px >= p : c.px <= p))) continue;
      const Ord& o = orders_.at(base(refs[i]));
      const bool hidden = o.where == 0 ? (is_res(refs[i]) || o.cls() == 1) : (o.has(fHeld) && o.display == 'N');
      C x{refs[i], c.px, c.qty, 0, 0, part_prio(refs[i]), c.imbalance_only, c.market};
      if (kind == 'H') {
        x.rank = c.market ? 0 : 1;
        x.disp = hidden ? 1 : 0;
      } else {
        x.rank = c.market ? 0 : (hidden ? 2 : 1);
      }
      if (!c.imbalance_only) (c.buy ? rb : rs) += c.qty;
      (c.buy ? bc : sc).push_back(x);
    }
    auto sorter = [&](bool buy) {
      return [buy, kind](const C& a, const C& b) {
        if (a.rank != b.rank) return a.rank < b.rank;
        if (!a.market && a.px != b.px) return buy ? a.px > b.px : a.px < b.px;
        if (kind == 'H' && a.disp != b.disp) return a.disp < b.disp;
        if (a.prio != b.prio) return a.prio < b.prio;
        return base(a.ref) < base(b.ref);
      };
    };
    std::sort(bc.begin(), bc.end(), sorter(true));
    std::sort(sc.begin(), sc.end(), sorter(false));
    struct F {
      std::uint64_t ref;
      std::uint32_t qty;
    };
    auto give = [&](const std::vector<C>& cs, std::uint64_t reg_total) {
      std::vector<F> out;
      std::uint64_t reg = std::min<std::uint64_t>(reg_total, r.volume), io = r.volume - reg;
      for (const C& c : cs) {
        std::uint64_t& pool = c.io ? io : reg;
        const std::uint64_t q = std::min<std::uint64_t>(pool, c.qty);
        pool -= q;
        if (q > 0) out.push_back(F{c.ref, static_cast<std::uint32_t>(q)});
      }
      return out;
    };
    const std::vector<F> buys = give(bc, rb), sells = give(sc, rs);
    auto flag = [&](const Ord& o) -> char {
      if (kind == 'O') return o.has(fIO) ? 'M' : 'O';
      if (kind == 'C') return o.has(fIO) ? 'L' : 'C';
      return ipo ? 'H' : 'K';
    };
    auto c_msg = [&](std::uint64_t part, std::uint32_t q, std::uint64_t mn) {
      if (!shown(part)) return;
      const Ord& o = orders_.at(base(part));
      itch50::OrderExecutedWithPrice c;
      c.order_ref = o.itch_ref;
      c.executed_shares = q;
      c.match_number = mn;
      c.printable = itch50::YesNo::No;
      c.execution_price = p;
      itch(c, l);
    };
    auto settle = [&](const F& f) { consume_part(f.ref, f.qty); };
    std::size_t i = 0, j = 0;
    std::uint32_t bq = buys.empty() ? 0 : buys[0].qty, sq = sells.empty() ? 0 : sells[0].qty;
    while (i < buys.size() && j < sells.size()) {
      const std::uint32_t q = std::min(bq, sq);
      const std::uint64_t mn = next_match_++;
      const Ord& b = orders_.at(base(buys[i].ref));
      const Ord& s = orders_.at(base(sells[j].ref));
      o_exec(b.sess, b.urn, b.idx, q, p, flag(b), mn);
      o_exec(s.sess, s.urn, s.idx, q, p, flag(s), mn);
      c_msg(buys[i].ref, q, mn);
      c_msg(sells[j].ref, q, mn);
      volume += q;
      bq -= q;
      sq -= q;
      if (bq == 0) {
        settle(buys[i]);
        if (++i < buys.size()) bq = buys[i].qty;
      }
      if (sq == 0) {
        settle(sells[j]);
        if (++j < sells.size()) sq = sells[j].qty;
      }
    }
  }
  if (kind == 'H' && volume == 0) return;
  itch50::CrossTrade q;
  q.shares = volume;
  q.stock = sym(l).symbol;
  q.cross_price = volume > 0 ? p : 0;
  q.match_number = next_match_++;
  q.cross_type = static_cast<itch50::CrossType>(kind);
  itch(q, l);
  if (volume > 0) last_sale(l, p);
  if (!rq_.empty()) refresh_all();
}

inline void RefEngine::cancel_pending(std::uint16_t l, char which, char why, bool held) {
  const std::list<std::uint64_t> pend = sym(l).pending;
  for (std::uint64_t ref : pend) {
    const Ord& o = orders_.at(ref);
    if (o.cross == which || (held && o.has(fHeld))) kill(ref, o.has(fCxlPending) ? 'U' : why);
  }
}

inline void RefEngine::post_held(std::uint16_t l) {
  const std::list<std::uint64_t> pend = sym(l).pending;
  for (std::uint64_t ref : pend) {
    Ord& o = orders_.at(ref);
    if (!o.has(fHeld)) continue;
    if (o.has(fCxlPending)) {
      kill(ref, 'U');
      continue;
    }
    if (o.has(fPostOnly) && sym(l).halt == 0) {
      PxE4 px = o.px;
      const char po = post_only(l, o.side, &px, sess_[o.sess]);
      if (po == 'F' || po == 'G') {
        kill(ref, po);
        continue;
      }
      o.px = px;
    }
    sym(l).pending.remove(ref);
    o.flags = static_cast<std::uint16_t>(o.flags & ~fHeld);
    to_book_by_prio(ref);
    i_add(orders_.at(ref));
  }
}

inline void RefEngine::open_cross(std::uint16_t l) {
  if (sym(l).halt != 0) {
    cancel_pending(l, 'O', 'H', false);
    post_held(l);
    sym(l).opened = true;
    return;
  }
  const CrossResult r = cross_at(l, 'O', false, false);
  if (r.valid && r.volume > 0 && !price_tests(l, r.price)) {
    cancel_pending(l, 'O', 'X', true);
    execute(l, 'O', CrossResult{}, false);
    sym(l).opened = true;
    return;
  }
  execute(l, 'O', r, false);
  cancel_pending(l, 'O', 'I', false);
  post_held(l);
  uncross(l);
  sym(l).opened = true;
}

inline void RefEngine::close_cross(std::uint16_t l) {
  if (sym(l).halt != 0) {
    cancel_pending(l, 'C', 'H', false);
    sym(l).closed = true;
    return;
  }
  const CrossResult r = cross_at(l, 'C', false, false);
  execute(l, 'C', r, false);
  cancel_pending(l, 'C', 'I', false);
  uncross(l);
  sym(l).closed = true;
}

inline void RefEngine::noii(std::uint16_t l, char kind, bool eoii) {
  std::uint64_t paired = 0, imb = 0;
  char dir = 'O';
  PxE4 far = 0, near = 0, crp = 0;
  if (kind == 'H') {
    std::vector<CrossInterest> v;
    std::vector<std::uint64_t> refs;
    interest(l, 'H', false, v, refs);
    const CrossResult r = cross_at(l, 'H', false, false);
    if (r.valid && !v.empty()) {
      paired = r.volume;
      imb = r.imbalance;
      dir = r.side;
      if (!r.market_unexecuted) far = near = crp = r.price;
    }
  } else {
    std::vector<CrossInterest> v;
    std::vector<std::uint64_t> refs;
    interest(l, kind, true, v, refs);
    if (!v.empty()) {
      const CrossResult r = cross_at(l, kind, false, true);
      if (r.valid) {
        paired = r.volume;
        imb = r.imbalance;
        dir = r.side;
        crp = r.price;
        if (!eoii) {
          const CrossResult n = cross_at(l, kind, false, false);
          near = n.valid && n.volume > 0 ? n.price : 0;
          const CrossResult f = cross_at(l, kind, true, false);
          far = f.valid && f.volume > 0 ? f.price : 0;
        }
      }
    }
  }
  char pvi = ' ';
  if (!eoii && near > 0 && crp > 0) {
    const PxE4 d = near > crp ? near - crp : crp - near;
    const PxE4 pct = d * 100 / std::max(near, crp);
    pvi = pct < 1 ? 'L' : (pct < 10 ? static_cast<char>('0' + pct) : (pct < 20 ? 'A' : (pct < 30 ? 'B' : 'C')));
  }
  itch50::Noii m;
  m.paired_shares = paired;
  m.imbalance_shares = imb;
  m.imbalance_direction = static_cast<itch50::ImbalanceDirection>(dir);
  m.stock = sym(l).symbol;
  m.far_price = far;
  m.near_price = near;
  m.current_reference_price = crp;
  m.cross_type = static_cast<itch50::NoiiCrossType>(kind);
  m.price_variation_indicator = static_cast<itch50::PriceVariation>(pvi);
  itch(m, l);
}

// After a period without matching: the front orders of the best bid and offer
// trade until the book is not crossed; the earlier order sets the price.
inline void RefEngine::uncross(std::uint16_t l) {
  for (;;) {
    PxE4 bpx = 0, apx = 0;
    Level* bl = best_level(l, 'B', &bpx);
    Level* al = best_level(l, 'S', &apx);
    if (bl == nullptr || al == nullptr || bpx < apx) break;
    const std::uint64_t bp = bl->q[0].empty() ? bl->q[1].front() : bl->q[0].front();
    const std::uint64_t ap = al->q[0].empty() ? al->q[1].front() : al->q[0].front();
    const std::uint64_t bpr = part_prio(bp), apr = part_prio(ap);
    const bool buy_first = bpr < apr || (bpr == apr && base(bp) < base(ap));
    const std::uint64_t ep = buy_first ? bp : ap, lp = buy_first ? ap : bp;
    Ord& e = orders_.at(base(ep));
    Ord& lt = orders_.at(base(lp));
    const char eflag = is_res(ep) ? 'u' : (e.cls() == 0 ? 'A' : 'J');
    Taker t;
    t.l = l;
    t.side = lt.side;
    t.acct = lt.acct;
    t.firm = lt.firm;
    t.aiq = lt.aiq;
    t.aiq_group = lt.aiq_group;
    if (is_self(t, e)) {
      const char act = aiq_act(lt.aiq);
      if (act == 'W') {
        kill(base(lp), 'Q');
      } else if (act == 'O') {
        kill(base(ep), 'Q');
      } else {
        const std::uint32_t d = std::min(part_leaves(ep), part_leaves(lp));
        aiq_notice(e.sess, e.urn, e.idx, d, e.px, eflag, lt.aiq);
        aiq_notice(lt.sess, lt.urn, lt.idx, d, e.px, 'R', lt.aiq);
        if (shown(ep)) i_reduce(e, d);
        if (shown(lp)) i_reduce(lt, d);
        consume_part(ep, d);
        consume_part(lp, d);
      }
      continue;
    }
    const PxE4 px = e.px;
    const std::uint32_t q = std::min(part_leaves(ep), part_leaves(lp));
    const std::uint64_t mn = next_match_++;
    o_exec(e.sess, e.urn, e.idx, q, px, eflag, mn);
    o_exec(lt.sess, lt.urn, lt.idx, q, px, 'R', mn);
    if (shown(ep)) {
      itch50::OrderExecuted x;
      x.order_ref = e.itch_ref;
      x.executed_shares = q;
      x.match_number = mn;
      itch(x, l);
    } else {
      itch50::Trade x;
      x.order_ref = 0;
      x.side = Side::Buy;
      x.shares = q;
      x.stock = sym(l).symbol;
      x.price = px;
      x.match_number = mn;
      itch(x, l);
    }
    if (shown(lp)) {
      itch50::OrderExecutedWithPrice c;
      c.order_ref = lt.itch_ref;
      c.executed_shares = q;
      c.match_number = mn;
      c.printable = itch50::YesNo::No;
      c.execution_price = px;
      itch(c, l);
    }
    consume_part(ep, q);
    consume_part(lp, q);
    last_sale(l, px);
  }
  if (!rq_.empty()) refresh_all();
}

// ============================================================================ OUCH

inline void RefEngine::ouch_in(std::span<const std::byte> p, bool malformed) {
  if (p.size() < 16) return;
  const std::uint32_t sid = load_le32(p.data());
  const std::uint32_t acct_id = load_le32(p.data() + 4);
  const std::size_t len = load_le16(p.data() + 10);
  if (p.size() - 16 < len) return;
  const int s = find_sess(sid);
  if (s < 0) return;
  const auto su = static_cast<std::uint32_t>(s);
  if (accts_[sess_[su].acct].id != acct_id) return;
  started_ = true;
  const std::span<const std::byte> msg = p.subspan(16, len);
  const char t = msg.empty() ? '\0' : static_cast<char>(msg[0]);
  const std::uint32_t a = sess_[su].acct;
  const bool valid = !malformed && ouch50::validate_inbound(msg).has_value();
  const std::uint8_t idx = ouch50::peek_user_ref_idx(msg);
  if (t == 'O' || t == 'U' || t == 'C' || t == 'D' || t == 'E') {
    const auto urn = ouch50::peek_new_user_ref_num(msg);
    if (!urn) return;
    const std::uint32_t last = accts_[a].last.count(idx) ? accts_[a].last[idx] : 0;
    if (*urn <= last) return;
    if (t == 'U') return replace(su, a, msg, valid, *urn, idx);
    accts_[a].last[idx] = *urn;
    if (!valid) {
      const std::uint16_t why =
          malformed ? std::uint16_t{0x000F} : static_cast<std::uint16_t>(ouch50::validate_inbound(msg).error());
      o_reject(su, *urn, idx, why, t == 'O' && msg.size() >= 45 ? Alpha<14>::from_wire(msg.data() + 31) : Alpha<14>{});
      return;
    }
    if (t == 'O') enter(su, a, ouch50::in::EnterOrderView(msg), *urn, idx);
    if (t == 'C') mass_cancel(su, a, ouch50::in::MassCancelView(msg), *urn, idx);
    if (t == 'D' || t == 'E') entry_switch(su, a, msg, *urn, idx, t == 'D');
  } else if (t == 'X' || t == 'M' || t == 'Q') {
    if (!valid) return;
    if (t == 'X') cancel(a, ouch50::in::CancelOrderView(msg), idx);
    if (t == 'M') modify(a, ouch50::in::ModifyOrderView(msg), idx);
    if (t == 'Q') {
      ouch50::out::AccountQueryResponse m;
      const std::uint32_t last = accts_[a].last.count(idx) ? accts_[a].last[idx] : 0;
      m.next_user_ref_num = last + 1;
      ouch(su, m, idx_tag(idx));
    }
  }
}

inline std::uint16_t RefEngine::checks(Req& q, const ouch50::TagSet& t, const Sess& s, std::uint16_t l, bool replace,
                                       Route& route) {
  using ouch50::Tag;
  route = Route::Match;
  if (q.iso == 'Y') return 0x0008;
  const bool cross = q.cross == 'O' || q.cross == 'C' || q.cross == 'H';
  if (q.cross != 'N' && !cross) return 0x0014;
  if (t.has(Tag::HandleInst) && static_cast<char>(t.handle_inst) != ' ') {
    const char h = static_cast<char>(t.handle_inst);
    if (h == 'I') {
      if (q.cross != 'O' && q.cross != 'C') return 0x0014;
      q.io = true;
    } else {
      return (h == 'O' || h == 'T' || h == 'Q') ? 0x001A : 0x0014;
    }
  }
  if (t.has(Tag::CustomerType) && static_cast<char>(t.customer_type) == 'R') return 0x001A;
  if (q.peg != 'L') {
    if (q.peg == 'M' && q.post_only) return 0x001B;
    if (q.peg == 'm') return 0x0011;
    if (q.peg != 'M') return 0x0005;
    if (cross) return 0x0011;
  }
  if (t.has(Tag::PegOffset) && t.peg_offset != 0) return 0x0005;
  if (t.has(Tag::DiscretionPrice) || t.has(Tag::DiscretionPriceType) || t.has(Tag::DiscretionPegOffset) ||
      t.has(Tag::RandomReserves))
    return 0x000F;
  if (t.has(Tag::TradeNow) && static_cast<char>(t.trade_now) == 'Y') return 0x000F;
  const Sym& y = sym(l);
  if (q.maxf != 0 && (q.maxf < y.lot || q.maxf >= q.qty || q.display == 'N' || q.tif == '3' || q.market ||
                      q.minq != 0 || q.peg != 'L' || cross))
    return 0x0004;
  if (q.minq != 0) {
    if (q.minq < y.lot || q.minq > q.qty || cross || q.post_only || q.peg != 'L') return 0x000D;
    q.tif = '3';  // MinQty orders never rest
  }
  if (!aiq_ok(q.aiq)) return 0x0040;
  if (q.tif == '6' && !q.has_expire) return 0x000F;
  if (q.marking == 'T') {  // Rule 201
    if (y.regsho != '0' && y.regsho != '1' && y.regsho != '2') return 0x0032;
    if (y.regsho != '0') {
      const PxE4 nbb = disp_best(l, 'B');
      if (q.market || (nbb > 0 && q.px <= nbb)) return 0x0023;
    }
  }
  if (cross) {
    if (session_ == 'C') return 0x0002;
    if (q.post_only) return 0x0014;
    if (q.market && q.io) return 0x0014;
    if (!q.market && q.px % tick_at(l, q.px) != 0) return 0x001D;
    const bool buy = q.side == 'B';
    bool late = false;
    if (q.cross == 'O') {
      if (session_ != 'P' || y.opened) return 0x0014;
      if (q.market) {
        if (miles_ & mMooCut) return 0x0014;
      } else if (!q.io) {
        if (miles_ & mLooCut) return 0x0014;
        late = (miles_ & mMooCut) != 0;
      }
    } else if (q.cross == 'C') {
      if ((session_ != 'P' && session_ != 'R') || y.closed) return 0x0014;
      if (q.market) {
        if (miles_ & mMocCut) return 0x0014;
      } else if (!q.io) {
        if (miles_ & mLocCut) return 0x0014;
        late = (miles_ & mMocCut) != 0;
        if (late && y.cref1 == 0 && y.cref2 == 0) return 0x000E;
      }
    } else if (y.halt == 0) {
      return 0x0014;
    }
    if (late) {
      const PxE4 r1 = q.cross == 'O' ? y.prior_close : y.cref1;
      const PxE4 r2 = q.cross == 'O' ? y.oref2 : y.cref2;
      PxE4 ref = 0;
      if (r1 > 0 && r2 > 0) {
        ref = buy ? std::max(r1, r2) : std::min(r1, r2);
      } else {
        ref = r1 > 0 ? r1 : (r2 > 0 ? r2 : 0);
      }
      if (ref > 0) {
        if (s.late == 1) q.px = buy ? std::min(q.px, ref) : std::max(q.px, ref);
        if (s.late == 2 && (buy ? q.px > ref : q.px < ref)) return 0x0019;
      }
    }
    route = Route::Cross;
    return 0;
  }
  if (q.peg == 'M') {
    if (q.market || session_ != 'R') return 0x0011;
    if (q.px % tick_at(l, q.px) != 0) return 0x001D;
    if (y.halt != 0) return 0x0007;
    q.display = 'N';
    route = Route::Peg;
    return 0;
  }
  if (q.market) {
    if (replace || q.tif != '3') return 0x001D;
    if (!(s.flags & 4)) return 0x002C;
  }
  if (q.post_only && q.tif == '3') return 0x000F;
  if (!q.market && q.px % tick_at(l, q.px) != 0) return 0x001D;
  if (session_ == 'C') return 0x0002;
  const bool imm = q.tif == '3' || q.market;
  if (y.halt != 0) {
    if (imm) return 0x0007;
    route = Route::RestOnly;
    return 0;
  }
  if (session_ == 'P' && q.tif == '0') {
    if (q.maxf != 0) return 0x0004;
    route = Route::Held;
  } else if (session_ == 'A' && q.tif == '0') {
    return 0x0002;
  }
  return 0;
}

inline char RefEngine::post_only(std::uint16_t l, char side, PxE4* px, const Sess& s) {
  PxE4 best = 0;
  const Level* lv = best_level(l, side == 'B' ? 'S' : 'B', &best);
  if (lv == nullptr || !crosses(side, best, *px)) return 0;
  const char why = level_qty(*lv, 0) > 0 ? 'G' : 'F';
  const PxE4 tk = sym(l).tick;
  const PxE4 np = side == 'B' ? (best > 10000 ? best - tk : best - 1) : (best >= 10000 ? best + tk : best + 1);
  if ((s.flags & 8) || np < 1 || np > 1'999'999'900) return why;
  *px = np;
  return 'S';
}

inline void RefEngine::aiq_notice(std::uint32_t s, std::uint32_t urn, std::uint8_t idx, std::uint32_t d, PxE4 px,
                                  char flag, char aiq) {
  if (!aiq_details(aiq)) {
    o_canceled(s, urn, idx, d, 'Q');
    return;
  }
  ouch50::out::AiqCanceled m;
  m.user_ref_num = urn;
  m.decrement_shares = d;
  m.reason = ouch50::CancelReason::SelfMatchPrevention;
  m.quantity_prevented_from_trading = d;
  m.execution_price = static_cast<std::uint64_t>(px);
  m.liquidity_flag = static_cast<ouch50::LiquidityFlag>(flag);
  m.aiq_strategy = static_cast<ouch50::AiqStrategy>(aiq);
  ouch(s, m, idx_tag(idx));
}

inline bool RefEngine::walk(Taker& t) {
  bool act = false;
  const PxE4 m = mid(t.l, &act);
  const char opp = t.side == 'B' ? 'S' : 'B';
  auto in_band = [&](PxE4 p) { return t.bhi == 0 || (p >= t.blo && p <= t.bhi); };
  if (t.peg && !act) return false;
  const bool pegs_ok = act && crosses(t.side, m, t.limit) && in_band(m);
  auto peg_ok = [&](const Ord& o) { return o.side == 'B' ? m <= o.px : m >= o.px; };
  if (t.minq > 0) {
    // MinQty (aggregate): the non-self-matching contra shares within reach.
    std::uint64_t avail = 0;
    std::vector<std::pair<PxE4, const Level*>> lvls;
    for (const auto& [px, lv] : side_map(t.l, opp)) lvls.emplace_back(px, &lv);
    if (opp == 'B') std::reverse(lvls.begin(), lvls.end());  // best first
    for (const auto& [px, lv] : lvls) {
      if (!crosses(t.side, px, t.limit) || !in_band(px)) break;
      for (int c = 0; c < 2; ++c)
        for (std::uint64_t e : lv->q[c])
          if (!is_self(t, orders_.at(base(e)))) avail += part_leaves(e);
    }
    if (pegs_ok)
      for (std::uint64_t r : sym(t.l).pegs[opp == 'B' ? 0 : 1])
        if (peg_ok(orders_.at(r)) && !is_self(t, orders_.at(r))) avail += orders_.at(r).leaves;
    if (avail < t.minq) return false;
  }
  while (t.rem > 0) {
    std::uint64_t part = 0;
    bool have_peg = false;
    if (pegs_ok) {
      for (std::uint64_t r : sym(t.l).pegs[opp == 'B' ? 0 : 1]) {
        if (peg_ok(orders_.at(r))) {
          part = r;
          have_peg = true;
          break;
        }
      }
    }
    PxE4 best = 0;
    Level* lv = best_level(t.l, opp, &best);
    const bool level_ok = lv != nullptr && crosses(t.side, best, t.limit) && in_band(best);
    PxE4 px = 0;
    char rflag = 'A';
    if (have_peg && (!level_ok || (t.side == 'B' ? best > m : best < m))) {
      px = m;
      rflag = 'k';
    } else {
      if (lv == nullptr) return false;
      if (!level_ok) return true;
      const int c = lv->q[0].empty() ? 1 : 0;
      part = lv->q[c].front();
      px = best;
      rflag = is_res(part) ? 'u' : (c == 0 ? 'A' : 'J');
    }
    Ord& r = orders_.at(base(part));
    ++t.touches;
    const char tflag = t.peg ? 'm' : 'R';
    if (is_self(t, r)) {
      const char act2 = aiq_act(t.aiq);
      if (act2 == 'W') {
        taker_msgs_.push_back(sink().size());
        o_canceled(t.sess, t.urn, t.idx, t.rem, 'Q');
        t.rem = 0;
        return false;
      }
      if (act2 == 'O') {
        kill(base(part), 'Q');
        continue;
      }
      const std::uint32_t d = std::min(t.rem, part_leaves(part));
      aiq_notice(r.sess, r.urn, r.idx, d, px, rflag, t.aiq);
      taker_msgs_.push_back(sink().size());
      aiq_notice(t.sess, t.urn, t.idx, d, px, tflag, t.aiq);
      if (shown(part)) i_reduce(r, d);
      t.rem -= d;
      t.done += d;
      consume_part(part, d);
      continue;
    }
    const std::uint32_t f = std::min(t.rem, part_leaves(part));
    const std::uint64_t mn = next_match_++;
    ++t.fills;
    o_exec(r.sess, r.urn, r.idx, f, px, rflag, mn);
    o_exec(t.sess, t.urn, t.idx, f, px, tflag, mn);
    if (shown(part)) {
      itch50::OrderExecuted x;
      x.order_ref = r.itch_ref;
      x.executed_shares = f;
      x.match_number = mn;
      itch(x, r.locate);
    } else {
      itch50::Trade x;
      x.order_ref = 0;
      x.side = Side::Buy;
      x.shares = f;
      x.stock = sym(t.l).symbol;
      x.price = px;
      x.match_number = mn;
      itch(x, t.l);
    }
    t.rem -= f;
    t.done += f;
    consume_part(part, f);
    last_sale(t.l, px);
  }
  return false;
}

// q shares of a part executed or self-match decremented (done counts on the
// order). A reserve order's display that falls below a round lot is queued
// for a refresh; an empty display leaves its queue until then.
inline void RefEngine::consume_part(std::uint64_t part, std::uint32_t q) {
  const std::uint64_t ref = base(part);
  Ord& o = orders_.at(ref);
  o.done += q;
  if (is_res(part)) {
    o.reserve -= q;
    if (o.reserve == 0) unqueue(o.locate, o.side, o.px, 1, ref | kRes);
    return;
  }
  o.leaves -= q;
  if (o.reserve == 0) {
    if (o.leaves == 0) erase_order(ref);
    return;
  }
  if (o.leaves == 0) {
    unqueue(o.locate, o.side, o.px, 0, ref);
    o.off = true;
  }
  if (o.leaves < sym(o.locate).lot && !o.queued) {
    o.queued = true;
    rq_.push_back(ref);
  }
}

inline void RefEngine::refresh_all() {
  const std::vector<std::uint64_t> q = rq_;
  rq_.clear();
  for (std::uint64_t ref : q) {
    if (!orders_.count(ref)) continue;
    Ord& o = orders_.at(ref);
    o.queued = false;
    const std::uint32_t lot = sym(o.locate).lot;
    if (o.reserve == 0) {
      if (o.leaves == 0) erase_order(ref);
      continue;
    }
    if (o.leaves >= lot) continue;
    const std::uint32_t disp = o.maxf / lot * lot;
    const std::uint32_t add = std::min(disp - o.leaves, o.reserve);
    if (!o.off) {
      i_delete(o.locate, o.itch_ref);
      unqueue(o.locate, o.side, o.px, 0, ref);
    }
    o.reserve -= add;
    if (o.reserve == 0) unqueue(o.locate, o.side, o.px, 1, ref | kRes);
    o.leaves += add;
    o.itch_ref = next_ref_++;
    o.prio = index_;
    o.off = false;
    side_map(o.locate, o.side)[o.px].q[0].push_back(ref);
    i_add(o);
    ouch50::out::OrderRestated m;
    m.user_ref_num = o.urn;
    m.reason = ouch50::RestatedReason::DisplayRefresh;
    ouch50::TagSet tg;
    tg.set_secondary_ord_ref_num(o.itch_ref);
    tg.set_display_quantity(o.leaves);
    if (o.idx != 0) tg.set_user_ref_idx(o.idx);
    ouch(o.sess, m, tg);
  }
}

// A resting order on the book (reserve orders: display plus reserve part).
inline void RefEngine::rest(const Req& q, std::uint16_t l, std::uint32_t a, std::uint32_t s, std::uint64_t ref,
                            PxE4 px, std::uint32_t leaves, std::uint32_t done) {
  Ord o = make(q, l, a, s, ref, px, leaves, done);
  if (q.maxf != 0) {
    const std::uint32_t disp = q.maxf / sym(l).lot * sym(l).lot;
    if (o.leaves > disp) {
      o.reserve = o.leaves - disp;
      o.leaves = disp;
      o.rprio = o.prio;
    }
  }
  orders_[ref] = o;
  urns_[std::make_tuple(a, q.idx, q.urn)] = ref;
  side_map(l, o.side)[o.px].q[o.cls()].push_back(ref);
  if (o.reserve > 0) side_map(l, o.side)[o.px].q[1].push_back(ref | kRes);
  i_add(orders_.at(ref));
}

// A user decrease (not all shares): the reserve first, then the display ('X').
inline void RefEngine::reduce_user(std::uint64_t ref, std::uint32_t d) {
  Ord& o = orders_.at(ref);
  const std::uint32_t k = std::min(d, o.reserve);
  if (k > 0) {
    o.reserve -= k;
    if (o.reserve == 0) unqueue(o.locate, o.side, o.px, 1, ref | kRes);
    d -= k;
  }
  if (d == 0) return;
  if (o.where == 0 && o.display != 'N') i_reduce(o, d);
  o.leaves -= d;
}

inline RefEngine::Ord RefEngine::make(const Req& q, std::uint16_t l, std::uint32_t a, std::uint32_t s,
                                      std::uint64_t ref, PxE4 px, std::uint32_t leaves, std::uint32_t done) const {
  Ord o;
  o.ref = ref;
  o.itch_ref = ref;
  o.prio = index_;
  o.locate = l;
  o.side = q.side;
  o.marking = q.marking;
  o.display = q.display;
  o.tif = q.tif;
  o.capacity = q.capacity;
  o.iso = q.iso;
  o.cross = q.cross;
  o.aiq = q.aiq;
  o.px = q.market ? 0 : px;
  o.leaves = leaves;
  o.done = done;
  o.minq = q.minq;
  o.maxf = q.maxf;
  o.urn = q.urn;
  o.acct = a;
  o.sess = s;
  o.expire = q.expire;
  o.firm = q.firm;
  o.group = q.group;
  o.aiq_group = q.aiq_group;
  o.idx = q.idx;
  o.rpx = q.rpx;
  std::uint16_t f = 0;
  if (q.post_only) f |= fPostOnly;
  if (q.has_expire) f |= fHasExpire;
  if (q.io) f |= fIO;
  if (q.market) f |= fMarket;
  if (q.peg == 'M') f |= fMidPeg;
  if (q.located) f |= fLocated;
  o.flags = f;
  return o;
}

// After the 'A'/'U': off-book, rest-only, or the matching outputs and remainder.
inline void RefEngine::place(const Req& q, Route route, Taker& tk, std::uint64_t ref, PxE4 px, char po,
                             std::vector<ROut>& buf, bool collar_stop, bool dead) {
  const std::uint16_t l = tk.l;
  if (route == Route::Cross || route == Route::Held) {
    if (tk.rem == 0) return;
    Ord o = make(q, l, tk.acct, tk.sess, ref, px, tk.rem, tk.done);
    o.where = 1;
    if (route == Route::Held) o.flags = static_cast<std::uint16_t>(o.flags | fHeld);
    orders_[ref] = o;
    urns_[std::make_tuple(tk.acct, q.idx, q.urn)] = ref;
    sym(l).pending.push_back(ref);
    return;
  }
  if (route == Route::RestOnly) {
    if (tk.rem == 0) return;
    rest(q, l, tk.acct, tk.sess, ref, px, tk.rem, tk.done);
    return;
  }
  // An 'A'/'U' with Order State Dead is the order's last message (OUCH 5.0
  // §3.2-3.3): its own self-match and remainder notices are dropped; resting
  // orders' messages and the ITCH side stay.
  if (po == 'F' || po == 'G') return;
  for (std::size_t i = 0, k = 0; i < buf.size(); ++i) {
    if (dead && k < taker_msgs_.size() && taker_msgs_[k] == i) {
      ++k;
      --sess_[tk.sess].outs;  // counted when it was buffered, never sent
      continue;
    }
    out_->push_back(std::move(buf[i]));
  }
  if (tk.rem > 0) {
    if (q.tif == '3' || q.market) {
      if (!dead) o_canceled(tk.sess, tk.urn, tk.idx, tk.rem, q.market && collar_stop ? 'K' : 'I');
    } else if (q.peg == 'M') {
      Ord o = make(q, l, tk.acct, tk.sess, ref, q.px, tk.rem, tk.done);
      o.where = 2;
      orders_[ref] = o;
      urns_[std::make_tuple(tk.acct, q.idx, q.urn)] = ref;
      sym(l).pegs[q.side == 'B' ? 0 : 1].push_back(ref);
    } else {
      rest(q, l, tk.acct, tk.sess, ref, px, tk.rem, tk.done);
    }
  }
  if (!rq_.empty()) refresh_all();
}

inline void RefEngine::enter(std::uint32_t s, std::uint32_t a, const ouch50::in::EnterOrderView& v, std::uint32_t urn,
                             std::uint8_t idx) {
  using ouch50::Tag;
  ouch50::TagSet t;
  (void)ouch50::parse_tags(v.tags(), t);
  Req q;
  q.marking = static_cast<char>(v.side());
  q.side = q.marking == 'B' ? 'B' : 'S';
  q.qty = v.quantity();
  q.market = v.price() == 0x7FFFFFFFull || v.price() == 2'000'000'000ull;
  q.px = q.market ? 0 : static_cast<PxE4>(v.price());
  q.tif = static_cast<char>(v.time_in_force());
  q.display = static_cast<char>(v.display());
  q.capacity = static_cast<char>(v.capacity());
  q.iso = static_cast<char>(v.inter_market_sweep_eligibility());
  q.cross = static_cast<char>(v.cross_type());
  q.post_only = t.has(Tag::PostOnly) && static_cast<char>(t.post_only) == 'P';
  q.firm = t.has(Tag::Firm) ? t.firm : (accts_[a].firms.empty() ? Mpid4{} : accts_[a].firms[0]);
  q.group = t.has(Tag::GroupID) ? t.group_id : 0;
  q.aiq = t.has(Tag::AIQStrategy) ? static_cast<char>(t.aiq_strategy) : '*';
  if (q.aiq == '*') q.aiq = sess_[s].aiq;
  q.aiq_group = t.has(Tag::AIQGroupID) ? t.aiq_group_id : Alpha<2>{};
  q.expire = t.has(Tag::ExpireTime) ? t.expire_time : 0;
  q.has_expire = t.has(Tag::ExpireTime);
  q.peg = t.has(Tag::PriceType) ? static_cast<char>(t.price_type) : 'L';
  q.minq = t.has(Tag::MinQty) ? t.min_qty : 0;
  q.maxf = t.has(Tag::MaxFloor) ? t.max_floor : 0;
  q.located = t.has(Tag::SharesLocated) && static_cast<char>(t.shares_located) == 'Y';
  q.urn = urn;
  q.idx = idx;
  const int li = find_sym(v.symbol());
  Route route = Route::Match;
  std::uint16_t rej = 0;
  auto slot = [&](const Mpid4& f) {
    for (std::size_t i = 0; i < accts_[a].firms.size(); ++i)
      if (accts_[a].firms[i] == f) return static_cast<int>(i);
    return -1;
  };
  const int k = slot(q.firm);
  if (li == 0) {
    rej = 0x0017;
  } else if ((t.has(Tag::Firm) && k < 0) || (k >= 0 && ((accts_[a].disabled >> k) & 1)) || rk_.accts[a].killed) {
    rej = 0x000C;
  } else {
    rej = checks(q, t, sess_[s], static_cast<std::uint16_t>(li), false, route);
  }
  if (rej == 0) rej = risk_check(a, s, static_cast<std::uint16_t>(li), q, v.price(), false, nullptr, &q.rpx);
  if (rej != 0) {
    o_reject(s, urn, idx, rej, v.cl_ord_id());
    return;
  }
  const auto l = static_cast<std::uint16_t>(li);
  const std::uint64_t ref = next_ref_++;
  Taker tk;
  tk.l = l;
  tk.side = q.side;
  tk.rem = q.qty;
  tk.acct = a;
  tk.sess = s;
  tk.urn = urn;
  tk.idx = idx;
  tk.firm = q.firm;
  tk.aiq = q.aiq;
  tk.aiq_group = q.aiq_group;
  tk.peg = q.peg == 'M';
  tk.minq = q.minq;
  if (session_ == 'R' && sym(l).bhi > 0) {
    tk.blo = sym(l).blo;
    tk.bhi = sym(l).bhi;
  }
  PxE4 px = q.px;
  char po = 0;
  std::vector<ROut> buf;
  bool collar_stop = false;
  bool dead = false;
  if (route == Route::Match || route == Route::Peg) {
    if (q.post_only) po = post_only(l, q.side, &px, sess_[s]);
    const bool po_cancel = po == 'F' || po == 'G';
    tk.limit = px;
    if (tk.peg) {
      bool act = false;
      const PxE4 m = mid(l, &act);
      if (act) tk.limit = q.side == 'B' ? std::min(px, m) : std::max(px, m);
    }
    if (q.market) {
      PxE4 best = 0;
      const Level* lv = best_level(l, q.side == 'B' ? 'S' : 'B', &best);
      const PxE4 band = lv ? std::max<PxE4>(2500, best / 20) : 0;
      tk.limit = lv ? (q.side == 'B' ? best + band : best - band) : 0;
    }
    taker_msgs_.clear();
    if (!po_cancel) {
      buffer_ = &buf;
      collar_stop = walk(tk);
      buffer_ = nullptr;
    }
    const bool imm = q.tif == '3' || q.market;
    const bool rests = !po_cancel && tk.rem > 0 && !imm;
    dead = tk.fills == 0 && !rests;
  }
  ouch50::out::OrderAccepted m;
  m.user_ref_num = urn;
  m.side = v.side();
  m.quantity = q.qty;
  m.symbol = v.symbol();
  m.price = q.market ? v.price() : static_cast<std::uint64_t>(px);
  m.time_in_force = static_cast<ouch50::TimeInForce>(q.tif);
  m.display = static_cast<ouch50::Display>(q.display);
  m.order_reference_number = ref;
  m.capacity = v.capacity();
  m.inter_market_sweep_eligibility = v.inter_market_sweep_eligibility();
  m.cross_type = v.cross_type();
  m.order_state = dead ? ouch50::OrderState::Dead : ouch50::OrderState::Live;
  m.cl_ord_id = v.cl_ord_id();
  ouch50::TagSet echo = t;
  echo.present &= ouch50::out::OrderAccepted::kAllowedTags;
  ouch(s, m, echo);
  place(q, route, tk, ref, px, po, buf, collar_stop, dead);
}

inline void RefEngine::replace(std::uint32_t s, std::uint32_t a, std::span<const std::byte> msg, bool valid,
                               std::uint32_t nurn, std::uint8_t idx) {
  using ouch50::Tag;
  const std::uint32_t ourn = load_be32(msg.data() + 1);
  const auto it = urns_.find(std::make_tuple(a, idx, ourn));
  if (it == urns_.end()) return;
  const std::uint64_t oref = it->second;
  const Ord old = orders_.at(oref);
  if (frozen(old)) {
    accts_[a].last[idx] = nurn;
    o_reject(s, nurn, idx, 0x0015, valid ? ouch50::in::ReplaceOrderView(msg).cl_ord_id() : Alpha<14>{});
    return;
  }
  if (!valid) return kill(oref, 'U');
  const ouch50::in::ReplaceOrderView v(msg);
  int k = -1;
  for (std::size_t i = 0; i < accts_[a].firms.size(); ++i)
    if (accts_[a].firms[i] == old.firm) k = static_cast<int>(i);
  if ((k >= 0 && ((accts_[a].disabled >> k) & 1)) || rk_.accts[a].killed) {
    accts_[a].last[idx] = nurn;
    o_reject(s, nurn, idx, 0x000C, v.cl_ord_id());
    return;
  }
  ouch50::TagSet t;
  (void)ouch50::parse_tags(v.tags(), t);
  Req q;
  q.side = old.side;
  q.marking = t.has(Tag::Side) ? static_cast<char>(t.side) : old.marking;
  q.qty = v.quantity();
  q.market = v.price() == 0x7FFFFFFFull || v.price() == 2'000'000'000ull;
  q.px = q.market ? 0 : static_cast<PxE4>(v.price());
  q.tif = static_cast<char>(v.time_in_force());
  q.display = static_cast<char>(v.display());
  q.capacity = old.capacity;
  q.iso = static_cast<char>(v.inter_market_sweep_eligibility());
  q.cross = old.cross;
  q.io = old.has(fIO);
  q.post_only = t.has(Tag::PostOnly) ? static_cast<char>(t.post_only) == 'P' : old.has(fPostOnly);
  q.firm = old.firm;
  q.group = old.group;
  if (t.has(Tag::AIQStrategy)) {
    q.aiq = static_cast<char>(t.aiq_strategy);
    if (q.aiq == '*') q.aiq = sess_[s].aiq;
  } else {
    q.aiq = old.aiq;
  }
  q.aiq_group = t.has(Tag::AIQGroupID) ? t.aiq_group_id : old.aiq_group;
  q.expire = t.has(Tag::ExpireTime) ? t.expire_time : old.expire;
  q.has_expire = t.has(Tag::ExpireTime) || old.has(fHasExpire);
  q.peg = t.has(Tag::PriceType) ? static_cast<char>(t.price_type) : (old.has(fMidPeg) ? 'M' : 'L');
  q.minq = t.has(Tag::MinQty) ? t.min_qty : old.minq;
  q.maxf = t.has(Tag::MaxFloor) ? t.max_floor : old.maxf;
  q.located = t.has(Tag::SharesLocated) ? static_cast<char>(t.shares_located) == 'Y' : old.has(fLocated);
  q.urn = nurn;
  q.idx = idx;
  Route route = Route::Match;
  const bool same_dir = (q.marking == 'B') == (old.side == 'B');
  const std::uint16_t rej = same_dir ? checks(q, t, sess_[s], old.locate, true, route) : std::uint16_t{0x0009};
  if (rej != 0) return kill(oref, 'U');
  accts_[a].last[idx] = nurn;
  if (const std::uint16_t rc = risk_check(a, s, old.locate, q, v.price(), true, &old, &q.rpx); rc != 0)
    return o_reject(s, nurn, idx, rc, v.cl_ord_id());
  const std::uint16_t l = old.locate;
  const std::uint64_t nref = next_ref_++;
  const std::uint32_t leaves = q.qty > old.done ? q.qty - old.done : 0;
  erase_order(oref);
  PxE4 px = q.px;
  char po = 0;
  if (leaves > 0 && route == Route::Match && q.post_only) po = post_only(l, q.side, &px, sess_[s]);
  const bool po_cancel = po == 'F' || po == 'G';
  Taker tk;
  tk.l = l;
  tk.side = q.side;
  tk.limit = px;
  tk.rem = leaves;
  tk.done = old.done;
  tk.acct = a;
  tk.sess = s;
  tk.urn = nurn;
  tk.idx = idx;
  tk.firm = q.firm;
  tk.aiq = q.aiq;
  tk.aiq_group = q.aiq_group;
  tk.peg = q.peg == 'M';
  tk.minq = q.minq;
  if (tk.peg) {
    bool act = false;
    const PxE4 m = mid(l, &act);
    if (act) tk.limit = q.side == 'B' ? std::min(px, m) : std::max(px, m);
  }
  if (session_ == 'R' && sym(l).bhi > 0) {
    tk.blo = sym(l).blo;
    tk.bhi = sym(l).bhi;
  }
  std::vector<ROut> buf;
  taker_msgs_.clear();
  if ((route == Route::Match || route == Route::Peg) && !po_cancel && leaves > 0) {
    buffer_ = &buf;
    (void)walk(tk);
    buffer_ = nullptr;
  }
  const bool imm = q.tif == '3';
  bool rests, dead;
  if (route == Route::Match || route == Route::Peg) {
    rests = !po_cancel && tk.rem > 0 && !imm;
    dead = tk.fills == 0 && !rests;
  } else {
    rests = leaves > 0;
    dead = leaves == 0;
  }
  ouch50::out::OrderReplaced m;
  m.orig_user_ref_num = old.urn;
  m.user_ref_num = nurn;
  m.side = static_cast<ouch50::Side>(q.marking);
  m.quantity = leaves;
  m.symbol = sym(l).symbol;
  m.price = q.market ? v.price() : static_cast<std::uint64_t>(px);
  m.time_in_force = static_cast<ouch50::TimeInForce>(q.tif);
  m.display = static_cast<ouch50::Display>(q.display);
  m.order_reference_number = nref;
  m.capacity = static_cast<ouch50::Capacity>(old.capacity);
  m.inter_market_sweep_eligibility = v.inter_market_sweep_eligibility();
  m.cross_type = static_cast<ouch50::CrossType>(old.cross);
  m.order_state = dead ? ouch50::OrderState::Dead : ouch50::OrderState::Live;
  m.cl_ord_id = v.cl_ord_id();
  ouch50::TagSet echo = t;
  echo.present &= ouch50::out::OrderReplaced::kAllowedTags;
  ouch(s, m, echo);
  const bool book_route = route == Route::Match || route == Route::RestOnly;
  const bool untouched = book_route && tk.touches == 0 && rests && tk.rem == leaves;
  if (untouched && old.where == 0 && old.display != 'N' && q.display == old.display && q.maxf == 0 && old.maxf == 0 &&
      old.reserve == 0) {
    itch50::OrderReplace u;
    u.original_order_ref = old.itch_ref;
    u.new_order_ref = nref;
    u.shares = leaves;
    u.price = px;
    itch(u, l);
    orders_[nref] = make(q, l, a, s, nref, px, leaves, old.done);
    urns_[std::make_tuple(a, idx, nurn)] = nref;
    to_book(nref);
    return;
  }
  if (old.where == 0 && old.display != 'N') i_delete(l, old.itch_ref);
  if (po_cancel || leaves == 0) return;  // 'U' with Order State Dead: nothing follows
  place(q, route, tk, nref, px, 0, buf, false, dead);
}

inline bool RefEngine::frozen_request(std::uint64_t ref, bool full) {
  Ord& o = orders_.at(ref);
  if (!frozen(o)) return false;
  if (full) {
    o.flags = static_cast<std::uint16_t>(o.flags | fCxlPending);
    if (!o.has(fPendSent)) {
      o.flags = static_cast<std::uint16_t>(o.flags | fPendSent);
      ouch50::out::CancelPending m;
      m.user_ref_num = o.urn;
      ouch(o.sess, m, idx_tag(o.idx));
    }
  } else if (!o.has(fRejSent)) {
    o.flags = static_cast<std::uint16_t>(o.flags | fRejSent);
    ouch50::out::CancelReject m;
    m.user_ref_num = o.urn;
    ouch(o.sess, m, idx_tag(o.idx));
  }
  return true;
}

inline void RefEngine::cancel(std::uint32_t a, const ouch50::in::CancelOrderView& v, std::uint8_t idx) {
  const auto it = urns_.find(std::make_tuple(a, idx, v.user_ref_num()));
  if (it == urns_.end()) return;
  const std::uint64_t ref = it->second;
  const Ord o = orders_.at(ref);
  const std::uint32_t open = o.leaves + o.reserve;
  const std::uint32_t nl = v.quantity() > o.done ? v.quantity() - o.done : 0;
  if (nl >= open) return;
  if (frozen_request(ref, nl == 0)) return;
  const std::uint32_t d = open - nl;
  o_canceled(o.sess, o.urn, o.idx, d, 'U');
  if (nl == 0) {
    if (o.where == 0 && o.display != 'N') i_delete(o.locate, o.itch_ref);
    erase_order(ref);
  } else {
    reduce_user(ref, d);
  }
}

inline void RefEngine::modify(std::uint32_t a, const ouch50::in::ModifyOrderView& v, std::uint8_t idx) {
  const auto it = urns_.find(std::make_tuple(a, idx, v.user_ref_num()));
  if (it == urns_.end()) return;
  const std::uint64_t ref = it->second;
  Ord& o = orders_.at(ref);
  const char nm = static_cast<char>(v.side());
  const bool remark = nm != o.marking;
  if (remark && (nm == 'B' || o.marking == 'B')) return;
  const std::uint32_t open = o.leaves + o.reserve;
  const std::uint32_t nl = v.quantity() > o.done ? v.quantity() - o.done : 0;
  const bool dec = nl < open;
  if (!remark && !dec) return;
  if (frozen_request(ref, false)) return;
  o.marking = nm;
  ouch50::TagSet t;
  (void)ouch50::parse_tags(v.tags(), t);
  ouch50::TagSet e;
  if (t.has(ouch50::Tag::SharesLocated)) e.set_shares_located(t.shares_located);
  if (t.has(ouch50::Tag::LocateBroker)) e.set_locate_broker(t.locate_broker);
  if (o.idx != 0) e.set_user_ref_idx(o.idx);
  ouch50::out::OrderModified m;
  m.user_ref_num = o.urn;
  m.side = static_cast<ouch50::Side>(nm);
  m.quantity = dec ? nl : open;
  ouch(o.sess, m, e);
  if (!dec) return;
  if (nl == 0) {
    if (o.where == 0 && o.display != 'N') i_delete(o.locate, o.itch_ref);
    erase_order(ref);
  } else {
    reduce_user(ref, open - nl);
  }
}

inline void RefEngine::mass_cancel(std::uint32_t s, std::uint32_t a, const ouch50::in::MassCancelView& v,
                                   std::uint32_t urn, std::uint8_t idx) {
  using ouch50::Tag;
  const Mpid4 def = accts_[a].firms.empty() ? Mpid4{} : accts_[a].firms[0];
  const Mpid4 firm = v.firm().blank() ? def : v.firm();
  if (std::find(accts_[a].firms.begin(), accts_[a].firms.end(), firm) == accts_[a].firms.end()) {
    o_reject(s, urn, idx, 0x000C, Alpha<14>{});
    return;
  }
  int l = 0;
  if (!v.symbol().blank()) {
    l = find_sym(v.symbol());
    if (l == 0) {
      o_reject(s, urn, idx, 0x0017, Alpha<14>{});
      return;
    }
  }
  ouch50::TagSet t;
  (void)ouch50::parse_tags(v.tags(), t);
  ouch50::out::MassCancelResponse m;
  m.user_ref_num = urn;
  m.firm = v.firm();
  m.symbol = v.symbol();
  ouch50::TagSet echo;
  if (t.has(Tag::GroupID)) echo.set_group_id(t.group_id);
  if (t.has(Tag::Side)) echo.set_side(t.side);
  if (t.has(Tag::UserRefIdx)) echo.set_user_ref_idx(t.user_ref_idx);
  ouch(s, m, echo);
  for (const std::uint64_t ref : refs_of_acct(a)) {
    const Ord& o = orders_.at(ref);
    if (!(o.firm == firm)) continue;
    if (l != 0 && o.locate != l) continue;
    if (t.has(Tag::Side) && o.side != (static_cast<char>(t.side) == 'B' ? 'B' : 'S')) continue;
    if (t.has(Tag::GroupID) && o.group != t.group_id) continue;
    if (t.has(Tag::UserRefIdx) && t.user_ref_idx != 0 && o.idx != t.user_ref_idx) continue;
    if (frozen(o)) continue;
    kill(ref, 'U');
  }
}

inline void RefEngine::entry_switch(std::uint32_t s, std::uint32_t a, std::span<const std::byte> msg,
                                    std::uint32_t urn, std::uint8_t idx, bool disable) {
  const Mpid4 given = Mpid4::from_wire(msg.data() + 5);
  const Mpid4 def = accts_[a].firms.empty() ? Mpid4{} : accts_[a].firms[0];
  const Mpid4 firm = given.blank() ? def : given;
  int k = -1;
  for (std::size_t i = 0; i < accts_[a].firms.size(); ++i)
    if (accts_[a].firms[i] == firm) k = static_cast<int>(i);
  if (k < 0) {
    o_reject(s, urn, idx, 0x000C, Alpha<14>{});
    return;
  }
  ouch50::TagSet t;
  (void)ouch50::parse_tags(ouch50::in::DisableOrderEntryView(msg).tags(), t);
  ouch50::TagSet echo;
  if (t.has(ouch50::Tag::UserRefIdx)) echo.set_user_ref_idx(t.user_ref_idx);
  if (disable) {
    accts_[a].disabled = static_cast<std::uint8_t>(accts_[a].disabled | (1u << k));
    ouch50::out::DisableOrderEntryResponse m;
    m.user_ref_num = urn;
    m.firm = given;
    ouch(s, m, echo);
  } else {
    accts_[a].disabled = static_cast<std::uint8_t>(accts_[a].disabled & ~(1u << k));
    ouch50::out::EnableOrderEntryResponse m;
    m.user_ref_num = urn;
    m.firm = given;
    ouch(s, m, echo);
  }
}

}  // namespace lle::engine::ref
