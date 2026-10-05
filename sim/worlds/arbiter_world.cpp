// arbiter world (09 §2 `arbiter`, S-09; 03-protocols §7): the production feed
// path over the simulated network. Two publisher nodes play the primary's and
// the backup's `md` stage: each publishes the same ITCH stream on its own
// MoldUDP64 line (multicast, different packet boundaries), keeps a MessageRing
// behind a RerequestServer, and serves GLIMPSE snapshots over a stream. Client
// nodes run LineArbiter over both lines, re-request gaps from either server,
// fetch a snapshot when the arbiter asks for one (or at a late join after a
// restart), and build an ITCH book from what is delivered.
//
// Oracles (the canonical stream lives in the harness):
//   O-ARB   every client delivers each sequence exactly once, in order, with the
//           published bytes (a snapshot splice restarts the stream at its G);
//           end of session exactly once, after the last message
//   O-LINE  every line packet and re-request reply carries, per sequence
//           number, exactly the canonical message bytes
//   O-BOOK  a client's book (snapshot + delivered messages) equals, by
//           books_digest, the book built from the canonical stream
//   O-LIVE  after healing every client reaches end of session
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "book/itch_adapter.h"
#include "book/variants.h"
#include "common/alpha.h"
#include "common/assert.h"
#include "common/endian.h"
#include "env/buggify.h"
#include "proto/glimpse/glimpse.h"
#include "proto/glimpse/snapshot_server.h"
#include "proto/itch50/itch50.h"
#include "proto/moldudp64/line_arbiter.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/moldudp64/packetizer.h"
#include "proto/moldudp64/rerequest_server.h"
#include "sim/dist.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

namespace {

namespace itch = lle::itch50;
using lle::mold::LineArbiter;
using lle::mold::LineArbiterConfig;
using lle::mold::Source;

constexpr std::uint16_t kServicePort = 7600;   // publisher: line sends + re-request service
constexpr std::uint16_t kSnapshotPort = 7601;  // publisher: GLIMPSE spins
constexpr std::uint16_t kClientPort = 7700;
constexpr env::Endpoint kGroup[2] = {{0xEF02'0001u, 7800}, {0xEF02'0002u, 7800}};  // lines A, B
const mold::Session kSession("SIMFEED001");

using Book = book::OptBook<>;
book::BookConfig book_config() {
  book::BookConfig c;
  c.reserve_orders = 4096;
  c.reserve_levels = 512;
  return c;
}

// ---- feed state: the book-relevant state after messages 1..k ----------------
// Used to generate a valid stream, and by publishers as the snapshot view.
struct FeedState {
  struct Order {
    Locate loc;
    Side side;
    PxE4 px;
    Qty shares;
    std::uint64_t prio;  // time priority: adds and replaces go to the back
  };
  std::vector<std::pair<Locate, Symbol8>> directory;
  std::map<OrderRef, Order> orders;
  std::uint64_t next_prio = 1;
  SeqNo applied = 0;

  void apply(std::span<const std::byte> m) {
    ++applied;
    const char t = static_cast<char>(m[0]);
    switch (t) {
      case 'R': {
        const itch::StockDirectoryView v(m.data());
        directory.emplace_back(v.stock_locate(), v.stock());
        break;
      }
      case 'A': {
        const itch::AddOrderView v(m.data());
        orders[v.order_ref()] = Order{v.stock_locate(), v.side(), v.price(), v.shares(), next_prio++};
        break;
      }
      case 'E': {
        const itch::OrderExecutedView v(m.data());
        reduce(v.order_ref(), v.executed_shares());
        break;
      }
      case 'X': {
        const itch::OrderCancelView v(m.data());
        reduce(v.order_ref(), v.cancelled_shares());
        break;
      }
      case 'D':
        orders.erase(itch::OrderDeleteView(m.data()).order_ref());
        break;
      case 'U': {
        const itch::OrderReplaceView v(m.data());
        const auto it = orders.find(v.original_order_ref());
        LLE_ASSERT(it != orders.end(), "replace of an unknown order");
        const Order o{it->second.loc, it->second.side, v.price(), v.shares(), next_prio++};
        orders.erase(it);
        orders[v.new_order_ref()] = o;
        break;
      }
      default:
        break;
    }
  }
  void reduce(OrderRef ref, Qty q) {
    const auto it = orders.find(ref);
    LLE_ASSERT(it != orders.end() && it->second.shares >= q, "reduce beyond the order");
    it->second.shares -= q;
    if (it->second.shares == 0) orders.erase(it);
  }

  // glimpse::SnapshotStateLike
  [[nodiscard]] SeqNo snapshot_next_seq() const { return applied + 1; }
  template <class F>
  void visit_system_events(F&& f) const {
    f(itch::SystemEvent{.stock_locate = 0, .tracking_number = 0, .timestamp = 1,
                        .event_code = itch::EventCode::StartOfMessages});
  }
  template <class F>
  void visit_stock_directory(F&& f) const {
    for (const auto& [loc, sym] : directory) f(directory_msg(loc, sym));
  }
  template <class F>
  void visit_trading_actions(F&&) const {}
  template <class F>
  void visit_reg_sho(F&&) const {}
  template <class F>
  void visit_operational_halts(F&&) const {}
  template <class F>
  void visit_orders(F&& f) const {
    // Re-adding in time priority rebuilds every level's FIFO exactly.
    std::vector<std::pair<std::uint64_t, OrderRef>> by_prio;
    by_prio.reserve(orders.size());
    for (const auto& [ref, o] : orders) by_prio.emplace_back(o.prio, ref);
    std::sort(by_prio.begin(), by_prio.end());
    for (const auto& [prio, ref] : by_prio) {
      const Order& o = orders.at(ref);
      f(itch::AddOrder{.stock_locate = o.loc, .tracking_number = 0, .timestamp = 2, .order_ref = ref, .side = o.side,
                       .shares = o.shares, .stock = symbol_of(o.loc), .price = o.px});
    }
  }
  [[nodiscard]] Symbol8 symbol_of(Locate loc) const {
    for (const auto& [l, s] : directory) {
      if (l == loc) return s;
    }
    return Symbol8("?");
  }
  static itch::StockDirectory directory_msg(Locate loc, Symbol8 sym) {
    return itch::StockDirectory{.stock_locate = loc, .tracking_number = 0, .timestamp = 1, .stock = sym,
                                .market_category = itch::MarketCategory::NasdaqGlobalSelect,
                                .financial_status = itch::FinancialStatus::Normal, .round_lot_size = 100,
                                .round_lots_only = itch::YesNo::No,
                                .issue_classification = itch::IssueClassification::CommonStock,
                                .issue_sub_type = Alpha<2>("Z"), .authenticity = itch::Authenticity::LiveProduction,
                                .short_sale_threshold = itch::YesNoBlank::No, .ipo_flag = itch::IpoFlag::NotNewIpo,
                                .luld_tier = itch::LuldTier::Tier1, .etp_flag = itch::YesNoBlank::No,
                                .etp_leverage_factor = 0, .inverse_indicator = itch::YesNo::No};
  }
};
static_assert(glimpse::SnapshotStateLike<FeedState>);

struct ClientProc;

// ---- harness ---------------------------------------------------------------
struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_arb = 0;
  OracleId o_line = 0;
  OracleId o_book = 0;
  bool verbose = false;

  std::vector<std::byte> canon;  // canonical message i at [off[i], off[i+1])
  std::vector<std::size_t> off;
  std::vector<Nanos> at;  // publish time of message i
  std::uint64_t ref_digest = 0;

  struct ClientTruth {
    SeqNo expected = 0;  // next sequence the client must deliver; 0: awaiting a snapshot
    bool ended = false;
    std::uint64_t delivered = 0;
    std::uint64_t snapshots = 0;
  };
  std::vector<ClientTruth> truth;
  std::vector<ClientProc*> clients;
  std::uint64_t spins = 0;
  std::uint64_t rerequests_served = 0;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  [[nodiscard]] std::uint64_t total() const { return off.size() - 2; }
  [[nodiscard]] std::span<const std::byte> message(SeqNo i) const {
    return std::span<const std::byte>(canon).subspan(off[i], off[i + 1] - off[i]);
  }

  void add(std::span<const std::byte> m, Nanos t) {
    canon.insert(canon.end(), m.begin(), m.end());
    off.push_back(canon.size());
    at.push_back(t);
  }

  // A valid stream: directory, then adds, executions, cancels, deletes and
  // replaces on live orders around a per-symbol random walk.
  void generate(std::uint64_t seed, std::uint64_t n, Nanos span_ns) {
    Prng r(mix64(seed ^ 0xFEED));
    off.assign(1, 0);
    off.push_back(0);
    at.assign(1, 0);
    const Nanos dt = std::max<Nanos>(1, span_ns / static_cast<Nanos>(n));
    Nanos t = dt;
    std::array<std::byte, itch::kMaxMsgLen> buf{};
    FeedState st;
    const auto put = [&](const auto& msg) {
      const std::size_t len = itch::encode(buf, msg);
      LLE_ASSERT(len != 0, "ITCH encode");
      const std::span<const std::byte> m(buf.data(), len);
      st.apply(m);
      add(m, t);
      t += dt;
    };
    put(itch::SystemEvent{.stock_locate = 0, .tracking_number = 0, .timestamp = 1,
                          .event_code = itch::EventCode::StartOfMessages});
    const auto locs = static_cast<Locate>(2 + r.below(5));
    std::vector<PxE4> mid(locs + 1u, 0);
    for (Locate l = 1; l <= locs; ++l) {
      std::array<char, 16> name{};  // "SYM" + up to 10 digits + NUL; Symbol8 keeps the first 8
      std::snprintf(name.data(), name.size(), "SYM%u", static_cast<unsigned>(l));
      put(FeedState::directory_msg(l, Symbol8(name.data())));
      mid[l] = static_cast<PxE4>(100 + r.below(400)) * kPxScale;
    }
    std::vector<OrderRef> live;
    OrderRef next_ref = 1;
    std::uint64_t ts = 100;
    while (total() < n) {
      ++ts;
      const std::uint64_t pick = r.below(100);
      if (live.empty() || pick < 40) {
        const auto l = static_cast<Locate>(1 + r.below(locs));
        mid[l] = std::max<PxE4>(kPxScale, mid[l] + (static_cast<PxE4>(r.below(5)) - 2) * 100);
        const Side side = r.below(2) == 0 ? Side::Buy : Side::Sell;
        const PxE4 px = side == Side::Buy ? mid[l] - static_cast<PxE4>(1 + r.below(10)) * 100
                                          : mid[l] + static_cast<PxE4>(1 + r.below(10)) * 100;
        const OrderRef ref = next_ref++;
        put(itch::AddOrder{.stock_locate = l, .tracking_number = 0, .timestamp = ts, .order_ref = ref, .side = side,
                           .shares = static_cast<Qty>(100 * (1 + r.below(10))), .stock = st.symbol_of(l),
                           .price = std::max<PxE4>(100, px)});
        live.push_back(ref);
        continue;
      }
      const std::size_t k = static_cast<std::size_t>(r.below(live.size()));
      const OrderRef ref = live[k];
      const FeedState::Order ord = st.orders.at(ref);
      const auto drop = [&] {
        live[k] = live.back();
        live.pop_back();
      };
      if (pick < 55) {
        const auto q = static_cast<Qty>(1 + r.below(ord.shares));
        put(itch::OrderExecuted{.stock_locate = ord.loc, .tracking_number = 0, .timestamp = ts, .order_ref = ref,
                                .executed_shares = q, .match_number = ts});
        if (q == ord.shares) drop();
      } else if (pick < 70 && ord.shares > 1) {
        const auto q = static_cast<Qty>(1 + r.below(ord.shares - 1));
        put(itch::OrderCancel{.stock_locate = ord.loc, .tracking_number = 0, .timestamp = ts, .order_ref = ref,
                              .cancelled_shares = q});
      } else if (pick < 88) {
        put(itch::OrderDelete{.stock_locate = ord.loc, .tracking_number = 0, .timestamp = ts, .order_ref = ref});
        drop();
      } else {
        const OrderRef nref = next_ref++;
        put(itch::OrderReplace{.stock_locate = ord.loc, .tracking_number = 0, .timestamp = ts,
                               .original_order_ref = ref, .new_order_ref = nref,
                               .shares = static_cast<Qty>(100 * (1 + r.below(10))),
                               .price = std::max<PxE4>(100, ord.px + (static_cast<PxE4>(r.below(3)) - 1) * 100)});
        live[k] = nref;
      }
    }
    // Reference book from the canonical stream.
    Book ref(book_config());
    for (SeqNo i = 1; i <= total(); ++i) {
      const auto m = message(i);
      (void)book::apply_itch(ref, m.data(), m.size());
    }
    ref_digest = ref.books_digest();
  }

  // O-LINE: every message in a line packet or a re-request reply is canonical.
  void check_packet(std::span<const std::byte> pkt, const char* what) {
    const auto pv = mold::PacketView::parse(pkt);
    if (!pv) {
      o->fail(o_line, std::string(what) + ": malformed MoldUDP64 packet");
      return;
    }
    bool ok = true;
    pv->for_each([&](SeqNo s, std::span<const std::byte> m) {
      if (!ok) return;
      if (s == 0 || s > total() || m.size() != message(s).size() ||
          std::memcmp(m.data(), message(s).data(), m.size()) != 0) {
        o->fail(o_line, std::string(what) + ": sequence " + std::to_string(s) + " carries non-canonical bytes");
        ok = false;
      }
    });
    if (ok) o->pass(o_line);
  }
};

// ---- publisher: one line, re-request server, snapshot server ---------------
struct PubConfig {
  std::size_t max_packet = 1472;
  Nanos heartbeat = 10 * kMs;
  std::uint32_t b_flush_every = 0;  // line B: flush every k messages (0: every poll, like A)
};

struct PublisherProc : Process {
  struct Stage {
    PublisherProc* p;
    bool poll() { return p->poll(); }
  };

  PublisherProc(Node& n, Harness& h, int line, const PubConfig& cfg)
      : node_(n), h_(h), line_(line), cfg_(cfg), port_(n, kServicePort), snap_(n),
        store_(h.total() + 16, (h.total() + 16) * itch::kMaxMsgLen),
        rr_(mold::RerequestConfig{kSession, 1472, 200, 500'000, 1024}, store_),
        rng_(n.rng(3)), stage_{this} {
    // A restarted publisher (re)builds its state and store from the stream up
    // to now and publishes from there: what it missed, the other line and the
    // re-request servers cover.
    const Nanos now = n.clock().now_mono();
    while (next_ <= h_.total() && h_.at[next_] <= now) {
      state_.apply(h_.message(next_));
      LLE_ASSERT(store_.append(h_.message(next_)));
      ++next_;
    }
    pub_.emplace(mold::PacketizerConfig{kSession, cfg.max_packet, cfg.heartbeat, 120 * kSec, next_});
    b_left_ = cfg_.b_flush_every;
    LLE_ASSERT(snap_.listen(env::Endpoint{0, kSnapshotPort}).has_value());
    n.add_stage(stage_, line == 0 ? "md_a" : "md_b");
  }

  bool poll() {
    bool did = false;
    const Nanos now = node_.clock().now_mono();
    const auto emit = [&](std::span<const std::byte> pkt) { port_.send(kGroup[line_], pkt); };
    bool published = false;
    while (next_ <= h_.total() && h_.at[next_] <= now) {
      const auto m = h_.message(next_);
      LLE_ASSERT(store_.append(m));
      state_.apply(m);
      (void)pub_->append(m, now, emit);
      ++next_;
      published = true;
      // Line B stands for the backup's md: its input arrives in different
      // chunks, so its packet boundaries differ from line A's.
      if (cfg_.b_flush_every != 0 && --b_left_ == 0) {
        pub_->flush(now, emit);
        b_left_ = 1 + static_cast<std::uint32_t>(rng_.below(cfg_.b_flush_every));
      }
    }
    if (published && (cfg_.b_flush_every == 0) && !SIM_BUGGIFY("arbiter_world.delay_flush")) pub_->flush(now, emit);
    if (next_ > h_.total() && !pub_->ended()) pub_->end_session(now, emit);
    did = pub_->on_timer(now, emit) || published || did;

    port_.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      if (SIM_BUGGIFY("arbiter_world.rerequest_server_refuses")) return;  // a busy server drops it
      const auto out = rr_.on_request(d.data, d.src, now, [&](const env::Endpoint& to, std::span<const std::byte> b) {
        ++h_.rerequests_served;
        port_.send(to, b);
      });
      (void)out;
    });

    snap_.poll([&](const env::StreamEvent& ev) {
      did = true;
      if (ev.kind == env::StreamEventKind::Accepted) {
        // Spin the current state (GLIMPSE), framed as <u16 length><message>.
        Spin s{ev.conn, {}};
        glimpse::SnapshotServer{}.emit(state_, [&](std::span<const std::byte> m) {
          std::array<std::byte, 2> len{};
          store_be16(len.data(), static_cast<std::uint16_t>(m.size()));
          s.out.insert(s.out.end(), len.begin(), len.end());
          s.out.insert(s.out.end(), m.begin(), m.end());
        });
        ++h_.spins;
        spins_.push_back(std::move(s));
      } else if (ev.kind == env::StreamEventKind::Closed) {
        std::erase_if(spins_, [&](const Spin& s) { return s.conn == ev.conn; });
      }
    });
    for (Spin& s : spins_) {
      if (s.done) continue;
      const std::size_t n = snap_.write(s.conn, std::span<const std::byte>(s.out).subspan(s.sent));
      s.sent += n;
      did = did || n > 0;
      if (s.sent == s.out.size()) {
        snap_.close(s.conn);
        s.done = true;
      }
    }
    std::erase_if(spins_, [](const Spin& s) { return s.done; });
    return did;
  }

  struct Spin {
    env::ConnId conn;
    std::vector<std::byte> out;
    std::size_t sent = 0;
    bool done = false;
  };

  Node& node_;
  Harness& h_;
  int line_;
  PubConfig cfg_;
  DatagramPort port_;
  StreamPort snap_;
  mold::MessageRing store_;
  mold::RerequestServer<mold::MessageRing> rr_;
  std::optional<mold::Packetizer> pub_;
  FeedState state_;
  SeqNo next_ = 1;
  Rng rng_;
  std::uint32_t b_left_ = 0;
  std::vector<Spin> spins_;
  Stage stage_;
};

// ---- client: LineArbiter + book --------------------------------------------
struct ClientProc : Process {
  struct Stage {
    ClientProc* p;
    bool poll() { return p->poll(); }
  };
  struct Sink {
    ClientProc* c;
    void on_message(SeqNo s, std::span<const std::byte> m) { c->deliver(s, m); }
    void send_request(mold::Server v, std::span<const std::byte> req) { c->port_.send(c->servers_[static_cast<int>(v)], req); }
    void on_snapshot_needed(SeqNo next, SeqNo known_end) {
      c->h_.log("client %u needs a snapshot at %llu (known end %llu)", c->id_, static_cast<unsigned long long>(next),
                static_cast<unsigned long long>(known_end));
      SIM_PROBE("arbiter_world.snapshot_needed");
      c->start_snapshot();
    }
    void on_end_of_session(SeqNo e) { c->end(e); }
  };

  ClientProc(Node& n, Harness& h, std::uint32_t id, const LineArbiterConfig& cfg, env::Endpoint srv_a,
             env::Endpoint srv_b, env::Endpoint snap_a, env::Endpoint snap_b)
      : node_(n), h_(h), id_(id), port_(n, kClientPort), snap_(n), servers_{srv_a, srv_b}, snaps_{snap_a, snap_b},
        sink_{this}, stage_{this} {
    port_.join(kGroup[0]);
    port_.join(kGroup[1]);
    LineArbiterConfig c = cfg;
    Harness::ClientTruth& t = h_.truth[id_];
    t.ended = false;
    if (n.incarnation() == 0) {
      c.first_seq = 1;
      t.expected = 1;
      book_ = std::make_unique<Book>(book_config());
    } else {
      // Late join after a restart: GLIMPSE snapshot, then the live feed.
      c.first_seq = 0;
      t.expected = 0;
      SIM_PROBE("arbiter_world.late_join");
    }
    arb_ = std::make_unique<LineArbiter>(c);
    if (n.incarnation() != 0) start_snapshot();
    h_.clients[id_] = this;
    n.add_stage(stage_, "arb");
  }
  ~ClientProc() override {
    if (h_.clients[id_] == this) h_.clients[id_] = nullptr;
  }

  bool poll() {
    bool did = false;
    const Nanos now = node_.clock().now_mono();
    port_.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      Source src;
      if (d.dst == kGroup[0]) {
        src = Source::LineA;
      } else if (d.dst == kGroup[1]) {
        src = Source::LineB;
      } else if (d.src == servers_[0]) {
        src = Source::RerequestA;
      } else if (d.src == servers_[1]) {
        src = Source::RerequestB;
      } else {
        return;
      }
      h_.check_packet(d.data, mold::is_line(src) ? "line packet" : "re-request reply");
      arb_->on_packet(src, d.data, now, sink_);
    });
    if (arb_->next_deadline() <= now) {
      arb_->on_timer(now, sink_);
      did = true;
    }
    did = poll_snapshot(now) || did;
    return did;
  }

  void deliver(SeqNo s, std::span<const std::byte> m) {
    Harness::ClientTruth& t = h_.truth[id_];
    if (t.expected == 0 || s != t.expected) {
      h_.o->fail(h_.o_arb, "client " + std::to_string(id_) + " delivered " + std::to_string(s) + ", expected " +
                               (t.expected == 0 ? std::string("a snapshot first") : std::to_string(t.expected)));
      return;
    }
    const auto want = h_.message(s);
    if (m.size() != want.size() || std::memcmp(m.data(), want.data(), m.size()) != 0) {
      h_.o->fail(h_.o_arb, "client " + std::to_string(id_) + " delivered non-canonical bytes at " + std::to_string(s));
      return;
    }
    h_.o->pass(h_.o_arb);
    ++t.expected;
    ++t.delivered;
    (void)book::apply_itch(*book_, m.data(), m.size());
  }

  void end(SeqNo e) {
    Harness::ClientTruth& t = h_.truth[id_];
    if (t.ended) h_.o->fail(h_.o_arb, "client " + std::to_string(id_) + " got end of session twice");
    if (e != t.expected || e != h_.total() + 1) {
      h_.o->fail(h_.o_arb, "client " + std::to_string(id_) + " end of session at " + std::to_string(e) +
                               " with next expected " + std::to_string(t.expected));
    }
    t.ended = true;
  }

  void start_snapshot() {
    if (fetching_) return;
    fetching_ = true;
    rx_.clear();
    spin_book_ = std::make_unique<Book>(book_config());
    conn_ = env::kNoConn;
    retry_at_ = node_.clock().now_mono();
  }

  bool poll_snapshot(Nanos now) {
    if (!fetching_) return false;
    bool did = false;
    if (conn_ == env::kNoConn && now >= retry_at_) {
      ++attempt_;
      rx_.clear();
      spin_book_ = std::make_unique<Book>(book_config());
      conn_ = snap_.connect(snaps_[(id_ + attempt_) % 2]).value_or(env::kNoConn);
      did = true;
    }
    snap_.poll([&](const env::StreamEvent& ev) {
      did = true;
      if (ev.conn != conn_) return;
      if (ev.kind == env::StreamEventKind::Data) {
        rx_.insert(rx_.end(), ev.data.begin(), ev.data.end());
        consume_spin();
      } else if (ev.kind == env::StreamEventKind::Closed) {
        conn_ = env::kNoConn;
        if (fetching_) retry_at_ = now + 5 * kMs;  // incomplete: try the other server
      }
    });
    return did;
  }

  void consume_spin() {
    std::size_t at = 0;
    std::optional<SeqNo> g;
    while (!g && rx_.size() - at >= 2) {
      const std::size_t n = load_be16(rx_.data() + at);
      if (rx_.size() - at - 2 < n) break;
      const std::span<const std::byte> m(rx_.data() + at + 2, n);
      at += 2 + n;
      if (n > 0 && static_cast<char>(m[0]) == glimpse::kEndOfSnapshotType) {
        const auto e = glimpse::decode_end_of_snapshot(m);
        LLE_ASSERT(e.has_value(), "bad end of snapshot");
        g = *e;
      } else {
        (void)book::apply_itch(*spin_book_, m.data(), m.size());
      }
    }
    rx_.erase(rx_.begin(), rx_.begin() + static_cast<std::ptrdiff_t>(at));
    // Splice last: resuming can deliver buffered messages and even ask for the
    // next snapshot, which restarts this fetch's buffers.
    if (g) finish_snapshot(*g);
  }

  void finish_snapshot(SeqNo g) {
    Harness::ClientTruth& t = h_.truth[id_];
    ++t.snapshots;
    h_.log("client %u spliced a snapshot at G=%llu (expected %llu)", id_, static_cast<unsigned long long>(g),
           static_cast<unsigned long long>(t.expected));
    if (t.expected != 0 && g < t.expected) {
      h_.o->fail(h_.o_arb, "client " + std::to_string(id_) + " got a snapshot at " + std::to_string(g) +
                               " older than its next expected " + std::to_string(t.expected));
      return;
    }
    fetching_ = false;
    snap_.close(conn_);
    conn_ = env::kNoConn;
    book_ = std::move(spin_book_);  // the book restarts from the snapshot state
    t.expected = g;
    arb_->resume_from_snapshot(g, node_.clock().now_mono(), sink_);
  }

  Node& node_;
  Harness& h_;
  std::uint32_t id_;
  DatagramPort port_;
  StreamPort snap_;
  env::Endpoint servers_[2];
  env::Endpoint snaps_[2];
  Sink sink_;
  std::unique_ptr<LineArbiter> arb_;
  std::unique_ptr<Book> book_;
  std::unique_ptr<Book> spin_book_;
  bool fetching_ = false;
  env::ConnId conn_ = env::kNoConn;
  Nanos retry_at_ = 0;
  std::uint32_t attempt_ = 0;
  std::vector<std::byte> rx_;
  Stage stage_;
};

}  // namespace

Report run_arbiter(const Options& o) {
  // The harness outlives the world: process destructors still report to it.
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0xA4B);
  h->w = &w;
  h->o = &w.oracles();
  h->verbose = o.verbose;
  h->o_arb = w.oracles().activate(kOArb);
  h->o_line = w.oracles().activate(kOLine);
  h->o_book = w.oracles().activate(kOBook);
  const std::uint64_t n = 1000 + wl.below(4001);
  h->generate(o.seed, n, o.plan.safety_ns * 8 / 10);

  PubConfig pa;
  pa.heartbeat = log_uniform(wl, kMs, 50 * kMs);
  PubConfig pb = pa;
  pb.max_packet = static_cast<std::size_t>(300 + wl.below(1173));
  pb.b_flush_every = static_cast<std::uint32_t>(1 + wl.below(16));

  LineArbiterConfig ac;
  ac.session = kSession;
  ac.reorder_capacity = wl.below(2) == 0 ? 1024 : 4096;
  ac.gap_timeout = log_uniform(wl, 20 * kUs, 5 * kMs);
  ac.request_timeout = log_uniform(wl, kMs, 50 * kMs);
  ac.max_outstanding = static_cast<std::uint32_t>(1 + wl.below(8));
  ac.request_max_count = static_cast<std::uint16_t>(8 + wl.below(57));
  ac.snapshot_gap_messages = wl.below(3) == 0 ? 0 : 200 + wl.below(4801);
  ac.max_gap_age = wl.below(2) == 0 ? 0 : log_uniform(wl, 50 * kMs, 500 * kMs);

  Node& na = w.add_node("md_a", NodeOptions{true, true});
  Node& nb = w.add_node("md_b", NodeOptions{true, true});
  const auto clients = static_cast<std::uint32_t>(1 + wl.below(3));
  h->truth.assign(clients, Harness::ClientTruth{});
  h->clients.assign(clients, nullptr);
  Harness* hp = h.get();
  na.set_boot([hp, pa](Node& nd, BootReason) { nd.emplace_process<PublisherProc>(nd, *hp, 0, pa); });
  nb.set_boot([hp, pb](Node& nd, BootReason) { nd.emplace_process<PublisherProc>(nd, *hp, 1, pb); });
  const env::Endpoint srv_a{na.ip(), kServicePort};
  const env::Endpoint srv_b{nb.ip(), kServicePort};
  const env::Endpoint snap_a{na.ip(), kSnapshotPort};
  const env::Endpoint snap_b{nb.ip(), kSnapshotPort};
  for (std::uint32_t c = 0; c < clients; ++c) {
    Node& nc = w.add_node("client" + std::to_string(c), NodeOptions{true, true});
    nc.set_boot([=](Node& nd, BootReason) {
      nd.emplace_process<ClientProc>(nd, *hp, c, ac, srv_a, srv_b, snap_a, snap_b);
    });
  }
  for (NodeId i = 0; i < w.node_count(); ++i) w.node(i).boot();

  // O-BOOK at the end: every client's book equals the canonical one.
  w.oracles().add_final_check(hp->o_book, [hp] {
    for (std::size_t c = 0; c < hp->clients.size(); ++c) {
      const ClientProc* cp = hp->clients[c];
      if (cp == nullptr || !cp->book_) continue;
      hp->o->check(hp->o_book, cp->book_->books_digest() == hp->ref_digest,
                   "client " + std::to_string(c) + " book differs from the canonical book");
    }
  });

  const auto converged = [hp] {
    for (std::size_t c = 0; c < hp->truth.size(); ++c) {
      if (!hp->truth[c].ended || hp->clients[c] == nullptr) return false;
    }
    return true;
  };
  return finish(
      w, WorldKind::Arbiter, o, converged,
      [hp, clients] {
        std::uint64_t snaps = 0;
        for (const auto& t : hp->truth) snaps += t.snapshots;
        return "messages=" + std::to_string(hp->total()) + " clients=" + std::to_string(clients) +
               " snapshots=" + std::to_string(snaps) + " spins=" + std::to_string(hp->spins) +
               " rerequest_replies=" + std::to_string(hp->rerequests_served);
      });
}

}  // namespace lle::sim::worlds::detail
