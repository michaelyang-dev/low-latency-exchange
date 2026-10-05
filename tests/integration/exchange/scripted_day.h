#pragma once
// The scripted trading day run against a real exchanged process (N-03 end-to-end):
// pre-market orders for the opening cross, continuous trading (enter, execute, replace,
// cancel), a regulatory halt and its operator release through the authenticated admin
// port, cancel-on-disconnect, the closing cross, the expiry sweeps and the end of day.
//
// Every step ends with the node's barrier (control `sync`): what the clients sent is
// sequenced, applied, released and handed to the sockets, so each step's responses can
// be checked before the next starts, and the journal is the same run after run (manual
// clock, inputs in a fixed order). A step can be followed by a SIGKILL and a restart:
// recovery replays the journal, the clients log in again asking for their next
// expected sequence number, and the day continues (restart test, T05).
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "describe.h"
#include "engine/scenario.h"
#include "harness.h"
#include "verify.h"

namespace lle::exch::test {

inline bool dump_enabled() { return std::getenv("LLE_E2E_DUMP") != nullptr; }

class ScriptedDay {
 public:
  struct Options {
    std::string name = "day";
    std::string runner = "threads";
    std::vector<int> kill_after;  // SIGKILL + restart after these steps
    std::uint64_t drop_a = 0;  // subscriber drops every n-th packet of line A / B
    std::uint64_t drop_b = 0;
    SeqNo drop_seq = 0;  // dropped on both lines: filled only by re-request
    std::size_t max_packet_b = 200;  // small: line B splits packets differently from line A
    std::function<void(ScriptedDay&, std::size_t)> after_step;  // called after each step
    std::function<void(ScriptedDay&)> before_restart;            // node down, before the restart
    std::function<void(ScriptedDay&)> after_restart;             // node up, clients logged in again
    bool glimpse = false;                                        // run the snapshot service
    bool metrics = false;                                        // shared-memory metrics segment
    bool record = false;                                         // keep raw line packets (pcaps)
    std::vector<std::string> extra;                              // more configuration lines

    // Options with a name; set the rest as members (GCC's -Wmissing-field-initializers
    // rejects partial designated initializers).
    static Options named(std::string n) {
      Options o;
      o.name = std::move(n);
      return o;
    }
  };

  explicit ScriptedDay(Options o) : o_(std::move(o)), dir_(fresh_dir(o_.name)), cleanup_(dir_) {
    spec_.name = o_.name.substr(0, 12);
    spec_.data_dir = (dir_ / "data").string();
    spec_.runner = o_.runner;
    spec_.line_a = sub_.port_a();
    spec_.line_b = sub_.port_b();
    spec_.max_packet_b = o_.max_packet_b;
    if (o_.glimpse) {
      spec_.extra.push_back("[glimpse]");
      spec_.extra.push_back("listen = " + e2e_host_text() + ":0");
      spec_.extra.push_back("user = GLIMPS");
      spec_.extra.push_back("password = " + gw::Credential::make("glimpse-pw", std::vector<std::uint8_t>{1, 2, 3}).text());
    }
    spec_.metrics = o_.metrics;
    for (const std::string& l : o_.extra) spec_.extra.push_back(l);
    sub_.record(o_.record);
    if (o_.drop_a) sub_.drop_every(0, o_.drop_a);
    if (o_.drop_b) sub_.drop_every(1, o_.drop_b);
    if (o_.drop_seq) sub_.drop_sequence(o_.drop_seq);
    for (const SessionDef& s : spec_.sessions) clients_[s.user] = std::make_unique<OuchClient>(s.user, s.password);
  }

  // Runs every step; returns false (with a gtest failure recorded) on the first problem.
  void run() {
    ex_ = std::make_unique<Exchange>(spec_, dir_);
    ASSERT_TRUE(ex_->start()) << ex_->output();
    attach();
    const auto steps = script();
    for (std::size_t i = 0; i < steps.size(); ++i) {
      SCOPED_TRACE("step " + std::to_string(i));
      steps[i]();
      if (::testing::Test::HasFatalFailure()) return;
      if (o_.after_step) {
        o_.after_step(*this, i);
        if (::testing::Test::HasFatalFailure()) return;
      }
      if (std::find(o_.kill_after.begin(), o_.kill_after.end(), static_cast<int>(i)) != o_.kill_after.end()) {
        restart();
        if (::testing::Test::HasFatalFailure()) return;
      }
    }
  }

  // ---- accessors for the checks -----------------------------------------------------------
  [[nodiscard]] OuchClient& c(const std::string& user) { return *clients_.at(user); }
  [[nodiscard]] MoldSubscriber& sub() { return sub_; }
  [[nodiscard]] Exchange& ex() { return *ex_; }
  [[nodiscard]] const std::filesystem::path& dir() const { return dir_; }
  [[nodiscard]] const NodeSpec& spec() const { return spec_; }
  [[nodiscard]] std::uint64_t final_index() const { return final_index_; }
  [[nodiscard]] int restarts() const { return restarts_; }
  [[nodiscard]] std::map<std::string, std::uint32_t> session_ids() const {
    std::map<std::string, std::uint32_t> m;
    for (const SessionDef& s : spec_.sessions) m[s.user] = s.id;
    return m;
  }
  // Messages each client received since the mark set by mark().
  void mark() {
    for (auto& [u, cl] : clients_) marks_[u] = cl->received().size();
  }
  [[nodiscard]] std::vector<Ouch> since_mark(const std::string& user) {
    std::vector<Ouch> v;
    const auto& r = c(user).received();
    for (std::size_t i = marks_[user]; i < r.size(); ++i) v.push_back(Ouch{r[i].msg});
    return v;
  }

 private:
  void attach() {
    sub_.set_servers(ex_->port("rerequest"), ex_->port("rerequest"));
    admin_ = std::make_unique<AdminClient>(ex_->port("admin"), 1, key_bytes(spec_.operator_key));
  }

  void login(const std::string& user) {
    const SessionDef* d = nullptr;
    for (const SessionDef& s : spec_.sessions)
      if (s.user == user) d = &s;
    ASSERT_NE(d, nullptr);
    ASSERT_EQ(c(user).login(ex_->port(d->gw == 0 ? "gw0" : "gw1")), 'A') << user << "\n" << ex_->output();
  }

  void send(const std::string& user, const Bytes& msg) { c(user).send(msg); }

  // Each listed client received exactly these messages since the mark (Ouch::str()),
  // with timestamps at or after `from` (time of day) and within the second after it.
  void expect(const std::map<std::string, std::vector<std::string>>& want, const std::string& from) {
    for (const auto& [u, msgs] : want) {
      ASSERT_TRUE(c(u).wait_count(marks_[u] + msgs.size(), 5s))
          << u << " got " << c(u).received().size() - marks_[u] << " of " << msgs.size() << "\n" << ex_->status();
    }
    for (auto& [u, cl] : clients_) cl->settle(20ms);
    sub_.poll(0);
    const auto t0 = parse_hms_ns(from);
    for (auto& [u, cl] : clients_) {
      const auto got = since_mark(u);
      const auto it = want.find(u);
      const std::vector<std::string> none;
      const std::vector<std::string>& exp = it == want.end() ? none : it->second;
      ASSERT_EQ(got.size(), exp.size()) << u << ": " << describe(got);
      for (std::size_t i = 0; i < got.size(); ++i) {
        EXPECT_EQ(got[i].str(), exp[i]) << u << " message " << i;
        EXPECT_GE(got[i].ts(), t0) << u << " message " << i << " timestamp";
        EXPECT_LT(got[i].ts(), t0 + kNsPerSec) << u << " message " << i << " timestamp";
      }
      if (dump_enabled())
        for (const Ouch& m : got) std::printf("  %s <- %s (%llu)\n", u.c_str(), m.str().c_str(), static_cast<unsigned long long>(m.ts()));
    }
  }
  // Sends one message and checks every client's responses to it.
  void act(const std::string& user, const Bytes& msg, const std::map<std::string, std::vector<std::string>>& want,
           const std::string& from) {
    mark();
    send(user, msg);
    expect(want, from);
    step_sync();
  }
  static std::string describe(const std::vector<Ouch>& v) {
    std::string s;
    for (const Ouch& m : v) s += "[" + m.str() + "] ";
    return s;
  }
  static std::uint64_t parse_hms_ns(const std::string& t) {
    const auto h = static_cast<std::uint64_t>(std::stoul(t.substr(0, 2)));
    const auto m = static_cast<std::uint64_t>(std::stoul(t.substr(3, 2)));
    const auto sec = static_cast<std::uint64_t>(std::stoul(t.substr(6, 2)));
    return ((h * 60 + m) * 60 + sec) * static_cast<std::uint64_t>(kNsPerSec);
  }

  void step_sync() { ex_->sync(); }

  void restart() {
    ++restarts_;
    // Clients lose their connections with the process (no End of Session).
    ex_->kill9();
    for (auto& [u, cl] : clients_) cl->drop();
    if (o_.before_restart) {
      o_.before_restart(*this);
      if (::testing::Test::HasFatalFailure()) return;
    }
    ASSERT_TRUE(ex_->start()) << ex_->output();
    attach();
    for (const auto& [u, logged] : logged_in_) {
      if (logged) login(u);
    }
    ex_->sync();
    if (o_.after_restart) o_.after_restart(*this);
  }

  static engine::EnterArgs order(UserRefNum urn, char side, Qty qty, const char* symbol, std::uint64_t price,
                                 char cross = 'N') {
    engine::EnterArgs a;
    a.urn = urn;
    a.side = static_cast<ouch50::Side>(side);
    a.qty = qty;
    a.symbol = symbol;
    a.price = price;
    a.cross = static_cast<ouch50::CrossType>(cross);
    return a;
  }

  std::vector<std::function<void()>> script();

  Options o_;
  std::filesystem::path dir_;
  ScopedDir cleanup_;  // destroyed last: after the process and the clients
  MoldSubscriber sub_;
  NodeSpec spec_;
  std::unique_ptr<Exchange> ex_;
  std::unique_ptr<AdminClient> admin_;
  std::map<std::string, std::unique_ptr<OuchClient>> clients_;
  std::map<std::string, bool> logged_in_;
  std::map<std::string, std::size_t> marks_;
  std::uint64_t final_index_ = 0;
  int restarts_ = 0;
};

}  // namespace lle::exch::test

namespace lle::exch::test {

// The day. Each order is sent after the previous order's responses arrived, so the
// journal (and every output byte) is the same in every run. Expected responses are the
// OUCH fields (Ouch::str(): type, UserRefNum, side, quantity, symbol, price, order
// reference, cross type, order state, liquidity, match number, cancel reason); their
// timestamps are checked to lie in the step's time window. The reasons are the OUCH 5.0
// and matching-rules readings cited in docs/design/matching-rules.md.
inline std::vector<std::function<void()>> ScriptedDay::script() {
  constexpr std::uint64_t kMkt = ouch50::kMarketPrice;
  std::vector<std::function<void()>> s;
  // 0. Pre-market: log in. Each session's stream starts with Start of Day (the 03:00
  //    system event, replayed from the store on login).
  s.push_back([this] {
    ex_->clock("09:00:00");
    for (const char* u : {"ALPHA", "BRAVO", "CHARL"}) {
      mark();
      login(u);
      logged_in_[u] = true;
      expect({{u, {"S event=S"}}}, "03:00:00");
    }
    step_sync();
  });
  // 1. Orders for the opening cross (09:10, pre-market): Day limit orders are held for
  //    the open (matching-rules §6), CHARL's market-on-open order joins the cross.
  s.push_back([this] {
    ex_->clock("09:10:00");
    act("ALPHA", engine::enter_msg(order(1, 'B', 300, "AAPL", 1'501'000)),
        {{"ALPHA", {"A urn=1 B 300 AAPL @1501000 ref=1 cross=N state=L"}}}, "09:10:00");
    act("BRAVO", engine::enter_msg(order(1, 'S', 200, "AAPL", 1'500'000)),
        {{"BRAVO", {"A urn=1 S 200 AAPL @1500000 ref=2 cross=N state=L"}}}, "09:10:00");
    act("CHARL", engine::enter_msg(order(1, 'S', 100, "AAPL", kMkt, 'O')),
        {{"CHARL", {"A urn=1 S 100 AAPL @2147483647 ref=3 cross=O state=L"}}}, "09:10:00");
    act("ALPHA", engine::enter_msg(order(2, 'B', 100, "MSFT", 2'990'000)),
        {{"ALPHA", {"A urn=2 B 100 MSFT @2990000 ref=4 cross=N state=L"}}}, "09:10:00");
  });
  // 2. 09:30 opening cross (§9.7): 300 shares at $150.00; market-on-open first, then the
  //    held orders by price and time; one match number per pair, liquidity 'O'. MSFT has
  //    no cross (zero-share Q) and its held buy joins the book.
  s.push_back([this] {
    mark();
    ex_->clock("09:30:00");
    step_sync();
    expect({{"ALPHA", {"E urn=1 qty=100 @1500000 liq=O match=1", "E urn=1 qty=200 @1500000 liq=O match=2"}},
            {"BRAVO", {"E urn=1 qty=200 @1500000 liq=O match=2"}},
            {"CHARL", {"E urn=1 qty=100 @1500000 liq=O match=1"}}},
           "09:30:00");
  });
  // 3-4. Continuous trading: a resting sell, then a buy that takes 200 of it
  //    (resting 'A' added, aggressor 'R' removed, §7.2).
  s.push_back([this] {
    ex_->clock("09:31:00");
    act("ALPHA", engine::enter_msg(order(3, 'S', 500, "AAPL", 1'510'000)),
        {{"ALPHA", {"A urn=3 S 500 AAPL @1510000 ref=5 cross=N state=L"}}}, "09:31:00");
    act("BRAVO", engine::enter_msg(order(2, 'B', 200, "AAPL", 1'510'000)),
        {{"ALPHA", {"E urn=3 qty=200 @1510000 liq=A match=5"}},
         {"BRAVO", {"A urn=2 B 200 AAPL @1510000 ref=6 cross=N state=L", "E urn=2 qty=200 @1510000 liq=R match=5"}}},
        "09:31:00");
  });
  // 5. Replace: the quantity is the total over the chain (OUCH §2.2), 400 - 200 executed
  //    = 200 open at the new price, a new order reference (§3.3).
  s.push_back([this] {
    engine::ReplaceArgs r;
    r.orig = 3;
    r.urn = 4;
    r.qty = 400;
    r.price = 1'515'000;
    act("ALPHA", engine::replace_msg(r), {{"ALPHA", {"U orig=3 urn=4 qty=200 @1515000 ref=7 state=L"}}}, "09:31:00");
  });
  // 6. Cancel to zero: 'C' with the decrement, reason U (user).
  s.push_back([this] {
    act("ALPHA", engine::cancel_msg(4, 0), {{"ALPHA", {"C urn=4 qty=200 reason=U"}}}, "09:31:00");
  });
  // 7. MSFT: the formerly held buy rests on the book; a sell takes it.
  s.push_back([this] {
    act("BRAVO", engine::enter_msg(order(3, 'S', 100, "MSFT", 2'990'000)),
        {{"ALPHA", {"E urn=2 qty=100 @2990000 liq=A match=6"}},
         {"BRAVO", {"A urn=3 S 100 MSFT @2990000 ref=8 cross=N state=L", "E urn=3 qty=100 @2990000 liq=R match=6"}}},
        "09:31:00");
  });
  // 8. A resting bid of the cancel-on-disconnect session, and an order for a symbol
  //    that does not exist: the engine rejects it from the journaled bytes (ADR-027).
  s.push_back([this] {
    act("CHARL", engine::enter_msg(order(2, 'B', 50, "AAPL", 1'400'000)),
        {{"CHARL", {"A urn=2 B 50 AAPL @1400000 ref=9 cross=N state=L"}}}, "09:31:00");
    // 0x0017 = 23: invalid symbol (matching-rules §4 step 1).
    act("CHARL", engine::enter_msg(order(3, 'B', 50, "ZZZZ", 1'400'000)), {{"CHARL", {"J urn=3 reason=23"}}},
        "09:31:00");
  });
  // 9. 10:00 regulatory halt through the authenticated admin port; an order entered while
  //    halted is accepted and rests without matching (§4 step 18).
  s.push_back([this] {
    ex_->clock("10:00:00");
    mark();
    ASSERT_TRUE(admin_->command("halt AAPL T1")) << admin_->last_error();
    step_sync();
    expect({}, "10:00:00");
    act("BRAVO", engine::enter_msg(order(4, 'B', 100, "AAPL", 1'505'000)),
        {{"BRAVO", {"A urn=4 B 100 AAPL @1505000 ref=10 cross=N state=L"}}}, "10:00:00");
  });
  // 10. Operator release (resume): the halt cross finds no contra; trading resumes.
  s.push_back([this] {
    ex_->clock("10:05:00");
    mark();
    ASSERT_TRUE(admin_->command("resume AAPL")) << admin_->last_error();
    step_sync();
    expect({}, "10:05:00");
  });
  // 11. CHARL's connection drops: cancel-on-disconnect (§13.6), reason Z; the cancel
  //    waits in its stream until it logs in again.
  s.push_back([this] {
    ex_->clock("10:10:00");
    c("CHARL").drop();
    logged_in_["CHARL"] = false;
    // The gateway sees the close asynchronously: wait until its Disconnect is sequenced.
    bool gone = false;
    for (int i = 0; i < 400 && !gone; ++i) {
      ex_->sync();
      gone = Control::field(ex_->status(), "sessions") == 2;
      if (!gone) std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(gone) << ex_->status();
    step_sync();
  });
  // 12. Closing-cross orders after the 15:50 close freeze: a MOC buy and a LOC sell.
  s.push_back([this] {
    ex_->clock("15:51:00");
    act("ALPHA", engine::enter_msg(order(5, 'B', 100, "AAPL", kMkt, 'C')),
        {{"ALPHA", {"A urn=5 B 100 AAPL @2147483647 ref=11 cross=C state=L"}}}, "15:51:00");
    act("BRAVO", engine::enter_msg(order(5, 'S', 100, "AAPL", 1'500'000, 'C')),
        {{"BRAVO", {"A urn=5 S 100 AAPL @1500000 ref=12 cross=C state=L"}}}, "15:51:00");
  });
  // 13. 16:00 closing cross (§9.7, liquidity 'C'): the MOC buy pairs with the LOC sell at
  //    $150.50 (the buy imbalance moves the price to the best bid); then the close's
  //    expiry sweep cancels the remaining Day order (reason E, §12).
  s.push_back([this] {
    mark();
    ex_->clock("16:00:00");
    step_sync();
    expect({{"ALPHA", {"E urn=5 qty=100 @1505000 liq=C match=7"}},
            {"BRAVO", {"E urn=5 qty=100 @1505000 liq=C match=7", "C urn=4 qty=100 reason=E"}}},
           "16:00:00");
  });
  // 14. CHARL logs in again asking for its next sequence number and receives the
  //    cancel-on-disconnect it missed (sequence recovery from the store, 03 §5).
  s.push_back([this] {
    ex_->clock("16:01:00");
    mark();
    login("CHARL");
    logged_in_["CHARL"] = true;
    expect({{"CHARL", {"C urn=2 qty=50 reason=Z"}}}, "10:10:00");
    step_sync();
  });
  // 15. The end of the day: End of Messages (20:05: OUCH End of Day), DayEnd, then
  //    SoupBinTCP End of Session and MoldUDP64 end of session (06 §10).
  s.push_back([this] {
    mark();
    ex_->clock("20:06:00");
    const std::string r = ex_->cmd("end-day");
    ASSERT_EQ(r.rfind("ok ", 0), 0u) << r;
    final_index_ = Control::value(r);
    for (const char* u : {"ALPHA", "BRAVO", "CHARL"}) {
      c(u).settle(100ms);
      EXPECT_TRUE(c(u).ended()) << u << ": no End of Session";
    }
    EXPECT_TRUE(sub_.wait_end(5s)) << "no MoldUDP64 end of session";
    expect({{"ALPHA", {"S event=E"}}, {"BRAVO", {"S event=E"}}, {"CHARL", {"S event=E"}}}, "20:05:00");
  });
  return s;
}

}  // namespace lle::exch::test

namespace lle::exch::test {

// Every output byte the clients, the feed and the output log hold equals the journal's
// regeneration (journal_replay --emit), with no duplicated or missing SoupBinTCP sequence.
inline void check_regeneration(ScriptedDay& day, const std::string& tag) {
  SCOPED_TRACE(tag);
  const Regenerated r = regenerate(day.ex().journal_dir(), day.dir() / ("regen-" + tag));
  ASSERT_EQ(r.exit_code, 0) << r.report;
  EXPECT_NE(r.report.find("invalid payloads: 0, stamping violations: 0"), std::string::npos) << r.report;
  // The feed the subscriber assembled (lines A and B, re-requests) is the regenerated ITCH.
  ASSERT_EQ(r.itch.size(), day.sub().messages().size());
  EXPECT_TRUE(r.itch == day.sub().messages()) << "feed differs from the journal's regeneration";
  // The output log holds the same released stream.
  EXPECT_TRUE(outlog_bytes(day.ex().outlog_dir() + "/itch.bin") == framed(r.itch)) << "itch.bin";
  for (const auto& [user, id] : day.session_ids()) {
    const auto it = r.ouch.find(id);
    ASSERT_NE(it, r.ouch.end()) << user;
    // Every OUCH byte each client received, in order, is the regeneration of its session.
    EXPECT_TRUE(day.c(user).stream() == it->second) << user << ": OUCH stream differs from the regeneration";
    char name[32];
    std::snprintf(name, sizeof name, "/soup-%06u.bin", id);
    EXPECT_TRUE(outlog_bytes(day.ex().outlog_dir() + name) == it->second) << user << ": output log differs";
    EXPECT_EQ(day.c(user).duplicates(), 0u) << user;
    EXPECT_EQ(day.c(user).gaps(), 0u) << user;
  }
}

}  // namespace lle::exch::test
