#pragma once
// Failover trials on localhost (plan 10 §5, §7; R-06 integration, R-10 skeleton).
//
// One trial runs a primary (A), a backup (B) and witnessd as processes, two traders
// (ALPHA sells on gw0, BRAVO buys on gw1) holding their session on the primary and a
// mirror-attached instance on the backup (10 §3), and a subscriber on both MoldUDP64
// lines and both re-request servers. The A-B data link goes through a relay with a cut
// switch. A trial is one functional class of plan 10 §7:
//
//   F1          SIGKILL the primary under load; B takes over (PROMOTE); A restarts and
//               rejoins as the backup.
//   F1-partial  F1 while a large resting order is being filled in parts.
//   F1-divergent  F1 after the A-B link was cut for a moment (less than T_ack): A has
//               sequenced and journaled records B never received, so the restarted A
//               truncates its journal at B's end of epoch 1 (EPOCH_END, KIP-101) before
//               it catches up.
//   F6          cut the A-B link with both nodes alive: A goes solo (SOLO), B is never
//               granted anything (it learns it is deposed and exits); after the link is
//               restored B restarts and rejoins.
//   F7          SIGKILL the backup: A goes solo; B restarts and rejoins.
//   F7-resume   F7, and then the solo primary A is SIGKILLed and restarts too: the
//               witness grants it RESUME (it is the solo primary of record) and it
//               continues the day in a new epoch before B rejoins.
//
// Rejoin is 10 §5: RECOVERING with a new incarnation, EPOCH_END truncation by epoch,
// engine reload, CATCHUP_REQ, and the JOIN the primary relays to the witness at zero lag.
// After the trial both nodes stop cleanly and the oracles run:
//   O-LEDGER   every order accepted once; every execution reported once to each side;
//              fills add up (exactly once across the failover; 10 §8);
//   O-STREAM   each session's primary and mirror connections agree byte for byte where
//              they overlap, and the session's stream equals journal_replay --emit-ouch
//              of the final primary's journal; no duplicate or missing sequence number;
//   O-MOLD     the feed assembled from both lines and both re-request servers equals
//              the ITCH regeneration of the final primary's journal with no gap; every
//              line packet from every sender carries exactly the feed's bytes at its
//              sequence numbers; on each line, each sender's sequence numbers never step
//              back (forward jumps, where a line was switched over, are counted);
//   O-JOURNAL  after the rejoin the two journals are identical (journal_diff);
//   O-CLASS    the witness granted what the class implies (PROMOTE / SOLO, then JOIN)
//              and nothing else; F6: no takeover, B exits as deposed (code 3).
// Timings are software timestamps on one host: indicative only. The lab (T25) replaces
// the capture with a hardware-timestamped one; analyze_pcap.py reads either.
//
// The trial records everything the oracles use in its directory (trial.json, the
// line capture capture.pcap, the clients' streams, both journals), so
// bench/failover/check_trial_oracles.py re-checks a trial independently.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "describe.h"
#include "engine/scenario.h"
#include "harness.h"
#include "verify.h"

namespace lle::exch::test::ha {

// ---- witnessd -----------------------------------------------------------------------------

class Witness {
 public:
  Witness(const std::filesystem::path& dir, int tie_break_ms) {
    state_ = (dir / "witness.state").string();
    init_ = run_capture({LLE_WITNESSD, "--state", state_, "--init", "--primary", "0", "--inc0", "1", "--inc1", "1"});
    proc_ = std::make_unique<Process>(LLE_WITNESSD,
                                      std::vector<std::string>{"--state", state_, "--listen", "127.0.0.1:0",
                                                               "--tie-break-ms", std::to_string(tie_break_ms)},
                                      (dir / "witness.out").string());
    if (proc_->wait_output("listening on port ", 10s)) {
      const std::string out = proc_->output();
      port_ = static_cast<std::uint16_t>(std::stoul(out.substr(out.find("listening on port ") + 18)));
    }
  }
  [[nodiscard]] std::uint16_t port() const { return port_; }
  [[nodiscard]] std::string output() const { return proc_->output(); }
  [[nodiscard]] const std::string& init_output() const { return init_; }
  [[nodiscard]] std::size_t count(const std::string& token) const {
    const std::string out = output();
    std::size_t n = 0;
    for (auto at = out.find(token); at != std::string::npos; at = out.find(token, at + 1)) ++n;
    return n;
  }

 private:
  std::string state_;
  std::string init_;
  std::unique_ptr<Process> proc_;
  std::uint16_t port_ = 0;
};

// ---- the A-B data link --------------------------------------------------------------------

// Node n sends its replication datagrams to port_for(n); the relay forwards them to the
// other node's bind port unless the link is cut.
class UdpRelay {
 public:
  UdpRelay() : fd_{udp_bound(0), udp_bound(0)} {}
  ~UdpRelay() {
    stop_.store(true);
    if (thread_.joinable()) thread_.join();
    for (int f : fd_) ::close(f);
  }
  UdpRelay(const UdpRelay&) = delete;
  UdpRelay& operator=(const UdpRelay&) = delete;

  [[nodiscard]] std::uint16_t port_for(int node) const { return local_port(fd_[node]); }
  void start(std::uint16_t bind_a, std::uint16_t bind_b) {
    dst_[0] = bind_b;  // from A to B
    dst_[1] = bind_a;  // from B to A
    thread_ = std::thread([this] { loop(); });
  }
  void cut(bool on) { cut_.store(on); }
  [[nodiscard]] std::uint64_t forwarded() const { return forwarded_.load(); }
  [[nodiscard]] std::uint64_t dropped() const { return dropped_.load(); }

 private:
  void loop() {
    std::byte buf[65536];
    while (!stop_.load()) {
      pollfd p[2] = {{fd_[0], POLLIN, 0}, {fd_[1], POLLIN, 0}};
      ::poll(p, 2, 5);
      for (int i = 0; i < 2; ++i) {
        for (;;) {
          const ssize_t n = ::recv(fd_[i], buf, sizeof buf, MSG_DONTWAIT);
          if (n <= 0) break;
          if (cut_.load()) {
            dropped_.fetch_add(1);
            continue;
          }
          sockaddr_in a{};
          a.sin_family = AF_INET;
          a.sin_port = htons(dst_[i]);
          a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
          ::sendto(fd_[1 - i], buf, static_cast<std::size_t>(n), 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
          forwarded_.fetch_add(1);
        }
      }
    }
  }

  int fd_[2];
  std::uint16_t dst_[2] = {0, 0};
  std::atomic<bool> stop_{false};
  std::atomic<bool> cut_{false};
  std::atomic<std::uint64_t> forwarded_{0};
  std::atomic<std::uint64_t> dropped_{0};
  std::thread thread_;
};

// ---- trial ----------------------------------------------------------------------------------

struct TrialOptions {
  std::filesystem::path dir;  // working directory (kept: the oracle checker reads it)
  std::uint32_t seed = 1;     // picks the fault point within phase 2
  int heartbeat_ms = 2;
  int t_d_ms = 1500;  // generous for sanitizer builds; the lab uses the tuned values (R-09)
  int t_ack_ms = 1000;
  int rto_ms = 20;  // above the A-B round trip of sanitizer builds (go-back-N retransmission)
  int tie_break_ms = 500;
  std::uint32_t phase1 = 100;  // orders (pairs, or buys against the resting order) before the fault
  std::uint32_t phase2 = 120;  // in flight around the fault
  std::uint32_t phase3 = 80;   // after the rejoin
  bool rejoin = true;          // restart the lost node and rejoin it
  bool repl_thread = false;    // the replica on its own thread ([ha] repl_thread: "split")
  std::chrono::milliseconds step_timeout{30'000};
};

struct TrialResult {
  std::string cls;
  bool pass = false;
  std::vector<std::string> violations;
  std::vector<std::string> notes;
  std::map<std::string, double> ms;         // timings in ms (software timestamps: indicative)
  std::map<std::string, std::int64_t> num;  // counts
  std::map<std::string, std::string> str;   // paths, roles, ids

  [[nodiscard]] std::string json() const {
    auto esc = [](const std::string& s) {
      std::string o;
      for (char c : s) {
        if (c == '"' || c == '\\') o += '\\';
        if (c == '\n') {
          o += "\\n";
          continue;
        }
        o += c;
      }
      return o;
    };
    std::ostringstream o;
    o << "{\n  \"class\": \"" << esc(cls) << "\",\n  \"pass\": " << (pass ? "true" : "false") << ",\n  \"violations\": [";
    for (std::size_t i = 0; i < violations.size(); ++i) o << (i ? ", " : "") << "\"" << esc(violations[i]) << "\"";
    o << "],\n  \"notes\": [";
    for (std::size_t i = 0; i < notes.size(); ++i) o << (i ? ", " : "") << "\"" << esc(notes[i]) << "\"";
    o << "],\n  \"ms\": {";
    bool first = true;
    for (const auto& [k, v] : ms) {
      char b[64];
      std::snprintf(b, sizeof b, "%.3f", v);
      o << (first ? "" : ", ") << "\"" << k << "\": " << b;
      first = false;
    }
    o << "},\n  \"num\": {";
    first = true;
    for (const auto& [k, v] : num) {
      o << (first ? "" : ", ") << "\"" << k << "\": " << v;
      first = false;
    }
    o << "},\n  \"str\": {";
    first = true;
    for (const auto& [k, v] : str) {
      o << (first ? "" : ", ") << "\"" << k << "\": \"" << esc(v) << "\"";
      first = false;
    }
    o << "}\n}\n";
    return o.str();
  }
};

// One node of a localhost pair: manual clock, the subscriber's lines, the A-B link
// through `relay`, witnessd at `witness`.
inline NodeSpec paired_node(int n, const std::filesystem::path& dir, const MoldSubscriber& sub, std::uint16_t witness,
                            const UdpRelay& relay, const std::uint16_t (&bind)[2], const TrialOptions& o) {
  NodeSpec s;
  s.name = n == 0 ? "haA" : "haB";
  s.node_id = n;
  s.data_dir = (dir / s.name).string();
  s.mode = "paired";
  s.clock = "manual";  // one scheduled time per sequencer step (exchange_ha_test.cpp)
  s.start = "02:59:00";
  s.line_a = sub.port_a();
  s.line_b = sub.port_b();
  s.max_packet_b = 300;
  s.extra = {"[ha]",
             "bind = 127.0.0.1:" + std::to_string(bind[n]),
             "peer = 127.0.0.1:" + std::to_string(relay.port_for(n)),
             "witness = 127.0.0.1:" + std::to_string(witness),
             "primary = 0",
             "heartbeat_ms = " + std::to_string(o.heartbeat_ms),
             "t_d_ms = " + std::to_string(o.t_d_ms),
             "t_ack_ms = " + std::to_string(o.t_ack_ms),
             "rto_ms = " + std::to_string(o.rto_ms)};
  if (o.repl_thread) s.extra.push_back("repl_thread = true");
  return s;
}

inline const std::vector<std::string>& trial_classes() {
  static const std::vector<std::string> v = {"F1", "F1-partial", "F1-divergent", "F6", "F7", "F7-resume"};
  return v;
}

namespace detail {

struct Ledger {
  std::map<std::uint32_t, int> accepted;
  std::map<std::uint64_t, int> executions;  // match -> reports in this stream
  std::map<std::uint32_t, std::uint64_t> filled;
  void add(const Ouch& m) {
    if (m.type() == 'A') ++accepted[m.urn()];
    if (m.type() == 'E') {
      ++executions[m.e_match()];
      filled[m.urn()] += m.e_qty();
    }
  }
};

struct Trader {
  std::string user;
  std::string pw;
  int gw = 0;
  char side = 'S';
  std::array<std::unique_ptr<OuchClient>, 2> conn;
};

class Trial {
 public:
  Trial(std::string cls, TrialOptions o) : o_(std::move(o)) { r_.cls = std::move(cls); }

  TrialResult run() {
    const auto& cls = trial_classes();
    if (std::find(cls.begin(), cls.end(), r_.cls) == cls.end()) {
      fail("unknown class " + r_.cls);
      return finish();
    }
    partial_ = r_.cls == "F1-partial";
    std::filesystem::create_directories(o_.dir);
    if (!setup()) return finish();
    if (!phase(1, o_.phase1, true)) return finish();
    if (!fault()) return finish();
    if (o_.rejoin && !rejoin()) return finish();
    if (!phase(3, o_.phase3, o_.rejoin)) return finish();
    wrap_up();
    return finish();
  }

 private:
  // ---- set-up ------------------------------------------------------------------------------
  bool setup() {
    witness_ = std::make_unique<Witness>(o_.dir, o_.tie_break_ms);
    if (witness_->port() == 0) return fail("witnessd did not start: " + witness_->init_output() + witness_->output());
    const std::uint16_t bind[2] = {free_port(SOCK_DGRAM), free_port(SOCK_DGRAM)};  // NOLINT
    relay_.start(bind[0], bind[1]);
    sub_.record(true);
    for (int n = 0; n < 2; ++n) {
      const NodeSpec s = paired_node(n, o_.dir, sub_, witness_->port(), relay_, bind, o_);
      ex_[static_cast<std::size_t>(n)] = std::make_unique<Exchange>(s, o_.dir);
      r_.str[n == 0 ? "journal_a" : "journal_b"] = ex_[static_cast<std::size_t>(n)]->journal_dir();
    }
    // Both nodes start together (a primary that hears no backup for T_ack goes solo).
    ex(0).launch();
    ex(1).launch();
    if (!ex(0).wait_ready() || !ex(1).wait_ready()) return fail("a node did not start:\n" + ex(0).output() + ex(1).output());
    refresh_servers();
    if (!wait_roles("P", "B")) return fail("no paired start: " + ex(0).status() + " | " + ex(1).status());
    if (o_.repl_thread && ex(0).output().find("replica on its own thread") == std::string::npos)
      return fail("repl_thread requested but the node did not split: " + ex(0).output());
    for (int n : {1, 0}) {
      const std::string c = ex(n).cmd("clock 09:31:00");
      if (c.rfind("ok", 0) != 0) return fail("clock on node " + std::to_string(n) + ": " + c);
    }
    traders_[0] = Trader{"ALPHA", "alpha-pw", 0, 'S', {}};
    traders_[1] = Trader{"BRAVO", "bravo-pw", 1, 'B', {}};
    for (Trader& t : traders_) {
      for (int n = 0; n < 2; ++n) {
        t.conn[static_cast<std::size_t>(n)] = std::make_unique<OuchClient>(t.user, t.pw);
        const char c = t.conn[static_cast<std::size_t>(n)]->login(gw_port(n, t.gw));
        if (c != 'A') return fail(t.user + " login on node " + std::to_string(n) + ": " + std::string(1, c));
      }
    }
    r_.num["session_ALPHA"] = 1;  // the SoupBinTCP session ids (NodeSpec)
    r_.num["session_BRAVO"] = 2;
    r_.num["phase1"] = o_.phase1;
    r_.num["phase2"] = o_.phase2;
    r_.num["phase3"] = o_.phase3;
    r_.num["partial"] = partial_ ? 1 : 0;
    r_.num["rejoin"] = o_.rejoin ? 1 : 0;
    r_.num["repl_thread"] = o_.repl_thread ? 1 : 0;
    // A second login of a session on the same port is refused (10 §3, 03 §5).
    OuchClient dup("ALPHA", "alpha-pw");
    if (dup.login(gw_port(0, 0)) != 'S') fail("a second login of ALPHA on the primary's port was not refused with S");
    return true;
  }

  // ---- order flow ----------------------------------------------------------------------------
  static Bytes enter(std::uint32_t urn, char side, std::uint32_t qty) {
    engine::EnterArgs e;
    e.urn = urn;
    e.side = static_cast<ouch50::Side>(side);
    e.qty = qty;
    e.symbol = "AAPL";
    e.price = 1'500'000;
    return engine::enter_msg(e);
  }
  [[nodiscard]] std::uint32_t total_orders() const { return o_.phase1 + o_.phase2 + o_.phase3; }
  // The k-th order of the day (1-based): a crossing pair, or (F1-partial) a buy against
  // ALPHA's resting order, which is entered first.
  void send_order(std::uint32_t k) {
    OuchClient& a = *traders_[0].conn[static_cast<std::size_t>(primary_)];
    OuchClient& b = *traders_[1].conn[static_cast<std::size_t>(primary_)];
    if (partial_) {
      if (k == 1 && a.logged_in()) a.send(enter(1, 'S', total_orders() * 100));
    } else if (a.logged_in()) {
      a.send(enter(k, 'S', 100));
    }
    if (b.logged_in()) b.send(enter(k, 'B', 100));
    sent_ = std::max(sent_, k);
  }
  void pump(int ms) {
    for (Trader& t : traders_)
      for (auto& c : t.conn)
        if (c && c->connected()) c->poll(0);  // (no connections yet while the pair starts)
    sub_.poll(ms);
  }

  // The session's stream from its two connections: they must agree where they overlap.
  Bytes merged(Trader& t, bool note_problem) {
    const std::vector<Received>& p = t.conn[0]->received();
    const std::vector<Received>& m = t.conn[1]->received();
    const std::size_t n = std::min(p.size(), m.size());
    for (std::size_t i = 0; i < n; ++i) {
      if (p[i].seq != m[i].seq || p[i].msg != m[i].msg) {
        if (note_problem) fail(t.user + ": the two connections' streams differ at sequence " + std::to_string(p[i].seq));
        break;
      }
    }
    return p.size() >= m.size() ? t.conn[0]->stream() : t.conn[1]->stream();
  }
  Ledger ledger(Trader& t) {
    Ledger l;
    const OuchClient& c = t.conn[0]->received().size() >= t.conn[1]->received().size() ? *t.conn[0] : *t.conn[1];
    for (const Received& r : c.received()) l.add(Ouch{r.msg});
    return l;
  }
  // Orders 1..n answered (accepted and filled) on the session's stream, and, with
  // `mirror`, the backup's connections caught up with the primary's.
  bool complete(std::uint32_t n, bool mirror) {
    Ledger la = ledger(traders_[0]), lb = ledger(traders_[1]);
    if (partial_) {
      if (la.accepted[1] < 1 || la.filled[1] < std::uint64_t{n} * 100) return false;
    } else {
      for (std::uint32_t u = 1; u <= n; ++u)
        if (la.accepted[u] < 1 || la.filled[u] < 100) return false;
    }
    for (std::uint32_t u = 1; u <= n; ++u)
      if (lb.accepted[u] < 1 || lb.filled[u] < 100) return false;
    if (mirror) {
      for (Trader& t : traders_)
        if (t.conn[0]->received().size() != t.conn[1]->received().size()) return false;
    }
    return true;
  }
  bool wait_complete(std::uint32_t n, bool mirror, const std::string& what) {
    const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
    while (!complete(n, mirror) && std::chrono::steady_clock::now() < end) pump(1);
    if (complete(n, mirror)) return true;
    return fail(what + ": orders 1.." + std::to_string(n) + " not all answered" + (mirror ? " on both nodes" : "") +
                " (ALPHA " + std::to_string(traders_[0].conn[0]->received().size()) + "/" +
                std::to_string(traders_[0].conn[1]->received().size()) + ", BRAVO " +
                std::to_string(traders_[1].conn[0]->received().size()) + "/" +
                std::to_string(traders_[1].conn[1]->received().size()) + " messages) " + statuses());
  }

  // Phase 1: steady paired trading; phase 3: after the rejoin.
  bool phase(int which, std::uint32_t count, bool mirror) {
    const std::uint32_t first = which == 1 ? 1 : o_.phase1 + o_.phase2 + 1;
    for (std::uint32_t k = first; k < first + count; ++k) {
      send_order(k);
      if (k % 25 == 0) pump(0);
    }
    return wait_complete(first + count - 1, mirror, "phase " + std::to_string(which));
  }

  // ---- the fault ---------------------------------------------------------------------------
  bool fault() {
    // Senders seen so far: line A from the primary's md, line B from the backup's.
    for (int i = 0; i < 20; ++i) pump(2);
    if (sub_.sources(0).size() != 1 || sub_.sources(1).size() != 1)
      return fail("before the fault each line has one sender: " + sub_.summary());
    sender_[0] = sub_.sources(0).begin()->first;  // node A's md socket
    sender_[1] = sub_.sources(1).begin()->first;  // node B's md socket
    r_.num["sender_a_port"] = sender_[0];
    r_.num["sender_b_port"] = sender_[1];
    // The fault point within phase 2 (seeded).
    std::uint64_t mix = (std::uint64_t{o_.seed} + 1) * 0x9E3779B97F4A7C15ull;
    mix ^= mix >> 29;
    const std::uint32_t at = 1 + static_cast<std::uint32_t>(mix % o_.phase2);
    r_.num["fault_after_order"] = o_.phase1 + at;
    for (std::uint32_t k = o_.phase1 + 1; k <= o_.phase1 + at; ++k) send_order(k);
    pump(0);
    const bool kill_primary = takeover_class();
    victim_ = kill_primary ? 0 : 1;
    const int survivor = 1 - victim_;
    std::uint32_t next = o_.phase1 + at + 1;
    if (r_.cls == "F1-divergent") {
      // The primary goes on sequencing (and journaling) for a while without its backup;
      // nothing of it can be released. It dies before T_ack would make it go solo.
      relay_.cut(true);
      const std::uint32_t extra = std::min<std::uint32_t>(10, o_.phase1 + o_.phase2 + 1 - next);
      for (std::uint32_t i = 0; i < extra; ++i) send_order(next++);
      const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(o_.t_ack_ms / 3);
      while (std::chrono::steady_clock::now() < until) pump(2);
      r_.num["sequenced_during_cut"] = static_cast<std::int64_t>(Control::field(ex(0).status(), "seq")) -
                                       static_cast<std::int64_t>(Control::field(ex(1).status(), "seq"));
    }
    t_fault_ = realtime_ns();
    r_.num["t_fault_ns"] = t_fault_;
    const auto fault_steady = std::chrono::steady_clock::now();
    if (r_.cls == "F6") {
      relay_.cut(true);
    } else {
      ex(victim_).kill9();
      for (Trader& t : traders_) t.conn[static_cast<std::size_t>(victim_)]->drop();
      if (r_.cls == "F1-divergent") relay_.cut(false);
      refresh_servers();
    }
    // The survivor becomes the solo primary: B by takeover (F1), A by SOLO (F6, F7).
    std::set<std::string> victim_roles;
    const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
    bool solo = false;
    while (!solo && std::chrono::steady_clock::now() < end) {
      solo = role(survivor) == "SP";
      if (r_.cls == "F6") victim_roles.insert(role(victim_));
      if (!solo) pump(2);
    }
    if (!solo) return fail("the survivor never became the solo primary: " + statuses());
    r_.ms["fault_to_solo_primary"] =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - fault_steady).count();
    primary_ = survivor;
    if (r_.cls == "F6") {
      // Never a takeover: B froze, its PROMOTE was refused while W heard A, and once A's
      // SOLO epoch existed B learned it was deposed and exited (10 §4).
      const int code = ex(victim_).proc().wait_exit(o_.step_timeout);
      r_.num["deposed_exit_code"] = code;
      if (code != 3) fail("F6: the cut-off backup did not exit as deposed (exit " + std::to_string(code) + ")");
      for (const std::string& r : victim_roles)
        if (r == "SP" || r == "P") fail("F6: the cut-off backup became " + r);
      for (Trader& t : traders_) t.conn[static_cast<std::size_t>(victim_)]->drop();
      refresh_servers();
    }
    if (kill_primary) resend_unacked();
    if (r_.cls == "F7-resume") {
      // The solo primary of record restarts (10 §5 step 1): RESUME, a new epoch.
      const std::uint32_t last = std::min(o_.phase1 + o_.phase2, next + 9);
      for (; next <= last; ++next) send_order(next);
      pump(1);  // some of them in flight when it dies
      ex(0).kill9();
      for (Trader& t : traders_) t.conn[0]->drop();
      const auto t0 = std::chrono::steady_clock::now();
      ex(0).launch();
      if (!ex(0).wait_ready(std::chrono::milliseconds(o_.step_timeout)))
        return fail("F7-resume: the solo primary did not come back: " + ex(0).output());
      refresh_servers();
      if (ex(0).output().find("rejoin: resumed as the solo primary at") == std::string::npos)
        return fail("F7-resume: no RESUME: " + ex(0).output());
      const auto end2 = std::chrono::steady_clock::now() + o_.step_timeout;
      while (role(0) != "SP" && std::chrono::steady_clock::now() < end2) pump(2);
      if (role(0) != "SP") return fail("F7-resume: not the solo primary after RESUME: " + statuses());
      r_.ms["restart_to_resumed"] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
      for (Trader& t : traders_) {
        const char c = t.conn[0]->login(gw_port(0, t.gw));
        if (c != 'A') return fail(t.user + " login after RESUME: " + std::string(1, c));
      }
      resend_unacked();
    }
    for (std::uint32_t k = next; k <= o_.phase1 + o_.phase2; ++k) send_order(k);
    return wait_complete(o_.phase1 + o_.phase2, false, "phase 2 (after the fault)");
  }

  // The clients continue on the primary's connections: re-send, in order, every order not
  // seen accepted on either connection (10 §3 client rule; UserRefNum dedupe).
  void resend_unacked() {
    for (int i = 0; i < 50; ++i) pump(2);
    std::uint32_t resent = 0;
    for (std::size_t ti = 0; ti < traders_.size(); ++ti) {
      Trader& t = traders_[ti];
      std::set<std::uint32_t> acked;
      for (auto& c : t.conn)
        for (const Received& r : c->received())
          if (Ouch{r.msg}.type() == 'A') acked.insert(Ouch{r.msg}.urn());
      OuchClient& c = *t.conn[static_cast<std::size_t>(primary_)];
      if (partial_ && ti == 0) {
        if (acked.count(1) == 0) {
          c.send(enter(1, 'S', total_orders() * 100));
          ++resent;
        }
        continue;
      }
      for (std::uint32_t u = 1; u <= sent_; ++u) {
        if (acked.count(u) == 0) {
          c.send(enter(u, t.side, 100));
          ++resent;
        }
      }
    }
    r_.num["orders_resent"] += resent;
  }

  // ---- rejoin (10 §5) ------------------------------------------------------------------------
  bool rejoin() {
    if (r_.cls == "F6") relay_.cut(false);
    const auto t0 = std::chrono::steady_clock::now();
    ex(victim_).launch();
    if (!ex(victim_).wait_ready(std::chrono::milliseconds(o_.step_timeout)))
      return fail("the restarted node did not come up: " + ex(victim_).output());
    refresh_servers();
    const std::string want_p = "P", want_b = "B";
    const bool ok = primary_ == 0 ? wait_roles(want_p, want_b) : wait_roles(want_b, want_p);
    if (!ok) return fail("no paired mode after the rejoin: " + statuses());
    r_.ms["restart_to_paired"] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    const std::string out = ex(victim_).output();
    if (out.find("rejoin: catching up from") == std::string::npos)
      fail("the restarted node did not rejoin through RECOVERING: " + out);
    const bool truncated = out.find("rejoin: journal truncated to") != std::string::npos;
    r_.num["rejoin_truncated"] = truncated ? 1 : 0;
    if (r_.cls == "F1-divergent" && !truncated) fail("F1-divergent: the restarted node did not truncate its journal: " + out);
    // The mirror connections log in again at their next expected sequence number.
    for (Trader& t : traders_) {
      const char c = t.conn[static_cast<std::size_t>(victim_)]->login(gw_port(victim_, t.gw));
      if (c != 'A') return fail(t.user + " mirror login on the rejoined node: " + std::string(1, c));
    }
    return wait_complete(o_.phase1 + o_.phase2, true, "mirror catch-up after the rejoin");
  }

  // ---- the end of the trial and the oracles ------------------------------------------------
  void wrap_up() {
    const int backup = 1 - primary_;
    const std::string s = ex(primary_).cmd("sync");
    if (s.rfind("ok", 0) != 0) fail("sync on the primary: " + s);
    if (o_.rejoin) {
      const std::uint64_t want = Control::field(ex(primary_).status(), "seq");
      const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
      while (Control::field(ex(backup).status(), "seq") < want && std::chrono::steady_clock::now() < end) pump(2);
      if (Control::field(ex(backup).status(), "seq") < want) fail("the backup did not catch up: " + statuses());
    }
    const std::uint64_t itch = Control::field(ex(primary_).status(), "itch");
    if (!sub_.wait_messages(itch, std::chrono::milliseconds(o_.step_timeout)))
      fail("feed incomplete: " + sub_.summary() + " of " + std::to_string(itch));
    for (int i = 0; i < 20; ++i) pump(2);
    r_.str["final_primary"] = primary_ == 0 ? "A" : "B";
    r_.str["final_primary_journal"] = ex(primary_).journal_dir();
    r_.num["line_a_port"] = sub_.port_a();
    r_.num["line_b_port"] = sub_.port_b();
    // Artifacts for the independent checker.
    (void)sub_.write_capture((o_.dir / "capture.pcap").string());
    (void)sub_.write_binary_file((o_.dir / "feed.bin").string());
    std::filesystem::create_directories(o_.dir / "clients");
    for (Trader& t : traders_)
      for (int n = 0; n < 2; ++n) {
        const Bytes b = t.conn[static_cast<std::size_t>(n)]->stream();
        std::ofstream((o_.dir / "clients" / (t.user + "." + (n == 0 ? "A" : "B") + ".bin")).string(), std::ios::binary)
            .write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
      }
    // What the witness granted, before the nodes stop (a node left alone for T_ack or T_d
    // would ask for more).
    grants_ = {witness_->count("PROMOTE granted"), witness_->count("SOLO granted"), witness_->count("JOIN granted"),
               witness_->count("RESUME granted")};
    // Both stop at once, so neither outlives its partner long enough to react.
    for (int n : {backup, primary_})
      if (ex(n).running()) (void)ex(n).cmd("shutdown");
    for (int n : {backup, primary_}) {
      const int code = ex(n).proc().wait_exit(o_.step_timeout);
      if (code != 0) fail("node " + std::string(n == 0 ? "A" : "B") + " stopped with " + std::to_string(code));
    }
    oracles();
  }

  void oracles() {
    // O-LEDGER
    Ledger la = ledger(traders_[0]), lb = ledger(traders_[1]);
    const std::uint32_t n = total_orders();
    if (partial_) {
      if (la.accepted[1] != 1) fail("O-LEDGER: ALPHA's resting order accepted " + std::to_string(la.accepted[1]) + " times");
      if (la.filled[1] != std::uint64_t{n} * 100)
        fail("O-LEDGER: ALPHA's resting order filled " + std::to_string(la.filled[1]) + " of " + std::to_string(n * 100));
      if (la.accepted.size() != 1) fail("O-LEDGER: ALPHA has unexpected orders");
    } else {
      for (std::uint32_t u = 1; u <= n; ++u) {
        if (la.accepted[u] != 1) fail("O-LEDGER: ALPHA urn " + std::to_string(u) + " accepted " + std::to_string(la.accepted[u]) + " times");
        if (la.filled[u] != 100) fail("O-LEDGER: ALPHA urn " + std::to_string(u) + " filled " + std::to_string(la.filled[u]));
      }
    }
    for (std::uint32_t u = 1; u <= n; ++u) {
      if (lb.accepted[u] != 1) fail("O-LEDGER: BRAVO urn " + std::to_string(u) + " accepted " + std::to_string(lb.accepted[u]) + " times");
      if (lb.filled[u] != 100) fail("O-LEDGER: BRAVO urn " + std::to_string(u) + " filled " + std::to_string(lb.filled[u]));
    }
    std::map<std::uint64_t, int> both = la.executions;
    for (const auto& [m, c] : lb.executions) both[m] += c;
    if (both.size() != n) fail("O-LEDGER: " + std::to_string(both.size()) + " match numbers for " + std::to_string(n) + " fills");
    for (const auto& [m, c] : both)
      if (c != 2) fail("O-LEDGER: match " + std::to_string(m) + " reported " + std::to_string(c) + " times");
    r_.num["orders"] = n;
    r_.num["executions"] = static_cast<std::int64_t>(both.size());

    // O-STREAM
    std::map<std::string, Bytes> session;
    for (Trader& t : traders_) {
      session[t.user] = merged(t, true);
      for (auto& c : t.conn)
        if (c->duplicates() + c->gaps() != 0)
          fail("O-STREAM: " + t.user + " saw " + std::to_string(c->duplicates()) + " duplicates and " +
               std::to_string(c->gaps()) + " gaps");
    }
    const Regenerated rg = regenerate(ex(primary_).journal_dir(), o_.dir / "regen");
    if (rg.exit_code != 0) {
      fail("journal_replay of the final primary failed: " + rg.report);
      return;
    }
    if (rg.ouch.count(1) == 0 || rg.ouch.at(1) != session["ALPHA"]) fail("O-STREAM: ALPHA's stream differs from the regeneration");
    if (rg.ouch.count(2) == 0 || rg.ouch.at(2) != session["BRAVO"]) fail("O-STREAM: BRAVO's stream differs from the regeneration");

    // O-MOLD
    const std::vector<Bytes>& feed = sub_.messages();
    r_.num["feed_messages"] = static_cast<std::int64_t>(feed.size());
    if (feed != rg.itch)
      fail("O-MOLD: the assembled feed (" + std::to_string(feed.size()) + ") differs from the ITCH regeneration (" +
           std::to_string(rg.itch.size()) + ")");
    mold_lines(rg.itch);

    // O-JOURNAL
    if (o_.rejoin) {
      int code = 0;
      const std::string d = run_capture({LLE_JOURNAL_DIFF, ex(0).journal_dir(), ex(1).journal_dir()}, &code);
      r_.str["journal_diff"] = d.substr(0, d.find('\n'));
      if (code != 0) fail("O-JOURNAL: the journals differ after the rejoin: " + d);
    }

    // O-CLASS
    const auto [promotes, solos, joins, resumes] = grants_;
    r_.num["grants_promote"] = static_cast<std::int64_t>(promotes);
    r_.num["grants_solo"] = static_cast<std::int64_t>(solos);
    r_.num["grants_join"] = static_cast<std::int64_t>(joins);
    r_.num["grants_resume"] = static_cast<std::int64_t>(resumes);
    const bool takeover = takeover_class();
    if (takeover && (promotes != 1 || solos != 0)) fail("O-CLASS: expected one PROMOTE grant and no SOLO");
    if (!takeover && (promotes != 0 || solos != 1)) fail("O-CLASS: expected one SOLO grant and no PROMOTE (no takeover)");
    if (o_.rejoin && joins != 1) fail("O-CLASS: expected one JOIN grant, got " + std::to_string(joins));
    const std::size_t want_resumes = r_.cls == "F7-resume" ? 1 : 0;
    if (resumes != want_resumes) fail("O-CLASS: " + std::to_string(resumes) + " RESUME grants, expected " + std::to_string(want_resumes));

    // Takeover time (F1): last line-A packet from the old primary before the fault to
    // the first line-A packet from the new primary (plan 10 §7 definition).
    if (takeover) {
      std::int64_t last_old = 0, first_new = 0;
      for (const auto& p : sub_.packet_log()) {
        if (p.line != 0) continue;
        if (p.sender == sender_[0] && p.rx_ns <= t_fault_) last_old = p.rx_ns;
        if (p.sender == sender_[1] && p.rx_ns > t_fault_ && first_new == 0) first_new = p.rx_ns;
      }
      if (first_new == 0) fail("no line-A packet from the new primary");
      if (last_old != 0 && first_new != 0) r_.ms["t_takeover"] = static_cast<double>(first_new - last_old) / 1e6;
      if (first_new != 0) r_.ms["fault_to_first_line_a"] = static_cast<double>(first_new - t_fault_) / 1e6;
    }
  }

  // Every line packet carries the feed's bytes at its sequence numbers; per (line,
  // sender) sequence numbers never step back.
  void mold_lines(const std::vector<Bytes>& feed) {
    std::map<std::pair<int, std::uint16_t>, SeqNo> next;  // next expected per (line, sender)
    std::int64_t jumps = 0, packets = 0, mismatches = 0, back = 0;
    for (const auto& p : sub_.packet_log()) {
      const auto v = mold::PacketView::parse(p.bytes);
      if (!v) {
        fail("O-MOLD: malformed packet on line " + std::to_string(p.line));
        continue;
      }
      ++packets;
      v->for_each([&](SeqNo s, std::span<const std::byte> m) {
        if (s == 0 || s > feed.size() || !std::equal(m.begin(), m.end(), feed[s - 1].begin(), feed[s - 1].end())) ++mismatches;
      });
      const auto key = std::make_pair(p.line, p.sender);
      const auto it = next.find(key);
      const SeqNo first = v->seq();
      if (it != next.end()) {
        if (first < it->second && v->message_count() > 0) ++back;
        if (first > it->second) ++jumps;
      }
      next[key] = std::max(it == next.end() ? SeqNo{0} : it->second, v->is_end_of_session() ? first : v->end_seq());
    }
    r_.num["line_packets"] = packets;
    r_.num["line_forward_jumps"] = jumps;
    if (mismatches != 0) fail("O-MOLD: " + std::to_string(mismatches) + " line messages differ from the feed");
    if (back != 0) fail("O-MOLD: " + std::to_string(back) + " packets stepped back in a sender's sequence");
    std::set<std::uint16_t> senders_a;
    for (const auto& [k, s] : next)
      if (k.first == 0) senders_a.insert(k.second);
    r_.num["line_a_senders"] = static_cast<std::int64_t>(senders_a.size());
  }

  // ---- helpers ------------------------------------------------------------------------------
  // The F1 family: the primary dies and the backup takes over (PROMOTE).
  [[nodiscard]] bool takeover_class() const { return r_.cls.rfind("F1", 0) == 0; }
  Exchange& ex(int n) { return *ex_[static_cast<std::size_t>(n)]; }
  std::uint16_t gw_port(int node, int gw) { return ex(node).port(gw == 0 ? "gw0" : "gw1"); }
  std::string role(int n) {
    if (!ex(n).running()) return "down";
    const std::string s = ex(n).status();
    const auto at = s.find("role=");
    if (at == std::string::npos) return "?";
    return s.substr(at + 5, s.find(' ', at) - at - 5);
  }
  // The subscriber re-requests from the running nodes (a restarted node has new ports).
  void refresh_servers() {
    std::uint16_t p[2] = {0, 0};
    for (int n = 0; n < 2; ++n)
      if (ex(n).running()) p[n] = ex(n).port("rerequest");
    sub_.set_servers(p[0] != 0 ? p[0] : p[1], p[1] != 0 ? p[1] : p[0]);
  }
  std::string statuses() { return "[A " + ex(0).status() + "] [B " + ex(1).status() + "]"; }
  bool wait_roles(const std::string& a, const std::string& b) {
    const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
    while (std::chrono::steady_clock::now() < end) {
      if (role(0) == a && role(1) == b) return true;
      pump(5);
    }
    return false;
  }
  bool fail(const std::string& m) {
    r_.violations.push_back(m);
    return false;
  }
  TrialResult finish() {
    r_.pass = r_.violations.empty();
    r_.num["relay_dropped"] = static_cast<std::int64_t>(relay_.dropped());
    r_.str["dir"] = o_.dir.string();
    std::ofstream((o_.dir / "trial.json").string()) << r_.json();
    return r_;
  }

  TrialOptions o_;
  TrialResult r_;
  bool partial_ = false;
  std::unique_ptr<Witness> witness_;
  UdpRelay relay_;
  MoldSubscriber sub_;
  std::array<std::unique_ptr<Exchange>, 2> ex_;
  std::array<Trader, 2> traders_;
  int primary_ = 0;
  int victim_ = 1;
  std::uint32_t sent_ = 0;
  std::uint16_t sender_[2] = {0, 0};
  std::int64_t t_fault_ = 0;
  std::array<std::size_t, 4> grants_{};  // PROMOTE, SOLO, JOIN, RESUME
};

}  // namespace detail

inline TrialResult run_trial(const std::string& cls, const TrialOptions& o) { return detail::Trial(cls, o).run(); }

}  // namespace lle::exch::test::ha
