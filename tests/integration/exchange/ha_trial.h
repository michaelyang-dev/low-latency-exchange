#pragma once
// Failover trials (plan 10 §5, §7; R-06 integration, R-10): on one host, or on the lab's
// hosts A, B and C (T25).
//
// One trial runs a primary (A), a backup (B) and witnessd, two traders (ALPHA sells on
// gw0, BRAVO buys on gw1) holding their session on the primary and a mirror-attached
// instance on the backup (10 §3), optionally a prober (DELTA: an order or a cancel every
// `probe_us`, for T_new and the release stall), and a subscriber on both MoldUDP64 lines
// and both re-request servers. A trial is one class of plan 10 §7:
//
//   F1          SIGKILL the primary under load; B takes over (PROMOTE); A restarts and
//               rejoins as the backup.
//   F1-partial  F1 while a large resting order is being filled in parts.
//   F1-divergent  F1 after the A-B link was cut for a moment (less than T_ack): A has
//               sequenced and journaled records B never received, so the restarted A
//               truncates its journal at B's end of epoch 1 (EPOCH_END, KIP-101) before
//               it catches up.
//   F2          SIGSTOP the primary; B takes over; SIGCONT: A must exit as deposed (3),
//               with no output of the new epoch on its lines; it restarts and rejoins.
//   F3          (lab) every data NIC of the primary down; B takes over; the NICs come
//               back: A exits as deposed; it restarts and rejoins.
//   F4          (lab) kernel panic on the primary's host (sysrq, panic=5 reboot).
//   F5          (lab) the primary's host powered off through its BMC, then on again.
//   F6          cut the A-B link with both nodes alive: A goes solo (SOLO), B is never
//               granted anything (it learns it is deposed and exits); after the link is
//               restored B restarts and rejoins.
//   F7          SIGKILL the backup: A goes solo; B restarts and rejoins.
//   F7-resume   F7, and then the solo primary A is SIGKILLed and restarts too: the
//               witness grants it RESUME (it is the solo primary of record) and it
//               continues the day in a new epoch before B rejoins.
//   F8          kill witnessd: no epoch change, the pair keeps trading (no rejoin).
//   F9          F1 while snapshotd is writing a snapshot of A's journal (a .snap.tmp
//               exists at the kill).
//   F10         (lab) F1 under the background load of the paired-mode T20 rate.
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
//   O-CLASS    the witness granted what the class implies (PROMOTE / SOLO, then JOIN;
//              F8: nothing) and nothing else; F2, F3, F6: the cut-off node exits as
//              deposed (code 3).
// Timings on one host are software timestamps: indicative only. In the lab (TrialOptions::
// lab_spec, written by bench/failover/run_trials.py --lab) the nodes run on hosts A and B
// through the lab's commands, witnessd, the clients and the capture run here on host C,
// the capture is the hardware-timestamped one (tcpdump -j adapter_unsynced), and
// analyze_pcap.py computes T_takeover from it; this process records the artifacts and
// the takeover's journal positions (the new epoch's first ITCH sequence number, for
// T_new) and the survivor's nlog breakdown.
//
// The trial records everything the oracles use in its directory (trial.json, the
// line capture capture.pcap, the clients' streams, both journals), so
// bench/failover/check_trial_oracles.py re-checks a trial independently.
#include <spawn.h>
#include <sys/wait.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
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
#include "journal/posix_segment_dir.h"
#include "journal/reader.h"
#include "verify.h"

namespace lle::exch::test::ha {

// ---- shell commands (the lab's deployment) --------------------------------------------------

struct ShResult {
  int code = -1;  // exit status; -1 killed by a signal or by the timeout
  bool timed_out = false;
  std::string out;  // stdout and stderr
};

// Runs `cmd` with /bin/sh in its own process group; past `timeout` the group is killed.
inline ShResult run_sh(const std::string& cmd, std::chrono::milliseconds timeout, const std::filesystem::path& scratch) {
  static std::atomic<int> counter{0};
  std::filesystem::create_directories(scratch);
  const std::string out_path = (scratch / ("sh-" + std::to_string(::getpid()) + "-" + std::to_string(counter.fetch_add(1)) + ".out")).string();
  ShResult r;
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
  posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
  posix_spawnattr_t at;
  posix_spawnattr_init(&at);
  posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP);
  posix_spawnattr_setpgroup(&at, 0);
  std::string c = cmd;
  char sh[] = "/bin/sh";
  char dash_c[] = "-c";
  char* argv[] = {sh, dash_c, c.data(), nullptr};
  pid_t pid = -1;
  const int rc = posix_spawn(&pid, "/bin/sh", &fa, &at, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  posix_spawnattr_destroy(&at);
  if (rc != 0) {
    r.out = "posix_spawn failed";
    return r;
  }
  const auto end = std::chrono::steady_clock::now() + timeout;
  int st = 0;
  for (;;) {
    const pid_t w = ::waitpid(pid, &st, WNOHANG);
    if (w == pid) break;
    if (std::chrono::steady_clock::now() >= end) {
      ::kill(-pid, SIGKILL);
      ::waitpid(pid, &st, 0);
      r.timed_out = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  if (!r.timed_out) r.code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
  std::ifstream f(out_path);
  std::stringstream ss;
  ss << f.rdbuf();
  r.out = ss.str();
  std::error_code ec;
  std::filesystem::remove(out_path, ec);
  return r;
}

inline std::uint32_t parse_ipv4(const std::string& text) {
  in_addr a{};
  return ::inet_pton(AF_INET, text.c_str(), &a) == 1 ? ntohl(a.s_addr) : 0;
}
// "A.B.C.D:P" -> (address, port); (0, 0) if malformed.
inline std::pair<std::uint32_t, std::uint16_t> parse_endpoint(const std::string& text) {
  const auto colon = text.rfind(':');
  if (colon == std::string::npos) return {0, 0};
  const std::uint32_t ip = parse_ipv4(text.substr(0, colon));
  const unsigned long port = std::strtoul(text.c_str() + colon + 1, nullptr, 10);
  if (ip == 0 || port == 0 || port > 65535) return {0, 0};
  return {ip, static_cast<std::uint16_t>(port)};
}

// The lab description the runner resolved (bench/failover/run_trials.py --lab): one
// "key = value" per line, '#' comments. Commands are /bin/sh lines with {name}
// placeholders the trial fills in ({trial}, {dest}, {pcap}, {stderr}, {fresh}, {seed}).
class LabSpec {
 public:
  static std::optional<LabSpec> load(const std::string& path, std::string* error) {
    std::ifstream f(path);
    if (!f) {
      *error = "cannot read " + path;
      return std::nullopt;
    }
    LabSpec s;
    int n = 0;
    for (std::string line; std::getline(f, line);) {
      ++n;
      const auto b = line.find_first_not_of(" \t");
      if (b == std::string::npos || line[b] == '#') continue;
      const auto eq = line.find('=');
      if (eq == std::string::npos) {
        *error = path + ":" + std::to_string(n) + ": no '='";
        return std::nullopt;
      }
      auto trim = [](std::string v) {
        const auto x = v.find_first_not_of(" \t");
        const auto y = v.find_last_not_of(" \t\r");
        return x == std::string::npos ? std::string() : v.substr(x, y - x + 1);
      };
      s.kv_[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
    }
    return s;
  }
  [[nodiscard]] bool has(const std::string& k) const { return kv_.contains(k) && !kv_.at(k).empty(); }
  [[nodiscard]] std::string get(const std::string& k, const std::string& def = "") const {
    const auto it = kv_.find(k);
    return it == kv_.end() ? def : it->second;
  }
  [[nodiscard]] int get_int(const std::string& k, int def) const {
    return has(k) ? static_cast<int>(std::strtol(get(k).c_str(), nullptr, 10)) : def;
  }
  // The values of prefix.0, prefix.1, ... in order.
  [[nodiscard]] std::vector<std::string> list(const std::string& prefix) const {
    std::vector<std::string> out;
    for (int i = 0; has(prefix + "." + std::to_string(i)); ++i) out.push_back(get(prefix + "." + std::to_string(i)));
    return out;
  }
  // Command `k` with {name} replaced from `vars`; unknown placeholders stay.
  [[nodiscard]] std::string expand(const std::string& k, const std::map<std::string, std::string>& vars) const {
    std::string s = get(k);
    for (const auto& [name, v] : vars) {
      const std::string key = "{" + name + "}";
      for (auto at = s.find(key); at != std::string::npos; at = s.find(key, at + v.size())) s.replace(at, key.size(), v);
    }
    return s;
  }

 private:
  std::map<std::string, std::string> kv_;
};

// ---- witnessd -----------------------------------------------------------------------------

class Witness {
 public:
  Witness(const std::filesystem::path& dir, int tie_break_ms, const std::string& listen = "127.0.0.1:0") {
    state_ = (dir / "witness.state").string();
    init_ = run_capture({LLE_WITNESSD, "--state", state_, "--init", "--primary", "0", "--inc0", "1", "--inc1", "1"});
    proc_ = std::make_unique<Process>(LLE_WITNESSD,
                                      std::vector<std::string>{"--state", state_, "--listen", listen, "--tie-break-ms",
                                                               std::to_string(tie_break_ms)},
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
  // F8: the witness dies (its output stays readable).
  void kill() { proc_->kill(SIGKILL); }
  [[nodiscard]] bool alive() { return proc_->alive(); }

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
  bool rejoin = true;          // restart the lost node and rejoin it (never for F8)
  bool repl_thread = false;    // the replica on its own thread ([ha] repl_thread: "split")
  int probe_us = 0;            // DELTA's probe orders every probe_us around the fault (0: none)
  std::string lab_spec;        // the lab's resolved description (empty: everything on this host)
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
        if (static_cast<unsigned char>(c) < 0x20) continue;
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

// What a class does (plan 10 §7).
struct ClassInfo {
  bool takeover = false;  // the primary is lost and B takes over (PROMOTE)
  bool solo = false;      // the backup is lost or cut off and A goes solo (SOLO)
  bool lab_only = false;  // needs the lab's hosts (NICs, kernel, BMC, background load)
  bool deposed = false;   // the cut-off node lives on and must exit as deposed (3)
};
inline const std::map<std::string, ClassInfo>& class_table() {
  static const std::map<std::string, ClassInfo> t = {
      {"F1", {true, false, false, false}},          {"F1-partial", {true, false, false, false}},
      {"F1-divergent", {true, false, false, false}}, {"F2", {true, false, false, true}},
      {"F3", {true, false, true, true}},            {"F4", {true, false, true, false}},
      {"F5", {true, false, true, false}},           {"F6", {false, true, false, true}},
      {"F7", {false, true, false, false}},          {"F7-resume", {false, true, false, false}},
      {"F8", {false, false, false, false}},         {"F9", {true, false, false, false}},
      {"F10", {true, false, true, false}},
  };
  return t;
}
inline std::vector<std::string> trial_classes() {
  std::vector<std::string> v;
  for (const auto& [k, info] : class_table()) v.push_back(k);
  return v;
}

// The traders' and the prober's sessions (NodeSpec defaults plus DELTA).
inline void trial_sessions(NodeSpec& s) {
  s.accounts.push_back("400 FRMD");
  s.sessions.push_back(SessionDef{4, 400, "DELTA", "delta-pw", 0, "market"});
}

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
  trial_sessions(s);
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

// One node of the lab's pair (exchange_failover_trial --render-config): the node's own
// addresses and fixed ports, the lines' groups, the A-B link, witnessd on host C, and
// the lab's overrides ("node.X.override.N" after "common.override.N").
inline NodeSpec lab_node(int n, const LabSpec& lab, const TrialOptions& o) {
  const std::string me = n == 0 ? "node.A." : "node.B.", peer = n == 0 ? "node.B." : "node.A.";
  NodeSpec s;
  s.name = n == 0 ? "haA" : "haB";
  s.node_id = n;
  s.data_dir = lab.get(me + "data_dir");
  s.mode = "paired";
  s.clock = "manual";
  s.start = "02:59:00";
  s.host_ip = lab.get(me + "ip");
  const auto la = parse_endpoint(lab.get("lines.a")), lb = parse_endpoint(lab.get("lines.b"));
  s.line_a_ip = ipv4_text(la.first);
  s.line_a = la.second;
  s.line_b_ip = ipv4_text(lb.first);
  s.line_b = lb.second;
  s.gw0 = static_cast<std::uint16_t>(lab.get_int(me + "port.gw0", 0));
  s.gw1 = static_cast<std::uint16_t>(lab.get_int(me + "port.gw1", 0));
  s.rerequest = static_cast<std::uint16_t>(lab.get_int(me + "port.rerequest", 0));
  s.control = static_cast<std::uint16_t>(lab.get_int(me + "port.control", 0));
  s.admin = static_cast<std::uint16_t>(lab.get_int(me + "port.admin", 0));
  s.max_packet_b = 300;
  trial_sessions(s);
  s.extra = {"[ha]",
             "bind = " + lab.get(me + "repl"),
             "peer = " + lab.get(peer + "repl"),
             "witness = " + lab.get("witness.listen"),
             "primary = 0",
             "heartbeat_ms = " + std::to_string(o.heartbeat_ms),
             "t_d_ms = " + std::to_string(o.t_d_ms),
             "t_ack_ms = " + std::to_string(o.t_ack_ms),
             "rto_ms = " + std::to_string(o.rto_ms)};
  if (o.repl_thread) s.extra.push_back("repl_thread = true");
  s.overrides = lab.list("common.override");
  for (const std::string& v : lab.list(me + "override")) s.overrides.push_back(v);
  return s;
}

// ---- the data nodes: on this host, or on the lab's hosts ---------------------------------

class TrialNode {
 public:
  virtual ~TrialNode() = default;
  [[nodiscard]] virtual std::string name() const = 0;  // "A" or "B"
  // Starts the node: the first time on an empty data directory (the day starts), later
  // as a restart on what the last process left.
  virtual void launch() = 0;
  virtual bool wait_ready(std::chrono::milliseconds timeout) = 0;
  virtual bool running() = 0;
  // A control-port line and its reply ("err ..." if the node does not answer in time).
  virtual std::string cmd(const std::string& line, int reply_ms = 90'000) = 0;
  std::string status() { return cmd("status", 5'000); }
  virtual void kill9() = 0;
  virtual void signal(int sig) = 0;  // SIGSTOP, SIGCONT
  // The exit code once the process ended: -1 killed by a signal, -2 still running.
  virtual int wait_exit(std::chrono::milliseconds timeout) = 0;
  virtual std::string output() = 0;
  [[nodiscard]] virtual std::uint16_t port(const std::string& name) = 0;
  [[nodiscard]] virtual std::uint32_t host() const = 0;
  // After the node stopped: its journal, log and nlog where this process reads them.
  virtual bool collect() = 0;
  [[nodiscard]] virtual std::string journal_dir() const = 0;
  [[nodiscard]] virtual std::string nlog_path() const = 0;
  [[nodiscard]] virtual std::string snapshots_dir() const = 0;
};

class LocalNode final : public TrialNode {
 public:
  LocalNode(const NodeSpec& s, const std::filesystem::path& dir) : ex_(s, dir) {}
  [[nodiscard]] std::string name() const override { return ex_.spec().node_id == 0 ? "A" : "B"; }
  void launch() override { ex_.launch(); }
  bool wait_ready(std::chrono::milliseconds t) override { return ex_.wait_ready(t); }
  bool running() override { return ex_.running(); }
  std::string cmd(const std::string& line, int reply_ms) override { return ex_.cmd(line, reply_ms); }
  void kill9() override { ex_.kill9(); }
  void signal(int sig) override { ex_.signal(sig); }
  int wait_exit(std::chrono::milliseconds t) override { return ex_.proc().wait_exit(t); }
  std::string output() override { return ex_.output(); }
  std::uint16_t port(const std::string& n) override { return ex_.port(n); }
  [[nodiscard]] std::uint32_t host() const override { return e2e_host(); }
  bool collect() override { return true; }
  [[nodiscard]] std::string journal_dir() const override { return ex_.journal_dir(); }
  [[nodiscard]] std::string nlog_path() const override {
    return ex_.spec().data_dir + "/logs/" + ex_.spec().name + "-20261001.nlog";
  }
  [[nodiscard]] std::string snapshots_dir() const override { return ex_.spec().data_dir + "/snapshots/20261001"; }

 private:
  Exchange ex_;
};

// A node on one of the lab's hosts, driven by the lab's commands (node.A.start, ...;
// lab/failover/t25_node.sh over ssh) and its control port.
class LabNode final : public TrialNode {
 public:
  LabNode(const LabSpec& lab, int n, std::filesystem::path trial_dir)
      : lab_(&lab), n_(n), pre_(n == 0 ? "node.A." : "node.B."), dir_(std::move(trial_dir)) {
    host_ = parse_ipv4(lab.get(pre_ + "ip"));
  }
  // Whatever the trial's outcome, no node outlives it (the next trial's start is fresh).
  ~LabNode() override {
    if (starts_ != 0) (void)sh("kill9", {}, std::chrono::milliseconds(15'000));
  }
  LabNode(const LabNode&) = delete;
  LabNode& operator=(const LabNode&) = delete;
  [[nodiscard]] std::string name() const override { return n_ == 0 ? "A" : "B"; }
  void launch() override {
    ctl_.reset();
    const ShResult r = sh("start", {{"fresh", starts_ == 0 ? "--fresh" : ""}}, std::chrono::milliseconds(60'000));
    ++starts_;
    if (r.code != 0) last_error_ = "start: exit " + std::to_string(r.code) + ": " + r.out;
  }
  bool wait_ready(std::chrono::milliseconds t) override {
    const auto end = std::chrono::steady_clock::now() + t;
    while (std::chrono::steady_clock::now() < end) {
      if (connect() && ctl_->cmd("status", 5'000).find("role=") != std::string::npos) return true;
      ctl_.reset();
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
  }
  bool running() override { return connect(); }
  std::string cmd(const std::string& line, int reply_ms) override {
    if (!connect()) return "err not running";
    std::string r = ctl_->cmd(line, reply_ms);
    if (r.rfind("err ", 0) == 0) ctl_.reset();
    return r;
  }
  void kill9() override {
    ctl_.reset();
    (void)sh("kill9", {}, std::chrono::milliseconds(15'000));
  }
  void signal(int sig) override {
    if (sig == SIGSTOP) ctl_.reset();
    (void)sh(sig == SIGSTOP ? "stop" : "cont", {}, std::chrono::milliseconds(15'000));
  }
  int wait_exit(std::chrono::milliseconds t) override {
    const auto end = std::chrono::steady_clock::now() + t;
    for (;;) {
      const ShResult r = sh("exit_code", {}, std::chrono::milliseconds(15'000));
      if (r.code == 0) {
        const std::string v = r.out.substr(0, r.out.find('\n'));
        if (!v.empty() && v.find_first_not_of("0123456789") == std::string::npos) {
          const int code = std::stoi(v);
          return code >= 128 ? -1 : code;  // 128 + N: killed by signal N
        }
      }
      if (std::chrono::steady_clock::now() >= end) return -2;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  std::string output() override { return sh("output", {}, std::chrono::milliseconds(30'000)).out; }
  std::uint16_t port(const std::string& name) override {
    return static_cast<std::uint16_t>(lab_->get_int(pre_ + "port." + name, 0));
  }
  [[nodiscard]] std::uint32_t host() const override { return host_; }
  bool collect() override {
    const std::filesystem::path dest = dir_ / ("node" + name());
    std::filesystem::create_directories(dest);
    const ShResult r = sh("collect", {{"dest", dest.string()}}, std::chrono::milliseconds(600'000));
    if (r.code != 0) last_error_ = "collect: exit " + std::to_string(r.code) + ": " + r.out;
    return r.code == 0;
  }
  [[nodiscard]] std::string journal_dir() const override { return (dir_ / ("node" + name()) / "journal").string(); }
  [[nodiscard]] std::string nlog_path() const override { return (dir_ / ("node" + name()) / "node.nlog").string(); }
  [[nodiscard]] std::string snapshots_dir() const override { return {}; }  // on the host: the lab's F9 command watches it
  [[nodiscard]] const std::string& last_error() const { return last_error_; }
  // A lab command of this node (node.X.<what>), if the lab described it.
  [[nodiscard]] bool can(const std::string& what) const { return lab_->has(pre_ + what); }
  ShResult sh(const std::string& what, std::map<std::string, std::string> vars, std::chrono::milliseconds timeout) {
    vars.emplace("trial", dir_.string());
    vars.emplace("node", name());
    if (!lab_->has(pre_ + what)) return ShResult{127, false, "the lab describes no " + pre_ + what};
    return run_sh(lab_->expand(pre_ + what, vars), timeout, dir_ / "sh");
  }

 private:
  bool connect() {
    if (ctl_ && ctl_->ok()) return true;
    ctl_ = std::make_unique<Control>(port("control"), host_, 1'000);
    if (!ctl_->ok()) {
      ctl_.reset();
      return false;
    }
    return true;
  }

  const LabSpec* lab_;
  int n_;
  std::string pre_;
  std::filesystem::path dir_;
  std::uint32_t host_ = 0;
  int starts_ = 0;
  std::unique_ptr<Control> ctl_;
  std::string last_error_;
};

// ---- the prober (T_new, release stall) ------------------------------------------------------

// DELTA's probes on one connection, on a thread of their own: every `interval_us` an
// order (buy 100 AAPL at 149.00, below the traders' 150.00) or the cancel of the last
// one, so every probe is a record with ITCH output (Add Order, Order Delete) and the
// book holds at most one probe order. Open loop: a late tick is sent at once and the
// next is scheduled from it. The client belongs to the thread between start and stop.
class Prober {
 public:
  static constexpr std::uint64_t kPrice = 1'490'000;  // $149.00 (OUCH: 4 decimals)

  Prober() : c_("DELTA", "delta-pw") {}
  ~Prober() { stop(); }
  Prober(const Prober&) = delete;
  Prober& operator=(const Prober&) = delete;

  char login(std::uint32_t host, std::uint16_t port) { return c_.at(host).login(port); }
  void start(int interval_us) {
    if (interval_us <= 0 || th_.joinable()) return;
    run_.store(true);
    th_ = std::thread([this, interval_us] { loop(interval_us); });
  }
  void stop() {
    run_.store(false);
    if (th_.joinable()) th_.join();
  }
  [[nodiscard]] bool running() const { return th_.joinable(); }
  // After stop() (or before start()).
  OuchClient& client() { return c_; }
  [[nodiscard]] std::uint64_t sent() const { return sent_; }
  [[nodiscard]] std::uint64_t late() const { return late_; }
  // Probe orders entered: UserRefNums 1..entered().
  [[nodiscard]] std::uint32_t entered() const { return urn_; }
  // After stop(): polls until every probe order has its answer (accepted or rejected)
  // and the last cancel of an accepted order its Order Canceled, or `limit` passes;
  // false if something is still unanswered. On a loaded host thousands of probes can be
  // queued in the sockets and the gateway when the probing stops, and a quiet period
  // alone (a node not scheduled for a while) ended the trial inside that backlog.
  bool drain(std::chrono::milliseconds limit) {
    const auto end = std::chrono::steady_clock::now() + limit;
    const std::uint32_t cancelled = resting_ == 0 ? urn_ : 0;  // the last message was its cancel
    for (;;) {
      for (; scanned_ < c_.received().size(); ++scanned_) {
        const Ouch m{c_.received()[scanned_].msg};
        if (m.type() == 'A' || m.type() == 'J') answered_.insert(m.urn());
        if (m.type() == 'A' && m.urn() == cancelled) cancel_due_ = true;
        if (m.type() == 'C' && m.urn() == cancelled) cancel_answered_ = true;
      }
      const bool done = answered_.size() >= urn_ && (!cancel_due_ || cancel_answered_);
      if (done) return true;
      if (std::chrono::steady_clock::now() >= end || !c_.connected()) return false;
      c_.poll(5);
    }
  }

 private:
  void loop(int interval_us) {
    const auto step = std::chrono::microseconds(interval_us);
    auto next = std::chrono::steady_clock::now();
    while (run_.load(std::memory_order_relaxed)) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= next) {
        if (c_.logged_in()) {
          // A probe the client could not queue (the node stopped reading) is not sent:
          // the next tick tries again with the same UserRefNum.
          if (resting_ == 0) {
            engine::EnterArgs e;
            e.urn = urn_ + 1;
            e.side = ouch50::Side::Buy;
            e.qty = 100;
            e.symbol = "AAPL";
            e.price = kPrice;
            if (c_.send(engine::enter_msg(e))) {
              urn_ = e.urn;
              resting_ = urn_;
              ++sent_;
            }
          } else if (c_.send(engine::cancel_msg(resting_, 0))) {
            resting_ = 0;
            ++sent_;
          }
        }
        if (now - next > step) ++late_;
        next = (now - next > step ? now : next) + step;
      }
      c_.poll(0);
      if (std::chrono::steady_clock::now() + std::chrono::microseconds(30) < next)
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    c_.poll(0);
  }

  OuchClient c_;
  std::thread th_;
  std::atomic<bool> run_{false};
  std::uint32_t urn_ = 0;
  std::uint32_t resting_ = 0;
  std::uint64_t sent_ = 0;
  std::uint64_t late_ = 0;
  std::size_t scanned_ = 0;          // received() messages drain() has looked at
  std::set<std::uint32_t> answered_;  // probe orders accepted or rejected
  bool cancel_due_ = false;
  bool cancel_answered_ = false;
};

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

// "YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ ..." (nlog_decode --time wall) -> UNIX ns; 0 if not.
inline std::int64_t nlog_wall_ns(const std::string& line) {
  if (line.size() < 30 || line[4] != '-' || line[10] != 'T' || line[29] != 'Z') return 0;
  std::tm t{};
  t.tm_year = std::stoi(line.substr(0, 4)) - 1900;
  t.tm_mon = std::stoi(line.substr(5, 2)) - 1;
  t.tm_mday = std::stoi(line.substr(8, 2));
  t.tm_hour = std::stoi(line.substr(11, 2));
  t.tm_min = std::stoi(line.substr(14, 2));
  t.tm_sec = std::stoi(line.substr(17, 2));
  const std::int64_t secs = static_cast<std::int64_t>(::timegm(&t));
  return secs * 1'000'000'000 + std::stoll(line.substr(20, 9));
}

class Trial {
 public:
  Trial(std::string cls, TrialOptions o) : o_(std::move(o)) { r_.cls = std::move(cls); }

  TrialResult run() {
    const auto& t = class_table();
    const auto it = t.find(r_.cls);
    if (it == t.end()) {
      fail("unknown class " + r_.cls);
      return finish();
    }
    info_ = it->second;
    partial_ = r_.cls == "F1-partial";
    if (r_.cls == "F8") o_.rejoin = false;  // nobody is lost
    if (r_.cls == "F9" && o_.probe_us == 0) {
      o_.probe_us = 5'000;  // records keep coming, so snapshots keep being written
      r_.notes.push_back("F9: probes every 5 ms (records for snapshotd to snapshot)");
    }
    std::filesystem::create_directories(o_.dir);
    if (!o_.lab_spec.empty()) {
      std::string err;
      auto spec = LabSpec::load(o_.lab_spec, &err);
      if (!spec) {
        fail("lab: " + err);
        return finish();
      }
      lab_ = std::make_unique<LabSpec>(std::move(*spec));
    }
    if (info_.lab_only && !lab_) {
      fail(r_.cls + " needs the lab's hosts (run_trials.py --lab)");
      return finish();
    }
    if (!setup()) return finish();
    if (!phase(1, o_.phase1, true)) return finish();
    if (!fault()) return finish();
    if (o_.rejoin && !rejoin()) return finish();
    if (!phase(3, o_.phase3, o_.rejoin || r_.cls == "F8")) return finish();
    wrap_up();
    return finish();
  }

 private:
  // ---- set-up ------------------------------------------------------------------------------
  bool setup() {
    r_.str["mode"] = lab_ ? "lab" : "local";
    r_.str["lab"] = lab_ ? lab_->get("lab.name", "lab") : "";
    r_.str["timestamps"] = lab_ ? lab_->get("lab.timestamps", "software") : "software";
    r_.num["probe_us"] = o_.probe_us;
    witness_ = std::make_unique<Witness>(o_.dir, o_.tie_break_ms, lab_ ? lab_->get("witness.listen") : "127.0.0.1:0");
    if (witness_->port() == 0) return fail("witnessd did not start: " + witness_->init_output() + witness_->output());
    if (lab_) {
      // The lines' groups, joined on host C's lab address; the hardware capture is the
      // lab's (capture.start), so no packet is kept here.
      const auto la = parse_endpoint(lab_->get("lines.a")), lb = parse_endpoint(lab_->get("lines.b"));
      const std::uint32_t c_ip = parse_ipv4(lab_->get("c.ip"));
      if (la.second == 0 || lb.second == 0 || c_ip == 0) return fail("lab: lines.a, lines.b and c.ip are required");
      if (!sub_.listen_line(0, la.first, la.second, c_ip) || !sub_.listen_line(1, lb.first, lb.second, c_ip))
        return fail("lab: cannot join the line groups on " + lab_->get("c.ip"));
      sub_.record(false);
      for (int n = 0; n < 2; ++n) ex_[static_cast<std::size_t>(n)] = std::make_unique<LabNode>(*lab_, n, o_.dir);
      if (!capture_start()) return false;
    } else {
      const std::uint16_t bind[2] = {free_port(SOCK_DGRAM), free_port(SOCK_DGRAM)};  // NOLINT
      relay_ = std::make_unique<UdpRelay>();
      relay_->start(bind[0], bind[1]);
      sub_.record(true);
      for (int n = 0; n < 2; ++n) {
        NodeSpec s = paired_node(n, o_.dir, sub_, witness_->port(), *relay_, bind, o_);
        if (r_.cls == "F9") s.overrides.push_back("journal.snapshot_every = 20");  // several snapshots a second
        ex_[static_cast<std::size_t>(n)] = std::make_unique<LocalNode>(s, o_.dir);
      }
    }
    r_.str["journal_a"] = ex(0).journal_dir();
    r_.str["journal_b"] = ex(1).journal_dir();
    // Both nodes start together (a primary that hears no backup for T_ack goes solo).
    ex(0).launch();
    ex(1).launch();
    if (!ex(0).wait_ready(o_.step_timeout) || !ex(1).wait_ready(o_.step_timeout))
      return fail("a node did not start:\n" + ex(0).output() + ex(1).output() + lab_error());
    refresh_servers();
    if (!wait_roles("P", "B")) return fail("no paired start: " + statuses());
    if (o_.repl_thread && ex(0).output().find("replica on its own thread") == std::string::npos)
      return fail("repl_thread requested but the node did not split: " + ex(0).output());
    if (r_.cls == "F9" && !snapshotd(true)) return false;
    for (int n : {1, 0}) {
      const std::string c = ex(n).cmd("clock 09:31:00");
      if (c.rfind("ok", 0) != 0) return fail("clock on node " + std::to_string(n) + ": " + c);
    }
    traders_[0] = Trader{"ALPHA", "alpha-pw", 0, 'S', {}};
    traders_[1] = Trader{"BRAVO", "bravo-pw", 1, 'B', {}};
    for (Trader& t : traders_) {
      for (int n = 0; n < 2; ++n) {
        t.conn[static_cast<std::size_t>(n)] = std::make_unique<OuchClient>(t.user, t.pw);
        const char c = t.conn[static_cast<std::size_t>(n)]->at(ex(n).host()).login(gw_port(n, t.gw));
        if (c != 'A') return fail(t.user + " login on node " + std::to_string(n) + ": " + std::string(1, c));
      }
    }
    // The prober's one connection is on the node that survives the fault (the takeover's
    // B, else A), so its stream is the session's whole stream.
    if (o_.probe_us > 0) {
      const int on = info_.takeover ? 1 : 0;
      const char c = prober_.login(ex(on).host(), gw_port(on, 0));
      if (c != 'A') return fail("DELTA login on node " + std::to_string(on) + ": " + std::string(1, c));
      r_.num["session_DELTA"] = 4;
      r_.str["probe_node"] = on == 0 ? "A" : "B";
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
    if (dup.at(ex(0).host()).login(gw_port(0, 0)) != 'S') fail("a second login of ALPHA on the primary's port was not refused with S");
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
    if (o_.probe_us > 0 && !prober_.running() && prober_.client().connected()) prober_.client().poll(0);
    sub_.poll(ms);
  }
  // A node's exit code, the clients and the subscriber served meanwhile.
  int wait_exit_pumping(int n) {
    const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
    for (;;) {
      const int code = ex(n).wait_exit(std::chrono::milliseconds(lab_ ? 0 : 5));
      if (code != -2 || std::chrono::steady_clock::now() >= end) return code;
      pump(5);
    }
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
    if (o_.probe_us > 0) prober_.start(o_.probe_us);  // probes flowing well before the fault
    // Senders seen so far: line A from the primary's md, line B from the backup's.
    for (int i = 0; i < 20; ++i) pump(2);
    if (sub_.sources(0).size() != 1 || sub_.sources(1).size() != 1)
      return fail("before the fault each line has one sender: " + sub_.summary());
    sender_[0] = sub_.sources(0).begin()->first;  // node A's md socket
    sender_[1] = sub_.sources(1).begin()->first;  // node B's md socket
    r_.num["sender_a_port"] = sender_[0];
    r_.num["sender_b_port"] = sender_[1];
    r_.str["sender_a_ip"] = ipv4_text(ex(0).host());
    r_.str["sender_b_ip"] = ipv4_text(ex(1).host());
    // The fault point within phase 2 (seeded).
    std::uint64_t mix = (std::uint64_t{o_.seed} + 1) * 0x9E3779B97F4A7C15ull;
    mix ^= mix >> 29;
    const std::uint32_t at = 1 + static_cast<std::uint32_t>(mix % o_.phase2);
    r_.num["fault_after_order"] = o_.phase1 + at;
    if (r_.cls == "F10" && !lab_cmd("load.start", "the background load")) return false;
    for (std::uint32_t k = o_.phase1 + 1; k <= o_.phase1 + at; ++k) send_order(k);
    pump(0);
    victim_ = info_.takeover ? 0 : 1;
    const int survivor = 1 - victim_;
    std::uint32_t next = o_.phase1 + at + 1;
    if (r_.cls == "F1-divergent") {
      // The primary goes on sequencing (and journaling) for a while without its backup;
      // nothing of it can be released. It dies before T_ack would make it go solo.
      if (!link_cut(true)) return false;
      const std::uint32_t extra = std::min<std::uint32_t>(10, o_.phase1 + o_.phase2 + 1 - next);
      for (std::uint32_t i = 0; i < extra; ++i) send_order(next++);
      const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(o_.t_ack_ms / 3);
      while (std::chrono::steady_clock::now() < until) pump(2);
      r_.num["sequenced_during_cut"] = static_cast<std::int64_t>(Control::field(ex(0).status(), "seq")) -
                                       static_cast<std::int64_t>(Control::field(ex(1).status(), "seq"));
    }
    if (r_.cls == "F9" && !wait_snapshot_in_progress()) return false;
    t_fault_ = realtime_ns();
    r_.num["t_fault_ns"] = t_fault_;
    const auto fault_steady = std::chrono::steady_clock::now();
    if (!inject()) return false;
    r_.num["t_fault_done_ns"] = realtime_ns();  // the fault command returned (lab: ssh, BMC)
    if (r_.cls == "F1-divergent" && !link_cut(false)) return false;
    if (r_.cls == "F8") return after_witness_death(next, fault_steady);
    // The survivor becomes the solo primary: B by takeover, A by SOLO (F6, F7).
    std::set<std::string> victim_roles;
    const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
    bool solo = false;
    while (!solo && std::chrono::steady_clock::now() < end) {
      solo = role(survivor) == "SP";
      if (r_.cls == "F6") victim_roles.insert(role(victim_));
      if (!solo) pump(2);
    }
    if (!solo) return fail("the survivor never became the solo primary: " + statuses() + outputs_tail());
    r_.ms["fault_to_solo_primary"] =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - fault_steady).count();
    primary_ = survivor;
    if (info_.deposed && !deposed_exit(victim_roles)) return false;
    if (r_.cls == "F4" || r_.cls == "F5") {
      if (!host_back()) return false;
    }
    if (info_.takeover) resend_unacked();
    if (r_.cls == "F7-resume") {
      // The solo primary of record restarts (10 §5 step 1): RESUME, a new epoch.
      const std::uint32_t last = std::min(o_.phase1 + o_.phase2, next + 9);
      for (; next <= last; ++next) send_order(next);
      // The probes measured F7; they stop, answered, before A dies (a probe lost with A's
      // process was never sequenced, and the prober does not re-send).
      if (o_.probe_us > 0) {
        stop_and_drain_probes();
        prober_.client().settle(300ms);
      }
      pump(1);  // some of them in flight when it dies
      ex(0).kill9();
      for (Trader& t : traders_) t.conn[0]->drop();
      const auto t0 = std::chrono::steady_clock::now();
      ex(0).launch();
      if (!ex(0).wait_ready(o_.step_timeout))
        return fail("F7-resume: the solo primary did not come back: " + ex(0).output() + lab_error());
      refresh_servers();
      if (ex(0).output().find("rejoin: resumed as the solo primary at") == std::string::npos)
        return fail("F7-resume: no RESUME: " + ex(0).output());
      const auto end2 = std::chrono::steady_clock::now() + o_.step_timeout;
      while (role(0) != "SP" && std::chrono::steady_clock::now() < end2) pump(2);
      if (role(0) != "SP") return fail("F7-resume: not the solo primary after RESUME: " + statuses());
      r_.ms["restart_to_resumed"] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
      for (Trader& t : traders_) {
        const char c = t.conn[0]->at(ex(0).host()).login(gw_port(0, t.gw));
        if (c != 'A') return fail(t.user + " login after RESUME: " + std::string(1, c));
      }
      if (o_.probe_us > 0) {
        const char c = prober_.client().at(ex(0).host()).login(gw_port(0, 0));
        if (c != 'A') return fail("DELTA login after RESUME: " + std::string(1, c));
      }
      resend_unacked();
    }
    for (std::uint32_t k = next; k <= o_.phase1 + o_.phase2; ++k) send_order(k);
    const bool ok = wait_complete(o_.phase1 + o_.phase2, false, "phase 2 (after the fault)");
    stop_and_drain_probes();
    if (r_.cls == "F10") (void)lab_cmd("load.stop", "the background load");
    return ok;
  }

  // The class's fault at t_fault_.
  bool inject() {
    const std::string& c = r_.cls;
    if (c == "F1" || c == "F1-partial" || c == "F1-divergent" || (c == "F9" && !lab_) || c == "F10" || c == "F7" ||
        c == "F7-resume") {
      ex(victim_).kill9();
    } else if (c == "F2") {
      ex(victim_).signal(SIGSTOP);
    } else if (c == "F3") {
      if (!node_cmd(victim_, "nics_down")) return false;
    } else if (c == "F4") {
      if (!node_cmd(victim_, "panic")) return false;
    } else if (c == "F5") {
      if (!node_cmd(victim_, "power_off")) return false;
    } else if (c == "F6") {
      if (!link_cut(true)) return false;
    } else if (c == "F8") {
      witness_->kill();
    }
    if (c == "F9" && lab_) {
      // On host A: waits for snapshotd's .snap.tmp, then SIGKILLs the node ("caught").
      if (!node_cmd(victim_, "kill_during_snapshot", std::chrono::milliseconds(120'000))) return false;
      r_.num["snapshot_in_progress"] = r_.str["cmd_A_kill_during_snapshot"].find("caught") != std::string::npos ? 1 : 0;
    }
    if (c != "F6" && c != "F8" && c != "F2" && c != "F3") {
      for (Trader& t : traders_) t.conn[static_cast<std::size_t>(victim_)]->drop();
      refresh_servers();
    }
    return true;
  }

  // F2, F3, F6: the cut-off node lives on; once it hears of the new epoch it must exit
  // as deposed (10 §4) without End of Session. F2 and F3 hear of it when they run or are
  // reachable again; F6's backup hears it from the witness with the link still cut (its
  // PROMOTE is refused while W hears A), and the link comes back for the rejoin.
  bool deposed_exit(const std::set<std::string>& victim_roles) {
    if (r_.cls == "F2") ex(victim_).signal(SIGCONT);
    if (r_.cls == "F3" && !node_cmd(victim_, "nics_up")) return false;
    const int code = wait_exit_pumping(victim_);
    if (r_.cls == "F6" && !link_cut(false)) return false;
    r_.num["deposed_exit_code"] = code;
    if (code != 3) fail(r_.cls + ": the cut-off node did not exit as deposed (exit " + std::to_string(code) + ")");
    for (const std::string& r : victim_roles)
      if (r == "SP" || r == "P") fail(r_.cls + ": the cut-off backup became " + r);
    for (Trader& t : traders_) t.conn[static_cast<std::size_t>(victim_)]->drop();
    refresh_servers();
    return true;
  }

  // F8: the pair goes on without a witness: no grant, no role change, phase 2 trades on
  // both nodes. Three detector timeouts of service are watched before phase 2 completes.
  bool after_witness_death(std::uint32_t next, std::chrono::steady_clock::time_point fault_steady) {
    const auto watch = fault_steady + std::chrono::milliseconds(3 * o_.t_d_ms);
    std::set<std::string> roles_a, roles_b;
    for (std::uint32_t k = next; k <= o_.phase1 + o_.phase2; ++k) {
      send_order(k);
      if (k % 10 == 0) pump(1);
    }
    while (std::chrono::steady_clock::now() < watch) {
      roles_a.insert(role(0));
      roles_b.insert(role(1));
      pump(5);
    }
    const bool ok = wait_complete(o_.phase1 + o_.phase2, true, "F8: phase 2 without a witness");
    roles_a.insert(role(0));
    roles_b.insert(role(1));
    auto join = [](const std::set<std::string>& s) {
      std::string o;
      for (const auto& x : s) o += (o.empty() ? "" : ",") + x;
      return o;
    };
    r_.str["f8_roles_a"] = join(roles_a);
    r_.str["f8_roles_b"] = join(roles_b);
    if (roles_a != std::set<std::string>{"P"} || roles_b != std::set<std::string>{"B"})
      fail("F8: roles changed without a witness: A " + join(roles_a) + ", B " + join(roles_b));
    // Plan 10 §7 also asks for an alarm within 10 ms: the replica has no witness liveness
    // check (it talks to W only to request an epoch), so there is nothing to alarm on.
    r_.notes.push_back("F8: no alarm criterion: the replica does not watch the witness between requests");
    stop_and_drain_probes();
    return ok;
  }

  // F9: waits (up to the step timeout) until snapshotd is writing a snapshot of A's
  // journal; on this host snapshotd is started here, in the lab by the F9 command.
  bool wait_snapshot_in_progress() {
    if (lab_) return true;  // node.A.kill_during_snapshot does the waiting on host A
    const std::string snaps = ex(0).snapshots_dir();
    const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
    while (std::chrono::steady_clock::now() < end) {
      std::error_code ec;
      for (const auto& e : std::filesystem::directory_iterator(snaps, ec))
        if (e.path().filename().string().ends_with(".snap.tmp")) {
          r_.num["snapshot_in_progress"] = 1;
          return true;
        }
      pump(0);
    }
    return fail("F9: snapshotd wrote no snapshot to kill A during (" + snaps + ")");
  }

  // F4, F5: the primary's host comes back (power on after F5); the node is restarted by
  // the rejoin.
  bool host_back() {
    if (r_.cls == "F5" && !node_cmd(victim_, "power_on")) return false;
    const auto t0 = std::chrono::steady_clock::now();
    if (!node_cmd(victim_, "wait_up", std::chrono::milliseconds(900'000))) return false;
    r_.ms["host_back"] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    return true;
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
    const auto t0 = std::chrono::steady_clock::now();
    ex(victim_).launch();
    if (!ex(victim_).wait_ready(o_.step_timeout))
      return fail("the restarted node did not come up: " + ex(victim_).output() + lab_error());
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
      const char c = t.conn[static_cast<std::size_t>(victim_)]->at(ex(victim_).host()).login(gw_port(victim_, t.gw));
      if (c != 'A') return fail(t.user + " mirror login on the rejoined node: " + std::string(1, c));
    }
    return wait_complete(o_.phase1 + o_.phase2, true, "mirror catch-up after the rejoin");
  }

  // ---- the end of the trial and the oracles ------------------------------------------------
  void wrap_up() {
    const int backup = 1 - primary_;
    // Every probe answered before the primary's counts are read: answers still queued
    // add records (and ITCH) after them.
    if (o_.probe_us > 0 && !prober_.drain(o_.step_timeout)) r_.notes.push_back("DELTA's probes did not all drain");
    const std::string s = ex(primary_).cmd("sync");
    if (s.rfind("ok", 0) != 0) fail("sync on the primary: " + s);
    const bool paired_end = o_.rejoin || r_.cls == "F8";
    if (paired_end) {
      const std::uint64_t want = Control::field(ex(primary_).status(), "seq");
      const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
      while (Control::field(ex(backup).status(), "seq") < want && std::chrono::steady_clock::now() < end) pump(2);
      if (Control::field(ex(backup).status(), "seq") < want) fail("the backup did not catch up: " + statuses());
    }
    const std::uint64_t itch = Control::field(ex(primary_).status(), "itch");
    if (!sub_.wait_messages(itch, std::chrono::milliseconds(o_.step_timeout)))
      fail("feed incomplete: " + sub_.summary() + " of " + std::to_string(itch));
    for (int i = 0; i < 20; ++i) pump(2);
    if (o_.probe_us > 0) prober_.client().settle(300ms);  // the last probes' answers
    r_.str["final_primary"] = primary_ == 0 ? "A" : "B";
    r_.num["line_a_port"] = lab_ ? parse_endpoint(lab_->get("lines.a")).second : sub_.port_a();
    r_.num["line_b_port"] = lab_ ? parse_endpoint(lab_->get("lines.b")).second : sub_.port_b();
    if (lab_) {
      r_.str["line_a"] = lab_->get("lines.a");
      r_.str["line_b"] = lab_->get("lines.b");
    }
    // Artifacts for the independent checker.
    if (!lab_) (void)sub_.write_capture((o_.dir / "capture.pcap").string());
    (void)sub_.write_binary_file((o_.dir / "feed.bin").string());
    std::filesystem::create_directories(o_.dir / "clients");
    auto save = [&](const std::string& name, const Bytes& b) {
      std::ofstream((o_.dir / "clients" / name).string(), std::ios::binary)
          .write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
    };
    for (Trader& t : traders_)
      for (int n = 0; n < 2; ++n) save(t.user + "." + (n == 0 ? "A" : "B") + ".bin", t.conn[static_cast<std::size_t>(n)]->stream());
    if (o_.probe_us > 0) save("DELTA.bin", prober_.client().stream());
    // What the witness granted, before the nodes stop (a node left alone for T_ack or T_d
    // would ask for more).
    grants_ = {witness_->count("PROMOTE granted"), witness_->count("SOLO granted"), witness_->count("JOIN granted"),
               witness_->count("RESUME granted")};
    // Both stop at once, so neither outlives its partner long enough to react.
    for (int n : {backup, primary_})
      if (ex(n).running()) (void)ex(n).cmd("shutdown", 5'000);
    for (int n : {backup, primary_}) {
      const int code = wait_exit_pumping(n);
      if (code != 0) fail("node " + std::string(n == 0 ? "A" : "B") + " stopped with " + std::to_string(code));
    }
    if (r_.cls == "F9") (void)snapshotd(false);
    if (lab_) {
      capture_stop();
      for (int n : {0, 1})
        if (!ex(n).collect()) fail("lab: collecting node " + ex(n).name() + "'s journal failed: " + lab_error());
    }
    r_.str["final_primary_journal"] = ex(primary_).journal_dir();
    r_.str["journal_a"] = ex(0).journal_dir();
    r_.str["journal_b"] = ex(1).journal_dir();
    oracles();
    takeover_positions();
    breakdown();
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
    // The probes: every probe order answered exactly once (accepted or rejected), none
    // executed (149.00 never crosses). An order with no answer at all is lost: the engine
    // took a later UserRefNum of the session first and ignored it as a resend.
    if (o_.probe_us > 0) {
      Ledger ld;
      std::map<std::uint32_t, int> rejected;
      for (const Received& rc : prober_.client().received()) {
        ld.add(Ouch{rc.msg});
        if (Ouch{rc.msg}.type() == 'J') ++rejected[Ouch{rc.msg}.urn()];
      }
      std::uint32_t unanswered = 0, first = 0, last = 0;
      for (std::uint32_t u = 1; u <= prober_.entered(); ++u) {
        const int answers = (ld.accepted.contains(u) ? ld.accepted.at(u) : 0) + (rejected.contains(u) ? rejected.at(u) : 0);
        if (answers > 1) fail("O-LEDGER: DELTA probe " + std::to_string(u) + " answered " + std::to_string(answers) + " times");
        if (answers == 0) {
          if (unanswered++ == 0) first = u;
          last = u;
        }
      }
      r_.num["probes_unanswered"] = unanswered;
      if (unanswered != 0)
        fail("O-LEDGER: " + std::to_string(unanswered) + " DELTA probe orders got no answer (UserRefNums " + std::to_string(first) +
             ".." + std::to_string(last) + ")");
      if (!ld.executions.empty()) fail("O-LEDGER: DELTA's probes executed");
      r_.num["probes_sent"] = static_cast<std::int64_t>(prober_.sent());
      r_.num["probes_late"] = static_cast<std::int64_t>(prober_.late());
      r_.num["probes_tx_waits"] = static_cast<std::int64_t>(prober_.client().tx_waits());
      r_.num["probes_tx_refused"] = static_cast<std::int64_t>(prober_.client().tx_refused());
      r_.num["probes_accepted"] = static_cast<std::int64_t>(ld.accepted.size());
    }

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
    if (o_.probe_us > 0) {
      const OuchClient& d = prober_.client();
      if (d.duplicates() + d.gaps() != 0) fail("O-STREAM: DELTA saw duplicates or gaps");
      if (rg.ouch.count(4) == 0 || rg.ouch.at(4) != d.stream()) fail("O-STREAM: DELTA's stream differs from the regeneration");
    }

    // O-MOLD
    const std::vector<Bytes>& feed = sub_.messages();
    r_.num["feed_messages"] = static_cast<std::int64_t>(feed.size());
    if (feed != rg.itch)
      fail("O-MOLD: the assembled feed (" + std::to_string(feed.size()) + ") differs from the ITCH regeneration (" +
           std::to_string(rg.itch.size()) + ")");
    if (!lab_) mold_lines(rg.itch);  // the lab's line packets are in its capture: check_trial_oracles.py

    // O-JOURNAL
    if (o_.rejoin || r_.cls == "F8") {
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
    if (info_.takeover && (promotes != 1 || solos != 0)) fail("O-CLASS: expected one PROMOTE grant and no SOLO");
    if (info_.solo && (promotes != 0 || solos != 1)) fail("O-CLASS: expected one SOLO grant and no PROMOTE (no takeover)");
    if (r_.cls == "F8" && promotes + solos + joins + resumes != 0) fail("O-CLASS: F8: the witness granted an epoch");
    if (o_.rejoin && joins != 1) fail("O-CLASS: expected one JOIN grant, got " + std::to_string(joins));
    const std::size_t want_resumes = r_.cls == "F7-resume" ? 1 : 0;
    if (resumes != want_resumes) fail("O-CLASS: " + std::to_string(resumes) + " RESUME grants, expected " + std::to_string(want_resumes));
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

  // The takeover's place in the final primary's journal: the new epoch's EpochStart, the
  // first ITCH sequence number of its records (T_new: analyze_pcap.py --new-epoch-seq) and
  // the first order acknowledgement of the new epoch (T_first_new_order_ack: client
  // receive time - fault time, both this host's clock). On this host also the line-A
  // takeover from the software capture (T_takeover, T_new: indicative).
  void takeover_positions() {
    if (!info_.takeover) return;
    auto d = journal::PosixSegmentDir::open(ex(primary_).journal_dir(), false, journal::PosixDeviceOptions{.read_only = true});
    if (!d) {
      fail("cannot open the final primary's journal: " + d.error());
      return;
    }
    std::uint64_t es_index = 0;
    std::uint32_t es_epoch = 0;
    std::set<std::pair<std::uint32_t, std::uint32_t>> new_orders;  // (session, UserRefNum) entered after it
    (void)journal::read_journal(*d, journal::ReadOptions{}, [&](const journal::RecordView& r, const journal::RecordLocation&) {
      if (es_index == 0 && r.type() == journal::RecordType::EpochStart) {
        if (const auto e = journal::decode_epoch_start(r); e && e->epoch > 1) {
          es_index = r.index();
          es_epoch = e->epoch;
        }
        return true;
      }
      if (es_index != 0 && r.type() == journal::RecordType::OuchInbound) {
        if (const auto in = journal::decode_ouch_inbound(r); in && in->msg.size() >= 5 && static_cast<char>(in->msg[0]) == 'O')
          new_orders.emplace(in->session_id, load_be32(in->msg.data() + 1));
      }
      return true;
    });
    if (es_index == 0) {
      fail("no EpochStart of a new epoch in the final primary's journal");
      return;
    }
    r_.num["new_epoch"] = es_epoch;
    r_.num["new_epoch_index"] = static_cast<std::int64_t>(es_index);
    // ITCH messages of the records up to the EpochStart.
    const std::string itch = (o_.dir / "regen" / "upto-epoch.itch").string();
    int code = 0;
    const std::string out = run_capture({LLE_JOURNAL_REPLAY, ex(primary_).journal_dir(), "--to", std::to_string(es_index), "--emit", itch}, &code);
    if (code != 0) {
      fail("journal_replay --to " + std::to_string(es_index) + " failed: " + out);
      return;
    }
    std::uint64_t before = 0;
    {
      const Bytes b = slurp(itch);
      for (std::size_t at = 0; at + 2 <= b.size();) {
        const std::size_t len = load_be16(b.data() + at);
        if (len == 0) break;
        ++before;
        at += 2 + len;
      }
    }
    const SeqNo first_new = before + 1;
    r_.num["new_epoch_first_itch_seq"] = static_cast<std::int64_t>(first_new);
    // The first acknowledgement of an order sequenced in the new epoch, on any connection.
    std::int64_t first_ack = 0;
    auto scan = [&](std::uint32_t session, const OuchClient& c) {
      for (const Received& rc : c.received()) {
        const Ouch m{rc.msg};
        if (m.type() == 'A' && new_orders.contains({session, m.urn()}) && (first_ack == 0 || rc.rx_ns < first_ack))
          first_ack = rc.rx_ns;
      }
    };
    scan(1, *traders_[0].conn[0]);
    scan(1, *traders_[0].conn[1]);
    scan(2, *traders_[1].conn[0]);
    scan(2, *traders_[1].conn[1]);
    if (o_.probe_us > 0) scan(4, prober_.client());
    if (first_ack != 0) r_.ms["t_first_new_order_ack"] = static_cast<double>(first_ack - t_fault_) / 1e6;
    if (lab_) return;  // the lab's line timings come from its capture (analyze_pcap.py)
    // Software capture (kernel receive times, this host's clock, like the fault time):
    // T_takeover = the new primary's first line-A packet - the old primary's last line-A
    // packet before the fault took effect (plan 10 §7; the fault command had returned by
    // t_fault_done: a stopped node's packets after SIGCONT do not count); T_new from the
    // same point to the first line-A packet carrying a message of the new epoch's records.
    const std::int64_t done = r_.num["t_fault_done_ns"];
    std::int64_t last_old = 0, first_b = 0, first_new_out = 0;
    for (const auto& p : sub_.packet_log()) {
      if (p.line != 0) continue;
      if (p.sender == sender_[1] && first_b == 0 && p.rx_ns > t_fault_) first_b = p.rx_ns;
      if (p.sender == sender_[0] && p.rx_ns <= done) last_old = std::max(last_old, p.rx_ns);
      if (p.sender == sender_[1] && first_new_out == 0 && p.rx_ns > t_fault_) {
        if (const auto v = mold::PacketView::parse(p.bytes); v && v->message_count() > 0 && v->end_seq() > first_new)
          first_new_out = p.rx_ns;
      }
    }
    if (first_b == 0) fail("no line-A packet from the new primary");
    if (last_old != 0 && first_b != 0) r_.ms["t_takeover"] = static_cast<double>(first_b - last_old) / 1e6;
    if (first_b != 0) r_.ms["fault_to_first_line_a"] = static_cast<double>(first_b - t_fault_) / 1e6;
    if (last_old != 0 && first_new_out != 0) r_.ms["t_new"] = static_cast<double>(first_new_out - last_old) / 1e6;
    // F2: the deposed primary's late packets carry nothing of the new epoch.
    if (r_.cls == "F2") {
      std::int64_t late = 0, bad = 0;
      for (const auto& p : sub_.packet_log()) {
        if (p.sender != sender_[0] || first_b == 0 || p.rx_ns <= first_b) continue;
        if (const auto v = mold::PacketView::parse(p.bytes); v && v->message_count() > 0) {
          ++late;
          if (v->end_seq() > first_new) ++bad;
        }
      }
      r_.num["deposed_late_packets"] = late;
      if (bad != 0) fail("F2: the deposed primary sent " + std::to_string(bad) + " packets with output of the new epoch");
    }
  }

  // The survivor's view of its takeover or SOLO from its nlog: frozen, PROMOTE or SOLO
  // sent, the grant applied; durations on the survivor's own log clock. Fault to freeze
  // (the detection) compares this host's fault time with the nlog's wall time, which
  // nlog_decode derives from TSC calibration records: two clocks even on one host (in the
  // VM they differed by tens of ms), so it is recorded as xclock_ and is indicative only.
  void breakdown() {
    if (r_.cls == "F8") return;
    const std::string path = ex(primary_).nlog_path();
    if (!std::filesystem::exists(path)) {
      r_.notes.push_back("no nlog of the survivor at " + path);
      return;
    }
    const std::string text = run_capture({LLE_NLOG_DECODE, "--time", "wall", path});
    std::int64_t frozen = 0, request = 0, granted = 0;
    std::istringstream in(text);
    for (std::string line; std::getline(in, line);) {
      const std::int64_t t = nlog_wall_ns(line);
      if (t == 0 || t < t_fault_ - 1'000'000'000) continue;
      if (frozen == 0 && line.find("repl: frozen at") != std::string::npos) frozen = t;
      if (request == 0 && (line.find("repl: PROMOTE from epoch") != std::string::npos ||
                           line.find("repl: SOLO from epoch") != std::string::npos))
        request = t;
      if (granted == 0 && request != 0 && line.find("repl: granted epoch") != std::string::npos) granted = t;
    }
    auto ms = [](std::int64_t a, std::int64_t b) { return static_cast<double>(b - a) / 1e6; };
    if (frozen != 0) r_.ms["xclock_fault_to_freeze"] = ms(t_fault_, frozen);
    if (frozen != 0 && request != 0) r_.ms["nlog_freeze_to_request"] = ms(frozen, request);
    if (request != 0 && granted != 0) r_.ms["nlog_request_to_grant"] = ms(request, granted);
  }

  // ---- helpers ------------------------------------------------------------------------------
  TrialNode& ex(int n) { return *ex_[static_cast<std::size_t>(n)]; }
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
    const int a = p[0] != 0 ? 0 : 1, b = p[1] != 0 ? 1 : 0;
    sub_.set_servers(p[a], p[b], ex(a).host(), ex(b).host());
  }
  std::string statuses() { return "[A " + ex(0).status() + "] [B " + ex(1).status() + "]"; }
  // The last lines each node printed (a node that died says why there).
  std::string outputs_tail(std::size_t n = 1500) {
    std::string r;
    for (int i = 0; i < 2; ++i) {
      const std::string out = ex(i).output();
      r += std::string("\n--- ") + (i == 0 ? "A" : "B") + " output (last " + std::to_string(n) + " bytes) ---\n" +
           (out.size() > n ? out.substr(out.size() - n) : out);
    }
    return r;
  }
  bool wait_roles(const std::string& a, const std::string& b) {
    const auto end = std::chrono::steady_clock::now() + o_.step_timeout;
    while (std::chrono::steady_clock::now() < end) {
      if (role(0) == a && role(1) == b) return true;
      pump(5);
    }
    return false;
  }
  void stop_probes() {
    if (o_.probe_us > 0) prober_.stop();
  }
  // Stops the probes and waits until the node has answered every one (Prober::drain).
  void stop_and_drain_probes() {
    if (o_.probe_us == 0) return;
    prober_.stop();
    if (!prober_.drain(o_.step_timeout)) r_.notes.push_back("DELTA's probes did not all drain");
  }
  // F9: snapshotd following A's journal (here a child process; in the lab the
  // node.A.snapshotd_start / snapshotd_stop commands).
  bool snapshotd(bool on) {
    if (lab_) return node_cmd(0, on ? "snapshotd_start" : "snapshotd_stop");
    if (!on) {
      if (snapd_) snapd_->kill(SIGTERM);
      return true;
    }
    snapd_ = std::make_unique<Process>(
        LLE_SNAPSHOTD,
        std::vector<std::string>{"--journal", ex(0).journal_dir(), "--snapshots", ex(0).snapshots_dir(), "--day", "20261001",
                                 "--follow", "--poll-ms", "1"},
        (o_.dir / "snapshotd.out").string());
    return snapd_->pid() > 0 ? true : fail("F9: snapshotd did not start");
  }
  // The A-B link: the relay here, the lab's link.cut / link.heal commands there.
  bool link_cut(bool on) {
    if (!lab_) {
      relay_->cut(on);
      return true;
    }
    return lab_cmd(on ? "link.cut" : "link.heal", on ? "the A-B link cut" : "the A-B link restore");
  }
  // A lab command of node n (node.X.<what>); a failure is a violation.
  bool node_cmd(int n, const std::string& what, std::chrono::milliseconds timeout = std::chrono::milliseconds(60'000)) {
    auto* node = dynamic_cast<LabNode*>(ex_[static_cast<std::size_t>(n)].get());
    if (node == nullptr) return fail(r_.cls + ": node." + ex(n).name() + "." + what + " needs the lab");
    const ShResult r = node->sh(what, {{"seed", std::to_string(o_.seed)}}, timeout);
    if (r.code != 0) return fail("lab: node." + ex(n).name() + "." + what + ": exit " + std::to_string(r.code) + (r.timed_out ? " (timeout)" : "") + ": " + r.out);
    r_.str["cmd_" + ex(n).name() + "_" + what] = r.out.substr(0, r.out.find('\n'));
    return true;
  }
  // A lab command that is not a node's (link.*, load.*, capture.*).
  bool lab_cmd(const std::string& key, const std::string& what,
               std::map<std::string, std::string> vars = {}, std::chrono::milliseconds timeout = std::chrono::milliseconds(60'000)) {
    if (!lab_ || !lab_->has(key)) return fail(what + ": the lab describes no " + key);
    vars.emplace("trial", o_.dir.string());
    vars.emplace("seed", std::to_string(o_.seed));
    const ShResult r = run_sh(lab_->expand(key, vars), timeout, o_.dir / "sh");
    if (r.code != 0) return fail(what + " (" + key + "): exit " + std::to_string(r.code) + (r.timed_out ? " (timeout)" : "") + ": " + r.out);
    return true;
  }
  // The lab's capture of both lines on host C (capture.start runs in the background and
  // writes {pcap}; capture.stop ends it; the tool's drop report goes to {stderr}).
  bool capture_start() {
    const std::map<std::string, std::string> v = {{"pcap", (o_.dir / "capture.pcap").string()},
                                                  {"stderr", (o_.dir / "capture.stderr").string()}};
    if (!lab_cmd("capture.start", "the line capture", v)) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(lab_->get_int("capture.settle_ms", 1'000)));
    return true;
  }
  void capture_stop() {
    const std::map<std::string, std::string> v = {{"pcap", (o_.dir / "capture.pcap").string()},
                                                  {"stderr", (o_.dir / "capture.stderr").string()}};
    (void)lab_cmd("capture.stop", "the line capture", v);
    // tcpdump: "N packets dropped by kernel", "N packets dropped by interface".
    std::ifstream f(o_.dir / "capture.stderr");
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string text = ss.str();
    std::int64_t drops = -1;
    for (const char* what : {" packets dropped by kernel", " packets dropped by interface"}) {
      const auto at = text.rfind(what);
      if (at == std::string::npos) continue;
      const auto b = text.find_last_not_of("0123456789", at - 1);
      const std::string count = text.substr(b == std::string::npos ? 0 : b + 1, at - (b == std::string::npos ? 0 : b + 1));
      if (!count.empty()) drops = (drops < 0 ? 0 : drops) + std::stoll(count);
    }
    r_.num["capture_drops"] = drops;  // -1: no drop report (the run is not valid for T25)
    if (drops != 0) r_.notes.push_back("capture drops " + std::to_string(drops) + ": invalid for T25");
  }
  std::string lab_error() {
    std::string e;
    for (const auto& n : ex_)
      if (auto* l = dynamic_cast<LabNode*>(n.get()); l != nullptr && !l->last_error().empty())
        e += " [" + l->name() + ": " + l->last_error() + "]";
    return e;
  }
  bool fail(const std::string& m) {
    r_.violations.push_back(m);
    return false;
  }
  TrialResult finish() {
    stop_probes();
    r_.pass = r_.violations.empty();
    r_.num["relay_dropped"] = relay_ ? static_cast<std::int64_t>(relay_->dropped()) : 0;
    r_.str["dir"] = o_.dir.string();
    std::ofstream((o_.dir / "trial.json").string()) << r_.json();
    return r_;
  }

  TrialOptions o_;
  TrialResult r_;
  ClassInfo info_{};
  bool partial_ = false;
  std::unique_ptr<LabSpec> lab_;
  std::unique_ptr<Witness> witness_;
  std::unique_ptr<UdpRelay> relay_;
  MoldSubscriber sub_;
  std::array<std::unique_ptr<TrialNode>, 2> ex_;
  std::array<Trader, 2> traders_;
  Prober prober_;
  std::unique_ptr<Process> snapd_;
  int primary_ = 0;
  int victim_ = 1;
  std::uint32_t sent_ = 0;
  std::uint16_t sender_[2] = {0, 0};
  std::int64_t t_fault_ = 0;
  std::array<std::size_t, 4> grants_{};  // PROMOTE, SOLO, JOIN, RESUME
};

}  // namespace detail

// A trial that never reached its paired start never tested a failover, and two causes
// lie outside the exchange: a node's port was taken before it bound it (rare now that
// free_port claims its ports), or (a loaded sanitizer build) the backup came up
// more than T_ack after the primary, which went solo and deposed it. Such a trial is
// repeated, in a fresh directory with new ports (at most twice); a start that fails
// every time still fails the test.
inline TrialResult run_trial(const std::string& cls, const TrialOptions& o) {
  std::vector<std::string> repeated;
  for (int attempt = 0;; ++attempt) {
    TrialOptions a = o;
    if (attempt > 0) a.dir = o.dir / ("retry" + std::to_string(attempt));
    TrialResult r = detail::Trial(cls, a).run();
    const auto it = std::find_if(r.violations.begin(), r.violations.end(), [](const std::string& v) {
      return (v.rfind("a node did not start", 0) == 0 && v.find("Address already in use") != std::string::npos) ||
             v.rfind("no paired start", 0) == 0;
    });
    if (r.pass || it == r.violations.end() || attempt == 2) {
      for (const std::string& n : repeated) r.notes.push_back("start repeated: " + n);
      return r;
    }
    repeated.push_back(it->substr(0, 200));
  }
}

}  // namespace lle::exch::test::ha
