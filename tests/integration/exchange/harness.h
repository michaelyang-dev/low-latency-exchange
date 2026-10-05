#pragma once
// End-to-end harness for exchanged on one host over loopback (07 §3, N-03): process
// control, a configuration writer, an OUCH client built from the SoupBinTCP and OUCH
// cores, a MoldUDP64 subscriber built from the line arbiter (lines A and B plus
// re-requests), the dev control port and the authenticated admin port.
//
// Everything is event driven with timeouts (the processes are real and the network is
// the kernel's): a helper waits for a condition and fails the test with what it saw.
//
// Addresses: the node's endpoints are on LLE_E2E_HOST and the test's own sockets (feed
// lines, re-request and client sockets) on LLE_E2E_PEER_HOST, both 127.0.0.1 unless set.
// The AF_XDP variant's suite (xsk_e2e.sh) runs the node in another network namespace
// (LLE_E2E_NETNS) behind a veth whose kernel addresses these are.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "admin/commands.h"
#include "admin/net.h"
#include "admin/protocol.h"
#include "common/endian.h"
#include "env/prod_clock.h"
#include "proto/moldudp64/line_arbiter.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/ouch50/ouch50.h"
#include "proto/soupbin/client_session.h"

extern char** environ;

namespace lle::exch::test {

using Bytes = std::vector<std::byte>;
using namespace std::chrono_literals;

inline Nanos mono() { return env::ProdClock{}.now_mono(); }

// ---- addresses (see the file comment) ---------------------------------------------------

inline std::uint32_t env_ipv4(const char* var) {
  const char* v = std::getenv(var);
  in_addr a{};
  if (v == nullptr || ::inet_pton(AF_INET, v, &a) != 1) return 0x7F000001u;
  return ntohl(a.s_addr);
}
// The node's address (host order) and as text.
inline std::uint32_t e2e_host() { return env_ipv4("LLE_E2E_HOST"); }
// The test's own address: where the node sends the feed lines.
inline std::uint32_t e2e_peer_host() { return env_ipv4("LLE_E2E_PEER_HOST"); }
inline std::string ipv4_text(std::uint32_t a) {
  return std::to_string(a >> 24) + "." + std::to_string((a >> 16) & 0xFF) + "." + std::to_string((a >> 8) & 0xFF) + "." +
         std::to_string(a & 0xFF);
}
inline std::string e2e_host_text() { return ipv4_text(e2e_host()); }
inline std::string e2e_peer_text() { return ipv4_text(e2e_peer_host()); }
// Wall-clock nanoseconds (capture timestamps, fault times in trial records).
inline std::int64_t realtime_ns() {
  timespec ts{};
  ::clock_gettime(CLOCK_REALTIME, &ts);
  return static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec;
}

// A peer that died (a killed node) must not kill the test with SIGPIPE on the next send.
inline const bool kSigpipeIgnored = [] {
  std::signal(SIGPIPE, SIG_IGN);
  return true;
}();

// ---- small socket helpers --------------------------------------------------------------

inline std::uint16_t free_port(int type) {
  const int s = ::socket(AF_INET, type, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(e2e_peer_host());
  ::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a);
  socklen_t len = sizeof a;
  ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
  ::close(s);
  return ntohs(a.sin_port);
}

inline int udp_bound(std::uint16_t port) {
  const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
  int big = 4 << 20;
  ::setsockopt(s, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(e2e_peer_host());
  if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
    ::close(s);
    return -1;
  }
  ::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL, 0) | O_NONBLOCK);
  return s;
}

inline std::uint16_t local_port(int s) {
  sockaddr_in a{};
  socklen_t len = sizeof a;
  ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
  return ntohs(a.sin_port);
}

// ---- processes ---------------------------------------------------------------------------

// A child process with stdout+stderr captured into a file; parses "key=value" tokens of
// its output on demand.
class Process {
 public:
  Process(const std::string& exe, std::vector<std::string> args, const std::string& log_path) : log_(log_path) {
    args.insert(args.begin(), exe);
    std::vector<char*> argv;
    for (auto& s : args) argv.push_back(s.data());
    argv.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    const int rc = posix_spawn(&pid_, exe.c_str(), &fa, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) pid_ = -1;
  }
  ~Process() { kill(SIGKILL); }
  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;

  [[nodiscard]] bool alive() {
    if (pid_ <= 0) return false;
    int st = 0;
    const pid_t r = ::waitpid(pid_, &st, WNOHANG);
    if (r == pid_) {
      status_ = st;
      pid_ = -1;
      return false;
    }
    return true;
  }
  void kill(int sig) {
    if (pid_ <= 0) return;
    ::kill(pid_, sig);
    int st = 0;
    ::waitpid(pid_, &st, 0);
    status_ = st;
    pid_ = -1;
  }
  // Exit code after the process ended (-1 if killed by a signal or still running).
  int wait_exit(std::chrono::milliseconds timeout) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (alive() && std::chrono::steady_clock::now() < end) std::this_thread::sleep_for(5ms);
    if (pid_ > 0) return -2;
    return WIFEXITED(status_) ? WEXITSTATUS(status_) : -1;
  }
  [[nodiscard]] std::string output() const {
    std::ifstream f(log_);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
  }
  // Waits for "token" to appear in the output; returns the output.
  bool wait_output(const std::string& token, std::chrono::milliseconds timeout) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < end) {
      if (output().find(token) != std::string::npos) return true;
      if (!alive()) return output().find(token) != std::string::npos;
      std::this_thread::sleep_for(5ms);
    }
    return false;
  }
  // The port of the last "name=A.B.C.D:P" in the output.
  [[nodiscard]] std::uint16_t port_of(const std::string& name) const {
    const std::string out = output();
    const std::string key = " " + name + "=";
    for (auto at = out.rfind(key); at != std::string::npos; at = at == 0 ? std::string::npos : out.rfind(key, at - 1)) {
      const auto colon = out.find(':', at + key.size());
      const auto end = out.find_first_of(" \n", at + key.size());
      if (colon == std::string::npos || (end != std::string::npos && colon > end)) continue;
      return static_cast<std::uint16_t>(std::stoul(out.substr(colon + 1)));
    }
    return 0;
  }
  [[nodiscard]] pid_t pid() const noexcept { return pid_; }

 private:
  std::string log_;
  pid_t pid_ = -1;
  int status_ = 0;
};

inline std::string run_capture(const std::vector<std::string>& args, int* exit_code = nullptr) {
  std::string cmd;
  for (const auto& a : args) cmd += "'" + a + "' ";
  std::string out;
  if (FILE* p = ::popen((cmd + "2>&1").c_str(), "r")) {
    char buf[512];
    while (std::fgets(buf, sizeof buf, p)) out += buf;
    const int st = ::pclose(p);
    if (exit_code != nullptr) *exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
  }
  return out;
}

// ---- control port --------------------------------------------------------------------------

class Control {
 public:
  explicit Control(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(e2e_host());
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }
  ~Control() {
    if (fd_ >= 0) ::close(fd_);
  }
  [[nodiscard]] bool ok() const { return fd_ >= 0; }
  std::string cmd(const std::string& line) {
    if (fd_ < 0) return "err not connected";
    const std::string l = line + "\n";
    if (::send(fd_, l.data(), l.size(), 0) != static_cast<ssize_t>(l.size())) return "err send";
    std::string reply;
    char c;
    for (;;) {
      pollfd p{fd_, POLLIN, 0};
      if (::poll(&p, 1, 90'000) != 1) return "err timeout";
      if (::recv(fd_, &c, 1, 0) != 1) return "err closed";
      if (c == '\n') return reply;
      reply += c;
    }
  }
  // "ok N" -> N
  static std::uint64_t value(const std::string& reply) {
    return reply.rfind("ok ", 0) == 0 ? std::stoull(reply.substr(3)) : 0;
  }
  static std::uint64_t field(const std::string& status, const std::string& key) {
    const auto at = status.find(" " + key + "=");
    if (at == std::string::npos) return 0;
    return std::stoull(status.substr(at + key.size() + 2));
  }

 private:
  int fd_ = -1;
};

// ---- OUCH over SoupBinTCP ------------------------------------------------------------------

struct Received {
  SeqNo seq = 0;
  Bytes msg;
};

class OuchClient {
 public:
  OuchClient(std::string user, std::string password) : user_(std::move(user)), password_(std::move(password)) {}
  ~OuchClient() { drop(); }
  OuchClient(const OuchClient&) = delete;
  OuchClient& operator=(const OuchClient&) = delete;

  // Connects and logs in requesting `next` (default: the next expected message). Returns
  // the login outcome: 'A' accepted, 'J' + reason, or 'X' on a connection failure.
  char login(std::uint16_t port, std::optional<SeqNo> next = std::nullopt, std::chrono::milliseconds timeout = 5s) {
    drop();
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    const int one = 1;
    ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(e2e_host());
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
      drop();
      return 'X';
    }
    ::fcntl(fd_, F_SETFL, ::fcntl(fd_, F_GETFL, 0) | O_NONBLOCK);
    soup::ClientConfig c;
    c.username = Alpha<soup::kUsernameLen>(user_);
    c.password = Alpha<soup::kPasswordLen>(password_);
    c.sequence = next.value_or(next_expected_);
    c.heartbeat_interval = 200'000'000;
    c.idle_timeout = 60 * kNsPerSec;
    sess_ = std::make_unique<soup::ClientSession>(c);
    logged_in_ = false;
    accepted_ = false;
    rejected_ = 0;
    ended_ = false;
    handle(sess_->connect(mono()));
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (!accepted_ && rejected_ == 0 && fd_ >= 0 && std::chrono::steady_clock::now() < end) poll(5);
    if (accepted_) return 'A';
    if (rejected_ != 0) return rejected_;
    return 'X';
  }

  void send(std::span<const std::byte> msg) {
    ASSERT_TRUE(sess_ && logged_in_) << user_ << ": not logged in";
    handle(sess_->send_unsequenced(msg, mono()));
  }
  void logout() {
    if (sess_ && fd_ >= 0) handle(sess_->logout(mono()));
    poll(20);
    drop();
  }
  // Closes the TCP connection without a logout (a client failure or a node crash).
  void drop() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
    logged_in_ = false;
  }

  // One round of I/O, waiting up to `ms` for input.
  void poll(int ms) {
    if (fd_ < 0 || !sess_) return;
    pollfd p{fd_, POLLIN, 0};
    if (::poll(&p, 1, ms) == 1) {
      std::byte buf[65536];
      const ssize_t n = ::recv(fd_, buf, sizeof buf, 0);
      if (n <= 0) {
        drop();
        return;
      }
      std::size_t off = 0;
      while (off < static_cast<std::size_t>(n) && sess_) {
        const soup::Actions& a = sess_->on_bytes(std::span<const std::byte>(buf + off, static_cast<std::size_t>(n) - off), mono());
        const std::size_t used = a.consumed;
        handle(a);
        off += used;
        if (used == 0) break;
      }
    }
    if (sess_ && fd_ >= 0) handle(sess_->on_timer(mono()));
  }

  // Polls until `n` sequenced messages have been received in total (or timeout).
  bool wait_count(std::size_t n, std::chrono::milliseconds timeout = 5s) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (received_.size() < n && std::chrono::steady_clock::now() < end) {
      if (fd_ < 0) return received_.size() >= n;
      poll(5);
    }
    return received_.size() >= n;
  }
  // Polls until no new message arrives for `quiet`.
  void settle(std::chrono::milliseconds quiet = 100ms) {
    auto last = std::chrono::steady_clock::now();
    std::size_t seen = received_.size();
    while (std::chrono::steady_clock::now() - last < quiet && fd_ >= 0) {
      poll(5);
      if (received_.size() != seen) {
        seen = received_.size();
        last = std::chrono::steady_clock::now();
      }
    }
  }

  [[nodiscard]] const std::vector<Received>& received() const noexcept { return received_; }
  [[nodiscard]] SeqNo next_expected() const noexcept { return next_expected_; }
  [[nodiscard]] bool logged_in() const noexcept { return logged_in_; }
  [[nodiscard]] bool ended() const noexcept { return ended_; }
  [[nodiscard]] bool connected() const noexcept { return fd_ >= 0; }
  [[nodiscard]] std::uint64_t duplicates() const noexcept { return duplicates_; }
  [[nodiscard]] std::uint64_t gaps() const noexcept { return gaps_; }
  // The whole received stream as [u16 length][message] records (for byte comparisons).
  [[nodiscard]] Bytes stream() const {
    Bytes out;
    for (const Received& r : received_) {
      std::byte len[2];
      store_be16(len, static_cast<std::uint16_t>(r.msg.size()));
      out.insert(out.end(), len, len + 2);
      out.insert(out.end(), r.msg.begin(), r.msg.end());
    }
    return out;
  }

 private:
  void handle(const soup::Actions& a) {
    for (const soup::Event& ev : a.events) {
      if (ev.kind == soup::EventKind::LoggedIn) logged_in_ = accepted_ = true;
      if (ev.kind == soup::EventKind::LoginRejected) rejected_ = ev.code;
      if (ev.kind == soup::EventKind::EndOfSession) ended_ = true;
    }
    for (const soup::Delivered& d : a.delivered) {
      if (d.seq == 0) continue;
      // Exactly-once bookkeeping: a re-login asks for next_expected_, so a sequence number
      // below it is a duplicate and one above it a gap.
      if (d.seq < next_expected_) {
        ++duplicates_;
        continue;
      }
      if (d.seq > next_expected_) ++gaps_;
      received_.push_back(Received{d.seq, Bytes(d.data.begin(), d.data.end())});
      next_expected_ = d.seq + 1;
    }
    if (fd_ >= 0 && !a.write.empty()) {
      const ssize_t n = ::send(fd_, a.write.data(), a.write.size(), 0);
      if (n > 0) sess_->consume_tx(static_cast<std::size_t>(n));
    }
    if (a.close) drop();
  }

  std::string user_;
  std::string password_;
  int fd_ = -1;
  std::unique_ptr<soup::ClientSession> sess_;
  bool logged_in_ = false;
  bool accepted_ = false;  // this login was accepted (the session may have ended since)
  char rejected_ = 0;
  bool ended_ = false;
  SeqNo next_expected_ = 1;
  std::vector<Received> received_;
  std::uint64_t duplicates_ = 0;
  std::uint64_t gaps_ = 0;
};

// ---- MoldUDP64 subscriber ------------------------------------------------------------------

class MoldSubscriber {
 public:
  MoldSubscriber() : line_a_(udp_bound(0)), line_b_(udp_bound(0)), rr_(udp_bound(0)) {
    mold::LineArbiterConfig c;
    c.first_seq = 1;
    c.gap_timeout = 20'000'000;
    c.request_timeout = 50'000'000;
    c.snapshot_gap_messages = 0;
    arb_ = std::make_unique<mold::LineArbiter>(c);
  }
  ~MoldSubscriber() {
    for (int s : {line_a_, line_b_, rr_}) ::close(s);
  }
  [[nodiscard]] std::uint16_t port_a() const { return local_port(line_a_); }
  [[nodiscard]] std::uint16_t port_b() const { return local_port(line_b_); }
  void set_servers(std::uint16_t a, std::uint16_t b) {
    server_[0] = a;
    server_[1] = b;
  }
  // Keep every received line packet as sent (before any induced drop), for pcaps.
  void record(bool on) { record_ = on; }
  // A nanosecond pcap of a line's packets as UDP datagrams to `port` (MoldUDP64 for the
  // dissectors: tools/spec/mold_tshark_check.sh decodes UDP port 26477).
  bool write_pcap(const std::string& path, int line, std::uint16_t port = 26477) const {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    auto u32 = [&](std::uint32_t v) { f.write(reinterpret_cast<const char*>(&v), 4); };
    auto u16 = [&](std::uint16_t v) { f.write(reinterpret_cast<const char*>(&v), 2); };
    u32(0xa1b23c4d);  // nanosecond-resolution pcap, host byte order
    u16(2);
    u16(4);
    u32(0);
    u32(0);
    u32(65535);
    u32(1);  // Ethernet
    std::uint32_t ns = 0;
    for (const Bytes& p : raw_[line]) {
      std::vector<std::uint8_t> fr(14 + 20 + 8 + p.size(), 0);
      fr[12] = 0x08;  // IPv4
      std::uint8_t* ip = fr.data() + 14;
      const std::size_t iplen = 20 + 8 + p.size();
      ip[0] = 0x45;
      ip[2] = static_cast<std::uint8_t>(iplen >> 8);
      ip[3] = static_cast<std::uint8_t>(iplen);
      ip[8] = 1;   // TTL
      ip[9] = 17;  // UDP
      const std::uint8_t src[4] = {10, 0, 0, 1}, dst[4] = {239, 1, 1, 1};
      std::memcpy(ip + 12, src, 4);
      std::memcpy(ip + 16, dst, 4);
      std::uint32_t sum = 0;
      for (int k = 0; k < 20; k += 2) sum += static_cast<std::uint32_t>((ip[k] << 8) | ip[k + 1]);
      while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
      ip[10] = static_cast<std::uint8_t>(~sum >> 8);
      ip[11] = static_cast<std::uint8_t>(~sum);
      std::uint8_t* udp = ip + 20;
      udp[0] = static_cast<std::uint8_t>(port >> 8);
      udp[1] = static_cast<std::uint8_t>(port);
      udp[2] = static_cast<std::uint8_t>(port >> 8);
      udp[3] = static_cast<std::uint8_t>(port);
      udp[4] = static_cast<std::uint8_t>((8 + p.size()) >> 8);
      udp[5] = static_cast<std::uint8_t>(8 + p.size());
      std::memcpy(udp + 8, p.data(), p.size());
      ns += 1000;
      u32(1'790'860'000u);  // seconds: the trading day (UTC)
      u32(ns);
      u32(static_cast<std::uint32_t>(fr.size()));
      u32(static_cast<std::uint32_t>(fr.size()));
      f.write(reinterpret_cast<const char*>(fr.data()), static_cast<std::streamsize>(fr.size()));
    }
    return static_cast<bool>(f);
  }
  // Drop, on both lines, every packet that carries message `seq`.
  void drop_sequence(SeqNo seq) { drop_seq_ = seq; }
  [[nodiscard]] std::uint64_t dropped_sequence_packets() const { return dropped_seq_packets_; }
  // Drop every k-th packet of a line (induced loss: re-requests and the other line fill it).
  void drop_every(int line, std::uint64_t k) { drop_every_[line] = k; }

  // Line B is read before line A: line B's small packets leave the publisher while line
  // A's packet is still filling (packetizer.h), so this is the order they arrive in, and
  // line A's packets then overlap partially what line B delivered (03 §7 case 2).
  void poll(int ms) {
    pollfd p[3] = {{line_a_, POLLIN, 0}, {line_b_, POLLIN, 0}, {rr_, POLLIN, 0}};
    ::poll(p, 3, ms);
    std::byte buf[65536];
    for (int i : {1, 0, 2}) {
      for (;;) {
        sockaddr_in from{};
        socklen_t flen = sizeof from;
        const ssize_t n = ::recvfrom(p[i].fd, buf, sizeof buf, 0, reinterpret_cast<sockaddr*>(&from), &flen);
        if (n <= 0) break;
        const std::span<const std::byte> pkt(buf, static_cast<std::size_t>(n));
        if (i < 2) {
          ++packets_[i];
          if (record_) {
            raw_[i].emplace_back(pkt.begin(), pkt.end());
            log_.push_back(LinePacket{i, ntohs(from.sin_port), realtime_ns(), Bytes(pkt.begin(), pkt.end())});
          }
          ++sources_[i][ntohs(from.sin_port)];
          last_source_[i] = ntohs(from.sin_port);
          if (pkt.size() >= mold::kHeaderLen) session_ = mold::decode_header(pkt.data()).session;
          if (drop_every_[i] != 0 && packets_[i] % drop_every_[i] == 0) continue;
          if (drop_seq_ != 0) {
            // Both lines lose the packets carrying drop_seq_: only a re-request fills it.
            if (auto v = mold::PacketView::parse(pkt); v && v->seq() <= drop_seq_ && drop_seq_ < v->end_seq()) {
              ++dropped_seq_packets_;
              continue;
            }
          }
          if (auto v = mold::PacketView::parse(pkt); v && v->message_count() > 0) ++data_packets_[i];
        }
        mold::Source src = i == 0 ? mold::Source::LineA : mold::Source::LineB;
        if (i == 2) {
          src = ntohs(from.sin_port) == server_[1] ? mold::Source::RerequestB : mold::Source::RerequestA;
          ++replies_;
        }
        arb_->on_packet(src, pkt, mono(), sink_);
      }
    }
    arb_->on_timer(mono(), sink_);
  }
  bool wait_messages(std::uint64_t n, std::chrono::milliseconds timeout = 5s) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (messages_.size() < n && std::chrono::steady_clock::now() < end) poll(5);
    return messages_.size() >= n;
  }
  bool wait_end(std::chrono::milliseconds timeout = 5s) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (!sink_.ended && std::chrono::steady_clock::now() < end) poll(5);
    return sink_.ended;
  }

  [[nodiscard]] const std::vector<Bytes>& messages() const noexcept { return messages_; }
  [[nodiscard]] const mold::LineArbiterMetrics& metrics() const { return arb_->metrics(); }
  [[nodiscard]] std::uint64_t packets(int line) const { return packets_[line]; }
  [[nodiscard]] std::uint64_t data_packets(int line) const { return data_packets_[line]; }
  [[nodiscard]] std::uint64_t requests_sent() const { return sink_.requests; }
  [[nodiscard]] std::uint64_t replies() const { return replies_; }
  // Packets of a line per sending UDP port (which node transmitted it), and the last sender.
  [[nodiscard]] const std::map<std::uint16_t, std::uint64_t>& sources(int line) const { return sources_[line]; }
  [[nodiscard]] std::uint16_t last_source(int line) const { return last_source_[line]; }
  [[nodiscard]] std::string summary() const {
    const auto& m = arb_->metrics();
    auto n = [](std::uint64_t v) { return std::to_string(v); };
    return "packets A " + n(packets_[0]) + " B " + n(packets_[1]) + "; data A " + n(data_packets_[0]) + " B " +
           n(data_packets_[1]) + "; duplicates A " + n(m.duplicate_packets[0]) + " B " + n(m.duplicate_packets[1]) +
           "; partial overlaps A " + n(m.partial_overlaps[0]) + " B " + n(m.partial_overlaps[1]) + "; gaps " +
           n(m.gaps_opened) + " filled by A " + n(m.gaps_filled_by_line[0]) + " B " + n(m.gaps_filled_by_line[1]) +
           " re-request " + n(m.gaps_filled_by_rerequest) + "; requests " + n(sink_.requests) + " replies " +
           n(replies_) + "; delivered " + n(messages_.size());
  }
  [[nodiscard]] SeqNo next_expected() const { return arb_->next_expected(); }
  [[nodiscard]] bool ended() const { return sink_.ended; }
  // Every line packet received while recording, in arrival order, with its sender's UDP
  // port and a software receive timestamp.
  struct LinePacket {
    int line = 0;
    std::uint16_t sender = 0;
    std::int64_t rx_ns = 0;
    Bytes bytes;
  };
  [[nodiscard]] const std::vector<LinePacket>& packet_log() const { return log_; }
  // A nanosecond pcap of both lines as received: UDP from 127.0.0.1:<sender> to
  // 127.0.0.1:<line port>, stamped with the software receive time (the lab capture puts
  // hardware timestamps in the same format, bench/failover/analyze_pcap.py).
  bool write_capture(const std::string& path) const {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    auto u32 = [&](std::uint32_t v) { f.write(reinterpret_cast<const char*>(&v), 4); };
    auto u16 = [&](std::uint16_t v) { f.write(reinterpret_cast<const char*>(&v), 2); };
    u32(0xa1b23c4d);
    u16(2);
    u16(4);
    u32(0);
    u32(0);
    u32(65535);
    u32(1);
    const std::uint16_t dst_port[2] = {port_a(), port_b()};
    for (const LinePacket& lp : log_) {
      const Bytes& p = lp.bytes;
      std::vector<std::uint8_t> fr(14 + 20 + 8 + p.size(), 0);
      fr[12] = 0x08;
      std::uint8_t* ip = fr.data() + 14;
      const std::size_t iplen = 20 + 8 + p.size();
      ip[0] = 0x45;
      ip[2] = static_cast<std::uint8_t>(iplen >> 8);
      ip[3] = static_cast<std::uint8_t>(iplen);
      ip[8] = 64;
      ip[9] = 17;
      const std::uint8_t lo[4] = {127, 0, 0, 1};
      std::memcpy(ip + 12, lo, 4);
      std::memcpy(ip + 16, lo, 4);
      std::uint32_t sum = 0;
      for (int k = 0; k < 20; k += 2) sum += static_cast<std::uint32_t>((ip[k] << 8) | ip[k + 1]);
      while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
      ip[10] = static_cast<std::uint8_t>(~sum >> 8);
      ip[11] = static_cast<std::uint8_t>(~sum);
      std::uint8_t* udp = ip + 20;
      const std::uint16_t dp = dst_port[lp.line];
      udp[0] = static_cast<std::uint8_t>(lp.sender >> 8);
      udp[1] = static_cast<std::uint8_t>(lp.sender);
      udp[2] = static_cast<std::uint8_t>(dp >> 8);
      udp[3] = static_cast<std::uint8_t>(dp);
      udp[4] = static_cast<std::uint8_t>((8 + p.size()) >> 8);
      udp[5] = static_cast<std::uint8_t>(8 + p.size());
      std::memcpy(udp + 8, p.data(), p.size());
      u32(static_cast<std::uint32_t>(lp.rx_ns / 1'000'000'000));
      u32(static_cast<std::uint32_t>(lp.rx_ns % 1'000'000'000));
      u32(static_cast<std::uint32_t>(fr.size()));
      u32(static_cast<std::uint32_t>(fr.size()));
      f.write(reinterpret_cast<const char*>(fr.data()), static_cast<std::streamsize>(fr.size()));
    }
    return static_cast<bool>(f);
  }
  // The MoldUDP64 session of the line packets received so far.
  [[nodiscard]] const mold::Session& session() const { return session_; }

  // NASDAQ BinaryFILE: [u16 BE length][message] ..., then a zero-length record.
  bool write_binary_file(const std::string& path) const {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    for (const Bytes& m : messages_) {
      char len[2] = {static_cast<char>(m.size() >> 8), static_cast<char>(m.size() & 0xFF)};
      f.write(len, 2);
      f.write(reinterpret_cast<const char*>(m.data()), static_cast<std::streamsize>(m.size()));
    }
    const char end[2] = {0, 0};
    f.write(end, 2);
    return static_cast<bool>(f);
  }

 private:
  struct Sink {
    MoldSubscriber* s;
    std::uint64_t requests = 0;
    bool ended = false;
    void on_message(SeqNo, std::span<const std::byte> msg) { s->messages_.emplace_back(msg.begin(), msg.end()); }
    void send_request(mold::Server server, std::span<const std::byte> req) {
      const std::uint16_t port = s->server_[server == mold::Server::A ? 0 : 1];
      if (port == 0) return;
      sockaddr_in a{};
      a.sin_family = AF_INET;
      a.sin_port = htons(port);
      a.sin_addr.s_addr = htonl(e2e_host());
      ::sendto(s->rr_, req.data(), req.size(), 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
      ++requests;
    }
    void on_snapshot_needed(SeqNo, SeqNo) {}
    void on_end_of_session(SeqNo) { ended = true; }
  };

  int line_a_;
  int line_b_;
  int rr_;
  std::unique_ptr<mold::LineArbiter> arb_;
  Sink sink_{this};
  std::uint16_t server_[2] = {0, 0};
  std::uint64_t replies_ = 0;
  SeqNo drop_seq_ = 0;
  std::uint64_t dropped_seq_packets_ = 0;
  bool record_ = false;
  std::vector<Bytes> raw_[2];
  std::vector<LinePacket> log_;
  std::map<std::uint16_t, std::uint64_t> sources_[2];
  std::uint16_t last_source_[2] = {0, 0};
  mold::Session session_{};
  std::uint64_t drop_every_[2] = {0, 0};
  std::uint64_t packets_[2] = {0, 0};
  std::uint64_t data_packets_[2] = {0, 0};
  std::vector<Bytes> messages_;
};

// Asks the re-request server `port` directly for messages [first, first + count) and
// returns what it served, in order (stops at the first message not served in time).
inline std::vector<Bytes> mold_rerequest(std::uint16_t port, const mold::Session& session, SeqNo first,
                                         std::uint16_t count, std::chrono::milliseconds timeout = 3s) {
  const int fd = udp_bound(0);
  std::map<SeqNo, Bytes> got;
  SeqNo next = first;
  const SeqNo end = first + count;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (next < end && std::chrono::steady_clock::now() < deadline) {
    std::byte req[mold::kRequestLen];
    (void)mold::encode_request(req, mold::RequestPacket{session, next, static_cast<std::uint16_t>(end - next)});
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(e2e_host());
    ::sendto(fd, req, sizeof req, 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
    pollfd p{fd, POLLIN, 0};
    ::poll(&p, 1, 50);
    std::byte buf[65536];
    for (;;) {
      const ssize_t n = ::recv(fd, buf, sizeof buf, MSG_DONTWAIT);
      if (n <= 0) break;
      if (auto v = mold::PacketView::parse(std::span<const std::byte>(buf, static_cast<std::size_t>(n)))) {
        v->for_each([&](SeqNo s, std::span<const std::byte> m) {
          if (s >= first && s < end) got.emplace(s, Bytes(m.begin(), m.end()));
        });
      }
    }
    while (next < end && got.contains(next)) ++next;
  }
  ::close(fd);
  std::vector<Bytes> out;
  for (SeqNo s = first; s < next; ++s) out.push_back(got.at(s));
  return out;
}

// ---- admin port ------------------------------------------------------------------------------

class AdminClient {
 public:
  AdminClient(std::uint16_t port, std::uint32_t op, std::vector<std::uint8_t> key)
      : port_(port), op_(op), key_(std::move(key)) {}
  // Sends one lle-admin command ("halt AAPL"); true if the port accepted it.
  bool command(const std::string& words_text) {
    std::istringstream in(words_text);
    std::vector<std::string> words;
    std::string w;
    while (in >> w) words.push_back(w);
    std::vector<std::string_view> views(words.begin(), words.end());
    const auto c = admin::parse_command(views);
    if (!c) {
      last_error_ = c.error();
      return false;
    }
    admin::Request r;
    r.operator_id = op_;
    r.sequence = ++seq_;
    r.command = c->command;
    r.tlv_version = 1;
    r.args = c->args;
    const auto frame = admin::encode_request(r, key_);
    const auto resp = admin::exchange(e2e_host_text(), port_, frame);
    if (!resp) {
      last_error_ = resp.error();
      return false;
    }
    const auto d = admin::decode_response(*resp, key_);
    if (!d || !d->accepted) {
      last_error_ = "rejected";
      return false;
    }
    return true;
  }
  [[nodiscard]] const std::string& last_error() const { return last_error_; }

 private:
  std::uint16_t port_;
  std::uint32_t op_;
  std::vector<std::uint8_t> key_;
  std::uint64_t seq_ = 0;
  std::string last_error_;
};

// ---- helpers ----------------------------------------------------------------------------------

inline Bytes slurp(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  std::vector<char> v((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  Bytes out(v.size());
  if (!v.empty()) std::memcpy(out.data(), v.data(), v.size());
  return out;
}

// journal_replay --emit-ouch framing: [u32 BE session][u16 BE length][message]; returns
// the per-session streams in [u16 length][message] form.
inline std::map<std::uint32_t, Bytes> split_ouch(const Bytes& f) {
  std::map<std::uint32_t, Bytes> out;
  std::size_t at = 0;
  while (at + 6 <= f.size()) {
    const std::uint32_t s = load_be32(f.data() + at);
    const std::size_t n = load_be16(f.data() + at + 4);
    Bytes& b = out[s];
    b.insert(b.end(), f.begin() + static_cast<std::ptrdiff_t>(at + 4), f.begin() + static_cast<std::ptrdiff_t>(at + 6 + n));
    at += 6 + n;
  }
  return out;
}

// BinaryFILE -> messages.
inline std::vector<Bytes> split_binary_file(const Bytes& f) {
  std::vector<Bytes> out;
  std::size_t at = 0;
  while (at + 2 <= f.size()) {
    const std::size_t n = load_be16(f.data() + at);
    if (n == 0) break;
    out.emplace_back(f.begin() + static_cast<std::ptrdiff_t>(at + 2), f.begin() + static_cast<std::ptrdiff_t>(at + 2 + n));
    at += 2 + n;
  }
  return out;
}

}  // namespace lle::exch::test

// ---- configuration -------------------------------------------------------------------------

#include "gateway/credentials.h"

namespace lle::exch::test {

struct SessionDef {
  std::uint32_t id = 0;
  std::uint32_t account = 0;
  std::string user;
  std::string password;
  int gw = 0;
  std::string flags = "market";
};

struct NodeSpec {
  std::string name = "ex";
  int node_id = 0;
  std::string data_dir;
  std::string mode = "solo";
  std::string runner = "threads";
  std::string clock = "manual";
  std::string start = "02:59:00";
  std::string schedule = "standard";
  std::uint16_t line_a = 0, line_b = 0;
  std::uint16_t rerequest = 0;
  std::uint16_t gw0 = 0, gw1 = 0;
  std::size_t max_packet_b = 1000;
  std::vector<std::string> symbols = {"AAPL prior=150.00 tier=1 adv=5000000", "MSFT prior=300.00 tier=1 adv=5000000"};
  std::vector<std::string> accounts = {"100 FRMA", "200 FRMB", "300 FRMC"};
  std::vector<SessionDef> sessions = {
      {1, 100, "ALPHA", "alpha-pw", 0, "market"},
      {2, 200, "BRAVO", "bravo-pw", 1, "market"},
      {3, 300, "CHARL", "charl-pw", 0, "market,cod"},
  };
  std::vector<std::string> extra;  // raw lines appended (e.g. a [ha] section)
  std::string operator_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  bool metrics = false;
};

inline std::vector<std::uint8_t> key_bytes(const std::string& hex) { return *gw::from_hex(hex); }

inline std::string config_text(const NodeSpec& s) {
  const std::vector<std::uint8_t> salt = {0x5A, 0x17, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  std::ostringstream o;
  // LLE_E2E_BACKEND selects the network backend of every node (epoll, busypoll, uring, ...).
  const char* backend = std::getenv("LLE_E2E_BACKEND");
  o << "[node]\nname = " << s.name << "\nid = " << s.node_id << "\ndata_dir = " << s.data_dir
    << "\nbackend = " << (backend != nullptr ? backend : "epoll") << "\nmode = " << s.mode
    << "\nrunner = " << s.runner << "\nidle_sleep_us = 20\nmetrics = " << (s.metrics ? "true" : "false") << "\n";
  o << "[day]\ndate = 20261001\nclock = " << s.clock << "\nstart = " << s.start << "\nschedule = " << s.schedule << "\n";
  o << "[journal]\nsegment_mib = 8\nspares = 1\nl2_mib = 32\n";
  const std::string host = e2e_host_text(), peer = e2e_peer_text();
  // AF_XDP: fixed ports, the ones xsk_e2e.sh steers to the stages' queues.
  const bool xsk = backend != nullptr && std::string(backend) == "xsk";
  const std::uint16_t gw0 = xsk ? 15000 : s.gw0, gw1 = xsk ? 15001 : s.gw1, rr = xsk ? 26479 : s.rerequest;
  o << "[gateway]\ngw0 = " << host << ":" << gw0 << "\ngw1 = " << host << ":" << gw1
    << "\nheartbeat_ms = 200\nidle_timeout_ms = 60000\nreplay_ring_msgs = 4096\nreplay_ring_mib = 2\n";
  o << "[md]\nline_a = " << peer << ":" << s.line_a << "\nline_b = " << peer << ":" << s.line_b << "\nrerequest = " << host
    << ":" << rr << "\nmax_packet_b = " << s.max_packet_b << "\nheartbeat_ms = 200\neos_linger_ms = 1000\n";
  o << "[admin]\nport = 0\nbind = " << host << "\noperator.1 = " << s.operator_key << "\n";
  o << "[control]\nport = 0\nbind = " << host << "\n";
  // Busy-poll device settings (busypoll_device_e2e.sh): checked, or applied with
  // LLE_E2E_DEVICE_SETUP, on LLE_E2E_NET_IF.
  if (const char* nif = std::getenv("LLE_E2E_NET_IF"); nif != nullptr && *nif != 0) {
    o << "[net]\nifname = " << nif << "\ndevice_setup = " << (std::getenv("LLE_E2E_DEVICE_SETUP") != nullptr ? "true" : "false")
      << "\n";
  }
  // The AF_XDP variant (xsk_e2e.sh): the stages on queues 0, 1 and 2 of LLE_E2E_XSK_IF
  // (a veth; copy mode, the dev/test override), the feed to the peer's MAC.
  if (xsk) {
    const char* ifn = std::getenv("LLE_E2E_XSK_IF");
    const char* mac = std::getenv("LLE_E2E_XSK_NEXT_HOP");
    const std::string i = ifn != nullptr ? ifn : "veth0";
    o << "[xsk]\ngw0 = " << i << ":0\ngw1 = " << i << ":1\nmd = " << i << ":2\nallow_copy = true\nlocal_ip = " << host
      << "\numem_frames = 4096\n";
    if (mac != nullptr) o << "next_hop_mac = " << mac << "\n";
  }
  o << "[symbols]\n";
  for (const auto& l : s.symbols) o << l << "\n";
  o << "[accounts]\n";
  for (const auto& l : s.accounts) o << l << "\n";
  o << "[sessions]\n";
  for (const SessionDef& d : s.sessions) {
    o << d.id << " account=" << d.account << " user=" << d.user
      << " password=" << gw::Credential::make(d.password, salt).text() << " gw=" << d.gw << " flags=" << d.flags << "\n";
  }
  for (const auto& l : s.extra) o << l << "\n";
  return o.str();
}

inline std::filesystem::path fresh_dir(const std::string& name) {
  const auto d = std::filesystem::temp_directory_path() / ("lle-e2e-" + name + "-" + std::to_string(::getpid()));
  std::filesystem::remove_all(d);
  std::filesystem::create_directories(d);
  return d;
}

// Removes a test's directory (journals, output logs, process output) when the test
// passed; kept for inspection on failure or with LLE_E2E_KEEP set.
class ScopedDir {
 public:
  explicit ScopedDir(std::filesystem::path p) : p_(std::move(p)) {}
  ~ScopedDir() {
    if (!::testing::Test::HasFailure() && std::getenv("LLE_E2E_KEEP") == nullptr) {
      std::error_code ec;
      std::filesystem::remove_all(p_, ec);
    }
  }
  ScopedDir(const ScopedDir&) = delete;
  ScopedDir& operator=(const ScopedDir&) = delete;
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return p_; }

 private:
  std::filesystem::path p_;
};

// One exchanged process with its control connection.
class Exchange {
 public:
  Exchange(const NodeSpec& spec, const std::filesystem::path& dir) : spec_(spec), dir_(dir) {
    std::filesystem::create_directories(dir_);
    config_ = (dir_ / (spec_.name + ".conf")).string();
    std::ofstream(config_) << config_text(spec_);
  }
  bool start(std::chrono::milliseconds timeout = 20s) {
    launch();
    return wait_ready(timeout);
  }
  // Two steps, so the nodes of a pair start together.
  // With LLE_E2E_NETNS the node runs in that network namespace (ip netns exec execs it,
  // so the process is the node itself).
  void launch() {
    ++starts_;
    const std::string log = (dir_ / (spec_.name + "-" + std::to_string(starts_) + ".out")).string();
    if (const char* ns = std::getenv("LLE_E2E_NETNS"); ns != nullptr && *ns != 0) {
      proc_ = std::make_unique<Process>("/usr/bin/env",
                                        std::vector<std::string>{"ip", "netns", "exec", ns, LLE_EXCHANGED, "--config", config_},
                                        log);
    } else {
      proc_ = std::make_unique<Process>(LLE_EXCHANGED, std::vector<std::string>{"--config", config_}, log);
    }
  }
  bool wait_ready(std::chrono::milliseconds timeout = 20s) {
    if (!proc_->wait_output("exchanged: ready", timeout)) return false;
    ctl_ = std::make_unique<Control>(proc_->port_of("control"));
    return ctl_->ok();
  }
  std::string cmd(const std::string& line) { return ctl_ ? ctl_->cmd(line) : std::string("err not running"); }
  [[nodiscard]] bool running() { return proc_ && proc_->alive(); }
  // Barrier: everything received so far is sequenced, applied, released and handed on.
  std::uint64_t sync() {
    const std::string r = cmd("sync");
    EXPECT_EQ(r.rfind("ok ", 0), 0u) << r;
    return Control::value(r);
  }
  void clock(const std::string& t) {
    const std::string r = cmd("clock " + t);
    EXPECT_EQ(r.rfind("ok ", 0), 0u) << "clock " << t << ": " << r;
  }
  std::string status() { return cmd("status"); }
  void kill9() {
    if (proc_) proc_->kill(SIGKILL);
    ctl_.reset();
  }
  int stop(std::chrono::milliseconds timeout = 20s) {
    if (!proc_) return -1;
    (void)cmd("shutdown");
    ctl_.reset();
    const int code = proc_->wait_exit(timeout);
    expect_xsk_traffic();
    expect_device_settings();
    return code;
  }
  // Busy-poll variants with LLE_E2E_NET_IF: the node reported the device as the variant
  // requires (busypoll_device_e2e.sh applies the settings through the node itself).
  void expect_device_settings() const {
    const char* b = std::getenv("LLE_E2E_BACKEND");
    const char* nif = std::getenv("LLE_E2E_NET_IF");
    if (b == nullptr || nif == nullptr || std::string(b).rfind("busypoll", 0) != 0 || !proc_) return;
    const std::string out = proc_->output();
    const auto at = out.find(std::string("exchanged: variant ") + b + " on " + nif + ":");
    ASSERT_NE(at, std::string::npos) << out;
    const std::string line = out.substr(at, out.find('\n', at) - at);
    EXPECT_NE(line.find("(as the variant requires)"), std::string::npos) << line;
  }
  // AF_XDP variant: the node reports its sockets at shutdown; the md stage's must have
  // sent the feed through AF_XDP (copy mode on the test's veth).
  void expect_xsk_traffic() const {
    const char* b = std::getenv("LLE_E2E_BACKEND");
    if (b == nullptr || std::string(b) != "xsk" || !proc_) return;
    const std::string out = proc_->output();
    const auto md = out.rfind("exchanged: xsk md ");
    ASSERT_NE(md, std::string::npos) << out;
    const std::string line = out.substr(md, out.find('\n', md) - md);
    EXPECT_NE(line.find(" copy: "), std::string::npos) << line;
    const auto tx = line.find(" tx ");
    ASSERT_NE(tx, std::string::npos) << line;
    EXPECT_GT(std::stoull(line.substr(tx + 4)), 0u) << "the feed did not leave through AF_XDP: " << line;
    EXPECT_NE(out.find("exchanged: xsk gw0 "), std::string::npos) << out;
  }
  [[nodiscard]] std::uint16_t port(const std::string& name) const { return proc_->port_of(name); }
  [[nodiscard]] Process& proc() { return *proc_; }
  [[nodiscard]] const NodeSpec& spec() const { return spec_; }
  [[nodiscard]] std::string journal_dir() const { return spec_.data_dir + "/journal/20261001"; }
  [[nodiscard]] std::string outlog_dir() const { return spec_.data_dir + "/outlog/20261001"; }
  [[nodiscard]] std::string output() const { return proc_ ? proc_->output() : std::string(); }

 private:
  NodeSpec spec_;
  std::filesystem::path dir_;
  std::string config_;
  int starts_ = 0;
  std::unique_ptr<Process> proc_;
  std::unique_ptr<Control> ctl_;
};

}  // namespace lle::exch::test
