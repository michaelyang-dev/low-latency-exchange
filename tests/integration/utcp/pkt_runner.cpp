// Packetdrill-style scripted tests for utcp::Connection (07 §2.4). Each
// tests/integration/utcp/*.pkt file is one test. Our own small format:
//
//   # comment
//   config key=value ...      (before the first event) mss rx_buffer tx_buffer max_inflight
//                             initial_rto min_rto max_rto time_wait fin_wait2_timeout
//                             max_retransmits max_syn_retransmits dupack_threshold iss peer_iss
//   <time> <command>
//
// <time> is decimal seconds, absolute ("0.100") or relative to the previous line
// ("+0.100"). Commands:
//
//   connect | listen          active open / accept the next injected SYN
//   < FLAGS a:b(n) [ack N] [win N] [mss N]    inject a segment from the peer
//   > FLAGS a:b(n) [ack N] [win N] [mss N]    expect the next segment utcp sends
//   write N | read N | close | abort
//   expect state STATE | expect event EV | expect reason R | expect readable N | expect none
//
// FLAGS are packetdrill letters: S F R P and '.' for ACK. Sequence numbers are relative,
// as in packetdrill: inbound seq and outbound ack count from the peer's ISN, outbound seq
// and inbound ack from ours. Inbound payload bytes are a pattern of their sequence number
// and `read` checks it. Timers fire at their exact deadlines; any segment utcp emits that
// no '>' line expects at that moment fails the test.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "net/utcp/connection.h"

#ifndef UTCP_PKT_DIR
#error "UTCP_PKT_DIR must point at tests/integration/utcp"
#endif

namespace lle::net::utcp {
namespace {

using namespace tcp_flag;

constexpr MacAddr kLocalMac{{0x02, 0, 0, 0, 0, 0x01}};
constexpr MacAddr kPeerMac{{0x02, 0, 0, 0, 0, 0x02}};
constexpr std::uint32_t kLocalIp = 0xC0A80001;  // 192.168.0.1
constexpr std::uint32_t kPeerIp = 0xC0000201;   // 192.0.2.1
constexpr std::uint16_t kLocalPort = 8080;
constexpr std::uint16_t kPeerPort = 50000;

std::byte pattern(std::uint32_t rel) { return std::byte{static_cast<unsigned char>('A' + rel % 26)}; }

std::string flags_str(std::uint8_t f) {
  std::string s;
  if (f & kSyn) s += 'S';
  if (f & kFin) s += 'F';
  if (f & kRst) s += 'R';
  if (f & kPsh) s += 'P';
  if (f & kAck) s += '.';
  return s;
}

// Parses decimal seconds ("0.25", "+1.5") into nanoseconds without floating point.
bool parse_time(const std::string& tok, Nanos prev, Nanos& out) {
  std::string t = tok;
  bool rel = false;
  if (!t.empty() && t[0] == '+') {
    rel = true;
    t = t.substr(1);
  }
  const auto dot = t.find('.');
  const std::string ip = t.substr(0, dot);
  std::string fp = dot == std::string::npos ? "" : t.substr(dot + 1);
  if (ip.empty() && fp.empty()) return false;
  if (fp.size() > 9) return false;
  while (fp.size() < 9) fp += '0';
  for (char c : ip + fp) {
    if (c < '0' || c > '9') return false;
  }
  const Nanos v = (ip.empty() ? 0 : std::stoll(ip)) * 1'000'000'000 + std::stoll(fp);
  out = rel ? prev + v : v;
  return true;
}

struct SegSpec {
  std::uint8_t flags = 0;
  std::uint32_t start = 0;
  std::uint32_t len = 0;
  bool has_ack = false;
  std::uint32_t ack = 0;
  bool has_win = false;
  std::uint32_t win = 0;
  bool has_mss = false;
  std::uint16_t mss = 0;
};

struct Line {
  int lineno = 0;
  Nanos t = 0;
  std::vector<std::string> tok;  // command tokens (after the time)
};

class Runner {
 public:
  explicit Runner(std::string name) : name_(std::move(name)) {}

  // Returns an empty string on success, else the failure description.
  std::string run(const std::string& path) {
    std::ifstream in(path);
    if (!in) return "cannot open " + path;
    std::string raw;
    int lineno = 0;
    Nanos prev = 0;
    bool events_started = false;
    while (std::getline(in, raw)) {
      ++lineno;
      const auto hash = raw.find('#');
      if (hash != std::string::npos) raw.resize(hash);
      std::istringstream ss(raw);
      std::vector<std::string> tok;
      for (std::string w; ss >> w;) tok.push_back(w);
      if (tok.empty()) continue;
      if (tok[0] == "config") {
        if (events_started) return at(lineno, "config after the first event");
        for (std::size_t i = 1; i < tok.size(); ++i) {
          if (std::string e = config(tok[i]); !e.empty()) return at(lineno, e);
        }
        continue;
      }
      events_started = true;
      Line l;
      l.lineno = lineno;
      if (!parse_time(tok[0], prev, l.t)) return at(lineno, "bad time '" + tok[0] + "'");
      if (l.t < prev) return at(lineno, "time goes backwards");
      prev = l.t;
      l.tok.assign(tok.begin() + 1, tok.end());
      if (l.tok.empty()) return at(lineno, "missing command");
      lines_.push_back(std::move(l));
    }
    conn_ = Connection(cfg_, LinkType::Ethernet);
    for (std::size_t i = 0; i < lines_.size(); ++i) {
      const Line& l = lines_[i];
      if (std::string e = advance_to(l); !e.empty()) return e;
      if (std::string e = execute(l); !e.empty()) return at(l.lineno, e);
      if (!conn_.invariants_ok()) return at(l.lineno, "connection invariants violated");
      // Anything utcp wants to send now must be expected by the next line.
      const bool next_expects = i + 1 < lines_.size() && lines_[i + 1].t == now_ && lines_[i + 1].tok[0] == ">";
      if (conn_.tx_pending() && !next_expects && !(l.tok[0] == "expect" || l.tok[0] == ">")) {
        return at(l.lineno, "unexpected outbound segment: " + peek_desc());
      }
      if (conn_.tx_pending() && !next_expects && l.tok[0] == ">") {
        return at(l.lineno, "unexpected further outbound segment: " + peek_desc());
      }
    }
    if (conn_.tx_pending()) return "end of script: unexpected outbound segment: " + peek_desc();
    return {};
  }

 private:
  std::string at(int lineno, const std::string& msg) const {
    return name_ + ":" + std::to_string(lineno) + ": " + msg;
  }

  std::string config(const std::string& kv) {
    const auto eq = kv.find('=');
    if (eq == std::string::npos) return "bad config '" + kv + "'";
    const std::string k = kv.substr(0, eq);
    const std::string v = kv.substr(eq + 1);
    Nanos t = 0;
    auto num = [&]() { return std::stoull(v); };
    auto dur = [&]() -> Nanos {
      (void)parse_time(v, 0, t);
      return t;
    };
    if (k == "mss") cfg_.mss = static_cast<std::uint16_t>(num());
    else if (k == "rx_buffer") cfg_.rx_buffer = static_cast<std::uint32_t>(num());
    else if (k == "tx_buffer") cfg_.tx_buffer = static_cast<std::uint32_t>(num());
    else if (k == "max_inflight") cfg_.max_inflight = static_cast<std::uint32_t>(num());
    else if (k == "initial_rto") cfg_.initial_rto = dur();
    else if (k == "min_rto") cfg_.min_rto = dur();
    else if (k == "max_rto") cfg_.max_rto = dur();
    else if (k == "time_wait") cfg_.time_wait = dur();
    else if (k == "fin_wait2_timeout") cfg_.fin_wait2_timeout = dur();
    else if (k == "max_retransmits") cfg_.max_retransmits = static_cast<std::uint8_t>(num());
    else if (k == "max_syn_retransmits") cfg_.max_syn_retransmits = static_cast<std::uint8_t>(num());
    else if (k == "dupack_threshold") cfg_.dupack_threshold = static_cast<std::uint8_t>(num());
    else if (k == "iss") iss_ = static_cast<std::uint32_t>(num());
    else if (k == "peer_iss") peer_iss_ = static_cast<std::uint32_t>(num());
    else return "unknown config key '" + k + "'";
    return {};
  }

  // Fires timers due before `l.t`; output they produce must match l (a '>' at that time).
  std::string advance_to(const Line& l) {
    while (true) {
      const Nanos d = conn_.deadline();
      if (d == kNoDeadline || d > l.t) break;
      now_ = d;
      events_ |= conn_.on_timer(now_).events;
      if (conn_.tx_pending() && !(l.tok[0] == ">" && now_ == l.t)) {
        return at(l.lineno, "segment emitted at " + std::to_string(now_) + " ns before this line: " + peek_desc());
      }
    }
    now_ = l.t;
    return {};
  }

  std::string peek_desc() {
    // Describing consumes the frame; this is only used to report a failure.
    std::vector<std::byte> buf(4096);
    const std::size_t n = conn_.next_tx(buf, now_);
    if (n == 0) return "(none)";
    auto seg = parse_tcp(std::span<const std::byte>(buf.data(), n), LinkType::Ethernet, true);
    return seg ? describe(*seg, false) : "(unparseable)";
  }

  std::string describe(const TcpSegment& s, bool inbound) const {
    const std::uint32_t seq0 = inbound ? peer_iss_ : iss_;
    const std::uint32_t ack0 = inbound ? iss_ : peer_iss_;
    std::ostringstream o;
    const std::uint32_t start = s.seq - seq0;
    o << flags_str(s.flags) << ' ' << start << ':' << start + s.payload.size() << '(' << s.payload.size() << ')';
    if (s.has(kAck)) o << " ack " << s.ack - ack0;
    o << " win " << s.window;
    if (s.mss != 0) o << " mss " << s.mss;
    return o.str();
  }

  static bool parse_flags(const std::string& f, std::uint8_t& out) {
    out = 0;
    for (char c : f) {
      switch (c) {
        case 'S': out |= kSyn; break;
        case 'F': out |= kFin; break;
        case 'R': out |= kRst; break;
        case 'P': out |= kPsh; break;
        case '.': out |= kAck; break;
        default: return false;
      }
    }
    return true;
  }

  static std::string parse_seg(const std::vector<std::string>& t, SegSpec& s) {
    if (t.size() < 3) return "segment needs FLAGS and a:b(n)";
    if (!parse_flags(t[1], s.flags)) return "bad flags '" + t[1] + "'";
    const std::string& r = t[2];
    const auto colon = r.find(':');
    const auto lp = r.find('(');
    const auto rp = r.find(')');
    if (colon == std::string::npos || lp == std::string::npos || rp == std::string::npos) return "bad range '" + r + "'";
    s.start = static_cast<std::uint32_t>(std::stoull(r.substr(0, colon)));
    const auto end = static_cast<std::uint32_t>(std::stoull(r.substr(colon + 1, lp - colon - 1)));
    s.len = static_cast<std::uint32_t>(std::stoull(r.substr(lp + 1, rp - lp - 1)));
    if (end - s.start != s.len) return "range length mismatch '" + r + "'";
    for (std::size_t i = 3; i + 1 < t.size(); i += 2) {
      const std::string& k = t[i];
      const auto v = std::stoull(t[i + 1]);
      if (k == "ack") {
        s.has_ack = true;
        s.ack = static_cast<std::uint32_t>(v);
      } else if (k == "win") {
        s.has_win = true;
        s.win = static_cast<std::uint32_t>(v);
      } else if (k == "mss") {
        s.has_mss = true;
        s.mss = static_cast<std::uint16_t>(v);
      } else {
        return "unknown segment field '" + k + "'";
      }
    }
    if ((t.size() - 3) % 2 != 0) return "dangling segment field";
    return {};
  }

  FlowAddr flow() const { return {kLocalMac, kPeerMac, kLocalIp, kPeerIp, kLocalPort, kPeerPort}; }

  std::string inject(const SegSpec& s) {
    std::vector<std::byte> payload(s.len);
    for (std::uint32_t i = 0; i < s.len; ++i) payload[i] = pattern(s.start + i);
    TcpHeaderSpec h;
    h.src_mac = kPeerMac;
    h.dst_mac = kLocalMac;
    h.src_ip = kPeerIp;
    h.dst_ip = kLocalIp;
    h.src_port = kPeerPort;
    h.dst_port = kLocalPort;
    h.seq = peer_iss_ + s.start;
    h.ack = s.has_ack ? iss_ + s.ack : 0;
    h.window = static_cast<std::uint16_t>(s.has_win ? s.win : 65535);
    h.mss_option = s.has_mss ? s.mss : 0;
    h.flags = s.flags;
    std::vector<std::byte> f(4096);
    const std::size_t n = build_tcp(f, LinkType::Ethernet, h, payload, {}, false);
    if (listening_) {
      if (!(s.flags & kSyn) || (s.flags & kAck)) return "listening: expected an inbound SYN";
      auto seg = parse_tcp(std::span<const std::byte>(f.data(), n), LinkType::Ethernet, true);
      events_ |= conn_.accept(flow(), *seg, iss_, now_).events;
      listening_ = false;
      return {};
    }
    events_ |= conn_.on_segment(std::span<const std::byte>(f.data(), n), now_).events;
    return {};
  }

  std::string expect_out(const SegSpec& want) {
    std::vector<std::byte> f(4096);
    const std::size_t n = conn_.next_tx(f, now_);
    if (n == 0) return "expected a segment, utcp sent nothing";
    auto seg = parse_tcp(std::span<const std::byte>(f.data(), n), LinkType::Ethernet, true);
    if (!seg) return std::string("utcp sent an unparseable frame: ") + to_string(seg.error());
    const std::string got = describe(*seg, false);
    const std::uint32_t start = seg->seq - iss_;
    bool ok = seg->flags == want.flags && start == want.start && seg->payload.size() == want.len;
    if (want.has_ack) ok = ok && seg->has(kAck) && seg->ack - peer_iss_ == want.ack;
    if (want.has_win) ok = ok && seg->window == want.win;
    if (want.has_mss) ok = ok && seg->mss == want.mss;
    if (!want.has_mss) ok = ok && seg->mss == 0;
    if (!ok) return "segment mismatch: got '" + got + "'";
    return {};
  }

  static bool event_bit(const std::string& n, std::uint32_t& bit) {
    if (n == "connected") bit = ev::kConnected;
    else if (n == "readable") bit = ev::kReadable;
    else if (n == "peer_fin") bit = ev::kPeerFin;
    else if (n == "closed") bit = ev::kClosed;
    else if (n == "writable") bit = ev::kWritable;
    else if (n == "time_wait") bit = ev::kTimeWait;
    else return false;
    return true;
  }

  std::string execute(const Line& l) {
    const auto& t = l.tok;
    const std::string& c = t[0];
    if (c == "connect") {
      events_ |= conn_.connect(flow(), iss_, now_).events;
      return {};
    }
    if (c == "listen") {
      listening_ = true;
      return {};
    }
    if (c == "<" || c == ">") {
      SegSpec s;
      if (std::string e = parse_seg(t, s); !e.empty()) return e;
      return c == "<" ? inject(s) : expect_out(s);
    }
    if (c == "write") {
      if (t.size() < 2) return "write needs a byte count";
      const std::size_t n = std::stoull(t[1]);
      std::vector<std::byte> b(n, std::byte{'w'});
      const Actions a = conn_.send(b, now_);
      events_ |= a.events;
      const std::size_t want = t.size() >= 4 && t[2] == "accepted" ? std::stoull(t[3]) : n;
      if (a.accepted != want) return "write accepted " + std::to_string(a.accepted) + ", expected " + std::to_string(want);
      return {};
    }
    if (c == "read") {
      if (t.size() < 2) return "read needs a byte count";
      const std::size_t n = std::stoull(t[1]);
      if (conn_.readable_bytes() < n) return "only " + std::to_string(conn_.readable_bytes()) + " bytes readable";
      const ByteRing::Spans sp = conn_.readable();
      for (std::size_t i = 0; i < n; ++i) {
        const std::byte b = i < sp.first.size() ? sp.first[i] : sp.second[i - sp.first.size()];
        if (b != pattern(static_cast<std::uint32_t>(read_off_ + i))) return "received byte mismatch at offset " + std::to_string(read_off_ + i);
      }
      read_off_ += n;
      events_ |= conn_.consume(n, now_).events;
      return {};
    }
    if (c == "close") {
      events_ |= conn_.close(now_).events;
      return {};
    }
    if (c == "abort") {
      events_ |= conn_.abort(now_).events;
      return {};
    }
    if (c == "expect") {
      if (t.size() < 2) return "expect what?";
      const std::string& w = t[1];
      if (w == "none") return conn_.tx_pending() ? "expected no output, utcp would send: " + peek_desc() : std::string{};
      if (t.size() < 3) return "expect " + w + " needs a value";
      if (w == "state") {
        return to_string(conn_.state()) == t[2] ? std::string{} : std::string("state is ") + to_string(conn_.state());
      }
      if (w == "reason") {
        return to_string(conn_.close_reason()) == t[2] ? std::string{}
                                                       : std::string("close reason is ") + to_string(conn_.close_reason());
      }
      if (w == "readable") {
        return conn_.readable_bytes() == std::stoull(t[2]) ? std::string{}
                                                            : "readable is " + std::to_string(conn_.readable_bytes());
      }
      if (w == "event") {
        std::uint32_t bit = 0;
        if (!event_bit(t[2], bit)) return "unknown event '" + t[2] + "'";
        if ((events_ & bit) == 0) return "event " + t[2] + " not raised";
        events_ &= ~bit;
        return {};
      }
      if (w == "no_event") {
        std::uint32_t bit = 0;
        if (!event_bit(t[2], bit)) return "unknown event '" + t[2] + "'";
        return (events_ & bit) == 0 ? std::string{} : "event " + t[2] + " was raised";
      }
      return "unknown expectation '" + w + "'";
    }
    return "unknown command '" + c + "'";
  }

  std::string name_;
  ConnConfig cfg_{};
  Connection conn_;
  std::vector<Line> lines_;
  Nanos now_ = 0;
  std::uint32_t iss_ = 1000;
  std::uint32_t peer_iss_ = 5'000'000;
  std::uint32_t events_ = 0;
  std::size_t read_off_ = 1;  // relative sequence number of the next byte to read
  bool listening_ = false;
};

std::vector<std::string> pkt_files() {
  std::vector<std::string> v;
  for (const auto& e : std::filesystem::directory_iterator(UTCP_PKT_DIR)) {
    if (e.path().extension() == ".pkt") v.push_back(e.path().filename().string());
  }
  std::sort(v.begin(), v.end());
  return v;
}

class PktScript : public ::testing::TestWithParam<std::string> {};

TEST_P(PktScript, Run) {
  Runner r(GetParam());
  const std::string err = r.run(std::string(UTCP_PKT_DIR) + "/" + GetParam());
  EXPECT_TRUE(err.empty()) << err;
}

std::string test_name(const ::testing::TestParamInfo<std::string>& i) {
  std::string n = i.param.substr(0, i.param.size() - 4);
  for (char& c : n) {
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) c = '_';
  }
  return n;
}

INSTANTIATE_TEST_SUITE_P(Utcp, PktScript, ::testing::ValuesIn(pkt_files()), test_name);

}  // namespace
}  // namespace lle::net::utcp
