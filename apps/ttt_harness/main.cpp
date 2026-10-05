// ttt_harness: the T18 tick-to-trade instrument (METHODOLOGY §12, §13; 07 §3, §4; WP
// N-12). It is the same for every refclient variant.
//
//   ttt_harness run --file DAY.bin --line-a GROUP:PORT --line-b GROUP:PORT --listen IP:PORT
//                   [--feed udp|xsk] [--ifname IF] [--timestamps off|software|hardware]
//                   [--rate MSGS_PER_S] [--trigger-rate PER_S] [--duration DUR] [--warmup DUR]
//                   [--min-triggers N] [--seed S] [--symbol SYM] [--trigger-locate N]
//                   [--trigger-price PX] [--trigger-side S|B] [--max-packet B] [--batch-delay DUR]
//                   [--start-delay DUR] [--linger DUR] [--cpu N] [--rx-cpu N] [--device-setup]
//                   [--xsk-queue Q] [--xsk-allow-copy] [--source-ip IP] [--next-hop-mac MAC] [--rerequest IP:PORT]
//                   [--test-drop-every N]
//                   [--calibration CAL.json] [--client-log FILE] [--out DIR] [--run-name NAME]
//   ttt_harness reflect   --listen IP:PORT [--ifname IF] [--timestamps M] [--cpu N] [--max-runtime DUR]
//   ttt_harness calibrate --peer IP:PORT [--ifname IF] [--timestamps M] [--count N] [--rate PER_S]
//                         [--out FILE]
//   ttt_harness analyze   --triggers RUN.triggers.bin [--harness-report RUN.json] [--client-log FILE]
//                         [--client-report FILE] [--calibration CAL.json] [--warmup DUR]
//                         [--min-triggers N] --out FILE
//
// run (host A, port A.p0): publishes line A and line B (the same MoldUDP64 packets, A
// first) from one port, so every trigger TX stamp comes from one PHC. Background: the
// day's messages at a constant rate; triggers: Add Orders for the trigger symbol at the
// trigger price on a seeded Poisson schedule, each followed by its Order Delete
// (client/ttt.h gives the plan). The packet carrying a trigger is sent at once on both
// lines with hardware TX timestamps requested for both copies (AF_XDP TX metadata with
// --feed xsk; SO_TIMESTAMPING on a dedicated trigger socket per line with --feed udp).
// A kernel TCP acceptor on the same port takes refclient's SoupBinTCP session(s) with
// SO_TIMESTAMPING RX, answers every Enter Order with Accepted + Canceled (IOC), and
// stamps the trigger whose ClOrdID it carries. Transmit and receive run on two threads
// (--cpu, --rx-cpu); the per-trigger records are preallocated and each thread writes
// only its own fields. The PHC is sampled before, during idle gaps and after the run to
// map the schedule into the PHC domain (client/phc_clock.h) for the lateness check.
// Output: NAME.json (flat metrics + verdict), NAME.triggers.bin (raw records),
// NAME.hdr (TTT_raw HdrHistogram log). With --rerequest the transmit thread also serves
// MoldUDP64 re-requests (kernel UDP, polled every 200 us) from a ring of the stream, so a
// packet lost on both lines is recovered instead of stalling the client; such a run is
// still invalid (the client reports feed_gap_free = false).
//
// reflect (host C) / calibrate (host A): the harness-side MAC/PHY + cable time c. The
// reflector echoes each probe at once and then sends a follow-up carrying the echo's RX
// and TX stamps on its own port; calibrate computes c = (RTT_A - turnaround_C) / 2 per
// probe from stamps of one PHC per subtraction and reports the median. (METHODOLOGY §13
// names an XDP_TX reflector; XDP_TX cannot report a TX timestamp, so turnaround_C would
// not be measurable. This kernel-socket reflector measures it on C's PHC instead; the
// subtraction is the same.)
//
// analyze: recomputes the verdict offline, adding refclient's order-stamp log
// (TTT_client), the calibration (TTT_cal and the ±250 ns consistency rule) and
// refclient's report (a gap-free feed).
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "client/cli.h"
#include "client/histogram.h"
#include "client/hwts_log.h"
#include "client/phc_clock.h"
#include "client/report.h"
#include "client/ring_store.h"
#include "client/ttt.h"
#include "client/variant.h"
#include "common/endian.h"
#include "env/prod_clock.h"
#include "net/common/stack.h"
#include "net/hwts/device.h"
#include "net/hwts/tx_correlator.h"
#include "proto/itch50/itch50.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/packetizer.h"
#include "proto/moldudp64/rerequest_server.h"
#include "proto/ouch50/ouch50.h"
#include "proto/soupbin/server_session.h"
#include "runtime/pinning.h"
#if defined(LLE_CLIENT_HAVE_XSK)
#include "net/utcp/linux/af_packet_port.h"
#include "net/utcp/linux/neigh_netlink.h"
#include "net/utcp/wire.h"
#include "net/xsk/socket.h"
#include "net/xsk/umem.h"
#endif

namespace {

using namespace lle;
using client::cli::Args;
namespace ttt = client::ttt;

std::atomic<bool> g_stop{false};
extern "C" void on_signal(int) { g_stop.store(true); }

Nanos dur(Args& a) {
  const std::string v = a.value();
  const auto d = client::cli::parse_duration(v);
  if (!d) a.die("bad duration: " + v);
  return *d;
}

bool write_text(const std::string& path, const std::string& s) {
  std::FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr) return false;
  const bool ok = std::fputs(s.c_str(), f) >= 0;
  return std::fclose(f) == 0 && ok;
}

// ---- the background day: an uncompressed ITCH 5.0 BinaryFILE, mapped and prefaulted ----
class DayFile {
 public:
  ~DayFile() {
    if (base_ != nullptr) ::munmap(base_, size_);
  }
  std::optional<std::string> open(const std::string& path) {
    if (path.ends_with(".gz")) return "the harness replays an uncompressed BinaryFILE (gunzip it first)";
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) return "cannot open " + path;
    struct stat st{};
    if (::fstat(fd_, &st) != 0 || st.st_size <= 0) return "cannot stat " + path;
    size_ = static_cast<std::size_t>(st.st_size);
    void* p = ::mmap(nullptr, size_, PROT_READ, MAP_SHARED, fd_, 0);
    ::close(fd_);
    if (p == MAP_FAILED) return "cannot map " + path;
    base_ = static_cast<std::byte*>(p);
    return std::nullopt;
  }
  // Counts up to `want` messages and touches their pages (no page faults during the run).
  std::uint64_t prefault(std::uint64_t want) {
    std::uint64_t n = 0;
    std::size_t at = 0;
    volatile std::uint8_t sink = 0;
    std::size_t last_page = ~std::size_t{0};
    while (n < want && at + 2 <= size_) {
      const std::size_t len = load_be16(base_ + at);
      if (at + 2 + len > size_ || len == 0) break;
      for (std::size_t q = at; q < at + 2 + len; q += 4096) {
        const std::size_t page = q / 4096;
        if (page != last_page) {
          sink = sink + std::to_integer<std::uint8_t>(base_[q]);
          last_page = page;
        }
      }
      at += 2 + len;
      ++n;
    }
    (void)sink;
    return n;
  }
  std::span<const std::byte> next() noexcept {
    if (pos_ + 2 > size_) return {};
    const std::size_t len = load_be16(base_ + pos_);
    if (pos_ + 2 + len > size_) return {};
    const std::span<const std::byte> m(base_ + pos_ + 2, len);
    pos_ += 2 + len;
    return m;
  }

 private:
  int fd_ = -1;
  std::byte* base_ = nullptr;
  std::size_t size_ = 0;
  std::size_t pos_ = 0;
};

struct RunOptions {
  std::string file;
  net::Endpoint line[2]{};
  net::Endpoint listen{};
  std::string feed = "udp";
  client::VariantConfig v;  // ifname, timestamps, cpu, device_setup, xsk settings (the harness port)
  int rx_cpu = -1;
  ttt::PlanConfig plan{};
  ttt::AnalysisConfig analysis{};
  Symbol8 symbol{"LLTRG"};
  std::uint16_t trigger_locate = 65000;
  PxE4 trigger_price = 10 * kPxScale;
  Side trigger_side = Side::Sell;
  std::uint32_t trigger_shares = 100;
  std::size_t max_packet = mold::kDefaultMaxPacket;
  Nanos batch_delay = 20'000;
  Nanos start_delay = 500'000'000;
  Nanos linger = 2 * kNsPerSec;
  std::string session = "LLETTT0001";
  net::Endpoint rerequest{};
  std::uint64_t test_drop_every = 0;  // tests: withhold every Nth data packet from both lines
  std::string calibration, client_log;
  std::string out = ".", run_name = "run-01";
};

// ---- feed transmit: kernel UDP ------------------------------------------------------------
// Background packets on one socket per line; trigger packets on a second socket per line
// with TX timestamps (only trigger sends are stamped). One thread sends both sockets of a
// line in order, so the kernel keeps the stream order on the wire.
class UdpFeed {
 public:
  std::optional<std::string> open(const RunOptions& o) {
    if (auto r = stack_.open(); !r) return net::to_string(r.error());
    for (int l = 0; l < 2; ++l) {
      dst_[l] = o.line[l];
      for (int t = 0; t < 2; ++t) {
        net::UdpConfig c;
        c.bind = net::Endpoint{o.line[l].ipv4 == net::kLoopbackV4 ? net::kLoopbackV4 : net::kAnyV4, 0};
        c.ifname = o.v.ifname;
        c.mcast_loop = true;
        c.sndbuf = 8 << 20;
        c.tx_ts = t == 1 ? o.v.timestamps : net::TsMode::Off;
        c.tx_slots = 256;
        if (auto r = stack_.open(port_[l][t], c); !r) return net::to_string(r.error());
      }
      corr_[l].init(net::hwts::KeyMode::Datagram, 1 << 16);
    }
    stamps_ = o.v.timestamps != net::TsMode::Off;
    return std::nullopt;
  }
  void send(int line, std::span<const std::byte> pkt, std::int64_t trigger) noexcept {
    const int t = trigger >= 0 ? 1 : 0;
    for (int attempt = 0; attempt < 100'000; ++attempt) {
      if (port_[line][t].send(dst_[line], pkt)) {
        if (t == 1 && stamps_) (void)corr_[line].on_send(static_cast<std::uint64_t>(trigger), pkt.size());
        return;
      }
      ++retries_;
    }
    ++failures_;
  }
  void kick() noexcept {}
  // f(trigger, line, const net::RxTimestamps&)
  template <class F>
  void drain(F&& f) {
    if (!stamps_) return;
    for (int l = 0; l < 2; ++l) {
      if (corr_[l].outstanding() == 0) continue;
      port_[l][1].drain_tx_timestamps([&](const net::TxStamp& s) {
        (void)corr_[l].on_stamp(s, [&](std::uint64_t tag, const net::TxStamp& st) { f(tag, l, st.ts); });
      });
    }
  }
  [[nodiscard]] std::size_t outstanding() const noexcept { return corr_[0].outstanding() + corr_[1].outstanding(); }
  void finish() {
    for (auto& c : corr_) c.expire_all();
  }
  [[nodiscard]] bool aligned() const noexcept { return true; }  // keyed by OPT_ID: misses are counted, never shifted
  void stats_json(client::JsonObject& j) const {
    j.str("feed", "udp").num("feed_send_retries", retries_).num("feed_send_failures", failures_);
    for (int l = 0; l < 2; ++l) {
      const std::string p = l == 0 ? "feed_a_" : "feed_b_";
      const auto& v = corr_[l].validity();
      j.num(p + "tx_ts_hw", v.hw).num(p + "tx_ts_sw", v.sw).num(p + "tx_ts_missing", v.missing);
      j.num(p + "tx_ts_unmatched", corr_[l].unmatched());
    }
  }
  [[nodiscard]] std::uint64_t failures() const noexcept { return failures_; }
  [[nodiscard]] bool software_seen() const noexcept { return corr_[0].validity().sw + corr_[1].validity().sw != 0; }

 private:
  net::Stack<net::BackendKind::Epoll> stack_{net::WaitPolicy::Spin};
  net::sock::UdpPort port_[2][2];
  net::Endpoint dst_[2]{};
  net::hwts::TxCorrelator corr_[2];
  bool stamps_ = false;
  std::uint64_t retries_ = 0, failures_ = 0;
};

#if defined(LLE_CLIENT_HAVE_XSK)
// ---- feed transmit: AF_XDP with TX-metadata timestamps (07 §3 "ttt_harness" I/O) -----------
// TX only (no XDP program needed). Frames are built in UMEM chunks; timestamps are
// requested for trigger frames only and their completions arrive in ring order. The
// socket's internal reap paths (full TX ring, no free UMEM frame) are kept unreachable
// and checked at the end (aligned()).
class XskFeed {
 public:
  std::optional<std::string> open(const RunOptions& o) {
    namespace xsk = net::xsk;
    namespace utcp = net::utcp;
    if (o.v.ifname.empty()) return std::string("--feed xsk needs --ifname");
    auto mac = utcp::interface_mac(o.v.ifname);
    if (!mac) return "interface_mac: " + std::string(std::strerror(mac.error()));
    mac_ = *mac;
    src_ip_ = o.v.xsk.local_ip;
    if (src_ip_ == 0) return std::string("--feed xsk needs --source-ip (the harness port's address)");
    xsk::UmemConfig uc;
    uc.frame_count = 16384;
    auto umem = xsk::Umem::create(uc);
    if (!umem) return std::string("umem: ") + umem.error().what;
    umem_ = std::move(*umem);
    xsk::XskConfig xc;
    xc.ifname = o.v.ifname;
    xc.queue = o.v.xsk.queue;
    xc.mode = o.v.xsk.allow_copy ? xsk::BindMode::AllowCopy : xsk::BindMode::ZeroCopyRequired;
    xc.fill_frames = 64;
    auto sock = xsk::XskSocket::create(*umem_, xc);
    if (!sock) return std::string("xsk socket: ") + sock.error().what + ": " + std::strerror(sock.error().err);
    sock_ = std::move(*sock);
    tx_limit_ = xc.tx_size - 32;
    for (int l = 0; l < 2; ++l) {
      dst_[l] = o.line[l];
      if (net::is_multicast(o.line[l].ipv4)) {
        dmac_[l] = utcp::MacAddr::ipv4_multicast(o.line[l].ipv4);
      } else if (o.v.xsk.next_hop) {
        dmac_[l] = *o.v.xsk.next_hop;
      } else {
        const auto m = utcp::resolve_via_kernel(o.v.ifname, o.line[l].ipv4, 3000);
        if (!m) return "no next hop for " + net::to_string(o.line[l]);
        dmac_[l] = *m;
      }
    }
    src_port_ = o.v.xsk.udp_port != 0 ? o.v.xsk.udp_port : 31999;
    stamps_ = o.v.timestamps != net::TsMode::Off;
    fifo_.init(1 << 16);
    return std::nullopt;
  }
  void send(int line, std::span<const std::byte> pkt, std::int64_t trigger) noexcept {
    namespace utcp = net::utcp;
    while (committed_ - reaped_ >= tx_limit_) {
      reap_into_done();
      if (committed_ - reaped_ >= tx_limit_) {
        ++stalls_;
        kick();
      }
    }
    std::span<std::byte> b = sock_->tx_acquire();
    if (b.size() < utcp::kUdpFrameOverhead + pkt.size()) {
      if (!b.empty()) (void)sock_->tx_commit(0);
      ++failures_;
      return;
    }
    std::memcpy(b.data() + utcp::kUdpFrameOverhead, pkt.data(), pkt.size());
    utcp::UdpHeaderSpec h;
    h.src_mac = mac_;
    h.dst_mac = dmac_[line];
    h.src_ip = src_ip_;
    h.dst_ip = dst_[line].ipv4;
    h.src_port = src_port_;
    h.dst_port = dst_[line].port;
    h.ip_id = ip_id_++;
    h.ttl = 8;
    const std::size_t n = utcp::finish_udp_in_place(b, h, pkt.size(), false);
    net::xsk::TxOptions opt;
    opt.timestamp = stamps_ && trigger >= 0;
    if (n == 0 || !sock_->tx_commit(n, opt)) {
      if (n == 0) (void)sock_->tx_commit(0);
      ++failures_;
      return;
    }
    ++committed_;
    if (opt.timestamp) (void)fifo_.push(Pending{static_cast<std::uint64_t>(trigger), line});
    dirty_ = true;
  }
  void kick() noexcept {
    if (!dirty_) return;
    dirty_ = false;
    (void)::sendto(sock_->fd(), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
  }
  template <class F>
  void drain(F&& f) {
    reap_into_done();
    while (!done_.empty()) {
      const Done d = done_.front();
      done_.pop();
      f(d.tag, d.line, net::RxTimestamps{0, d.ts});
    }
  }
  [[nodiscard]] std::size_t outstanding() const noexcept { return fifo_.size() + done_.size(); }
  void finish() { kick(); }
  [[nodiscard]] bool aligned() const {
    const net::xsk::XskStats st = sock_->stats();
    return st.tx_ts_completions == stamped_ && st.tx_ring_full == 0 && st.tx_no_frame == 0 && unmatched_ == 0;
  }
  void stats_json(client::JsonObject& j) const {
    const net::xsk::XskStats st = sock_->stats();
    j.str("feed", "xsk").boolean("feed_xsk_zero_copy", sock_->zero_copy());
    j.num("feed_tx_frames", st.tx_frames).num("feed_tx_completions", st.tx_completions);
    j.num("feed_tx_ts_completions", st.tx_ts_completions).num("feed_tx_stamped_seen", stamped_);
    j.num("feed_tx_ring_full", st.tx_ring_full).num("feed_tx_no_frame", st.tx_no_frame);
    j.num("feed_send_failures", failures_).num("feed_tx_stalls", stalls_).boolean("feed_tx_stamps_aligned", aligned());
  }
  [[nodiscard]] std::uint64_t failures() const noexcept { return failures_; }
  [[nodiscard]] bool software_seen() const noexcept { return false; }  // copy mode yields no stamp at all

 private:
  struct Pending {
    std::uint64_t tag = 0;
    int line = 0;
  };
  struct Done {
    std::uint64_t tag = 0;
    int line = 0;
    Nanos ts = 0;
  };
  void reap_into_done() noexcept {
    reaped_ += sock_->reap([this](Nanos ts) {
      ++stamped_;
      if (fifo_.empty()) {
        ++unmatched_;
        return;
      }
      const Pending p = fifo_.front();
      fifo_.pop();
      (void)done_.push(Done{p.tag, p.line, ts});
    });
  }

  std::unique_ptr<net::xsk::Umem> umem_;
  std::unique_ptr<net::xsk::XskSocket> sock_;
  net::utcp::MacAddr mac_{}, dmac_[2]{};
  std::uint32_t src_ip_ = 0;
  std::uint16_t src_port_ = 0, ip_id_ = 0;
  net::Endpoint dst_[2]{};
  bool stamps_ = false, dirty_ = false;
  std::uint64_t committed_ = 0, reaped_ = 0, tx_limit_ = 1024, stamped_ = 0, unmatched_ = 0;
  std::uint64_t failures_ = 0, stalls_ = 0;
  net::FixedQueue<Pending> fifo_;
  net::FixedQueue<Done> done_ = [] {
    net::FixedQueue<Done> q;
    q.init(1 << 16);
    return q;
  }();
};
#endif

// ---- order desk: kernel TCP acceptor with RX timestamps, on its own thread -----------------
class OrderDesk {
 public:
  OrderDesk(const RunOptions& o, const ttt::Plan& plan, ttt::TriggerRecord* recs)
      : o_(o), plan_(plan), recs_(recs), stack_(net::WaitPolicy::Default) {}

  std::optional<std::string> open() {
    if (auto r = stack_.open(); !r) return net::to_string(r.error());
    net::TcpConfig tc;
    tc.max_conns = 16;
    tc.rx_buf_bytes = 64 * 1024;
    tc.rx_ts = o_.v.timestamps;
    if (auto r = stack_.open(tcp_, tc); !r) return net::to_string(r.error());
    auto ep = tcp_.listen(o_.listen);
    if (!ep) return "listen " + net::to_string(o_.listen) + ": " + net::to_string(ep.error());
    return std::nullopt;
  }

  void run(const std::atomic<bool>& stop) {
    env::ProdClock clock;
    if (o_.rx_cpu >= 0) (void)rt::pin_current_thread(o_.rx_cpu);
    while (!stop.load(std::memory_order_relaxed)) {
      (void)stack_.wait(1'000'000);
      const Nanos now = clock.now_mono();
      tcp_.poll([&](const env::StreamEvent& ev) { on_event(ev, now); });
      for (Conn& c : conns_) {
        if (!c.s) continue;
        if (now >= c.s->actions().deadline) absorb(c, c.s->on_timer(now));
        flush(c);
      }
    }
  }

  void stats_json(client::JsonObject& j) const {
    j.num("desk_accepted", accepted_).num("desk_logins", logins_).num("desk_orders", orders_);
    j.num("desk_orders_unknown_clordid", unknown_).num("desk_other_messages", other_).num("desk_closed", closed_);
    const auto& ts = tcp_.stats().rx_ts;
    j.num("desk_rx_ts_hw", ts.hw).num("desk_rx_ts_sw", ts.sw).num("desk_rx_ts_missing", ts.missing);
  }
  [[nodiscard]] bool software_seen() const noexcept { return tcp_.stats().rx_ts.sw != 0; }
  [[nodiscard]] std::uint64_t orders() const noexcept { return orders_; }

 private:
  struct Policy {
    soup::LoginDecision authorize(const soup::LoginRequest&) { return soup::LoginDecision::Accept; }
  };
  using Session = soup::ServerSession<client::RingSequencedStore, Policy>;
  struct Conn {
    env::ConnId id = env::kNoConn;
    std::unique_ptr<client::RingSequencedStore> store;
    std::unique_ptr<Policy> policy;
    std::unique_ptr<Session> s;
  };

  void on_event(const env::StreamEvent& ev, Nanos now) {
    if (ev.kind == env::StreamEventKind::Accepted) {
      ++accepted_;
      Conn c;
      c.id = ev.conn;
      c.store = std::make_unique<client::RingSequencedStore>(std::size_t{1} << 16, std::size_t{8} << 20);
      c.policy = std::make_unique<Policy>();
      soup::ServerConfig sc;
      sc.session = soup::SessionId::from("LLETTT");
      sc.tx_capacity = 1 << 20;
      c.s = std::make_unique<Session>(sc, *c.store, *c.policy, now);
      conns_.push_back(std::move(c));
      return;
    }
    Conn* c = find(ev.conn);
    if (c == nullptr) return;
    if (ev.kind == env::StreamEventKind::Closed) {
      ++closed_;
      c->s.reset();
      c->id = env::kNoConn;
      return;
    }
    if (ev.kind != env::StreamEventKind::Data || !c->s) return;
    last_in_read_ = -1;
    std::span<const std::byte> in = ev.data;
    while (!in.empty() && c->s) {
      const soup::Actions& a = c->s->on_bytes(in, now);
      const std::size_t used = a.consumed;
      absorb(*c, a, now);
      if (used == 0) break;
      in = in.subspan(used);
    }
    // The read's RX stamp is the frame carrying its last byte (TCP reports the newest
    // skb's stamp): it belongs to the last order completed by this read.
    if (last_in_read_ >= 0) {
      ttt::TriggerRecord& r = recs_[last_in_read_];
      r.rx_hw = ev.hw_rx_ns;
      r.rx_flags = static_cast<std::uint8_t>(r.rx_flags & ~ttt::TriggerRecord::kSharedRead);
    }
    flush(*c);
  }

  void absorb(Conn& c, const soup::Actions& a, Nanos now = 0) {
    for (const soup::Event& e : a.events)
      if (e.kind == soup::EventKind::LoggedIn) ++logins_;
    for (const soup::Delivered& d : a.delivered) on_message(c, d.data, now);
    if (a.close) {
      flush(c);
      tcp_.close(c.id);
      c.s.reset();
      c.id = env::kNoConn;
    }
  }

  void on_message(Conn& c, std::span<const std::byte> m, Nanos now) {
    if (m.size() < ouch50::in::EnterOrder::kMinLen || static_cast<char>(m[0]) != 'O') {
      ++other_;
      return;
    }
    ++orders_;
    const ouch50::in::EnterOrder e = ouch50::in::EnterOrder::decode_base(m.data());
    // ClOrdID: the trigger's sequence number in decimal, left-justified.
    SeqNo seq = 0;
    bool digits = false;
    for (std::size_t i = 0; i < 14; ++i) {
      const char ch = static_cast<char>(m[31 + i]);
      if (ch < '0' || ch > '9') break;
      seq = seq * 10 + static_cast<SeqNo>(ch - '0');
      digits = true;
    }
    const std::int64_t k = digits ? plan_.trigger_of(seq) : -1;
    if (k < 0) {
      ++unknown_;
    } else {
      ttt::TriggerRecord& r = recs_[k];
      if ((r.rx_flags & ttt::TriggerRecord::kOrder) != 0) {
        r.rx_flags |= ttt::TriggerRecord::kDuplicate;
      } else {
        r.rx_flags |= ttt::TriggerRecord::kOrder | ttt::TriggerRecord::kSharedRead;  // cleared for the read's last order
        if (last_in_read_ >= 0) recs_[last_in_read_].rx_flags |= ttt::TriggerRecord::kSharedRead;
        last_in_read_ = k;
      }
    }
    // Accepted + Canceled (an IOC with nothing to execute against).
    ouch50::out::OrderAccepted acc;
    acc.timestamp = static_cast<std::uint64_t>(now);
    acc.user_ref_num = e.user_ref_num;
    acc.side = e.side;
    acc.quantity = e.quantity;
    acc.symbol = e.symbol;
    acc.price = e.price;
    acc.time_in_force = e.time_in_force;
    acc.display = e.display;
    acc.order_reference_number = ++order_ref_;
    acc.capacity = e.capacity;
    acc.inter_market_sweep_eligibility = e.inter_market_sweep_eligibility;
    acc.cross_type = e.cross_type;
    acc.order_state = ouch50::OrderState::Live;
    acc.cl_ord_id = e.cl_ord_id;
    std::byte buf[128];
    std::size_t n = ouch50::encode(std::span<std::byte>(buf), acc);
    if (n != 0) absorb(c, c.s->send_sequenced(std::span<const std::byte>(buf, n), now), now);
    if (!c.s) return;
    ouch50::out::OrderCanceled can;
    can.timestamp = static_cast<std::uint64_t>(now);
    can.user_ref_num = e.user_ref_num;
    can.quantity = e.quantity;
    can.reason = ouch50::CancelReason::ImmediateOrCancel;
    n = ouch50::encode(std::span<std::byte>(buf), can);
    if (n != 0) absorb(c, c.s->send_sequenced(std::span<const std::byte>(buf, n), now), now);
  }

  void flush(Conn& c) {
    if (!c.s || c.id == env::kNoConn) return;
    const auto w = c.s->actions().write;
    if (w.empty()) return;
    const std::size_t n = tcp_.write(c.id, w);
    if (n > 0) c.s->consume_tx(n);
  }

  Conn* find(env::ConnId id) {
    for (Conn& c : conns_)
      if (c.id == id) return &c;
    return nullptr;
  }

  const RunOptions& o_;
  const ttt::Plan& plan_;
  ttt::TriggerRecord* recs_;
  net::Stack<net::BackendKind::Epoll> stack_;
  net::sock::TcpPort tcp_;
  std::vector<Conn> conns_;
  std::int64_t last_in_read_ = -1;
  std::uint64_t order_ref_ = 0;
  std::uint64_t accepted_ = 0, logins_ = 0, orders_ = 0, unknown_ = 0, other_ = 0, closed_ = 0;
};

// ---- run --------------------------------------------------------------------------------------
template <class Feed>
int run_with(RunOptions& o) {
  client::DeviceReport dev;
  std::string err;
  if (!client::prepare_variant(o.v, dev, err)) {
    std::fprintf(stderr, "ttt_harness: %s\n", err.c_str());
    return 2;
  }
  DayFile day;
  if (auto e = day.open(o.file)) {
    std::fprintf(stderr, "ttt_harness: %s\n", e->c_str());
    return 2;
  }
  // Plan first with an unbounded day, then cap the background at what the day holds.
  const std::uint64_t want = o.plan.background_rate == 0
                                 ? 0
                                 : static_cast<std::uint64_t>(static_cast<u128>(o.plan.background_rate) *
                                                              static_cast<std::uint64_t>(o.plan.duration) /
                                                              static_cast<std::uint64_t>(kNsPerSec));
  std::fprintf(stderr, "ttt_harness: prefaulting %" PRIu64 " background messages...\n", want);
  o.plan.background_available = day.prefault(want);
  const ttt::Plan plan = ttt::build_plan(o.plan);
  std::fprintf(stderr, "ttt_harness: plan: %zu triggers, %" PRIu64 " background messages, %" PRIu64 " total\n",
               plan.trigger_seq.size(), plan.background, plan.messages());
  std::vector<ttt::TriggerRecord> recs(plan.trigger_seq.size());
  for (std::size_t k = 0; k < recs.size(); ++k) {
    recs[k].seq = plan.trigger_seq[k];
    recs[k].sched = plan.trigger_time[k];
    recs[k].phc = dev.phc_index;
  }

  Feed feed;
  if (auto e = feed.open(o)) {
    std::fprintf(stderr, "ttt_harness: feed: %s\n", e->c_str());
    return 1;
  }
  OrderDesk desk(o, plan, recs.data());
  if (auto e = desk.open()) {
    std::fprintf(stderr, "ttt_harness: order desk: %s\n", e->c_str());
    return 1;
  }
  std::atomic<bool> desk_stop{false};
  std::thread desk_thread([&] { desk.run(desk_stop); });

  std::optional<client::PhcClock> phc = client::PhcClock::open(dev.phc_index);
  client::PhcMap map;
  map.reserve(1 << 16);

  // Messages the harness injects.
  std::byte dir_msg[itch50::StockDirectory::kLen];
  {
    itch50::StockDirectory d{};
    d.stock_locate = o.trigger_locate;
    d.stock = o.symbol;
    d.round_lot_size = 100;
    (void)itch50::encode(std::span<std::byte>(dir_msg), d);
  }
  std::byte add_msg[itch50::AddOrder::kLen];
  std::byte del_msg[itch50::OrderDelete::kLen];
  auto build_trigger = [&](std::size_t k) {
    itch50::AddOrder a{};
    a.stock_locate = o.trigger_locate;
    a.order_ref = (std::uint64_t{1} << 60) + k;
    a.side = o.trigger_side;
    a.shares = o.trigger_shares;
    a.stock = o.symbol;
    a.price = o.trigger_price;
    (void)itch50::encode(std::span<std::byte>(add_msg), a);
    itch50::OrderDelete d{};
    d.stock_locate = o.trigger_locate;
    d.order_ref = a.order_ref;
    (void)itch50::encode(std::span<std::byte>(del_msg), d);
  };

  mold::PacketizerConfig pc;
  pc.session = mold::Session(o.session);
  pc.max_packet = o.max_packet;
  mold::Packetizer pk(pc);
  std::int64_t trigger_in_packet = -1;
  // Optional re-request service (kernel UDP) over a ring of the whole stream.
  std::unique_ptr<mold::MessageRing> ring;
  std::unique_ptr<mold::RerequestServer<mold::MessageRing>> rr_srv;
  net::Stack<net::BackendKind::Epoll> rr_stack(net::WaitPolicy::Spin);
  net::sock::UdpPort rr_port;
  std::uint64_t rr_served = 0;
  if (o.rerequest.port != 0) {
    ring = std::make_unique<mold::MessageRing>(std::max<std::size_t>(1024, plan.messages() + 16),
                                               std::max<std::size_t>(std::size_t{1} << 20, plan.messages() * 64));
    mold::RerequestConfig rc;
    rc.session = pc.session;
    rc.max_packet = o.max_packet;
    rr_srv = std::make_unique<mold::RerequestServer<mold::MessageRing>>(rc, *ring);
    net::UdpConfig uc;
    uc.bind = o.rerequest;
    if (auto r = rr_stack.open(); !r) {
      std::fprintf(stderr, "ttt_harness: rerequest: %s\n", net::to_string(r.error()).c_str());
      return 1;
    }
    if (auto r = rr_stack.open(rr_port, uc); !r) {
      std::fprintf(stderr, "ttt_harness: rerequest %s: %s\n", net::to_string(o.rerequest).c_str(),
                   net::to_string(r.error()).c_str());
      return 1;
    }
  }
  auto append = [&](std::span<const std::byte> m, Nanos now, auto& emit_fn) {
    if (ring) (void)ring->append(m);  // before it is published, so a request can always be served
    (void)pk.append(m, now, emit_fn);
  };
  client::Histogram bg_late;
  std::uint64_t packets = 0;
  std::uint64_t withheld = 0;
  auto emit = [&](std::span<const std::byte> pkt) {
    ++packets;
    // Test impairment: the packet is lost on both lines (only re-requests recover it).
    if (o.test_drop_every != 0 && pkt.size() > mold::kHeaderLen && packets % o.test_drop_every == 0 &&
        trigger_in_packet < 0) {
      ++withheld;
      return;
    }
    feed.send(0, pkt, trigger_in_packet);
    feed.send(1, pkt, trigger_in_packet);
    feed.kick();
  };
  auto on_stamp = [&](std::uint64_t k, int line, const net::RxTimestamps& ts) {
    if (k >= recs.size()) return;
    if (ts.hw_ns != 0) recs[k].tx_hw[line] = ts.hw_ns;
    else if (ts.sw_ns != 0) recs[k].tx_swts[line] = ts.sw_ns;
  };

  env::ProdClock clock;
  if (o.v.cpu >= 0) (void)rt::pin_current_thread(o.v.cpu);
  if (phc) {
    for (int i = 0; i < 8; ++i) map.add(phc->sample());
  }
  const Nanos t0 = clock.now_mono() + o.start_delay;
  const std::int64_t t0_real = clock.now_real() + o.start_delay;
  while (clock.now_mono() < t0) {
  }
  append(std::span<const std::byte>(dir_msg), t0, emit);  // seq 1
  pk.flush(t0, emit);

  std::uint64_t i = 0;  // next background message
  std::size_t k = 0;    // next trigger
  Nanos open_since = -1;  // schedule time of the first message in the open packet
  Nanos open_last = 0;    // ... and of the last
  Nanos last_sample = 0;
  Nanos last_rr_poll = 0;
  bool ended = false;
  Nanos end_at = 0;
  constexpr Nanos kNever = std::numeric_limits<Nanos>::max();
  for (;;) {
    const Nanos now = clock.now_mono();
    const Nanos el = now - t0;
    // Due events in schedule order (background first on ties).
    for (;;) {
      const Nanos tb = i < plan.background ? plan.bg_time(i) : kNever;
      const Nanos tt = k < plan.trigger_time.size() ? plan.trigger_time[k] : kNever;
      const Nanos t = std::min(tb, tt);
      if (t > el || t == kNever) break;
      if (tb <= tt) {
        const std::span<const std::byte> m = day.next();
        const std::uint64_t before = packets;
        append(m, now, emit);
        if (packets != before) {
          bg_late.record(el - open_last);  // a full packet: due when its last message was
          open_since = -1;
        }
        if (open_since < 0) open_since = tb;
        open_last = tb;
        ++i;
      } else {
        build_trigger(k);
        append(std::span<const std::byte>(add_msg), now, emit);  // may emit the open packet first
        trigger_in_packet = static_cast<std::int64_t>(k);
        pk.flush(now, emit);
        trigger_in_packet = -1;
        recs[k].tx_sw = clock.now_mono() - t0;
        recs[k].tx_flags |= ttt::TriggerRecord::kSent;
        append(std::span<const std::byte>(del_msg), now, emit);
        open_since = tt;
        open_last = tt;
        ++k;
      }
    }
    // A background packet that waited batch_delay goes out.
    if (pk.pending_messages() != 0 && open_since >= 0 && el - open_since >= o.batch_delay) {
      bg_late.record(el - (open_since + o.batch_delay));
      pk.flush(now, emit);
      open_since = -1;
    }
    if (now >= pk.next_deadline()) (void)pk.on_timer(now, emit);
    if (rr_srv && now - last_rr_poll >= 200'000) {
      last_rr_poll = now;
      (void)rr_stack.wait(0);
      rr_port.poll_rx([&](const env::RxDatagram& d) {
        (void)rr_srv->on_request(d.data, d.src, now, [&](const env::Endpoint& to, std::span<const std::byte> p) {
          for (int attempt = 0; attempt < 1000 && !rr_port.send(to, p); ++attempt) {
          }
          ++rr_served;
        });
      });
    }
    if (feed.outstanding() != 0) feed.drain(on_stamp);
    // PHC samples in idle gaps (>= 50 us to the next event), every 10 ms.
    if (phc && now - last_sample >= 10'000'000) {
      const Nanos tb = i < plan.background ? plan.bg_time(i) : kNever;
      const Nanos tt = k < plan.trigger_time.size() ? plan.trigger_time[k] : kNever;
      if (std::min(tb, tt) - el >= 50'000) {
        map.add(phc->sample());
        last_sample = now;
      }
    }
    if (!ended && i >= plan.background && k >= plan.trigger_time.size()) {
      pk.flush(now, emit);
      pk.end_session(now, emit);
      ended = true;
      end_at = now;
    }
    if (ended && now - end_at >= o.linger) break;
    if (g_stop.load(std::memory_order_relaxed)) break;
  }
  const Nanos t_end = clock.now_mono();
  for (int n = 0; n < 1000 && feed.outstanding() != 0; ++n) feed.drain(on_stamp);
  feed.finish();
  feed.drain(on_stamp);
  if (phc) {
    for (int n = 0; n < 8; ++n) map.add(phc->sample());
  }
  desk_stop.store(true);
  desk_thread.join();

  if (map.valid()) {
    for (ttt::TriggerRecord& r : recs) r.sched_phc = map.to_phc(t0 + r.sched);
  }

  // Analysis (the client log, when given, is local; on the lab it comes from host C and
  // `analyze` adds it).
  ttt::Calibration cal;
  if (!o.calibration.empty()) {
    if (auto c = client::read_flat_json(o.calibration)) {
      cal.have = c->contains("c_ns");
      if (cal.have) cal.c = std::stoll((*c)["c_ns"]);
      cal.valid = (*c)["valid"] == "true";
    }
  }
  std::vector<client::OrderStampRecord> client_log;
  if (!o.client_log.empty() && !client::read_hwts_log(o.client_log, client_log, &err))
    std::fprintf(stderr, "ttt_harness: %s\n", err.c_str());
  const bool aligned = feed.aligned();
  const bool sw = feed.software_seen() || desk.software_seen();
  const ttt::Analysis an = ttt::analyze(plan, recs, client_log, cal, o.analysis, aligned, sw);

  client::JsonObject j;
  // Background generator lateness (software clock): a load point fails if p99.9 > 1 us.
  const bool bg_ok = bg_late.count() == 0 || bg_late.percentile(99.9) <= o.analysis.max_lateness_p999;
  const bool run_valid = an.valid && bg_ok && feed.failures() == 0;
  j.boolean("valid", run_valid).boolean("run_valid", run_valid);
  j.str("instrument", "ttt_harness").str("target", "t18");
  ttt::analysis_json(j, an);
  bg_late.json(j, "bg_lateness_sw_");
  j.boolean("bg_lateness_ok", bg_ok).boolean("tx_stamps_aligned", aligned).boolean("software_stamps_seen", sw);
  j.num("seed", o.plan.seed).num("background_rate", o.plan.background_rate).num("trigger_rate", o.plan.trigger_rate);
  j.num("duration_ns", static_cast<std::uint64_t>(o.plan.duration)).num("warmup_ns", static_cast<std::uint64_t>(o.analysis.warmup));
  j.num("background_messages", plan.background).num("background_sent", i).num("messages", plan.messages());
  j.num("packets_per_line", packets).num("elapsed_ns", static_cast<std::uint64_t>(t_end - t0));
  j.num("rerequest_replies", rr_served).num("test_packets_withheld", withheld);
  j.num("phc_samples", map.size()).inum("phc_map_uncertainty_ns", map.valid() ? map.uncertainty() : -1);
  j.inum("phc_drift_ppb", map.drift_ppb());
  feed.stats_json(j);
  desk.stats_json(j);
  client::variant_json(j, o.v, dev);
  const std::string json = j.done();
  std::fputs(json.c_str(), stdout);
  const std::string base = o.out + "/" + o.run_name;
  bool ok = write_text(base + ".json", json);
  ttt::RunHeader h;
  h.seed = o.plan.seed;
  h.start_realtime_ns = t0_real;
  h.start_mono_ns = t0;
  h.phc = dev.phc_index;
  ok = ttt::write_triggers(base + ".triggers.bin", h, recs) && ok;
  ok = client::write_hdr_log(base + ".hdr", {}, an.raw, t_end - t0, t0_real / 1'000'000, "ttt_harness TTT_raw ns") && ok;
  if (!ok) std::fprintf(stderr, "ttt_harness: cannot write the outputs under %s\n", base.c_str());
  return ok ? 0 : 1;
}

int run(int argc, char** argv) {
  Args a(argc, argv, "ttt_harness run");
  RunOptions o;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--file") o.file = a.value();
    else if (f == "--line-a") o.line[0] = a.endpoint();
    else if (f == "--line-b") o.line[1] = a.endpoint();
    else if (f == "--listen") o.listen = a.endpoint();
    else if (f == "--feed") o.feed = a.value();
    else if (f == "--rx-cpu") o.rx_cpu = static_cast<int>(a.u64());
    else if (f == "--rate") o.plan.background_rate = a.u64();
    else if (f == "--trigger-rate") o.plan.trigger_rate = a.u64();
    else if (f == "--duration") o.plan.duration = dur(a);
    else if (f == "--seed") o.plan.seed = a.u64();
    else if (f == "--warmup") o.analysis.warmup = dur(a);
    else if (f == "--min-triggers") o.analysis.min_triggers = a.u64();
    else if (f == "--symbol") o.symbol = Symbol8(a.value());
    else if (f == "--trigger-locate") o.trigger_locate = static_cast<std::uint16_t>(a.u64());
    else if (f == "--trigger-price") {
      const std::string v = a.value();
      const auto p = client::cli::parse_price(v);
      if (!p) a.die("bad price: " + v);
      o.trigger_price = *p;
    } else if (f == "--trigger-side") {
      const std::string v = a.value();
      o.trigger_side = v == "B" || v == "buy" ? Side::Buy : Side::Sell;
    } else if (f == "--trigger-shares") o.trigger_shares = static_cast<std::uint32_t>(a.u64());
    else if (f == "--max-packet") o.max_packet = a.u64();
    else if (f == "--batch-delay") o.batch_delay = dur(a);
    else if (f == "--start-delay") o.start_delay = dur(a);
    else if (f == "--linger") o.linger = dur(a);
    else if (f == "--session") o.session = a.value();
    else if (f == "--rerequest") o.rerequest = a.endpoint();
    else if (f == "--test-drop-every") o.test_drop_every = a.u64();
    else if (f == "--source-ip") {
      const std::string v = a.value();
      const auto e = net::parse_endpoint(v + ":0");
      if (!e) a.die("bad --source-ip");
      o.v.xsk.local_ip = e->ipv4;
    } else if (f == "--calibration") o.calibration = a.value();
    else if (f == "--client-log") o.client_log = a.value();
    else if (f == "--out") o.out = a.value();
    else if (f == "--run-name") o.run_name = a.value();
    else if (client::parse_variant_flag(a, f, o.v)) {
    } else a.die("unknown flag " + f);
  }
  if (o.file.empty() || o.line[0].port == 0 || o.line[1].port == 0 || o.listen.port == 0)
    a.die("--file, --line-a, --line-b and --listen are required");
  o.v.variant = client::Variant::Epoll;  // the acceptor is kernel TCP; the feed backend is --feed
  if (o.feed == "udp") return run_with<UdpFeed>(o);
#if defined(LLE_CLIENT_HAVE_XSK)
  if (o.feed == "xsk") return run_with<XskFeed>(o);
#endif
  a.die("--feed: udp" + std::string(
#if defined(LLE_CLIENT_HAVE_XSK)
                            " | xsk"
#else
                            " (xsk is not built here)"
#endif
                            ));
}

// ---- reflector calibration ------------------------------------------------------------------
// Probe and reply datagrams (little-endian, both ends are this program):
//   probe     "LLEP" u32 id
//   echo      "LLEE" u32 id
//   follow-up "LLEF" u32 id, i64 rx_hw, i64 tx_hw, i64 rx_sw, i64 tx_sw, i32 phc
struct Followup {
  char magic[4] = {'L', 'L', 'E', 'F'};
  std::uint32_t id = 0;
  std::int64_t rx_hw = 0, tx_hw = 0, rx_sw = 0, tx_sw = 0;
  std::int32_t phc = -1;
  std::int32_t pad = 0;
};
static_assert(sizeof(Followup) == 48);

net::hwts::PhcStamp stamp_of(const net::RxTimestamps& t, int phc) {
  if (t.hw_ns != 0) return {phc, t.hw_ns};
  return {-1, t.sw_ns};
}

struct UdpEnd {
  net::Stack<net::BackendKind::Epoll> stack{net::WaitPolicy::Spin};
  net::sock::UdpPort port;
  net::hwts::TxCorrelator corr;
  std::optional<std::string> open(net::Endpoint bind, const client::VariantConfig& v) {
    if (auto r = stack.open(); !r) return net::to_string(r.error());
    net::UdpConfig c;
    c.bind = bind;
    c.ifname = v.ifname;
    c.rx_ts = v.timestamps;
    c.tx_ts = v.timestamps;
    if (auto r = stack.open(port, c); !r) return net::to_string(r.error());
    corr.init(net::hwts::KeyMode::Datagram, 1 << 16);
    return std::nullopt;
  }
};

int reflect(int argc, char** argv) {
  Args a(argc, argv, "ttt_harness reflect");
  net::Endpoint listen{};
  client::VariantConfig v;
  Nanos max_runtime = 0;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--listen") listen = a.endpoint();
    else if (f == "--max-runtime") max_runtime = dur(a);
    else if (client::parse_variant_flag(a, f, v)) {
    } else a.die("unknown flag " + f);
  }
  if (listen.port == 0) a.die("--listen is required");
  client::DeviceReport dev;
  std::string err;
  if (!client::prepare_variant(v, dev, err)) a.die(err);
  UdpEnd e;
  if (auto r = e.open(listen, v)) a.die(*r);
  if (v.cpu >= 0) (void)rt::pin_current_thread(v.cpu);
  struct Pending {
    std::uint32_t id = 0;
    net::Endpoint to{};
    net::RxTimestamps rx{};
  };
  std::vector<Pending> pend(1 << 16);
  env::ProdClock clock;
  const Nanos start = clock.now_mono();
  std::uint64_t probes = 0, followups = 0;
  constexpr std::uint64_t kFollowupTag = ~0ull;
  while (!g_stop.load() && (max_runtime == 0 || clock.now_mono() - start < max_runtime)) {
    (void)e.stack.wait(1'000'000);
    e.port.poll_rx_ts([&](const env::RxDatagram& d, const net::RxTimestamps& ts) {
      if (d.data.size() < 8 || std::memcmp(d.data.data(), "LLEP", 4) != 0) return;
      std::uint32_t id = 0;
      std::memcpy(&id, d.data.data() + 4, 4);
      std::byte echo[8];
      std::memcpy(echo, "LLEE", 4);
      std::memcpy(echo + 4, &id, 4);
      if (e.port.send(d.src, std::span<const std::byte>(echo, 8))) {
        (void)e.corr.on_send(id, 8);
        pend[id & 0xFFFF] = Pending{id, d.src, ts};
        ++probes;
      }
    });
    e.port.drain_tx_timestamps([&](const net::TxStamp& s) {
      (void)e.corr.on_stamp(s, [&](std::uint64_t tag, const net::TxStamp& st) {
        if (tag == kFollowupTag) return;
        const Pending& p = pend[tag & 0xFFFF];
        if (p.id != tag) return;
        Followup fu;
        fu.id = p.id;
        fu.rx_hw = p.rx.hw_ns;
        fu.rx_sw = p.rx.sw_ns;
        fu.tx_hw = st.ts.hw_ns;
        fu.tx_sw = st.ts.sw_ns;
        fu.phc = dev.phc_index;
        std::byte b[sizeof(Followup)];
        std::memcpy(b, &fu, sizeof fu);
        if (e.port.send(p.to, std::span<const std::byte>(b, sizeof b))) {
          (void)e.corr.on_send(kFollowupTag, sizeof b);
          ++followups;
        }
      });
    });
  }
  client::JsonObject j;
  j.str("mode", "reflect").num("probes", probes).num("followups", followups).inum("phc_index", dev.phc_index);
  client::variant_json(j, v, dev);
  std::fputs(j.done().c_str(), stdout);
  return 0;
}

int calibrate(int argc, char** argv) {
  Args a(argc, argv, "ttt_harness calibrate");
  net::Endpoint peer{};
  client::VariantConfig v;
  std::uint64_t count = 100'000, rate = 10'000;
  std::string out;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--peer") peer = a.endpoint();
    else if (f == "--count") count = a.u64();
    else if (f == "--rate") rate = a.u64();
    else if (f == "--out") out = a.value();
    else if (client::parse_variant_flag(a, f, v)) {
    } else a.die("unknown flag " + f);
  }
  if (peer.port == 0 || count == 0 || rate == 0) a.die("--peer, --count > 0 and --rate > 0 are required");
  client::DeviceReport dev;
  std::string err;
  if (!client::prepare_variant(v, dev, err)) a.die(err);
  UdpEnd e;
  if (auto r = e.open(net::Endpoint{peer.ipv4 == net::kLoopbackV4 ? net::kLoopbackV4 : net::kAnyV4, 0}, v)) a.die(*r);
  if (v.cpu >= 0) (void)rt::pin_current_thread(v.cpu);
  std::vector<ttt::ProbeResult> res(count);
  std::vector<std::uint8_t> got(count, 0);  // bit 0 echo, bit 1 follow-up, bit 2 TX stamp
  env::ProdClock clock;
  const Nanos t0 = clock.now_mono();
  const Nanos gap = kNsPerSec / static_cast<Nanos>(rate);
  std::uint64_t sent = 0;
  Nanos last_rx = t0;
  while (!g_stop.load()) {
    const Nanos now = clock.now_mono();
    if (sent < count && now - t0 >= static_cast<Nanos>(sent) * gap) {
      std::byte p[8];
      std::memcpy(p, "LLEP", 4);
      const auto id = static_cast<std::uint32_t>(sent);
      std::memcpy(p + 4, &id, 4);
      if (e.port.send(peer, std::span<const std::byte>(p, 8))) (void)e.corr.on_send(id, 8);
      ++sent;
    }
    e.port.poll_rx_ts([&](const env::RxDatagram& d, const net::RxTimestamps& ts) {
      if (d.data.size() < 8) return;
      std::uint32_t id = 0;
      std::memcpy(&id, d.data.data() + 4, 4);
      if (id >= count) return;
      last_rx = now;
      if (std::memcmp(d.data.data(), "LLEE", 4) == 0) {
        res[id].a_rx = stamp_of(ts, dev.phc_index);
        got[id] |= 1;
      } else if (std::memcmp(d.data.data(), "LLEF", 4) == 0 && d.data.size() >= sizeof(Followup)) {
        Followup fu;
        std::memcpy(&fu, d.data.data(), sizeof fu);
        res[id].c_rx = fu.rx_hw != 0 ? net::hwts::PhcStamp{fu.phc, fu.rx_hw} : net::hwts::PhcStamp{-1, fu.rx_sw};
        res[id].c_tx = fu.tx_hw != 0 ? net::hwts::PhcStamp{fu.phc, fu.tx_hw} : net::hwts::PhcStamp{-1, fu.tx_sw};
        got[id] |= 2;
      }
    });
    e.port.drain_tx_timestamps([&](const net::TxStamp& s) {
      (void)e.corr.on_stamp(s, [&](std::uint64_t tag, const net::TxStamp& st) {
        if (tag < count) {
          res[tag].a_tx = stamp_of(st.ts, dev.phc_index);
          got[tag] |= 4;
        }
      });
    });
    if (sent == count && now - last_rx > 500'000'000) break;  // replies have stopped coming
  }
  const ttt::CalibrationResult cr = ttt::calibrate(res);
  std::uint64_t complete = 0;
  for (const std::uint8_t g : got) complete += g == 7 ? 1u : 0u;
  client::JsonObject j;
  j.str("mode", "calibrate").boolean("valid", cr.valid).inum("c_ns", cr.c);
  j.num("probes", count).num("probes_complete", complete);
  j.num("rtt_pairs_ok", cr.rtt_acc.ok).num("rtt_pairs_missing", cr.rtt_acc.missing);
  j.num("rtt_pairs_software", cr.rtt_acc.software).num("rtt_pairs_cross_phc", cr.rtt_acc.cross_phc);
  j.num("turn_pairs_ok", cr.turn_acc.ok).num("turn_pairs_missing", cr.turn_acc.missing);
  j.num("turn_pairs_software", cr.turn_acc.software).num("turn_pairs_cross_phc", cr.turn_acc.cross_phc);
  cr.c2.json(j, "two_c_");
  client::variant_json(j, v, dev);
  const std::string json = j.done();
  std::fputs(json.c_str(), stdout);
  if (!out.empty() && !write_text(out, json)) a.die("cannot write " + out);
  return cr.valid ? 0 : 1;
}

// ---- offline analysis -----------------------------------------------------------------------
int analyze(int argc, char** argv) {
  Args a(argc, argv, "ttt_harness analyze");
  std::string triggers, harness_report, client_log, client_report, calibration, out;
  ttt::AnalysisConfig cfg;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--triggers") triggers = a.value();
    else if (f == "--harness-report") harness_report = a.value();
    else if (f == "--client-log") client_log = a.value();
    else if (f == "--client-report") client_report = a.value();
    else if (f == "--calibration") calibration = a.value();
    else if (f == "--warmup") cfg.warmup = dur(a);
    else if (f == "--min-triggers") cfg.min_triggers = a.u64();
    else if (f == "--out") out = a.value();
    else a.die("unknown flag " + f);
  }
  if (triggers.empty() || out.empty()) a.die("--triggers and --out are required");
  ttt::RunHeader h;
  std::vector<ttt::TriggerRecord> recs;
  std::string err;
  if (!ttt::read_triggers(triggers, h, recs, &err)) a.die(err);
  ttt::Plan plan;
  plan.trigger_seq.reserve(recs.size());
  plan.trigger_time.reserve(recs.size());
  for (const auto& r : recs) {
    plan.trigger_seq.push_back(r.seq);
    plan.trigger_time.push_back(r.sched);
  }
  std::map<std::string, std::string> hr;
  if (!harness_report.empty()) {
    auto m = client::read_flat_json(harness_report);
    if (!m) a.die("cannot read " + harness_report);
    hr = *m;
  }
  std::vector<client::OrderStampRecord> cl;
  if (!client_log.empty() && !client::read_hwts_log(client_log, cl, &err)) a.die(err);
  ttt::Calibration cal;
  if (!calibration.empty()) {
    auto c = client::read_flat_json(calibration);
    if (!c || !c->contains("c_ns")) a.die("cannot read c_ns from " + calibration);
    cal.have = true;
    cal.c = std::stoll((*c)["c_ns"]);
    cal.valid = (*c)["valid"] == "true";
  }
  const bool aligned = hr.empty() || hr["tx_stamps_aligned"] == "true";
  const bool sw = !hr.empty() && hr["software_stamps_seen"] == "true";
  const ttt::Analysis an = ttt::analyze(plan, recs, cl, cal, cfg, aligned, sw);
  client::JsonObject j;
  j.str("instrument", "ttt_harness").str("target", "t18").str("mode", "analyze");
  ttt::analysis_json(j, an);
  bool run_valid = an.valid;
  std::string extra;
  if (!hr.empty()) {
    const bool bg_ok = hr["bg_lateness_ok"] == "true";
    const bool feed_ok = hr["feed_send_failures"] == "0" || !hr.contains("feed_send_failures");
    j.boolean("bg_lateness_ok", bg_ok);
    if (!bg_ok) extra += "background generator lateness; ";
    if (!feed_ok) extra += "feed send failures; ";
    run_valid = run_valid && bg_ok && feed_ok;
    for (const char* k : {"bg_lateness_sw_p999_ns", "phc_map_uncertainty_ns", "phc_drift_ppb", "packets_per_line",
                          "background_rate", "trigger_rate", "seed"})
      if (hr.contains(k)) j.raw(k, hr[k]);
  }
  if (!client_report.empty()) {
    auto m = client::read_flat_json(client_report);
    if (!m) a.die("cannot read " + client_report);
    const bool gap_free = (*m)["feed_gap_free"] == "true";
    const bool cal_flag = (*m).contains("ttt_client_valid");
    j.boolean("client_feed_gap_free", gap_free);
    if (cal_flag) j.raw("client_report_ttt_client_valid", (*m)["ttt_client_valid"]);
    if (!gap_free) extra += "MoldUDP64 gap on the client (re-request or snapshot); ";
    run_valid = run_valid && gap_free;
  }
  if (cal.have && !cal.valid) extra += "calibration run invalid (TTT_cal not publishable); ";
  j.str("run_invalid_extra", extra);
  j.boolean("run_valid", run_valid).boolean("valid", run_valid);
  const std::string json = j.done();
  std::fputs(json.c_str(), stdout);
  if (!write_text(out, json)) a.die("cannot write " + out);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  const std::string mode = argc > 1 ? argv[1] : "";
  if (mode == "run") return run(argc - 1, argv + 1);
  if (mode == "reflect") return reflect(argc - 1, argv + 1);
  if (mode == "calibrate") return calibrate(argc - 1, argv + 1);
  if (mode == "analyze") return analyze(argc - 1, argv + 1);
  std::fprintf(stderr, "usage: ttt_harness run|reflect|calibrate|analyze ... (see apps/ttt_harness/main.cpp)\n%s",
               client::variant_flags_usage());
  return 2;
}
