// AF_XDP functional tests on veth pairs (07 §5 "AF_XDP copy mode"; R3a XskSmoke.VethCopyMode).
// Run as root inside namespace A by xsk_veth_test.sh, which provides:
//   LLE_XSK_IF / LLE_XSK_IF2        veth ends in this namespace (line A / line B)
//   LLE_XSK_LOCAL_IP / _LOCAL_IP2   their kernel-owned addresses
//   LLE_XSK_PEER_IP / _PEER_IP2     the peer namespace's addresses (UDP echo on port 7)
// Without them (or without root) every test is skipped. veth has no zero-copy and no
// hardware clock: these tests check function, never latency or hardware timestamps.
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "net/utcp/linux/af_packet_port.h"
#include "net/utcp/linux/neigh_netlink.h"
#include "net/xsk/datagram_port.h"
#include "net/xsk/frame_port.h"
#include "net/xsk/multicast.h"
#include "net/xsk/napi.h"
#include "net/xsk/socket.h"
#include "net/xsk/steer.h"
#include "net/xsk/umem.h"
#if defined(LLE_XSK_TEST_CLIENT)
#include "client/client_io.h"  // defines IoSpec etc. and includes client/xsk_io.h
#endif

namespace lle::net::xsk {
namespace {

using utcp::MacAddr;

std::uint32_t parse_ip(const char* s) {
  in_addr a{};
  return s != nullptr && ::inet_pton(AF_INET, s, &a) == 1 ? ntohl(a.s_addr) : 0;
}

struct Line {
  std::string ifname;
  std::uint32_t local_ip = 0;
  std::uint32_t peer_ip = 0;
  MacAddr mac;
  MacAddr peer_mac;
};

std::optional<Line> line(int which) {
  const char* ifn = std::getenv(which == 0 ? "LLE_XSK_IF" : "LLE_XSK_IF2");
  if (ifn == nullptr || ::geteuid() != 0) return std::nullopt;
  Line l;
  l.ifname = ifn;
  l.local_ip = parse_ip(std::getenv(which == 0 ? "LLE_XSK_LOCAL_IP" : "LLE_XSK_LOCAL_IP2"));
  l.peer_ip = parse_ip(std::getenv(which == 0 ? "LLE_XSK_PEER_IP" : "LLE_XSK_PEER_IP2"));
  auto mac = utcp::interface_mac(l.ifname);
  if (!mac || l.local_ip == 0 || l.peer_ip == 0) return std::nullopt;
  l.mac = *mac;
  auto pm = utcp::resolve_via_kernel(l.ifname, l.peer_ip, 2000);
  if (!pm) return std::nullopt;
  l.peer_mac = *pm;
  return l;
}

#define NEED_LINE(var, which)                                              \
  auto var##_opt = line(which);                                            \
  if (!var##_opt) GTEST_SKIP() << "needs root and xsk_veth_test.sh setup"; \
  const Line& var = *var##_opt

XskConfig copy_cfg(const Line& l) {
  XskConfig c;
  c.ifname = l.ifname;
  c.queue = 0;
  c.mode = BindMode::AllowCopy;  // veth: the dev/test override
  c.rx_metadata = true;
  c.fill_frames = 1024;
  return c;
}

XskDatagramConfig dgram_cfg(const Line& l, std::uint16_t port) {
  XskDatagramConfig d;
  d.local_mac = l.mac;
  d.local_ip = l.local_ip;
  d.local_port = port;
  d.static_next_hop = l.peer_mac;
  d.rx_ports[0] = port;
  return d;
}

std::span<const std::byte> bytes(const std::string& s) { return {reinterpret_cast<const std::byte*>(s.data()), s.size()}; }

// Polls `fn` until it returns true or the timeout expires.
template <class F>
bool wait_for(F&& fn, int timeout_ms = 5000) {
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < end) {
    if (fn()) return true;
  }
  return fn();
}

TEST(XskVeth, ZeroCopyEnforcedAndCopyModeOverride) {
  NEED_LINE(l, 0);
  {
    auto u = Umem::create(UmemConfig{});
    ASSERT_TRUE(u) << u.error().what << ": " << std::strerror(u.error().err);
    XskConfig c = copy_cfg(l);
    c.mode = BindMode::ZeroCopyRequired;
    auto s = XskSocket::create(**u, c);
    ASSERT_FALSE(s) << "veth must not report zero-copy";
    std::printf("[xsk] ZeroCopyRequired on veth refused: %s (%s)\n", s.error().what, std::strerror(s.error().err));
  }
  auto u = Umem::create(UmemConfig{});
  ASSERT_TRUE(u);
  auto s = XskSocket::create(**u, copy_cfg(l));
  ASSERT_TRUE(s) << s.error().what << ": " << std::strerror(s.error().err);
  EXPECT_FALSE((*s)->zero_copy());
  std::printf("[xsk] copy-mode bind ok; umem hugepages=%d tx_metadata=%d (0 none, 1 without flag, 2 with flag) len=%u\n",
              (*u)->hugepages(), static_cast<int>((*u)->tx_metadata_support()), (*u)->tx_metadata_len());
  EXPECT_EQ((*u)->tx_metadata_support(), TxMetadataSupport::WithFlag);  // kernel 7.0
  EXPECT_EQ((*u)->tx_metadata_len(), 24u);
}

// Free 2 MiB hugepages from /proc/meminfo.
long hugepages_free() {
  FILE* f = std::fopen("/proc/meminfo", "r");
  if (f == nullptr) return 0;
  char line_buf[256];
  long n = 0;
  while (std::fgets(line_buf, sizeof(line_buf), f) != nullptr) {
    if (std::sscanf(line_buf, "HugePages_Free: %ld", &n) == 1) break;
  }
  std::fclose(f);
  return n;
}

TEST(XskVeth, HugepageUmemWhenAvailable) {
  NEED_LINE(l, 0);
  const long free_before = hugepages_free();
  auto u = Umem::create(UmemConfig{});
  ASSERT_TRUE(u);
  std::printf("[xsk] UMEM on hugepages: %s (%ld free before)\n", (*u)->hugepages() ? "yes" : "no (fell back)", free_before);
  // 4096 x 4 KiB = 16 MiB = 8 hugepages; xsk_veth_test.sh reserves some.
  if (free_before >= 8) EXPECT_TRUE((*u)->hugepages());
  auto s = XskSocket::create(**u, copy_cfg(l));
  EXPECT_TRUE(s) << s.error().what << ": " << std::strerror(s.error().err);
  auto small = Umem::create(UmemConfig{64, 4096, 24, false});
  ASSERT_TRUE(small);
  EXPECT_FALSE((*small)->hugepages());  // normal pages when hugepages are not requested
}

TEST(XskVeth, SteerRedirectsOnlyConfiguredPorts) {
  NEED_LINE(l, 0);
  auto prog = SteerProgram::load(SteerConfig{LLE_XSK_BPF_OBJECT, l.ifname, true, false});
  ASSERT_TRUE(prog) << prog.error().what << ": " << std::strerror(prog.error().err);
  std::printf("[xsk] %s; attach=%s\n", (*prog)->load_note().c_str(),
              (*prog)->attach_mode() == AttachMode::Native ? "native (xdpdrv)" : "skb");
  EXPECT_TRUE((*prog)->device_bound()) << "veth implements the XDP RX-metadata kfuncs";
  auto u = Umem::create(UmemConfig{});
  ASSERT_TRUE(u);
  auto s = XskSocket::create(**u, copy_cfg(l));
  ASSERT_TRUE(s);
  ASSERT_TRUE((*prog)->set_xsk(0, (*s)->fd()));
  ASSERT_TRUE((*prog)->add_md_port(9000));
  XskDatagramPort dp(**s, dgram_cfg(l, 9000));

  // A kernel socket on 9001: its echoes must stay in the kernel.
  const int ks = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  sockaddr_in me{};
  me.sin_family = AF_INET;
  me.sin_port = htons(9001);
  me.sin_addr.s_addr = htonl(l.local_ip);
  ASSERT_EQ(::bind(ks, reinterpret_cast<sockaddr*>(&me), sizeof(me)), 0);
  sockaddr_in echo{};
  echo.sin_family = AF_INET;
  echo.sin_port = htons(7);
  echo.sin_addr.s_addr = htonl(l.peer_ip);

  constexpr int kN = 2000;
  int xsk_got = 0, kernel_got = 0, meta_present = 0, hw_nonzero = 0, wrong_port = 0;
  char kbuf[2048];
  for (int i = 0; i < kN; ++i) {
    const std::string m = "md-" + std::to_string(i);
    ASSERT_TRUE(dp.send(env::Endpoint{l.peer_ip, 7}, bytes(m)));
    const std::string k = "kernel-" + std::to_string(i);
    (void)::sendto(ks, k.data(), k.size(), 0, reinterpret_cast<sockaddr*>(&echo), sizeof(echo));
    auto drain = [&] {
      (void)dp.poll_rx([&](const env::RxDatagram& r) {
        ++xsk_got;
        if (r.dst.port != 9000) ++wrong_port;
        if (r.hw_rx_ns != 0) ++hw_nonzero;
      });
      while (::recv(ks, kbuf, sizeof(kbuf), 0) > 0) ++kernel_got;
    };
    drain();
    if (i % 64 == 63) (void)wait_for([&] { drain(); return xsk_got >= i - 32; }, 2000);
  }
  ASSERT_TRUE(wait_for([&] {
    (void)dp.poll_rx([&](const env::RxDatagram& r) {
      ++xsk_got;
      if (r.dst.port != 9000) ++wrong_port;
      if (r.hw_rx_ns != 0) ++hw_nonzero;
    });
    while (::recv(ks, kbuf, sizeof(kbuf), 0) > 0) ++kernel_got;
    return xsk_got >= kN && kernel_got >= kN;
  }));
  ::close(ks);
  (void)meta_present;
  const SteerStats st = (*prog)->stats();
  const XskStats xs = (*s)->stats();
  std::printf("[xsk] steer: redirect_udp=%llu pass=%llu meta_ts=%llu meta_nodata=%llu meta_fail=%llu; xsk rx=%llu "
              "meta_ts_valid=%llu (copy mode: never reported as HW) drops=%llu\n",
              static_cast<unsigned long long>(st.redirect_udp), static_cast<unsigned long long>(st.pass),
              static_cast<unsigned long long>(st.meta_ts), static_cast<unsigned long long>(st.meta_nodata),
              static_cast<unsigned long long>(st.meta_fail), static_cast<unsigned long long>(xs.rx_frames),
              static_cast<unsigned long long>(xs.rx_meta_ts_valid), static_cast<unsigned long long>(xs.drops()));
  EXPECT_EQ(xsk_got, kN);
  EXPECT_EQ(kernel_got, kN);
  EXPECT_EQ(wrong_port, 0);
  EXPECT_EQ(hw_nonzero, 0) << "copy mode must never surface hardware timestamps";
  EXPECT_GE(st.redirect_udp, static_cast<std::uint64_t>(kN));
  EXPECT_GE(st.pass, static_cast<std::uint64_t>(kN));
  EXPECT_EQ(st.meta_fail, 0u);
  EXPECT_EQ(st.meta_ts + st.meta_nodata, st.redirect_udp);
  EXPECT_EQ(xs.drops(), 0u);
  EXPECT_EQ(dp.stats().rx_bad, 0u);
}

TEST(XskVeth, DatagramBurstsZeroDrops) {
  NEED_LINE(l, 0);
  auto prog = SteerProgram::load(SteerConfig{LLE_XSK_BPF_OBJECT, l.ifname, true, false});
  ASSERT_TRUE(prog);
  auto u = Umem::create(UmemConfig{});
  ASSERT_TRUE(u);
  XskConfig c = copy_cfg(l);
  c.busy_poll = true;  // SO_PREFER_BUSY_POLL / SO_BUSY_POLL / SO_BUSY_POLL_BUDGET (root)
  auto s = XskSocket::create(**u, c);
  ASSERT_TRUE(s) << s.error().what << ": " << std::strerror(s.error().err);
  EXPECT_TRUE((*s)->busy_poll_enabled());
  ASSERT_TRUE((*prog)->set_xsk(0, (*s)->fd()));
  ASSERT_TRUE((*prog)->add_md_port(9100));
  XskDatagramPort dp(**s, dgram_cfg(l, 9100));
  constexpr int kBursts = 400, kBurst = 64;
  std::uint64_t got = 0, sent = 0;
  std::string payload(200, 'x');
  for (int b = 0; b < kBursts; ++b) {
    for (int i = 0; i < kBurst; ++i) sent += dp.send(env::Endpoint{l.peer_ip, 7}, bytes(payload)) ? 1u : 0u;
    ASSERT_TRUE(wait_for([&] {
      got += dp.poll_rx([](const env::RxDatagram&) {});
      return got >= sent;
    }));
  }
  const XskStats xs = (*s)->stats();
  std::printf("[xsk] bursts: sent=%llu received=%llu XDP_STATISTICS rx_dropped=%llu rx_invalid=%llu tx_invalid=%llu "
              "rx_ring_full=%llu fill_empty=%llu tx_ring_empty=%llu\n",
              static_cast<unsigned long long>(sent), static_cast<unsigned long long>(got),
              static_cast<unsigned long long>(xs.rx_dropped), static_cast<unsigned long long>(xs.rx_invalid_descs),
              static_cast<unsigned long long>(xs.tx_invalid_descs), static_cast<unsigned long long>(xs.rx_ring_full),
              static_cast<unsigned long long>(xs.rx_fill_ring_empty_descs),
              static_cast<unsigned long long>(xs.tx_ring_empty_descs));
  EXPECT_EQ(sent, std::uint64_t{kBursts} * std::uint64_t{kBurst});
  EXPECT_EQ(got, sent);
  EXPECT_EQ(xs.drops(), 0u);
}

TEST(XskVeth, TxMetadataTimestampRequest) {
  NEED_LINE(l, 0);
  auto prog = SteerProgram::load(SteerConfig{LLE_XSK_BPF_OBJECT, l.ifname, true, false});
  ASSERT_TRUE(prog);
  auto u = Umem::create(UmemConfig{});
  ASSERT_TRUE(u);
  auto s = XskSocket::create(**u, copy_cfg(l));
  ASSERT_TRUE(s);
  ASSERT_TRUE((*prog)->set_xsk(0, (*s)->fd()));
  ASSERT_TRUE((*prog)->add_md_port(9200));
  XskDatagramConfig dc = dgram_cfg(l, 9200);
  dc.tx_timestamps = true;
  XskDatagramPort dp(**s, dc);
  int got = 0;
  for (int i = 0; i < 100; ++i) ASSERT_TRUE(dp.send(env::Endpoint{l.peer_ip, 7}, bytes("ts")));
  ASSERT_TRUE(wait_for([&] {
    got += static_cast<int>(dp.poll_rx([](const env::RxDatagram&) {}));
    return got >= 100;
  }));
  Nanos nonzero = 0;
  (void)(*s)->reap([&](Nanos t) { nonzero += t != 0 ? 1 : 0; });
  const XskStats xs = (*s)->stats();
  std::printf("[xsk] TX metadata: %llu completions carried XDP_TXMD_FLAGS_TIMESTAMP; tx_invalid_descs=%llu "
              "(copy mode reports 0 as the timestamp)\n",
              static_cast<unsigned long long>(xs.tx_ts_completions), static_cast<unsigned long long>(xs.tx_invalid_descs));
  EXPECT_EQ(xs.tx_invalid_descs, 0u);
  EXPECT_EQ(xs.tx_ts_completions, 100u);
  EXPECT_EQ(nonzero, 0);
}

TEST(XskVeth, SharedUmemAcrossTwoDevices) {
  NEED_LINE(a, 0);
  NEED_LINE(b, 1);
  auto pa = SteerProgram::load(SteerConfig{LLE_XSK_BPF_OBJECT, a.ifname, true, false});
  auto pb = SteerProgram::load(SteerConfig{LLE_XSK_BPF_OBJECT, b.ifname, true, false});
  ASSERT_TRUE(pa && pb);
  auto u = Umem::create(UmemConfig{});
  ASSERT_TRUE(u);
  XskConfig ca = copy_cfg(a);
  XskConfig cb = copy_cfg(b);
  auto sa = XskSocket::create(**u, ca);  // owner of the UMEM registration
  ASSERT_TRUE(sa);
  auto sb = XskSocket::create(**u, cb);  // XDP_SHARED_UMEM, its own FILL/COMP pair
  ASSERT_TRUE(sb) << sb.error().what << ": " << std::strerror(sb.error().err);
  ASSERT_TRUE((*pa)->set_xsk(0, (*sa)->fd()));
  ASSERT_TRUE((*pb)->set_xsk(0, (*sb)->fd()));
  ASSERT_TRUE((*pa)->add_md_port(9300));
  ASSERT_TRUE((*pb)->add_md_port(9300));
  XskDatagramPort da(**sa, dgram_cfg(a, 9300));
  XskDatagramPort db(**sb, dgram_cfg(b, 9300));
  int got_a = 0, got_b = 0;
  for (int i = 0; i < 500; ++i) {
    ASSERT_TRUE(da.send(env::Endpoint{a.peer_ip, 7}, bytes("A")));
    ASSERT_TRUE(db.send(env::Endpoint{b.peer_ip, 7}, bytes("B")));
    got_a += static_cast<int>(da.poll_rx([](const env::RxDatagram&) {}));
    got_b += static_cast<int>(db.poll_rx([](const env::RxDatagram&) {}));
  }
  // One thread arbitrates both lines from one UMEM (07 §2.3).
  ASSERT_TRUE(wait_for([&] {
    got_a += static_cast<int>(da.poll_rx([](const env::RxDatagram&) {}));
    got_b += static_cast<int>(db.poll_rx([](const env::RxDatagram&) {}));
    return got_a >= 500 && got_b >= 500;
  }));
  EXPECT_EQ(got_a, 500);
  EXPECT_EQ(got_b, 500);
  EXPECT_EQ((*sa)->stats().drops() + (*sb)->stats().drops(), 0u);
}

TEST(XskVeth, MulticastMembershipHelper) {
  NEED_LINE(l, 0);
  auto m = MulticastMembership::join(l.ifname, utcp::ipv4(233, 54, 12, 1));
  ASSERT_TRUE(m) << m.error().what << ": " << std::strerror(m.error().err);
  auto ssm = MulticastMembership::join(l.ifname, utcp::ipv4(232, 1, 2, 3), l.peer_ip);
  ASSERT_TRUE(ssm) << ssm.error().what << ": " << std::strerror(ssm.error().err);
  // The kernel now lists the groups on the interface (and programs the MAC filter).
  FILE* f = std::fopen("/proc/net/igmp", "r");
  ASSERT_NE(f, nullptr);
  std::string all;
  char line_buf[256];
  while (std::fgets(line_buf, sizeof(line_buf), f) != nullptr) all += line_buf;
  std::fclose(f);
  EXPECT_NE(all.find("010C36E9"), std::string::npos) << all;  // 233.54.12.1, little-endian hex
}

TEST(XskVeth, NapiControl) {
  NEED_LINE(l, 0);
  // veth has a NAPI instance per rx queue only while an XDP program is attached.
  auto prog = SteerProgram::load(SteerConfig{LLE_XSK_BPF_OBJECT, l.ifname, true, false});
  ASSERT_TRUE(prog);
  const int ifindex = static_cast<int>(::if_nametoindex(l.ifname.c_str()));
  auto id = napi_id_for_rx_queue(ifindex, 0);
  if (!id) {
    std::printf("[xsk] napi: queue-get on veth rx0 gave no NAPI id (%s): the driver does not link the queue\n",
                std::strerror(id.error()));
    GTEST_SKIP() << "veth queue has no NAPI id";
  }
  auto info = napi_get(*id);
  ASSERT_TRUE(info) << std::strerror(info.error());
  std::printf("[xsk] napi id %u ifindex %d irq %d pid %d threaded %d\n", info->id, info->ifindex, info->irq, info->pid,
              info->threaded);
  auto set = napi_set_threaded(*id, NapiThreaded::BusyPoll);
  if (!set) {
    std::printf("[xsk] napi-set threaded=busy-poll refused: %s\n", std::strerror(set.error()));
  } else {
    auto after = napi_get(*id);
    ASSERT_TRUE(after);
    std::printf("[xsk] napi-set threaded=busy-poll ok: kthread pid %d, threaded=%d\n", after->pid, after->threaded);
    EXPECT_EQ(after->threaded, static_cast<int>(NapiThreaded::BusyPoll));
    EXPECT_GT(after->pid, 0);
    ASSERT_TRUE(napi_set_threaded(*id, NapiThreaded::Disabled));
  }
}


// ---- TX completion reporting (every reap path reports; copy mode never valid) ------

// Builds a UDP frame to the peer's discard port into a TX buffer; returns its length.
std::size_t udp_frame(std::span<std::byte> b, const Line& l, std::uint16_t ip_id) {
  utcp::UdpHeaderSpec h;
  h.src_mac = l.mac;
  h.dst_mac = l.peer_mac;
  h.src_ip = l.local_ip;
  h.dst_ip = l.peer_ip;
  h.src_port = 9400;
  h.dst_port = 9;
  h.ip_id = ip_id;
  std::memset(b.data() + utcp::kUdpFrameOverhead, 0x5A, 32);
  return utcp::finish_udp_in_place(b, h, 32, false);
}

struct CompletionLog {
  std::vector<TxCompletion> got;
  int phase = 0;              // which reap path is running
  std::array<int, 8> by_phase{};
  static void on(void* ctx, const TxCompletion& c) noexcept {
    auto* self = static_cast<CompletionLog*>(ctx);
    self->got.push_back(c);
    ++self->by_phase[static_cast<std::size_t>(self->phase)];
  }
};

TEST(XskVeth, TxCompletionHandlerEveryReapPath) {
  NEED_LINE(l, 0);
  auto u = Umem::create(UmemConfig{512, 4096, 24, false});
  ASSERT_TRUE(u);
  XskConfig c = copy_cfg(l);
  c.tx_size = 64;  // small, so the ring-full fallback in tx_commit() runs
  c.fill_frames = 64;
  c.reap_on_rx_poll = true;
  auto sp = XskSocket::create(**u, c);
  ASSERT_TRUE(sp) << sp.error().what << ": " << std::strerror(sp.error().err);
  XskSocket& s = **sp;
  CompletionLog log;
  log.got.reserve(8192);
  s.set_tx_completion_handler(&CompletionLog::on, &log);

  std::uint64_t cookie = 0;
  std::vector<std::uint64_t> want;  // cookies that must be reported, in commit order
  std::uint64_t want_ts = 0;
  // Commits one frame; frame k: timestamp (2 of 3), notify-only (some of the rest) or plain.
  auto commit = [&]() -> bool {
    std::span<std::byte> b = s.tx_acquire();
    if (b.empty()) return false;
    const std::size_t n = udp_frame(b, l, static_cast<std::uint16_t>(cookie));
    TxOptions o;
    ++cookie;
    o.cookie = cookie;
    o.timestamp = cookie % 3 != 0;
    o.notify = cookie % 6 == 0;
    if (!s.tx_commit(n, o)) return false;
    if (o.timestamp || o.notify) want.push_back(cookie);
    if (o.timestamp) ++want_ts;
    return true;
  };
  auto raw_kick = [&] { (void)::sendto(s.fd(), nullptr, 0, MSG_DONTWAIT, nullptr, 0); };

  // 1: flush().
  log.phase = 1;
  for (int i = 0; i < 40; ++i) ASSERT_TRUE(commit());
  ASSERT_TRUE(wait_for([&] { s.flush(); return s.tx_outstanding() == 0; }));
  // 2: tx_commit()'s fallback when the 64-entry TX ring is full (it flushes and reaps).
  log.phase = 2;
  for (int i = 0; i < 200; ++i) ASSERT_TRUE(commit());
  // 3: tx_acquire()'s internal reap when the UMEM has no free frame: kick without reaping.
  log.phase = 3;
  for (int i = 0; i < 2000; ++i) {
    if (!commit()) break;
    if (i % 16 == 15) raw_kick();
  }
  // 4: poll_rx() with reap_on_rx_poll.
  ASSERT_TRUE(wait_for([&] { raw_kick(); (void)s.reap(); return s.tx_outstanding() == 0; }));
  for (int i = 0; i < 20; ++i) ASSERT_TRUE(commit());
  raw_kick();
  log.phase = 4;
  for (int i = 0; i < 100 && s.tx_outstanding() != 0; ++i) {
    (void)s.poll_rx(0, [](std::span<const std::byte>, const RxMeta&) { return true; });
    raw_kick();
  }
  // 5: explicit reap().
  for (int i = 0; i < 20; ++i) ASSERT_TRUE(commit());
  raw_kick();
  log.phase = 5;
  ASSERT_TRUE(wait_for([&] { raw_kick(); (void)s.reap(); return s.tx_outstanding() == 0; }));

  std::printf("[xsk] completion handler: %zu reports; by path flush=%d commit-fallback=%d acquire=%d poll_rx=%d reap=%d\n",
              log.got.size(), log.by_phase[1], log.by_phase[2], log.by_phase[3], log.by_phase[4], log.by_phase[5]);
  ASSERT_EQ(log.got.size(), want.size());
  std::uint64_t ts_reports = 0;
  for (std::size_t i = 0; i < want.size(); ++i) {
    EXPECT_EQ(log.got[i].cookie, want[i]) << "report " << i << " out of order or wrong";
    EXPECT_EQ(log.got[i].ts_requested, want[i] % 3 != 0);
    EXPECT_FALSE(log.got[i].valid) << "copy mode must never report a hardware TX timestamp";
    EXPECT_EQ(log.got[i].hw_tx_ns, 0);
    ts_reports += log.got[i].ts_requested ? 1u : 0u;
  }
  for (int ph = 1; ph <= 5; ++ph) EXPECT_GT(log.by_phase[static_cast<std::size_t>(ph)], 0) << "reap path " << ph;
  const XskStats st = s.stats();
  EXPECT_EQ(st.tx_ts_completions, want_ts);
  EXPECT_EQ(ts_reports, want_ts);
  EXPECT_EQ(st.tx_completions_reported, want.size());
  EXPECT_EQ(st.tx_ts_valid, 0u);
  EXPECT_EQ(st.tx_invalid_descs, 0u);
  std::printf("[xsk] tx_ts_completions=%llu tx_ts_copy_mode=%llu (copy-mode values counted, not reported)\n",
              static_cast<unsigned long long>(st.tx_ts_completions), static_cast<unsigned long long>(st.tx_ts_copy_mode));
  s.set_tx_completion_handler(nullptr, nullptr);
}

TEST(XskVeth, FramePortCookiesReachHandler) {
  NEED_LINE(l, 0);
  auto u = Umem::create(UmemConfig{512, 4096, 24, false});
  ASSERT_TRUE(u);
  XskConfig c = copy_cfg(l);
  c.fill_frames = 64;  // leave most of the 512-frame UMEM for TX
  auto sp = XskSocket::create(**u, c);
  ASSERT_TRUE(sp);
  CompletionLog log;
  log.got.reserve(256);
  (*sp)->set_tx_completion_handler(&CompletionLog::on, &log);
  XskFramePort fp(**sp, XskFramePortConfig{false, true, false});  // tx_timestamps on every frame
  std::array<std::byte, 256> f{};
  const std::size_t n = udp_frame(f, l, 1);
  for (int i = 0; i < 100; ++i) ASSERT_TRUE(fp.send_frame(std::span<const std::byte>(f.data(), n)));
  EXPECT_EQ(fp.last_tx_cookie(), 100u);
  ASSERT_TRUE(wait_for([&] { fp.flush(); return (*sp)->tx_outstanding() == 0; }));
  ASSERT_EQ(log.got.size(), 100u);
  for (std::size_t i = 0; i < log.got.size(); ++i) {
    EXPECT_EQ(log.got[i].cookie, i + 1);
    EXPECT_TRUE(log.got[i].ts_requested);
    EXPECT_FALSE(log.got[i].valid);
  }
}

#if defined(LLE_XSK_TEST_CLIENT)
// The clients' StampingFramePort (src/client/xsk_io.h) receives every stamped completion
// even when the socket's own flush() reaps it (copy mode: stamps are 0, never hardware).
TEST(XskVeth, ClientStampingFramePortSeesEveryReap) {
  NEED_LINE(l, 0);
  auto u = Umem::create(UmemConfig{512, 4096, 24, false});
  ASSERT_TRUE(u);
  XskConfig c = copy_cfg(l);
  c.fill_frames = 64;
  auto sp = XskSocket::create(**u, c);
  ASSERT_TRUE(sp);
  client::FrameStampTracker tracker;
  tracker.init(1024);
  client::StampingFramePort port(**sp, tracker, true, false, 2048);
  auto frame = [&](std::uint32_t seq, std::uint8_t flags, std::size_t len) {
    std::vector<std::byte> b(128);
    utcp::TcpHeaderSpec h;
    h.src_mac = l.mac;
    h.dst_mac = l.peer_mac;
    h.src_ip = l.local_ip;
    h.dst_ip = l.peer_ip;
    h.src_port = 40123;
    h.dst_port = 9;
    h.seq = seq;
    h.flags = flags;
    h.window = 1000;
    std::vector<std::byte> pl(len, std::byte{7});
    b.resize(utcp::build_tcp(b, utcp::LinkType::Ethernet, h, pl, {}, false));
    return b;
  };
  using namespace utcp::tcp_flag;
  const std::uint32_t isn = 1000;
  ASSERT_TRUE(port.send_frame(frame(isn, kSyn, 0)));
  std::uint32_t off = 0;
  int stamped = 0;
  for (int i = 0; i < 300; ++i) {
    const std::size_t len = 10 + static_cast<std::size_t>(i % 40);
    ASSERT_TRUE(port.send_frame(frame(isn + 1 + off, kAck | kPsh, len)));
    off += static_cast<std::uint32_t>(len);
    ++stamped;
    if (i % 10 == 9) ASSERT_TRUE(port.send_frame(frame(isn + 1, kAck, 10)));  // retransmission: not stamped
    // Reaps from three places: the socket's own flush(), the port's flush(), and reap().
    if (i % 3 == 0) (*sp)->flush();
    if (i % 3 == 1) port.flush();
    if (i % 3 == 2) port.reap();
  }
  ASSERT_TRUE(wait_for([&] { port.flush(); return port.outstanding() == 0; }));
  std::size_t drained = 0;
  std::uint32_t next_first = 0;
  (void)tracker.drain([&](const client::FrameStampTracker::Stamped& s) {
    EXPECT_EQ(s.stamp.first, next_first);
    next_first = s.stamp.last + 1;
    EXPECT_EQ(s.stamp.ts.hw_ns, 0) << "copy mode";
    ++drained;
  });
  const XskStats st = (*sp)->stats();
  std::printf("[xsk] StampingFramePort: %d stamped frames, %zu stamps drained, socket tx_ts_completions=%llu, "
              "lost=%llu unmatched=%llu\n",
              stamped, drained, static_cast<unsigned long long>(st.tx_ts_completions),
              static_cast<unsigned long long>(tracker.lost_completions()),
              static_cast<unsigned long long>(tracker.unmatched_completions()));
  EXPECT_EQ(drained, static_cast<std::size_t>(stamped));
  EXPECT_EQ(next_first, off);
  EXPECT_EQ(port.stamped_completions(), st.tx_ts_completions);  // the completion-count check
  EXPECT_EQ(tracker.lost_completions(), 0u);
  EXPECT_EQ(tracker.unmatched_completions(), 0u);
  EXPECT_EQ(tracker.retransmissions(), 30u);
}
#endif

// Threaded NAPI busy polling (07 §2.3 sub-variant iv-t; kernel >= 6.19) on a netdevsim
// device created by xsk_veth_test.sh (LLE_XSK_NAPI_IF), in the root namespace.
TEST(XskNapi, ThreadedBusyPollOnNetdevsim) {
  const char* ifn = std::getenv("LLE_XSK_NAPI_IF");
  if (ifn == nullptr || ::geteuid() != 0) GTEST_SKIP() << "needs root and LLE_XSK_NAPI_IF";
  const int ifindex = static_cast<int>(::if_nametoindex(ifn));
  ASSERT_GT(ifindex, 0);
  auto id = napi_id_for_rx_queue(ifindex, 0);
  ASSERT_TRUE(id) << "queue-get: " << std::strerror(id.error());
  auto info = napi_get(*id);
  ASSERT_TRUE(info) << std::strerror(info.error());
  std::printf("[xsk] netdevsim %s rx0 -> napi %u (threaded=%d pid=%d)\n", ifn, *id, info->threaded, info->pid);
  auto set = napi_set_threaded(*id, NapiThreaded::BusyPoll);
  ASSERT_TRUE(set) << "napi-set threaded=busy-poll: " << std::strerror(set.error());
  auto after = napi_get(*id);
  ASSERT_TRUE(after);
  std::printf("[xsk] napi-set threaded=busy-poll: kthread pid %d, threaded=%d\n", after->pid, after->threaded);
  EXPECT_EQ(after->threaded, static_cast<int>(NapiThreaded::BusyPoll));
  EXPECT_GT(after->pid, 0);
  ASSERT_TRUE(napi_set_threaded(*id, NapiThreaded::Disabled));
  auto off = napi_get(*id);
  ASSERT_TRUE(off);
  EXPECT_EQ(off->threaded, static_cast<int>(NapiThreaded::Disabled));
}

}  // namespace
}  // namespace lle::net::xsk
