// UDP ping-pong RTT benchmark for the kernel-socket and io_uring backends (07 §1, §4;
// 12 for statistics). One binary, two roles:
//
//   net_udp_pingpong --role reflector --backend B --bind A:P [--wait default|spin|block]
//                    (the system under test: it runs the variant's wait strategy)
//   net_udp_pingpong --role sender --backend B --bind A:P --peer A:P
//                    [--rate 10000] [--count 100000] [--warmup 10000] [--size 64]
//                    [--poisson 0|1] [--seed N] [--wait ...] [--label TEXT]
//
// The sender is the instrument: keep it constant across variants (the driver script
// uses io_uring in spin mode) and vary only the reflector. It is OPEN-LOOP: datagram i is due at a precomputed time (fixed rate, or a
// seeded Poisson process) whether or not earlier replies came back, and its RTT is
// measured from that scheduled time, so a stalled sender or reflector shows up in the
// tail instead of silently thinning the sample (no coordinated omission). The RTT from
// the actual send time and the sender's lateness (actual − scheduled) are reported too.
//
// Times come from CLOCK_MONOTONIC in user space: these are SOFTWARE timestamps. Numbers
// from a VM or veth are functional comparisons between backends, never headline results
// (07 §2.5: headline intervals are differences of two NIC hardware timestamps).
#include <hdr/hdr_histogram.h>
#include <time.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "net/common/endpoint.h"
#include "net/common/stack.h"
#if defined(__linux__)
#include "net/busypoll/busypoll.h"
#endif

namespace {

using namespace lle;
using namespace lle::net;

Nanos now_ns() {
  timespec ts{};
  ::clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<Nanos>(ts.tv_sec) * kNsPerSec + ts.tv_nsec;
}

struct Args {
  std::map<std::string, std::string, std::less<>> kv;
  [[nodiscard]] std::string get(std::string_view k, std::string_view def = "") const {
    auto it = kv.find(k);
    return it == kv.end() ? std::string(def) : it->second;
  }
  [[nodiscard]] long long num(std::string_view k, long long def) const {
    const std::string v = get(k);
    return v.empty() ? def : std::strtoll(v.c_str(), nullptr, 10);
  }
};

// Wire format (little endian, host order: both ends run this binary).
struct Probe {
  std::uint64_t seq;
  Nanos sched_ns;
  Nanos sent_ns;
};
constexpr std::uint64_t kStop = ~std::uint64_t{0};

struct Hist {
  hdr_histogram* h = nullptr;
  Hist() { hdr_init(1, 10 * kNsPerSec, 3, &h); }
  ~Hist() { hdr_close(h); }
  Hist(const Hist&) = delete;
  Hist& operator=(const Hist&) = delete;
  void record(Nanos v) { hdr_record_value(h, v < 1 ? 1 : v); }
  void print(const char* name) const {
    std::printf("  %-28s n=%-8lld p50=%-8lld p90=%-8lld p99=%-8lld p99.9=%-8lld p99.99=%-8lld max=%-8lld (ns)\n", name,
                static_cast<long long>(h->total_count), static_cast<long long>(hdr_value_at_percentile(h, 50.0)),
                static_cast<long long>(hdr_value_at_percentile(h, 90.0)),
                static_cast<long long>(hdr_value_at_percentile(h, 99.0)),
                static_cast<long long>(hdr_value_at_percentile(h, 99.9)),
                static_cast<long long>(hdr_value_at_percentile(h, 99.99)), static_cast<long long>(hdr_max(h)));
  }
};

const char* wait_name(WaitPolicy w) {
  return w == WaitPolicy::Spin ? "spin" : (w == WaitPolicy::Block ? "block" : "default");
}

template <BackendKind K>
int reflector(const Args& a, WaitPolicy w) {
  Stack<K> st(w);
  if (auto r = st.open(); !r) {
    std::fprintf(stderr, "reflector: %s\n", to_string(r.error()).c_str());
    return 1;
  }
  const auto bind = parse_endpoint(a.get("--bind"));
  if (!bind) return 2;
  UdpConfig c;
  c.bind = *bind;
  c.rcvbuf = 4 << 20;
  typename Stack<K>::DatagramPort p;
  if (auto r = st.open(p, c); !r) {
    std::fprintf(stderr, "reflector: %s\n", to_string(r.error()).c_str());
    return 1;
  }
  const Nanos deadline = now_ns() + a.num("--duration-s", 600) * kNsPerSec;
#if defined(__linux__)
  const std::uint64_t bp_before = busypoll::busy_poll_rx_packets().value_or(0);
#endif
  bool stop = false;
  std::uint64_t echoed = 0;
  while (!stop && now_ns() < deadline) {
    (void)st.wait(10'000'000);
    p.poll_rx([&](const env::RxDatagram& d) {
      Probe pr{};
      if (d.data.size() >= sizeof(pr)) std::memcpy(&pr, d.data.data(), sizeof(pr));
      if (pr.seq == kStop) {
        stop = true;
        return;
      }
      if (p.send(d.src, d.data)) ++echoed;
    });
  }
  std::uint64_t bp = 0;
#if defined(__linux__)
  bp = busypoll::busy_poll_rx_packets().value_or(0) - bp_before;
#endif
  std::printf("reflector (SUT) backend=%s wait=%s echoed=%llu tx_dropped=%llu busy_poll_rx_packets=%llu\n", to_string(K),
              wait_name(w), static_cast<unsigned long long>(echoed), static_cast<unsigned long long>(p.stats().tx_dropped),
              static_cast<unsigned long long>(bp));
  return 0;
}

template <BackendKind K>
int sender(const Args& a, WaitPolicy w) {
  Stack<K> st(w);
  if (auto r = st.open(); !r) {
    std::fprintf(stderr, "sender: %s\n", to_string(r.error()).c_str());
    return 1;
  }
  const auto bind = parse_endpoint(a.get("--bind", "0.0.0.0:0"));
  const auto peer = parse_endpoint(a.get("--peer"));
  if (!bind || !peer) return 2;
  const long long rate = a.num("--rate", 10'000);
  const auto count = static_cast<std::uint64_t>(a.num("--count", 100'000));
  const auto warmup = static_cast<std::uint64_t>(a.num("--warmup", 10'000));
  const auto size = static_cast<std::size_t>(std::max<long long>(a.num("--size", 64), sizeof(Probe)));
  if (rate <= 0 || count == 0 || size > 1472) return 2;
  UdpConfig c;
  c.bind = *bind;
  c.rcvbuf = 4 << 20;
  typename Stack<K>::DatagramPort p;
  if (auto r = st.open(p, c); !r) {
    std::fprintf(stderr, "sender: %s\n", to_string(r.error()).c_str());
    return 1;
  }
  // Precomputed open-loop schedule (offsets from t0).
  std::vector<Nanos> sched(count);
  const Nanos period = kNsPerSec / rate;
  if (a.num("--poisson", 0) != 0) {
    Prng rng(static_cast<std::uint64_t>(a.num("--seed", 1)));
    Nanos t = 0;
    for (auto& s : sched) {
      const double u = (static_cast<double>(rng.next_u64() >> 11) + 0.5) * (1.0 / 9007199254740992.0);
      t += static_cast<Nanos>(-std::log(u) * static_cast<double>(period));
      s = t;
    }
  } else {
    for (std::uint64_t i = 0; i < count; ++i) sched[i] = static_cast<Nanos>(i) * period;
  }
  std::vector<std::byte> buf(size);
  Hist rtt_sched, rtt_send, late;
  std::vector<bool> seen(count, false);
  std::uint64_t next = 0, received = 0, dup = 0, send_fail = 0;
  const Nanos t0 = now_ns() + 20'000'000;
  const Nanos end = t0 + sched.back() + 2 * kNsPerSec;  // 2 s grace for the last replies
  auto on_rx = [&](const env::RxDatagram& d) {
    const Nanos now = now_ns();
    Probe pr{};
    if (d.data.size() < sizeof(pr)) return;
    std::memcpy(&pr, d.data.data(), sizeof(pr));
    if (pr.seq >= count || seen[pr.seq]) {
      ++dup;
      return;
    }
    seen[pr.seq] = true;
    ++received;
    if (pr.seq < warmup) return;
    rtt_sched.record(now - pr.sched_ns);
    rtt_send.record(now - pr.sent_ns);
  };
  while (received < count && now_ns() < end) {
    Nanos now = now_ns();
    while (next < count && now >= t0 + sched[next]) {
      const Probe pr{next, t0 + sched[next], now};
      std::memcpy(buf.data(), &pr, sizeof(pr));
      if (p.send(*peer, buf)) {
        if (next >= warmup) late.record(now - pr.sched_ns);
      } else {
        ++send_fail;
      }
      ++next;
      now = now_ns();
    }
    const Nanos until = next < count ? t0 + sched[next] - now : 1'000'000;
    (void)st.wait(until > 0 ? until : 0);
    p.poll_rx(on_rx);
  }
  Probe stop{kStop, 0, 0};
  std::memcpy(buf.data(), &stop, sizeof(stop));
  for (int i = 0; i < 3; ++i) (void)p.send(*peer, buf);
  for (int i = 0; i < 10; ++i) {
    (void)st.wait(1'000'000);
    p.poll_rx([](const env::RxDatagram&) {});
  }

  const std::string label = a.get("--label", "VM/veth, software (CLOCK_MONOTONIC) timing, NOT a headline number");
  std::printf("udp-pingpong backend=%s wait=%s rate=%lld/s%s size=%zu count=%llu warmup=%llu\n", to_string(K),
              wait_name(w), rate, a.num("--poisson", 0) != 0 ? " (poisson)" : "", size,
              static_cast<unsigned long long>(count), static_cast<unsigned long long>(warmup));
  std::printf("  label: %s\n", label.c_str());
  std::printf("  received=%llu lost=%llu send_fail=%llu dup_or_stray=%llu\n", static_cast<unsigned long long>(received),
              static_cast<unsigned long long>(count - received), static_cast<unsigned long long>(send_fail),
              static_cast<unsigned long long>(dup));
  rtt_sched.print("rtt from schedule (open-loop)");
  rtt_send.print("rtt from actual send");
  late.print("sender lateness");
  return received == count ? 0 : 3;
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  for (int i = 1; i + 1 < argc; i += 2) a.kv[argv[i]] = argv[i + 1];
  const auto kind = parse_backend(a.get("--backend", "epoll"));
  if (!kind) {
    std::fprintf(stderr, "unknown --backend\n");
    return 2;
  }
  const std::string w = a.get("--wait", "default");
  const WaitPolicy wait = w == "spin" ? WaitPolicy::Spin : (w == "block" ? WaitPolicy::Block : WaitPolicy::Default);
  const std::string role = a.get("--role", "sender");
  int rc = 2;
  const bool ok = with_backend(*kind, [&]<BackendKind K>() { rc = role == "reflector" ? reflector<K>(a, wait) : sender<K>(a, wait); });
  if (!ok) {
    std::fprintf(stderr, "backend %s not compiled in this build\n", to_string(*kind));
    return 77;
  }
  return rc;
}
