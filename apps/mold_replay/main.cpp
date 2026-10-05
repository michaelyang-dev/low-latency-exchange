// mold_replay: replays a NASDAQ ITCH 5.0 BinaryFILE as MoldUDP64 on two lines
// (03-protocols §6 and §9, 07 §3; WP P-12).
//
//   mold_replay --file DAY[.gz] --line-a IP:PORT --line-b IP:PORT
//               [--rerequest-a IP:PORT --rerequest-b IP:PORT] [--glimpse IP:PORT [--glimpse-delay DUR]]
//               [--rate MSGS_PER_S] [--seed S] [--loss-a P] [--loss-b P] [--dup P] [--reorder P]
//               [--reorder-delay DUR] [--outage FIRST:COUNT ...] [--outage-every N --outage-len L]
//               [--max-packet-a B] [--max-packet-b B] [--burst-a N] [--burst-b N]
//               [--max-messages N] [--start-delay DUR] [--linger DUR] [--report FILE]
//
// SIGINT or SIGTERM stops the replay early (for example during the linger) and
// still writes the report.
//
// Line A and line B carry the same message sequence (sequence = record index from
// 1), packetized independently (different maximum payloads and seeded burst
// cadences) and impaired independently: seeded per-line loss, duplication and
// reordering (client/lossy_line.h). A line endpoint is unicast (loopback tests)
// or a multicast group. Each line has a MoldUDP64 re-request server (shared
// message ring). The optional GLIMPSE-style snapshot service serves a spin of the
// replay state at accept time over SoupBinTCP. Rate control: as fast as possible
// (default) or N messages per second.
//
// The report (JSON) records the seeds, the impairment settings, per-line counts,
// re-request and snapshot counts and, with the snapshot service, the books digest
// of the replay state at the end (= a direct replay of the file).
#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "client/cli.h"
#include "client/replay_feed.h"
#include "client/snapshot_service.h"
#include "common/int128.h"
#include "env/prod_clock.h"
#include "net/common/stack.h"
#include "proto/itch50/binary_file.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/rerequest_server.h"

namespace {

using namespace lle;
using client::cli::Args;

// SIGINT/SIGTERM end the replay (typically during the end-of-session linger);
// the report is still written.
std::atomic<bool> g_stop{false};
extern "C" void on_signal(int) { g_stop.store(true); }

struct Options {
  std::string file;
  net::Endpoint line[2]{};
  net::Endpoint rerequest[2]{};
  net::Endpoint glimpse{};
  Nanos glimpse_delay = 0;  // tests: the snapshot port refuses connections this long
  std::string ifname;
  std::uint64_t rate = 0;  // msgs/s; 0 = as fast as possible
  client::ReplayFeedConfig feed;
  std::uint64_t outage_every = 0, outage_len = 0;
  std::uint64_t max_messages = 0;
  Nanos start_delay = 0;
  std::string report;
  // The re-request store: the last 4M messages (seconds of feed at 1M msgs/s,
  // more than a client's reorder window holds after a snapshot splice).
  std::size_t ring_messages = std::size_t{1} << 22;
  std::size_t ring_bytes = std::size_t{1} << 28;
  std::uint32_t rr_burst = 100'000;
  Nanos rr_refill = 10'000;  // 100k requests/s sustained per source
  std::size_t reserve_orders = std::size_t{1} << 22;
  std::size_t snapshot_ring_bytes = std::size_t{1} << 28;
  std::uint32_t batch = 4096;  // messages released per loop iteration at most
  net::BackendKind backend = net::BackendKind::Epoll;
  int sndbuf = 8 << 20;
};

[[noreturn]] void usage(const char* msg) {
  std::fprintf(stderr, "mold_replay: %s\n(see the header of apps/mold_replay/main.cpp for usage)\n", msg);
  std::exit(2);
}

Options parse(int argc, char** argv) {
  Options o;
  o.feed.end_of_session_linger = 5 * kNsPerSec;
  Args a(argc, argv, "mold_replay");
  std::uint32_t dup = 0, reorder = 0;
  Nanos reorder_delay = 200'000;
  while (!a.done()) {
    const std::string f = a.flag();
    auto ppm = [&]() {
      const std::string v = a.value();
      const auto p = client::cli::parse_ppm(v);
      if (!p) a.die("bad probability: " + v);
      return *p;
    };
    auto dur = [&]() {
      const std::string v = a.value();
      const auto d = client::cli::parse_duration(v);
      if (!d) a.die("bad duration: " + v);
      return *d;
    };
    if (f == "--file") o.file = a.value();
    else if (f == "--line-a") o.line[0] = a.endpoint();
    else if (f == "--line-b") o.line[1] = a.endpoint();
    else if (f == "--rerequest-a") o.rerequest[0] = a.endpoint();
    else if (f == "--rerequest-b") o.rerequest[1] = a.endpoint();
    else if (f == "--glimpse") o.glimpse = a.endpoint();
    else if (f == "--glimpse-delay") {
      const std::string v = a.value();
      const auto d = client::cli::parse_duration(v);
      if (!d) a.die("bad duration: " + v);
      o.glimpse_delay = *d;
    }
    else if (f == "--ifname") o.ifname = a.value();
    else if (f == "--rate") o.rate = a.u64();
    else if (f == "--seed") o.feed.seed = a.u64();
    else if (f == "--loss-a") o.feed.impair[0].loss_ppm = ppm();
    else if (f == "--loss-b") o.feed.impair[1].loss_ppm = ppm();
    else if (f == "--dup") dup = ppm();
    else if (f == "--reorder") reorder = ppm();
    else if (f == "--reorder-delay") reorder_delay = dur();
    else if (f == "--outage") {
      const std::string v = a.value();
      const std::size_t c = v.find(':');
      if (c == std::string::npos) a.die("--outage FIRST:COUNT");
      o.feed.outages.push_back(client::Outage{a.parse_u64(v.substr(0, c)), a.parse_u64(v.substr(c + 1))});
    } else if (f == "--outage-every") o.outage_every = a.u64();
    else if (f == "--outage-len") o.outage_len = a.u64();
    else if (f == "--max-packet-a") o.feed.max_packet[0] = a.u64();
    else if (f == "--max-packet-b") o.feed.max_packet[1] = a.u64();
    else if (f == "--burst-a") o.feed.max_burst[0] = static_cast<std::uint32_t>(a.u64());
    else if (f == "--burst-b") o.feed.max_burst[1] = static_cast<std::uint32_t>(a.u64());
    else if (f == "--heartbeat") o.feed.heartbeat_interval = dur();
    else if (f == "--linger") o.feed.end_of_session_linger = dur();
    else if (f == "--max-messages") o.max_messages = a.u64();
    else if (f == "--start-delay") o.start_delay = dur();
    else if (f == "--report") o.report = a.value();
    else if (f == "--ring-messages") o.ring_messages = a.u64();
    else if (f == "--ring-bytes") o.ring_bytes = a.u64();
    else if (f == "--rr-burst") o.rr_burst = static_cast<std::uint32_t>(a.u64());
    else if (f == "--reserve-orders") o.reserve_orders = a.u64();
    else if (f == "--snapshot-ring-bytes") o.snapshot_ring_bytes = a.u64();
    else if (f == "--batch") o.batch = static_cast<std::uint32_t>(a.u64());
    else if (f == "--backend") {
      const auto k = net::parse_backend(a.value());
      if (!k) a.die("unknown --backend");
      o.backend = *k;
    } else a.die("unknown flag " + f);
  }
  if (o.file.empty() || o.line[0].port == 0 || o.line[1].port == 0) usage("--file, --line-a and --line-b are required");
  for (auto& imp : o.feed.impair) {
    imp.dup_ppm = dup;
    imp.reorder_ppm = reorder;
    imp.max_reorder_delay = reorder_delay;
  }
  if (o.outage_every != 0 && o.outage_len != 0) {
    if (o.outage_len >= o.outage_every) a.die("--outage-len must be below --outage-every");
    const std::uint64_t limit = o.max_messages != 0 ? o.max_messages : std::uint64_t{1} << 40;
    for (SeqNo s = o.outage_every; s < limit && o.feed.outages.size() < 100'000; s += o.outage_every)
      o.feed.outages.push_back(client::Outage{s, o.outage_len});
  }
  std::sort(o.feed.outages.begin(), o.feed.outages.end(),
            [](const client::Outage& x, const client::Outage& y) { return x.first < y.first; });
  return o;
}

template <net::BackendKind K>
int run(const Options& o) {
  using StackT = net::Stack<K>;
  StackT stack(net::WaitPolicy::Spin);
  if (auto r = stack.open(); !r) {
    std::fprintf(stderr, "mold_replay: %s\n", net::to_string(r.error()).c_str());
    return 1;
  }
  typename StackT::DatagramPort out, rr[2];
  {
    net::UdpConfig c;
    c.bind = net::Endpoint{net::is_multicast(o.line[0].ipv4) ? net::kAnyV4 : o.line[0].ipv4, 0};
    c.sndbuf = o.sndbuf;
    c.ifname = o.ifname;
    c.mcast_loop = true;
    if (auto r = stack.open(out, c); !r) {
      std::fprintf(stderr, "mold_replay: line socket: %s\n", net::to_string(r.error()).c_str());
      return 1;
    }
  }
  for (int i = 0; i < 2; ++i) {
    if (o.rerequest[i].port == 0) continue;
    net::UdpConfig c;
    c.bind = o.rerequest[i];
    c.rcvbuf = 4 << 20;
    c.sndbuf = o.sndbuf;
    if (auto r = stack.open(rr[i], c); !r) {
      std::fprintf(stderr, "mold_replay: re-request %c: %s\n", 'A' + i, net::to_string(r.error()).c_str());
      return 1;
    }
  }
  // The snapshot service runs on its own thread (client/snapshot_service.h).
  std::unique_ptr<client::SnapshotService<K>> snap;
  if (o.glimpse.port != 0) {
    client::SnapshotServiceConfig sc;
    sc.listen = o.glimpse;
    sc.listen_delay = o.glimpse_delay;
    sc.book.reserve_orders = o.reserve_orders;
    sc.book.reserve_levels = std::size_t{1} << 20;
    sc.ring_bytes = o.snapshot_ring_bytes;
    snap = std::make_unique<client::SnapshotService<K>>(sc);
    if (auto r = snap->open(); !r) {
      std::fprintf(stderr, "mold_replay: glimpse: %s\n", net::to_string(r.error()).c_str());
      return 1;
    }
    snap->start();
  }

  itch50::BinaryFileReader reader;
  if (auto r = reader.open(o.file); !r) {
    std::fprintf(stderr, "mold_replay: %s\n", r.error().c_str());
    return 1;
  }

  client::ReplayFeed feed(o.feed);
  mold::MessageRing ring(o.ring_messages, o.ring_bytes);
  mold::RerequestConfig rc;
  rc.session = o.feed.session;
  rc.max_packet = o.feed.max_packet[0];
  rc.bucket_capacity = o.rr_burst;
  rc.refill_interval = o.rr_refill;
  mold::RerequestServer<mold::MessageRing> srv_a(rc, ring), srv_b(rc, ring);
  mold::RerequestServer<mold::MessageRing>* srv[2] = {&srv_a, &srv_b};
  std::uint64_t send_retries = 0, send_failures = 0;
  auto send = [&](int line, std::span<const std::byte> pkt) {
    for (int attempt = 0; attempt < 100'000; ++attempt) {
      if (out.send(o.line[line], pkt)) return;
      ++send_retries;  // EAGAIN/ENOBUFS on a full socket buffer: retry, never drop silently
    }
    ++send_failures;
  };

  env::ProdClock clock;
  const Nanos t_open = clock.now_mono();
  while (clock.now_mono() - t_open < o.start_delay) {
  }
  const Nanos t0 = clock.now_mono();
  std::uint64_t released = 0;
  bool eof = false, ended = false;
  std::string read_error;
  Nanos end_time = 0;

  // Pacing: message k is due at t0 + k / rate. After a stall the publisher catches
  // up by at most `max_debt` messages at full speed and then resets its base, so a
  // stall never turns into a burst the receivers' socket buffers cannot absorb.
  Nanos base_t = t0;
  std::uint64_t base_released = 0, pacing_resets = 0;
  const std::uint64_t max_debt = std::max<std::uint64_t>(o.batch, o.rate / 200);  // 5 ms of feed

  for (;;) {
    (void)stack.wait(0);
    const Nanos now = clock.now_mono();
    // 1. Release messages per the rate.
    if (!eof) {
      std::uint64_t target = released + o.batch;
      if (o.rate != 0) {
        std::uint64_t due =
            base_released + static_cast<std::uint64_t>(static_cast<u128>(now - base_t) * o.rate / 1'000'000'000u);
        if (due > released + max_debt) {
          base_t = now;
          base_released = released + max_debt;
          due = base_released;
          ++pacing_resets;
        }
        target = std::min(target, due);
      }
      while (released < target) {
        const itch50::Record r = reader.next();
        if (r.status == itch50::RecordStatus::Message) {
          (void)ring.append(r.data);  // before publishing, so a re-request can always be served
          (void)feed.append(r.data, now, send);
          if (snap) snap->publish(r.data);  // after it is on the lines and in the re-request store
          ++released;
          if (o.max_messages != 0 && released >= o.max_messages) {
            eof = true;
            break;
          }
          continue;
        }
        if (r.status == itch50::RecordStatus::Truncated || r.status == itch50::RecordStatus::IoError)
          read_error = reader.error().empty() ? "truncated input" : reader.error();
        eof = true;
        break;
      }
      if (eof) {
        feed.flush(now, send);
        feed.end_session(now, send);
        end_time = now;
        ended = true;
      }
    }
    // 2. Heartbeats, end-of-session repeats, delayed (reordered) packets.
    if (now >= feed.next_deadline()) feed.on_timer(now, send);
    // 3. Re-requests on each line's server.
    for (int i = 0; i < 2; ++i) {
      if (o.rerequest[i].port == 0) continue;
      rr[i].poll_rx([&](const env::RxDatagram& d) {
        (void)srv[i]->on_request(d.data, d.src, now, [&](const env::Endpoint& to, std::span<const std::byte> pkt) {
          for (int attempt = 0; attempt < 1000 && !rr[i].send(to, pkt); ++attempt) {
          }
        });
      });
    }
    if (ended && feed.done()) break;
    if (g_stop.load(std::memory_order_relaxed)) break;
  }
  if (snap) snap->stop();

  const Nanos elapsed = (end_time != 0 ? end_time : clock.now_mono()) - t0;
  const std::uint64_t digest = snap ? snap->stats().final_books_digest : 0;
  std::string j = "{\n";
  char buf[512];
  auto kv = [&](const char* k, std::uint64_t v, bool last = false) {
    std::snprintf(buf, sizeof buf, "  \"%s\": %" PRIu64 "%s\n", k, v, last ? "" : ",");
    j += buf;
  };
  j += "  \"file\": \"" + o.file + "\",\n";
  if (!read_error.empty()) j += "  \"read_error\": \"" + read_error + "\",\n";
  kv("seed", o.feed.seed);
  kv("messages", released);
  kv("elapsed_ns", static_cast<std::uint64_t>(elapsed));
  kv("rate_target", o.rate);
  kv("rate_achieved", elapsed > 0 ? static_cast<std::uint64_t>(static_cast<u128>(released) * 1'000'000'000u /
                                                                static_cast<std::uint64_t>(elapsed))
                                  : 0);
  for (std::size_t l = 0; l < 2; ++l) {
    const auto& ls = feed.line_stats(l);
    const auto& ps = feed.packetizer_stats(l);
    const auto& imp = o.feed.impair[l];
    const char L = static_cast<char>('a' + l);
    auto kl = [&](const char* k, std::uint64_t v) {
      std::snprintf(buf, sizeof buf, "  \"%c_%s\": %" PRIu64 ",\n", L, k, v);
      j += buf;
    };
    kl("loss_ppm", imp.loss_ppm);
    kl("dup_ppm", imp.dup_ppm);
    kl("reorder_ppm", imp.reorder_ppm);
    kl("max_packet", o.feed.max_packet[l]);
    kl("max_burst", o.feed.max_burst[l]);
    kl("data_packets", ps.data_packets);
    kl("heartbeats", ps.heartbeats);
    kl("eos_packets", ps.end_of_session_packets);
    kl("offered", ls.packets);
    kl("sent", ls.sent);
    kl("dropped", ls.dropped);
    kl("outage_dropped", ls.outage_dropped);
    kl("duplicated", ls.duplicated);
    kl("delayed", ls.delayed);
    kl("pool_full", ls.pool_full);
    kl("messages_dropped", ls.messages_dropped);
    const auto& rs = srv[l]->stats();
    kl("rr_requests", rs.requests);
    kl("rr_served", rs.served);
    kl("rr_messages", rs.messages_served);
    kl("rr_rate_limited", rs.rate_limited);
    kl("rr_unavailable", rs.unavailable);
    kl("rr_invalid", rs.invalid());
  }
  kv("outages", o.feed.outages.size());
  kv("send_retries", send_retries);
  kv("send_failures", send_failures);
  kv("tx_dropped_kernel", out.stats().tx_dropped);
  kv("pacing_resets", pacing_resets);
  kv("snapshot_spins", snap ? snap->stats().spins : 0);
  kv("snapshot_messages", snap ? snap->stats().spin_messages : 0);
  kv("snapshot_publisher_waits", snap ? snap->stats().publisher_waits : 0);
  kv("snapshot_applied", snap ? snap->stats().applied : 0);
  kv("final_live_orders", snap ? snap->stats().final_live_orders : 0);
  std::snprintf(buf, sizeof buf, "  \"final_books_digest\": \"%016" PRIx64 "\"\n", digest);
  j += buf;
  j += "}\n";
  std::fputs(j.c_str(), stdout);
  if (!o.report.empty()) {
    if (std::FILE* f = std::fopen(o.report.c_str(), "w")) {
      std::fputs(j.c_str(), f);
      std::fclose(f);
    }
  }
  return read_error.empty() && send_failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  const Options o = parse(argc, argv);
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  int rc = 2;
  if (!net::with_backend(o.backend, [&]<net::BackendKind K>() { rc = run<K>(o); })) {
    std::fprintf(stderr, "mold_replay: backend %s not compiled in\n", net::to_string(o.backend));
    return 2;
  }
  return rc;
}
