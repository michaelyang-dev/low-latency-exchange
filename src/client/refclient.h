#pragma once
// refclient v1 (07 §3, WP N-04; the T18 system under test, ADR-013): one hot
// thread runs, on every iteration,
//   1. poll line A, line B and the re-request socket (MoldUDP64 over UDP);
//   2. the LineArbiter (re-requests; snapshot join on large gaps);
//   3. the ITCH book (lle::book, the optimized LOB variant);
//   4. the T18 strategy;
//   5. OUCH encode;
//   6. write on the SoupBinTCP session (HA: the active instance only).
// The I/O is a template parameter (client_io.h): SockIo<K> for the kernel-socket
// variants (epoll, busypoll, uring, uring-napi) or XskIo (AF_XDP feed, utcp order
// entry), chosen at run time with with_variant_io(); the loop above is identical for
// every variant (07 §1, WP N-13). Everything on the hot path is preallocated at
// open(); the snapshot session and order-entry reconnects allocate a ClientSession
// each (recovery paths only).
//
// T18 client side (METHODOLOGY §13): with an order-stamp log, every order the
// strategy sends gets a record (hwts_log.h) with the receive timestamps of the
// packet the client acted on and the TX timestamp of the frame that carried the
// order, matched by stream offset (tx_stamps.h). TTT_client is computed from it.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include <vector>

#include "client/client_io.h"
#include "client/feed_handler.h"
#include "client/hwts_log.h"
#include "client/order_entry.h"
#include "client/strategy.h"
#include "client/tx_stamps.h"
#include "common/endian.h"
#include "common/types.h"
#include "env/prod_clock.h"
#include "log/nlog.h"
#include "metrics/segment.h"
#include "net/common/endpoint.h"
#include "proto/moldudp64/line_comparator.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/soupbin/client_session.h"

namespace lle::client {

struct RefClientConfig {
  // Feed. A line endpoint is unicast ip:port (bound locally) or group:port (joined).
  net::Endpoint line_a{}, line_b{};
  bool mcast_loop = true;  // kernel sockets: receive multicast sent on this host (tests)
  net::Endpoint rerequest_a{}, rerequest_b{};
  net::Endpoint glimpse{};  // port 0: no snapshot service
  soup::ClientConfig glimpse_login{};
  int rcvbuf = 8 << 20;
  FeedConfig feed{};
  // Orders (port 0: absent).
  bool trade = false;
  StrategyConfig strategy{};
  net::Endpoint primary{}, backup{};
  OrderEntryConfig orders{};
  Nanos reconnect_interval = kNsPerSec;  // order-entry instances; 0 = never reconnect
  // T18 order-stamp log: records preallocated (0: no log).
  std::size_t stamp_log_capacity = 0;
  int phc_index = -1;  // PHC of the port (VariantConfig ifname), stamped into every record
  // Loop.
  Nanos linger_after_end = 200'000'000;  // keep serving order entry after the feed ends
  Nanos max_runtime = 0;                 // 0 = until the feed ends
  Nanos snapshot_retry = 100'000'000;
  std::uint32_t drain_batches = 16;  // receive batches per line per iteration, at most
  bool verbose = false;
  // T10 HA line consistency (03 §5): compare line A and line B message by message
  // (and each re-request server's responses with its line). 0: off.
  std::size_t line_compare_window = 0;
};

struct RefClientResult {
  bool ok = false;
  std::string error;
  bool feed_ended = false;
  Nanos elapsed = 0;
  std::uint64_t snapshot_sessions = 0, snapshot_failures = 0;
  std::uint64_t order_responses = 0;
};

// The client's metrics segment (11 §3), refclient --metrics NAME, read by lle-top: the
// first arrivals per source (which line won each message), the gaps and how they were
// filled, orders and responses, and the A/B skew of the lines.
#define LLE_CLIENT_COUNTERS(X)                                                                                  \
  X(first_arrivals_line_a) X(first_arrivals_line_b) X(first_arrivals_rerequest_a) X(first_arrivals_rerequest_b) \
  X(delivered) X(gaps_opened) X(gaps_filled_line_a) X(gaps_filled_line_b) X(gaps_filled_rerequest)             \
  X(gaps_filled_snapshot) X(orders_sent) X(order_responses)
enum class ClientCtr : std::size_t {
#define LLE_CLIENT_ENUM(name) name,
  LLE_CLIENT_COUNTERS(LLE_CLIENT_ENUM)
#undef LLE_CLIENT_ENUM
      kCount
};
[[nodiscard]] inline metrics::Schema client_metrics_schema() {
  metrics::Schema s;
#define LLE_CLIENT_SPEC(name) s.counters.push_back(metrics::CounterSpec{#name, metrics::CounterKind::kCounter});
  LLE_CLIENT_COUNTERS(LLE_CLIENT_SPEC)
#undef LLE_CLIENT_SPEC
  s.histograms.push_back(metrics::HistogramSpec{"ab_skew", 1, 10'000'000'000, 2, "ns"});
  return s;
}

template <class Io, class Listener = book::NullListener>
class RefClient {
 public:
  using Feed = FeedHandler<Listener>;

  RefClient(const RefClientConfig& cfg, const VariantConfig& v)
      : cfg_(cfg), io_(v), feed_(cfg.feed), strat_(cfg.strategy), oe_(cfg.orders) {
    stamps_.reserve(cfg.stamp_log_capacity);
    for (auto& m : txm_) m.init(1 << 12);
  }
  RefClient(const RefClient&) = delete;
  RefClient& operator=(const RefClient&) = delete;

  std::expected<void, std::string> open() {
    IoSpec s;
    s.dgram.line_a = cfg_.line_a;
    s.dgram.line_b = cfg_.line_b;
    s.dgram.mcast_loop = cfg_.mcast_loop;
    s.dgram.request_port = true;
    s.dgram.request_loopback = cfg_.rerequest_a.ipv4 == net::kLoopbackV4;
    s.dgram.request_servers[0] = cfg_.rerequest_a;
    s.dgram.request_servers[1] = cfg_.rerequest_b;
    s.dgram.rcvbuf = cfg_.rcvbuf;
    s.stream.enabled = true;
    s.stream.max_conns = 8;
    s.stream.rx_buf_bytes = 256 * 1024;
    s.stream.rcvbuf = 4 << 20;
    // A snapshot spin is up to hundreds of megabytes; reading it in bounded slices
    // (about 2 MB, under 10 ms of work) keeps the UDP lines polled while it
    // arrives, so the kernel buffers do not overflow.
    s.stream.max_reads_per_poll = 8;
    s.stream.peers = {cfg_.primary, cfg_.backup, cfg_.glimpse, net::Endpoint{}};
    return io_.open(s);
  }

  // Runs until the feed ends (plus the linger), max_runtime, or *stop.
  RefClientResult run(const std::atomic<bool>* stop = nullptr) {
    RefClientResult res;
    const Nanos start = clock_.now_mono();
    start_ = start;
    Nanos now = start;
    if (cfg_.trade) {
      connect_instance(0, now);
      connect_instance(1, now);
    }
    Nanos ended_at = 0;
    for (;;) {
      if (stop != nullptr && stop->load(std::memory_order_relaxed)) break;
      // The variant's wait strategy decides whether this blocks (epoll, busypoll,
      // uring-napi), spins (uring) or returns at once (xsk ring polling).
      const Nanos deadline = next_deadline();
      (void)io_.wait(deadline <= now ? 0 : std::min<Nanos>(deadline - now, 1'000'000));
      now = clock_.now_mono();
      now_ = now;
      // Drain the lines (bounded): one batch per iteration falls behind a
      // full-rate feed whenever an iteration also carries snapshot work.
      for (std::uint32_t k = 0; k < cfg_.drain_batches; ++k) {
        const std::size_t got =
            io_.poll_datagrams([&](Chan ch, const env::RxDatagram& d, const net::RxTimestamps& ts) {
              mold::Source s = mold::Source::LineA;
              int side = 0;
              if (ch == Chan::LineB) {
                s = mold::Source::LineB;
                side = 1;
              } else if (ch == Chan::Request) {
                const bool b = d.src == cfg_.rerequest_b && !(d.src == cfg_.rerequest_a);
                s = b ? mold::Source::RerequestB : mold::Source::RerequestA;
                side = b ? 1 : 0;
              }
              if (cmp_) cmp_->on_packet(side, d.data);
              if (log_on()) note_packet(ch, d.data, ts);
              feed_.on_packet(s, d.data, now, *this);
            });
        if (got == 0) break;
      }
      if (now >= feed_.next_deadline()) feed_.on_timer(now, *this);
      note_feed(now);
      if (seg_ != nullptr && (++iterations_ & 1023) == 0) publish_metrics();
      io_.poll_streams([&](const env::StreamEvent& ev) { on_stream(ev, now); });
      if (cfg_.trade) {
        if (now >= oe_.next_deadline()) oe_.on_timer(now);
        maybe_reconnect(now);
      }
      if (snap_ && now >= snap_->actions().deadline) absorb_snapshot(snap_->on_timer(now), now);
      if (snap_wanted_ && !snap_ && snap_conn_ == env::kNoConn && now >= snap_retry_at_) start_snapshot(now, res);
      flush_all();
      if (log_on() && (txm_[0].outstanding() != 0 || txm_[1].outstanding() != 0)) drain_stamps();
      if (feed_.stats().ended && ended_at == 0) ended_at = now;
      if (ended_at != 0 && (!cfg_.trade || now - ended_at >= cfg_.linger_after_end)) break;
      if (cfg_.max_runtime > 0 && now - start >= cfg_.max_runtime) break;
    }
    feed_.finish();
    if (seg_ != nullptr) publish_metrics();
    if (log_on()) {
      drain_stamps();
      for (auto& m : txm_) m.expire_all();
    }
    res.feed_ended = feed_.stats().ended;
    res.elapsed = clock_.now_mono() - start;
    res.snapshot_sessions = snap_sessions_;
    res.snapshot_failures = snap_failures_;
    res.order_responses = responses_;
    res.ok = true;
    return res;
  }

  // --- FeedHandler downstream ----------------------------------------------------
  void on_book_message(SeqNo seq, std::span<const std::byte> msg) {
    if (cfg_.trade) {
      cur_msg_seq_ = seq;
      strat_.on_itch(seq, msg, *this);
    } else if (!msg.empty() && static_cast<char>(msg[0]) == 'R') {
      strat_.on_directory(msg);
    }
  }
  void on_snapshot_message(std::span<const std::byte> msg) {
    if (!msg.empty() && static_cast<char>(msg[0]) == 'R') strat_.on_directory(msg);
  }
  void send_request(mold::Server s, std::span<const std::byte> req) {
    (void)io_.send_request(s == mold::Server::A ? cfg_.rerequest_a : cfg_.rerequest_b, req);
  }
  void on_snapshot_needed(SeqNo next, SeqNo known_end) {
    snap_wanted_ = true;
    if (cfg_.verbose)
      std::fprintf(stderr,
                   "refclient: %.3f s: snapshot needed: next %llu known_end %llu buffered %zu delivered %llu "
                   "request timeouts A/B %llu/%llu overflows %llu\n",
                   static_cast<double>(now_ - start_) / 1e9, static_cast<unsigned long long>(next),
                   static_cast<unsigned long long>(known_end), feed_.arbiter().buffered(),
                   static_cast<unsigned long long>(feed_.stats().delivered),
                   static_cast<unsigned long long>(feed_.arbiter().metrics().request_timeouts[0]),
                   static_cast<unsigned long long>(feed_.arbiter().metrics().request_timeouts[1]),
                   static_cast<unsigned long long>(feed_.arbiter().metrics().buffer_overflows));
  }
  void on_end_of_session(SeqNo) {}

  // --- strategy output -------------------------------------------------------------
  [[nodiscard]] UserRefNum next_urn() noexcept { return oe_.next_urn(); }
  bool send(std::span<const std::byte> ouch) {
    const int a = oe_.active();
    const std::size_t before = a >= 0 ? oe_.tx(static_cast<std::size_t>(a)).size() : 0;
    const bool ok = oe_.send(ouch, now_);
    if (ok && log_on()) record_order(a, before);
    flush_orders();  // the order goes on the wire within this iteration (07 §3 step 6)
    if (ok && ouch.size() >= 5)  // after the wire: off the tick-to-trade path
      NLOG_INFO("client order '{}' urn {} sent on instance {}", static_cast<char>(ouch[0]), load_be32(ouch.data() + 1),
                a);
    return ok;
  }

  [[nodiscard]] const Feed& feed() const noexcept { return feed_; }
  // Publishes into `seg` (client_metrics_schema()) every 1,024 loop iterations and at the end.
  void set_metrics(metrics::Segment* seg) noexcept { seg_ = seg; }
  // The line comparator (nullptr unless line_compare_window > 0); finish() it after run().
  [[nodiscard]] mold::LineComparator* line_comparator() noexcept { return cmp_.get(); }
  [[nodiscard]] const TriggerStrategy& strategy() const noexcept { return strat_; }
  [[nodiscard]] const HaOrderEntry& orders() const noexcept { return oe_; }
  [[nodiscard]] Io& io() noexcept { return io_; }
  [[nodiscard]] const Io& io() const noexcept { return io_; }
  // The T18 order-stamp log (empty unless stamp_log_capacity > 0).
  [[nodiscard]] std::span<const OrderStampRecord> stamp_log() const noexcept { return stamps_; }
  [[nodiscard]] std::uint64_t stamp_log_overflow() const noexcept { return stamp_overflow_; }
  [[nodiscard]] net::TsValidity tx_stamp_validity() const noexcept {
    net::TsValidity v = txm_[0].validity();
    v.merge(txm_[1].validity());
    return v;
  }

 private:
  [[nodiscard]] bool log_on() const noexcept { return cfg_.stamp_log_capacity != 0; }

  // The packet the strategy may act on: its receive stamps and message range.
  void note_packet(Chan ch, std::span<const std::byte> pkt, const net::RxTimestamps& ts) noexcept {
    cur_line_ = static_cast<std::uint8_t>(ch);
    cur_ts_ = ts;
    if (pkt.size() >= mold::kHeaderLen) {
      cur_pkt_seq_ = load_be64(pkt.data() + 10);
      cur_pkt_count_ = load_be16(pkt.data() + 18);
    } else {
      cur_pkt_seq_ = 0;
      cur_pkt_count_ = 0;
    }
  }

  // One record per order; its TX stamp is expected at the offset of its last byte on
  // the active instance's stream when it was appended there.
  void record_order(int active_before, std::size_t tx_before) noexcept {
    if (stamps_.size() == stamps_.capacity()) {
      ++stamp_overflow_;
      return;
    }
    OrderStampRecord r;
    r.trigger_seq = cur_msg_seq_;
    r.rx_hw = cur_ts_.hw_ns;
    r.rx_sw = cur_ts_.sw_ns;
    r.phc = cfg_.phc_index;
    r.line = cur_line_;
    if (cur_msg_seq_ >= cur_pkt_seq_ && cur_msg_seq_ < cur_pkt_seq_ + cur_pkt_count_) r.flags |= OrderStampRecord::kInPacket;
    const int a = oe_.active();
    const auto ai = static_cast<std::size_t>(a);
    if (a >= 0 && a == active_before && oe_.tx(ai).size() > tx_before) {
      txm_[ai].expect(stamps_.size(), txm_[ai].written() + static_cast<std::uint32_t>(oe_.tx(ai).size()) - 1);
    } else {
      r.flags |= OrderStampRecord::kUntagged;
    }
    stamps_.push_back(r);  // reserved: no allocation
  }

  void drain_stamps() {
    (void)io_.drain_tx_stamps([&](env::ConnId c, const StreamTxStamp& s) {
      const std::size_t i = c == oe_conn_[0] ? 0 : c == oe_conn_[1] ? 1 : 2;
      if (i == 2) return;
      txm_[i].on_stamp(s, [&](std::uint64_t tag, const net::RxTimestamps& ts) {
        OrderStampRecord& r = stamps_[tag];
        r.tx_hw = ts.hw_ns;
        r.tx_sw = ts.sw_ns;
        r.flags |= OrderStampRecord::kTxSeen;
      });
    });
  }

  [[nodiscard]] Nanos next_deadline() const noexcept {
    Nanos d = feed_.next_deadline();
    if (cfg_.trade) d = std::min(d, oe_.next_deadline());
    if (snap_) d = std::min(d, snap_->actions().deadline);
    return d;
  }

  void connect_instance(std::size_t i, Nanos now) {
    const net::Endpoint& ep = i == 0 ? cfg_.primary : cfg_.backup;
    if (ep.port == 0) return;
    last_attempt_[i] = now;
    auto c = io_.connect(ep);
    if (c) {
      oe_conn_[i] = *c;
      oe_.on_connecting(i);
    }
  }

  void maybe_reconnect(Nanos now) {
    if (cfg_.reconnect_interval <= 0) return;
    for (std::size_t i = 0; i < 2; ++i) {
      if (oe_conn_[i] == env::kNoConn && now - last_attempt_[i] >= cfg_.reconnect_interval) connect_instance(i, now);
    }
  }

  void start_snapshot(Nanos now, RefClientResult&) {
    if (cfg_.glimpse.port == 0) return;
    auto c = io_.connect(cfg_.glimpse);
    snap_retry_at_ = now + cfg_.snapshot_retry;
    if (!c) {
      snapshot_failed("connect failed");
      return;
    }
    snap_conn_ = *c;
    snap_wanted_ = false;
    ++snap_sessions_;
  }

  // The feed's events for the node log (11 §3): every gap fill as it happens (by line
  // A or B, re-request or snapshot), and once a second the first arrivals per source
  // (which line won each message) since the last line.
  void note_feed(Nanos now) {
    const mold::LineArbiterMetrics& m = feed_.arbiter().metrics();
    if (m.gaps_filled_by_line[0] != logged_.gaps_filled_by_line[0] ||
        m.gaps_filled_by_line[1] != logged_.gaps_filled_by_line[1] ||
        m.gaps_filled_by_rerequest != logged_.gaps_filled_by_rerequest ||
        m.gaps_filled_by_snapshot != logged_.gaps_filled_by_snapshot) {
      NLOG_INFO("client gap filled: by line A {} line B {} re-request {} snapshot {} (next {})",
                m.gaps_filled_by_line[0] - logged_.gaps_filled_by_line[0],
                m.gaps_filled_by_line[1] - logged_.gaps_filled_by_line[1],
                m.gaps_filled_by_rerequest - logged_.gaps_filled_by_rerequest,
                m.gaps_filled_by_snapshot - logged_.gaps_filled_by_snapshot, feed_.arbiter().next_expected());
      logged_.gaps_filled_by_line = m.gaps_filled_by_line;
      logged_.gaps_filled_by_rerequest = m.gaps_filled_by_rerequest;
      logged_.gaps_filled_by_snapshot = m.gaps_filled_by_snapshot;
    }
    if (now < next_feed_log_) return;
    next_feed_log_ = now + 1'000'000'000;
    const auto d = [&](std::size_t s) { return m.first_arrivals[s] - logged_.first_arrivals[s]; };
    if (d(0) + d(1) + d(2) + d(3) != 0) {
      NLOG_INFO("client first arrivals: line A {} line B {} re-request A {} B {}; gaps opened {}", d(0), d(1), d(2), d(3),
                m.gaps_opened - logged_.gaps_opened);
    }
    logged_.first_arrivals = m.first_arrivals;
    logged_.gaps_opened = m.gaps_opened;
  }

  void publish_metrics() {
    const mold::LineArbiterMetrics& m = feed_.arbiter().metrics();
    auto set = [&](ClientCtr c, std::uint64_t v) { seg_->counter(static_cast<std::size_t>(c)).set(v); };
    set(ClientCtr::first_arrivals_line_a, m.first_arrivals[0]);
    set(ClientCtr::first_arrivals_line_b, m.first_arrivals[1]);
    set(ClientCtr::first_arrivals_rerequest_a, m.first_arrivals[2]);
    set(ClientCtr::first_arrivals_rerequest_b, m.first_arrivals[3]);
    set(ClientCtr::delivered, m.delivered);
    set(ClientCtr::gaps_opened, m.gaps_opened);
    set(ClientCtr::gaps_filled_line_a, m.gaps_filled_by_line[0]);
    set(ClientCtr::gaps_filled_line_b, m.gaps_filled_by_line[1]);
    set(ClientCtr::gaps_filled_rerequest, m.gaps_filled_by_rerequest);
    set(ClientCtr::gaps_filled_snapshot, m.gaps_filled_by_snapshot);
    set(ClientCtr::orders_sent, oe_.stats().sent);
    set(ClientCtr::order_responses, responses_);
    // A/B skew: what the arbiter's base-2 buckets gained since the last publication, at
    // each bucket's upper bound.
    metrics::Histogram h = seg_->histogram(std::size_t{0});
    for (std::size_t b = 0; b < mold::Log2Histogram::kBuckets; ++b) {
      const std::uint64_t n = m.skew_ns.bucket_count(b);
      const auto v = static_cast<std::int64_t>(b == 0 ? 1 : (b >= 63 ? std::int64_t{1} << 62 : (std::int64_t{1} << b) - 1));
      for (std::uint64_t k = skew_published_[b]; k < n; ++k) h.record(v);
      skew_published_[b] = n;
    }
    seg_->heartbeat();
  }

  void on_stream(const env::StreamEvent& ev, Nanos now) {
    const std::size_t inst = ev.conn == oe_conn_[0] ? 0 : ev.conn == oe_conn_[1] ? 1 : 2;
    const bool is_snap = ev.conn == snap_conn_ && snap_conn_ != env::kNoConn;
    switch (ev.kind) {
      case env::StreamEventKind::Connected:
        if (inst < 2) {
          txm_[inst].reset();  // stream offsets restart with the connection
          oe_.on_connected(inst, now);
          flush_orders();
        } else if (is_snap) {
          soup::ClientConfig c = cfg_.glimpse_login;
          c.sequence = 1;  // the whole spin (03-protocols §8: login with sequence 1)
          snap_.emplace(c);
          absorb_snapshot(snap_->connect(now), now);
        }
        break;
      case env::StreamEventKind::Data:
        if (inst < 2) {
          oe_.on_bytes(inst, ev.data, now, [&](SeqNo seq, std::span<const std::byte> m) {
            ++responses_;
            if (m.size() >= 13)
              NLOG_INFO("client response {} '{}' urn {} on instance {}", seq, static_cast<char>(m[0]),
                        load_be32(m.data() + 9), inst);
          });
          flush_orders();
        } else if (is_snap && snap_) {
          std::span<const std::byte> in = ev.data;
          while (!in.empty() && snap_) {
            const soup::Actions& a = snap_->on_bytes(in, now);
            const std::size_t used = a.consumed;
            absorb_snapshot(a, now);
            if (used == 0) break;
            in = in.subspan(used);
          }
        }
        break;
      case env::StreamEventKind::Closed:
        if (inst < 2) {
          oe_conn_[inst] = env::kNoConn;
          txm_[inst].reset();
          oe_.on_closed(inst, now);
          flush_orders();
        } else if (is_snap) {
          snap_conn_ = env::kNoConn;
          // Closed before Connected (the connect was refused or timed out) has no
          // session yet; it is a failed attempt all the same, retried after
          // snapshot_retry, or the client would wait for a snapshot forever.
          if (!snap_done_) snapshot_failed(snap_ ? "connection closed before End of Snapshot" : "connect refused");
          snap_.reset();
          snap_done_ = false;
        }
        break;
      case env::StreamEventKind::Accepted: break;
    }
  }

  void absorb_snapshot(const soup::Actions& a, Nanos now) {
    for (const soup::Event& e : a.events) {
      // A new spin starts from an empty book, whatever an earlier session left.
      if (e.kind == soup::EventKind::LoggedIn) feed_.begin_snapshot();
      if (e.kind == soup::EventKind::LoginRejected && cfg_.verbose)
        std::fprintf(stderr, "refclient: snapshot login rejected ('%c')\n", e.code);
    }
    for (const soup::Delivered& d : a.delivered) {
      if (d.seq == 0 || snap_done_) continue;
      const auto r = feed_.on_snapshot_payload(d.data, now, *this);
      if (r == Feed::SpinResult::Spliced || (r == Feed::SpinResult::Rejected && !d.data.empty() &&
                                             static_cast<char>(d.data[0]) == glimpse::kEndOfSnapshotType)) {
        snap_done_ = true;
        if (cfg_.verbose)
          std::fprintf(stderr, "refclient: %.3f s: snapshot %s: next %llu, %llu spin messages so far, buffered %zu\n",
                       static_cast<double>(now - start_) / 1e9, r == Feed::SpinResult::Spliced ? "spliced" : "rejected",
                       static_cast<unsigned long long>(feed_.arbiter().next_expected()),
                       static_cast<unsigned long long>(feed_.stats().snapshot_messages), feed_.arbiter().buffered());
      }
    }
    if (snap_done_ && snap_ && snap_->state() == soup::ClientSession::State::Active) (void)snap_->logout(now);
    if (a.close || (snap_ && snap_->state() == soup::ClientSession::State::Closed)) {
      flush_snapshot();
      if (snap_conn_ != env::kNoConn) io_.close(snap_conn_);
      snap_conn_ = env::kNoConn;
      if (!snap_done_) snapshot_failed("session closed before End of Snapshot");
      snap_.reset();
      snap_done_ = false;
    }
  }

  // The spin was not completed: its partial book is abandoned and, if the feed is
  // still waiting for a snapshot, another session is started.
  void snapshot_failed(const char* why) {
    ++snap_failures_;
    feed_.abort_snapshot();
    snap_wanted_ = feed_.arbiter().state() == mold::LineArbiter::State::AwaitingSnapshot;
    if (cfg_.verbose)
      std::fprintf(stderr, "refclient: %.3f s: snapshot session failed: %s\n", static_cast<double>(now_ - start_) / 1e9,
                   why);
  }

  void flush_orders() {
    for (std::size_t i = 0; i < 2; ++i) {
      if (oe_conn_[i] == env::kNoConn) continue;
      const std::span<const std::byte> tx = oe_.tx(i);
      if (!tx.empty()) {
        const std::size_t n = io_.write(oe_conn_[i], tx);
        if (n > 0) {
          txm_[i].on_written(n);
          oe_.consume_tx(i, n);
        }
      }
      if (oe_.wants_close(i) && oe_.tx(i).empty()) {
        io_.close(oe_conn_[i]);
        oe_conn_[i] = env::kNoConn;
        txm_[i].reset();
        oe_.on_closed(i, now_);
      }
    }
  }

  void flush_snapshot() {
    if (!snap_ || snap_conn_ == env::kNoConn) return;
    const std::span<const std::byte> tx = snap_->actions().write;
    if (!tx.empty()) {
      const std::size_t n = io_.write(snap_conn_, tx);
      if (n > 0) snap_->consume_tx(n);
    }
  }

  void flush_all() {
    if (cfg_.trade) flush_orders();
    flush_snapshot();
  }

  RefClientConfig cfg_;
  env::ProdClock clock_;
  Io io_;
  Feed feed_;
  std::unique_ptr<mold::LineComparator> cmp_ =
      cfg_.line_compare_window > 0 ? std::make_unique<mold::LineComparator>(cfg_.line_compare_window) : nullptr;
  TriggerStrategy strat_;
  HaOrderEntry oe_;
  std::array<env::ConnId, 2> oe_conn_{env::kNoConn, env::kNoConn};
  std::array<Nanos, 2> last_attempt_{};
  std::optional<soup::ClientSession> snap_;
  env::ConnId snap_conn_ = env::kNoConn;
  bool snap_wanted_ = false;
  bool snap_done_ = false;
  Nanos snap_retry_at_ = 0;
  std::uint64_t snap_sessions_ = 0, snap_failures_ = 0, responses_ = 0;
  mold::LineArbiterMetrics logged_{};  // the arbiter's counters as last logged
  metrics::Segment* seg_ = nullptr;
  std::uint64_t iterations_ = 0;
  std::array<std::uint64_t, mold::Log2Histogram::kBuckets> skew_published_{};
  Nanos next_feed_log_ = 0;
  Nanos now_ = 0;
  Nanos start_ = 0;
  // T18 order-stamp log.
  std::vector<OrderStampRecord> stamps_;
  std::array<StreamTxMatcher, 2> txm_;
  std::uint64_t stamp_overflow_ = 0;
  SeqNo cur_msg_seq_ = 0;
  SeqNo cur_pkt_seq_ = 0;
  std::uint32_t cur_pkt_count_ = 0;
  std::uint8_t cur_line_ = 0;
  net::RxTimestamps cur_ts_{};
};

}  // namespace lle::client
