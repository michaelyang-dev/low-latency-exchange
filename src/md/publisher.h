#pragma once
// The market-data stage md (07 §3, WP N-18; 01 §4 step 5, §7).
//
//   - Release-gated MoldUDP64 packetizer: ITCH outputs leave the egress ring only once
//     their journal index is <= the release watermark (Output Rule, ADR-005). Each
//     released message gets the next MoldUDP64 sequence number, so the sequence is the
//     count of released ITCH messages S(P), identical on both nodes (01 §6).
//   - Two lines from two packetizers fed the same messages but packetized
//     independently (line B has its own, by default smaller, maximum packet), so
//     receivers see partial overlaps (03 §7, T10). Which lines this node transmits is
//     the `lines` mask: both in single-node mode; line A on the primary and line B on
//     the backup in paired mode; both again on a primary that took over (10 §3, §4).
//     Both packetizers always run, so a line that is switched on mid-day continues at
//     the current sequence number.
//   - The re-request server (mold::RerequestServer) answers unicast requests from the
//     in-memory ring, then the output log (ItchStore).
//   - After the DayEnd marker: end of session on both lines, repeated for the linger
//     period (06 §10).
// Batching is opportunistic (packetizer.h): a packet goes out when the next message
// does not fit or when the stage finds no more released input; heartbeats after the
// heartbeat interval of silence. No allocation after construction.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>

#include "common/assert.h"
#include "common/types.h"
#include "env/concepts.h"
#include "log/nlog.h"
#include "md/egress.h"
#include "md/itch_store.h"
#include "md/work_meter.h"
#include "proto/itch50/itch50.h"
#include "net/common/port.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/moldudp64/packetizer.h"
#include "proto/moldudp64/rerequest_server.h"

namespace lle::md {

inline constexpr std::uint8_t kLineA = 1;
inline constexpr std::uint8_t kLineB = 2;

struct MdConfig {
  mold::Session session;                     // the day's MoldUDP64 session (DayStart)
  env::Endpoint line_a{};                    // destination: multicast group or unicast
  env::Endpoint line_b{};
  std::size_t max_packet_a = mold::kDefaultMaxPacket;
  std::size_t max_packet_b = 1000;           // independent packetization (07 §3)
  Nanos heartbeat_interval = kNsPerSec;
  Nanos end_of_session_linger = 30 * kNsPerSec;
  net::UdpConfig line_udp{};                 // the sending socket (TTL, interface, loop)
  net::UdpConfig rerequest_udp{};            // bind: the re-request server's port
  mold::RerequestConfig rerequest{};         // session filled in from `session`
  std::size_t ring_messages = std::size_t{1} << 18;
  std::size_t ring_bytes = std::size_t{16} << 20;
  std::string itch_log_path;                 // outlog itch.bin (empty: ring only)
  SeqNo first_seq = 1;                       // S(P) + 1 after recovery
  // After recovery: messages [republish_from, first_seq) were regenerated into the
  // output log and may never have been multicast (released only now, or the process
  // died before md sent them). They go out on the lines first, from the store, so the
  // lines continue without a gap for receivers to re-request. 0: nothing to republish.
  SeqNo republish_from = 0;
  std::size_t egress_batch = 1024;
};

struct MdShared {
  EgressRing* egress = nullptr;
  EgressState* state = nullptr;
  const std::atomic<std::uint8_t>* lines = nullptr;  // kLineA | kLineB
};

struct MdStats {
  std::uint64_t messages = 0;  // released ITCH messages sequenced
  std::uint64_t packets_a = 0, packets_b = 0;
  std::uint64_t bytes_a = 0, bytes_b = 0;
  std::uint64_t send_failures = 0;
  std::uint64_t refused = 0;  // messages a packetizer refused (must stay 0)
  std::uint64_t republished = 0;  // regenerated messages sent again after recovery
  std::uint64_t heartbeats = 0;
  std::uint64_t rerequests = 0, rerequests_served = 0, rerequests_refused = 0;
  std::uint64_t batch_hist[8] = {};  // messages per data packet on line A: 1, 2-3, 4-7, ..., >= 128
  bool ended = false;
};

template <class E>
concept MdEnvLike = requires {
  typename E::Net;
  typename E::Clock;
} && env::DatagramPortLike<typename E::Net::DatagramPort> && env::ClockLike<typename E::Clock>;

template <MdEnvLike Env>
class MdStage {
 public:
  using Net = typename Env::Net;
  using Udp = typename Net::DatagramPort;
  using Clock = typename Env::Clock;
  using Store = ItchStore<outlog::env_reader_t<Env>>;  // Env::OutlogReader, else POSIX

  MdStage(const MdConfig& cfg, Clock& clock, MdShared shared)
      : cfg_(cfg),
        clock_(&clock),
        sh_(shared),
        a_(packetizer_config(cfg, cfg.max_packet_a, line_start(cfg))),
        b_(packetizer_config(cfg, cfg.max_packet_b, line_start(cfg))),
        store_(cfg.ring_messages, cfg.ring_bytes, cfg.first_seq, cfg.itch_log_path),
        server_(rerequest_config(cfg), store_),
        work_(&clock) {
    LLE_ASSERT(sh_.egress != nullptr && sh_.state != nullptr && sh_.lines != nullptr, "md: not wired");
    republish_next_ = line_start(cfg);
    LLE_ASSERT(cfg.max_packet_a >= mold::kHeaderLen + mold::kBlockPrefixLen + itch50::kMaxMsgLen &&
                   cfg.max_packet_b >= mold::kHeaderLen + mold::kBlockPrefixLen + itch50::kMaxMsgLen,
               "md: a packet must hold the largest ITCH message");
  }
  MdStage(const MdStage&) = delete;
  MdStage& operator=(const MdStage&) = delete;

  std::expected<void, std::string> start() {
    auto r = open_net();
    if (!r) {
      error_ = r.error();
      state_.store(-1, std::memory_order_release);
      return r;
    }
    state_.store(1, std::memory_order_release);
    return {};
  }
  // Opens on the first poll, on the polling thread (io_uring SINGLE_ISSUER).
  void start_on_first_poll() noexcept { deferred_ = true; }
  [[nodiscard]] int start_state() const noexcept { return state_.load(std::memory_order_acquire); }
  [[nodiscard]] const std::string& error() const noexcept { return error_; }

  bool poll() {
    if (deferred_) [[unlikely]] {
      deferred_ = false;
      (void)start();
    }
    if (state_.load(std::memory_order_relaxed) != 1) return false;
    const Nanos now = clock_->now_mono();
    (void)net_.wait(0);
    bool did = false;
    if (republish_next_ < cfg_.first_seq) [[unlikely]] {
      republish(now);
      work_.finish();
      return true;  // the released stream follows once the regenerated tail is out
    }
    const std::size_t n = drain_released(*sh_.egress, *sh_.state, kMd, cfg_.egress_batch, [&](const OutEntry& e) {
      if (e.kind == OutKind::Itch) {
        on_itch(e.msg, now);
      } else if (e.kind == OutKind::DayEnd) {
        end_session(now);
      }
      return true;
    });
    if (n != 0) did = true;
    if (n < cfg_.egress_batch) {
      // The released input is empty for now: send the open packets (zero-latency path).
      did |= a_.flush(now, [&](std::span<const std::byte> p) { send_a(p); });
      did |= b_.flush(now, [&](std::span<const std::byte> p) { send_b(p); });
    }
    did |= a_.on_timer(now, [&](std::span<const std::byte> p) { send_a(p); });
    did |= b_.on_timer(now, [&](std::span<const std::byte> p) { send_b(p); });
    did |= rr_.poll_rx([&](const env::RxDatagram& d) { on_request(d, now); }) != 0;
    work_.finish();
    return did;
  }

  [[nodiscard]] SeqNo next_seq() const noexcept { return a_.next_seq(); }
  [[nodiscard]] const MdStats& stats() const noexcept { return stats_; }
  // Work time (md/work_meter.h). Items: released ITCH messages, republished messages,
  // re-requests and the end of session.
  [[nodiscard]] const WorkStats& work() const noexcept { return work_.stats(); }
  [[nodiscard]] const mold::RerequestStats& rerequest_stats() const noexcept { return server_.stats(); }
  [[nodiscard]] env::Endpoint rerequest_endpoint() const noexcept { return rr_.local(); }
  [[nodiscard]] Net& net() noexcept { return net_; }
  [[nodiscard]] Udp& line_port() noexcept { return tx_; }
  [[nodiscard]] Udp& rerequest_port() noexcept { return rr_; }

 private:
  std::expected<void, std::string> open_net() {
    if (auto r = net_.open(); !r) return std::unexpected("md: reactor: " + net::to_string(r.error()));
    if (auto r = net_.open(tx_, cfg_.line_udp); !r) return std::unexpected("md: line socket: " + net::to_string(r.error()));
    if (auto r = net_.open(rr_, cfg_.rerequest_udp); !r)
      return std::unexpected("md: re-request socket: " + net::to_string(r.error()));
    return {};
  }

  static mold::PacketizerConfig packetizer_config(const MdConfig& c, std::size_t max_packet, SeqNo first) {
    return mold::PacketizerConfig{c.session, max_packet, c.heartbeat_interval, c.end_of_session_linger, first};
  }
  static SeqNo line_start(const MdConfig& c) noexcept {
    return c.republish_from != 0 && c.republish_from < c.first_seq ? c.republish_from : c.first_seq;
  }

  // Up to one batch of the regenerated tail, from the store (output log).
  void republish(Nanos now) {
    for (std::size_t i = 0; i < cfg_.egress_batch && republish_next_ < cfg_.first_seq; ++i) {
      const auto m = store_.get(republish_next_);
      if (!m) {
        // Not readable: the lines jump to first_seq and receivers re-request the rest.
        NLOG_ERROR("md: cannot republish message {} (store); lines continue at {}", republish_next_, cfg_.first_seq);
        a_.flush(now, [&](std::span<const std::byte> p) { send_a(p); });
        b_.flush(now, [&](std::span<const std::byte> p) { send_b(p); });
        a_ = mold::Packetizer(packetizer_config(cfg_, cfg_.max_packet_a, cfg_.first_seq));
        b_ = mold::Packetizer(packetizer_config(cfg_, cfg_.max_packet_b, cfg_.first_seq));
        republish_next_ = cfg_.first_seq;
        return;
      }
      work_.start();
      work_.add();
      ++stats_.republished;
      (void)a_.append(*m, now, [&](std::span<const std::byte> p) { send_a(p); });
      (void)b_.append(*m, now, [&](std::span<const std::byte> p) { send_b(p); });
      ++republish_next_;
    }
    if (republish_next_ == cfg_.first_seq) {
      a_.flush(now, [&](std::span<const std::byte> p) { send_a(p); });
      b_.flush(now, [&](std::span<const std::byte> p) { send_b(p); });
      NLOG_INFO("md: republished {} regenerated messages before {}", stats_.republished, cfg_.first_seq);
    }
  }

  static mold::RerequestConfig rerequest_config(const MdConfig& c) {
    mold::RerequestConfig r = c.rerequest;
    r.session = c.session;
    r.max_packet = c.max_packet_a;
    return r;
  }

  [[nodiscard]] std::uint8_t lines() const noexcept { return sh_.lines->load(std::memory_order_acquire); }

  void on_itch(std::span<const std::byte> msg, Nanos now) {
    work_.start();
    work_.add();
    ++stats_.messages;
    (void)store_.append(msg);
    const auto ra = a_.append(msg, now, [&](std::span<const std::byte> p) { send_a(p); });
    const auto rb = b_.append(msg, now, [&](std::span<const std::byte> p) { send_b(p); });
    if (ra != mold::Packetizer::AppendResult::Ok || rb != mold::Packetizer::AppendResult::Ok) [[unlikely]] {
      // A refused message would shift that line's sequence numbers: configuration error
      // (max_packet below the largest ITCH message) or a message after end of session.
      ++stats_.refused;
      NLOG_ERROR("md: packetizer refused a {}-byte message (A {}, B {})", msg.size(), static_cast<std::uint8_t>(ra),
                 static_cast<std::uint8_t>(rb));
    }
  }

  void send_a(std::span<const std::byte> p) {
    if ((lines() & kLineA) == 0) return;
    const mold::PacketHeader h = mold::decode_header(p.data());
    if (h.is_heartbeat()) {
      ++stats_.heartbeats;
    } else if (!h.is_end_of_session()) {
      std::size_t bucket = 0;
      while (bucket < 7 && (std::size_t{2} << bucket) <= h.count) ++bucket;
      ++stats_.batch_hist[bucket];
    }
    note_state(h);
    if (tx_.send(cfg_.line_a, p)) {
      ++stats_.packets_a;
      stats_.bytes_a += p.size();
    } else {
      send_failed('A');
    }
  }
  void send_b(std::span<const std::byte> p) {
    if ((lines() & kLineB) == 0) return;
    if ((lines() & kLineA) == 0) note_state(mold::decode_header(p.data()));  // a backup: B is its line
    if (tx_.send(cfg_.line_b, p)) {
      ++stats_.packets_b;
      stats_.bytes_b += p.size();
    } else {
      send_failed('B');
    }
  }
  // Heartbeat state (11 §3): the lines go idle when the first heartbeat follows data
  // (a heartbeat interval of silence) and active again with the next data packet.
  void note_state(const mold::PacketHeader& h) {
    if (h.is_heartbeat()) {
      if (!idle_) NLOG_INFO("md lines idle at sequence {}: heartbeating", h.seq);
      idle_ = true;
    } else if (!h.is_end_of_session() && idle_) {
      NLOG_INFO("md lines active again at sequence {} ({} heartbeats so far)", h.seq, stats_.heartbeats);
      idle_ = false;
    }
  }
  void send_failed(char line) {
    if (stats_.send_failures++ % 1024 == 0)
      NLOG_WARN("md: a line {} packet was not sent ({} so far)", line, stats_.send_failures);
  }

  void end_session(Nanos now) {
    if (stats_.ended) return;
    work_.start();
    work_.add();
    stats_.ended = true;
    NLOG_INFO("md end of session at sequence {}", a_.next_seq());
    a_.end_session(now, [&](std::span<const std::byte> p) { send_a(p); });
    b_.end_session(now, [&](std::span<const std::byte> p) { send_b(p); });
  }

  void on_request(const env::RxDatagram& d, Nanos now) {
    work_.start();
    work_.add();
    ++stats_.rerequests;
    const mold::RequestOutcome o =
        server_.on_request(d.data, d.src, now, [&](const env::Endpoint& to, std::span<const std::byte> pkt) {
          (void)rr_.send(to, pkt);
        });
    if (o == mold::RequestOutcome::Served) {
      ++stats_.rerequests_served;
      NLOG_INFO("md re-request served from port {}", d.src.port);
    } else {
      ++stats_.rerequests_refused;
      NLOG_WARN("md re-request refused: outcome {}", static_cast<std::uint8_t>(o));
    }
  }

  MdConfig cfg_;
  Clock* clock_;
  MdShared sh_;
  Net net_;
  Udp tx_;
  Udp rr_;
  mold::Packetizer a_;
  mold::Packetizer b_;
  Store store_;
  mold::RerequestServer<Store> server_;
  MdStats stats_{};
  bool idle_ = false;  // the lines carry heartbeats only
  SeqNo republish_next_ = 1;
  bool deferred_ = false;
  std::atomic<int> state_{0};
  std::string error_;
  WorkMeter<Clock> work_;
};

}  // namespace lle::md
