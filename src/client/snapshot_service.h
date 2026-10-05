#pragma once
// mold_replay's GLIMPSE-style snapshot service on its own thread (03-protocols
// §8; 07 §3: the snapshot server runs on housekeeping cores, off the hot path).
//
// The publisher pushes every message it has published, in sequence order, into
// an SPSC byte ring; the service thread applies them to its ReplayBookState and
// serves SoupBinTCP snapshot sessions from that state. Building a spin of a
// full-day book (millions of orders) takes a fraction of a second; on the
// publisher's thread that stalled the lines and the re-request servers, which
// made clients time out and ask for more snapshots. Here only the service
// thread pauses, and the ring absorbs the stream meanwhile. A spin taken at
// position P is consistent: every message <= P was published (and stored for
// re-requests) before the publisher pushed it.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <thread>
#include <vector>

#include "client/glimpse_service.h"
#include "client/replay_state.h"
#include "concurrent/spsc_byte_ring.h"
#include "env/prod_clock.h"
#include "net/common/stack.h"

namespace lle::client {

struct SnapshotServiceConfig {
  net::Endpoint listen{};
  std::size_t ring_bytes = std::size_t{1} << 30;  // power of two: covers seconds of feed
  book::BookConfig book{};
  bool verbose = true;
  // Tests: the port refuses connections (nothing listens) for this long after start(),
  // then listens (refclient must retry a refused snapshot connect).
  Nanos listen_delay = 0;
};

struct SnapshotServiceStats {
  std::uint64_t applied = 0, spins = 0, spin_messages = 0, publisher_waits = 0;
  std::uint64_t final_books_digest = 0, final_live_orders = 0;
};

template <net::BackendKind K>
class SnapshotService {
 public:
  using StackT = net::Stack<K>;

  explicit SnapshotService(const SnapshotServiceConfig& cfg)
      : cfg_(cfg),
        stack_(net::WaitPolicy::Spin),
        storage_(std::make_unique<std::uint64_t[]>(cfg.ring_bytes / 8)),
        state_(std::make_unique<ReplayBookState>(cfg.book)) {
    ring_.init(reinterpret_cast<std::byte*>(storage_.get()), cfg.ring_bytes);
    scfg_.session = soup::SessionId::from("GLIMPSE");
    scfg_.tx_capacity = 1 << 20;
    scfg_.max_replay_per_call = 1 << 15;
  }
  SnapshotService(const SnapshotService&) = delete;
  SnapshotService& operator=(const SnapshotService&) = delete;
  ~SnapshotService() { stop(); }

  net::Result<void> open() {
    if (auto r = stack_.open(); !r) return r;
    net::TcpConfig tc;
    tc.max_conns = 16;
    tc.sndbuf = 4 << 20;
    if (auto r = stack_.open(tcp_, tc); !r) return r;
    if (cfg_.listen_delay > 0) return {};  // listen() from the service thread, later
    if (auto r = tcp_.listen(cfg_.listen); !r) return std::unexpected(r.error());
    listening_ = true;
    return {};
  }

  void start() { thread_ = std::thread([this] { loop(); }); }

  // Publisher thread: the next message in sequence order.
  void publish(std::span<const std::byte> msg) noexcept {
    for (;;) {
      std::byte* p = ring_.try_reserve(static_cast<std::uint32_t>(msg.size()));
      if (p != nullptr) {
        if (!msg.empty()) std::memcpy(p, msg.data(), msg.size());
        ring_.commit();
        return;
      }
      ++waits_;  // the service thread is behind (ring full): wait for it
    }
  }

  // Applies what is queued, then stops serving and joins.
  void stop() {
    if (!thread_.joinable()) return;
    stop_.store(true, std::memory_order_release);
    thread_.join();
    st_.final_books_digest = state_->books_digest();
    st_.final_live_orders = state_->live_orders();
    st_.publisher_waits = waits_;
  }

  [[nodiscard]] const SnapshotServiceStats& stats() const noexcept { return st_; }

 private:
  static constexpr Nanos kLinger = 30 * kNsPerSec;
  struct Conn {
    env::ConnId conn = env::kNoConn;
    std::unique_ptr<SnapshotSpinSession> s;
    Nanos done_at = 0;
  };

  void loop() {
    env::ProdClock clock;
    const Nanos t0 = clock.now_mono();
    for (;;) {
      const bool stopping = stop_.load(std::memory_order_acquire);
      const std::size_t n = ring_.drain(
          [&](const std::byte* p, std::uint32_t len) { state_->apply(++st_.applied, std::span<const std::byte>(p, len)); },
          4096);
      if (stopping && n == 0) break;
      (void)stack_.wait(0);
      const Nanos now = clock.now_mono();
      if (!listening_ && now - t0 >= cfg_.listen_delay) {
        if (auto r = tcp_.listen(cfg_.listen); r) {
          listening_ = true;
          if (cfg_.verbose)
            std::fprintf(stderr, "mold_replay: %.3f s: snapshot service listening\n", static_cast<double>(now - t0) / 1e9);
        }
      }
      tcp_.poll([&](const env::StreamEvent& ev) {
        if (ev.kind == env::StreamEventKind::Accepted) {
          Conn c;
          c.conn = ev.conn;
          c.s = std::make_unique<SnapshotSpinSession>(*state_, state_->live_orders() + 5 * 65536 + 64, now, scfg_);
          ++st_.spins;
          st_.spin_messages += c.s->spin().messages;
          if (cfg_.verbose)
            std::fprintf(stderr, "mold_replay: %.3f s: snapshot spin %llu: %llu messages, G=%llu (built in %.3f s)\n",
                         static_cast<double>(now - t0) / 1e9, static_cast<unsigned long long>(st_.spins),
                         static_cast<unsigned long long>(c.s->spin().messages),
                         static_cast<unsigned long long>(c.s->spin().next_seq),
                         static_cast<double>(clock.now_mono() - now) / 1e9);
          conns_.push_back(std::move(c));
          return;
        }
        for (auto& c : conns_) {
          if (c.conn != ev.conn) continue;
          if (ev.kind == env::StreamEventKind::Data && c.s) (void)c.s->on_bytes(ev.data, now);
          if (ev.kind == env::StreamEventKind::Closed) c.conn = env::kNoConn;
        }
      });
      for (auto& c : conns_) {
        if (c.conn == env::kNoConn || !c.s) continue;
        if (c.s->actions().deadline <= now) (void)c.s->on_timer(now);
        for (int k = 0; k < 64; ++k) {
          const auto w = c.s->actions().write;
          if (w.empty()) break;
          const std::size_t written = tcp_.write(c.conn, w);
          if (written == 0) break;
          if (c.s->consume_tx(written)) (void)c.s->on_timer(now);
        }
        // Lingering close: after End of Session the client logs out and closes.
        // Closing first, while its heartbeats sit unread in our receive buffer,
        // makes the kernel answer with a reset that can destroy the tail of the
        // spin (End of Snapshot included) before the client has read it.
        if (c.s->closed() && c.s->actions().write.empty()) {
          if (c.done_at == 0) c.done_at = now;
          if (now - c.done_at >= kLinger) {
            tcp_.close(c.conn);
            c.conn = env::kNoConn;
          }
        }
      }
      std::erase_if(conns_, [](const Conn& c) { return c.conn == env::kNoConn; });
    }
  }

  SnapshotServiceConfig cfg_;
  StackT stack_;
  typename StackT::StreamPort tcp_;
  std::unique_ptr<std::uint64_t[]> storage_;
  conc::SpscByteRing ring_;
  bool listening_ = false;
  std::unique_ptr<ReplayBookState> state_;
  soup::ServerConfig scfg_;
  std::vector<Conn> conns_;
  std::thread thread_;
  std::atomic<bool> stop_{false};
  std::uint64_t waits_ = 0;  // publisher thread only
  SnapshotServiceStats st_;  // service thread until stop()
};

}  // namespace lle::client
