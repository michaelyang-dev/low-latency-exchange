#pragma once
// The network-facing stages for one I/O variant (07 §1, §3): gateways gw0 and gw1, the md
// stage and the GLIMPSE server, instantiated for one Net type: net::Stack<K> for the
// kernel variants, XskNet for AF_XDP (xsk_net.h; the GLIMPSE server, housekeeping, stays
// on kernel sockets there). The variant is chosen at run time (node.backend); only this
// construction step is type-erased (cold), the stages themselves are concrete and
// polled directly.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "exchanged/clock.h"
#include "exchanged/config.h"
#include "exchanged/hosted.h"
#include "exchanged/metrics.h"
#include "exchanged/shared.h"
#include "gateway/gateway.h"
#include "md/glimpse_server.h"
#include "md/publisher.h"
#include "net/common/stack.h"

namespace lle::exch {

struct NetPorts {
  env::Endpoint gw[md::kGateways] = {};
  env::Endpoint rerequest{};
  env::Endpoint glimpse{};  // port 0: no snapshot service
};

class NetStagesBase {
 public:
  virtual ~NetStagesBase() = default;
  // The stages open their sockets on their first poll, on the thread that polls them
  // (an io_uring reactor is single-issuer). 0: pending, 1: all open, -1: failed (error).
  virtual void defer_start() = 0;
  [[nodiscard]] virtual int start_state(std::string* error) const = 0;
  // Appends the stages gw0, gw1 and md, each publishing into `m`.
  virtual void host_stages(std::vector<std::unique_ptr<HostedBase>>& out, NodeMetrics& m) = 0;
  [[nodiscard]] virtual NetPorts ports() const = 0;
  // Lines for the operator at shutdown (the AF_XDP sockets' mode and counters); empty
  // for the kernel variants. Cold; called once the stage threads have stopped.
  [[nodiscard]] virtual std::vector<std::string> report() const { return {}; }
};

template <class NetT>
struct GwEnvN {
  using Net = NetT;
  using OuchQueue = exch::OuchQueue;
  using SessionQueue = exch::SessionQueue;
  using Clock = NodeClock;
};
template <class NetT>
struct MdEnvN {
  using Net = NetT;
  using Clock = NodeClock;
};
template <net::BackendKind K>
using GwEnvK = GwEnvN<net::Stack<K>>;
template <net::BackendKind K>
using MdEnvK = MdEnvN<net::Stack<K>>;

template <class NetT, class GlimpseNetT = NetT>
class NetStagesT final : public NetStagesBase {
 public:
  NetStagesT(const gw::GatewayConfig gw_cfg[md::kGateways], const gw::SessionTable& table,
             std::span<const std::pair<std::uint32_t, SeqNo>> soup_next, const md::MdConfig& md_cfg,
             const md::GlimpseConfig* glimpse_cfg, Shared& sh, NodeClock& clock)
      : gw0_(gw_cfg[0], table, soup_next, sh.ouch, sh.events, clock,
             gw::GatewayShared{&sh.egress, &sh.egress_state, &sh.mirror}),
        gw1_(gw_cfg[1], table, soup_next, sh.ouch, sh.events, clock,
             gw::GatewayShared{&sh.egress, &sh.egress_state, &sh.mirror}),
        md_(md_cfg, clock, md::MdShared{&sh.egress, &sh.egress_state, &sh.lines}) {
    if (glimpse_cfg != nullptr) glimpse_.emplace(*glimpse_cfg, clock);
  }

  void defer_start() override {
    gw0_.start_on_first_poll();
    gw1_.start_on_first_poll();
    md_.start_on_first_poll();
    if (glimpse_) glimpse_->start_on_first_poll();
  }
  [[nodiscard]] int start_state(std::string* error) const override {
    const int st[] = {gw0_.start_state(), gw1_.start_state(), md_.start_state(), glimpse_ ? glimpse_->start_state() : 1};
    const std::string* err[] = {&gw0_.error(), &gw1_.error(), &md_.error(), glimpse_ ? &glimpse_->error() : nullptr};
    int all = 1;
    for (std::size_t i = 0; i < 4; ++i) {
      if (st[i] < 0) {
        if (error != nullptr && err[i] != nullptr) *error = *err[i];
        return -1;
      }
      if (st[i] == 0) all = 0;
    }
    return all;
  }
  void host_stages(std::vector<std::unique_ptr<HostedBase>>& out, NodeMetrics& m) override {
    out.push_back(host("gw0", gw0_, [this, &m] { publish_gw(0, m); }));
    out.push_back(host("gw1", gw1_, [this, &m] { publish_gw(1, m); }));
    out.push_back(host("md", md_, [this, &m] { publish_md(m); }));
    // Housekeeping (01 §7: never on the 8-core set): its own thread, or polled inline.
    if (glimpse_) {
      out.push_back(host("glimpse", *glimpse_, [this, &m] { m.set_work(Ctr::glimpse_work_tsc, glimpse_->work()); }));
    }
  }

 private:
  // gw0_* and gw1_* are the same block, at(0) sessions through at(10) replays.
  static_assert(static_cast<std::size_t>(Ctr::gw0_replays) - static_cast<std::size_t>(Ctr::gw0_sessions) == 10 &&
                static_cast<std::size_t>(Ctr::gw1_replays) - static_cast<std::size_t>(Ctr::gw1_sessions) == 10);
  void publish_gw(std::size_t i, NodeMetrics& m) {
    const gw::GatewayStats& s = i == 0 ? gw0_.stats() : gw1_.stats();
    const std::size_t base = i == 0 ? static_cast<std::size_t>(Ctr::gw0_sessions) : static_cast<std::size_t>(Ctr::gw1_sessions);
    auto at = [&](std::size_t k) { return static_cast<Ctr>(base + k); };
    m.set(at(0), s.sessions_live);
    m.set(at(1), s.logins + s.mirror_attaches);
    m.set(at(2), s.login_rejects);
    m.set(at(3), s.msgs_in);
    m.set(at(4), s.msgs_out);
    m.set(at(5), s.mpsc_full);
    m.set(at(6), s.violations);
    m.set(at(7), s.disconnects);
    m.set(at(8), s.truncated_in);
    m.set(at(9), s.cod_triggers);
    m.set(at(10), s.replays);
    m.set_work(i == 0 ? Ctr::gw0_work_tsc : Ctr::gw1_work_tsc, i == 0 ? gw0_.work() : gw1_.work());
  }
  void publish_md(NodeMetrics& m) {
    const md::MdStats& s = md_.stats();
    m.set(Ctr::md_messages, s.messages);
    m.set(Ctr::md_packets_a, s.packets_a);
    m.set(Ctr::md_packets_b, s.packets_b);
    m.set(Ctr::md_heartbeats, s.heartbeats);
    m.set(Ctr::md_rerequests, s.rerequests);
    m.set(Ctr::md_rerequests_served, s.rerequests_served);
    m.set(Ctr::md_next_seq, md_.next_seq());
    m.set(Ctr::md_rerequests_refused, s.rerequests_refused);
    m.set_work(Ctr::md_work_tsc, md_.work());
    // Packet-size distribution: record what was added since the last publication.
    metrics::Histogram h = m.md_batch();
    for (std::size_t b = 0; b < 8; ++b) {
      for (std::uint64_t k = published_hist_[b]; k < s.batch_hist[b]; ++k) h.record(std::int64_t{1} << b);
      published_hist_[b] = s.batch_hist[b];
    }
  }

 public:
  [[nodiscard]] std::vector<std::string> report() const override {
    if constexpr (requires(const NetT& n) { n.report_line(); }) {
      const char* names[] = {"gw0", "gw1", "md"};
      auto& self = const_cast<NetStagesT&>(*this);  // the stages expose their Net non-const only
      const NetT* nets[] = {&self.gw0_.net(), &self.gw1_.net(), &self.md_.net()};
      std::vector<std::string> out;
      for (int i = 0; i < 3; ++i) out.push_back(std::string("exchanged: xsk ") + names[i] + " " + nets[i]->report_line());
      return out;
    } else {
      return {};
    }
  }

  // The stages' Nets, configured before the stages start (AF_XDP placement).
  [[nodiscard]] NetT& gw_net(std::size_t i) noexcept { return i == 0 ? gw0_.net() : gw1_.net(); }
  [[nodiscard]] NetT& md_net() noexcept { return md_.net(); }
  // Kept alive as long as the stages (the AF_XDP variant's steering programs).
  void keep(std::shared_ptr<void> p) { keep_.push_back(std::move(p)); }

  [[nodiscard]] NetPorts ports() const override {
    NetPorts p;
    p.gw[0] = gw0_.listen_endpoint();
    p.gw[1] = gw1_.listen_endpoint();
    p.rerequest = md_.rerequest_endpoint();
    if (glimpse_) p.glimpse = glimpse_->listen_endpoint();
    return p;
  }

 private:
  // Declared first, destroyed last: the stages' sockets go before what they registered with.
  std::vector<std::shared_ptr<void>> keep_;
  gw::Gateway<GwEnvN<NetT>> gw0_;
  gw::Gateway<GwEnvN<NetT>> gw1_;
  md::MdStage<MdEnvN<NetT>> md_;
  std::optional<md::GlimpseServer<GwEnvN<GlimpseNetT>>> glimpse_;
  std::uint64_t published_hist_[8] = {};
};

template <net::BackendKind K>
using NetStages = NetStagesT<net::Stack<K>>;

// The stages for the configured variant (node.backend and, for xsk, [xsk]), or an error
// if it is not compiled into this build or its AF_XDP setup fails.
std::expected<std::unique_ptr<NetStagesBase>, std::string> make_net_stages(
    const ExchangeConfig& cfg, const gw::GatewayConfig gw_cfg[md::kGateways], const gw::SessionTable& table,
    std::span<const std::pair<std::uint32_t, SeqNo>> soup_next, const md::MdConfig& md_cfg,
    const md::GlimpseConfig* glimpse_cfg, Shared& sh, NodeClock& clock);

// True if this build has the AF_XDP variant (Linux with libbpf).
[[nodiscard]] bool xsk_compiled() noexcept;

}  // namespace lle::exch
