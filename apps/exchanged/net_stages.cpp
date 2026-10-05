#include "exchanged/net_stages.h"

#if defined(LLE_EXCHANGED_HAVE_XSK)
#include "exchanged/xsk_net.h"
#endif

namespace lle::exch {

bool xsk_compiled() noexcept {
#if defined(LLE_EXCHANGED_HAVE_XSK)
  return true;
#else
  return false;
#endif
}

namespace {

#if defined(LLE_EXCHANGED_HAVE_XSK)
// Variant (iv): the gateways and md on AF_XDP, each on its own (interface, queue); the
// GLIMPSE server on kernel sockets (epoll).
std::expected<std::unique_ptr<NetStagesBase>, std::string> make_xsk_stages(
    const ExchangeConfig& cfg, const gw::GatewayConfig gw_cfg[md::kGateways], const gw::SessionTable& table,
    std::span<const std::pair<std::uint32_t, SeqNo>> soup_next, const md::MdConfig& md_cfg,
    const md::GlimpseConfig* glimpse_cfg, Shared& sh, NodeClock& clock) {
  auto domain = XskDomain::create(cfg.xsk);
  if (!domain) return std::unexpected(domain.error());
  std::shared_ptr<XskDomain> d(std::move(*domain));
  XskStageNet places[3];
  const XskStage* st[3] = {&cfg.xsk.gw[0], &cfg.xsk.gw[1], &cfg.xsk.md};
  for (int i = 0; i < 3; ++i) {
    auto n = d->stage(*st[i]);
    if (!n) return std::unexpected(n.error());
    places[i] = *n;
  }
  if (md_cfg.rerequest_udp.bind.port == 0) return std::unexpected(std::string("xsk: md.rerequest needs a fixed port"));
  places[2].udp_source_port = cfg.xsk.md_source_port != 0 ? cfg.xsk.md_source_port : md_cfg.rerequest_udp.bind.port;
  auto stages = std::make_unique<NetStagesT<XskNet, net::Stack<net::BackendKind::Epoll>>>(gw_cfg, table, soup_next,
                                                                                            md_cfg, glimpse_cfg, sh, clock);
  stages->keep(d);
  stages->gw_net(0).configure(d.get(), places[0]);
  stages->gw_net(1).configure(d.get(), places[1]);
  stages->md_net().configure(d.get(), places[2]);
  return std::unique_ptr<NetStagesBase>(std::move(stages));
}
#endif

}  // namespace

std::expected<std::unique_ptr<NetStagesBase>, std::string> make_net_stages(
    const ExchangeConfig& cfg, const gw::GatewayConfig gw_cfg[md::kGateways], const gw::SessionTable& table,
    std::span<const std::pair<std::uint32_t, SeqNo>> soup_next, const md::MdConfig& md_cfg,
    const md::GlimpseConfig* glimpse_cfg, Shared& sh, NodeClock& clock) {
  if (cfg.backend == net::BackendKind::Xsk) {
#if defined(LLE_EXCHANGED_HAVE_XSK)
    return make_xsk_stages(cfg, gw_cfg, table, soup_next, md_cfg, glimpse_cfg, sh, clock);
#else
    return std::unexpected(std::string("backend xsk is not compiled into this build (Linux with libbpf)"));
#endif
  }
  std::unique_ptr<NetStagesBase> out;
  const bool ok = net::with_backend(cfg.backend, [&]<net::BackendKind K>() {
    out = std::make_unique<NetStages<K>>(gw_cfg, table, soup_next, md_cfg, glimpse_cfg, sh, clock);
  });
  if (!ok || !out) return std::unexpected(std::string("backend ") + net::to_string(cfg.backend) + " is not compiled into this build");
  return out;
}

}  // namespace lle::exch
