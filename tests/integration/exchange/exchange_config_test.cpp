// exchanged's configuration (07 §3 N-03, ADR-028): the file becomes the engine's
// tables (journaled as Config records at day start) and the node's settings; mistakes
// are refused with the line that holds them.
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include "exchanged/config.h"
#include "exchanged/xsk_config.h"
#include "gateway/credentials.h"
#include "md/stream_linger.h"
#include "repl/types.h"
#include "sequencer/engine_day.h"

namespace lle::exch {
namespace {

std::string cred() { return gw::Credential::make("pw", std::vector<std::uint8_t>{1, 2}).text(); }

std::string base() {
  return "[node]\nname = t1\nid = 1\ndata_dir = /tmp/x\nrunner = inline\nbackend = epoll\n"
         "[day]\ndate = 20261005\nclock = manual\nstart = 08:30:00.5\nschedule = early-close\nnoii_clock = false\n"
         "[symbols]\nAAPL prior=150.25 lot=100 tick=0.01 tier=1 adv=1000 regsho=0\nSPY prior=500 etp\n"
         "[accounts]\n100 FRMA,FRMB\n"
         "[sessions]\n7 account=100 user=alpha password=" +
         cred() + " gw=1 flags=cod,market late=reject aiq=N\n"
                  "[risk]\n100 max-order-qty 5000\n"
                  "[params]\nhalt-period 120\n";
}

TEST(ExchangeConfig, ParsesTheDayAndTheNode) {
  auto c = parse_config(base());
  ASSERT_TRUE(c.has_value()) << c.error();
  EXPECT_EQ(c->name, "t1");
  EXPECT_EQ(c->node_id, 1);
  EXPECT_EQ(c->runner, RunnerMode::Inline);
  EXPECT_EQ(c->clock, ClockMode::Manual);
  EXPECT_EQ(c->start, hms_ns(8, 30, 0, 500'000'000));
  ASSERT_EQ(c->symbols.size(), 2u);
  EXPECT_EQ(c->symbols[0].prior_close, 1'502'500);
  EXPECT_EQ(c->symbols[0].tick, 100u);
  EXPECT_EQ(c->symbols[1].flags & engine::SymbolEntry::kFlagEtp, engine::SymbolEntry::kFlagEtp);
  ASSERT_EQ(c->accounts.size(), 1u);
  EXPECT_EQ(c->accounts[0].firms[1], Mpid4("FRMB"));
  ASSERT_EQ(c->sessions.size(), 1u);
  EXPECT_EQ(c->sessions[0].flags, engine::SessionEntry::kCancelOnDisconnect | engine::SessionEntry::kMarketOrders);
  EXPECT_EQ(c->sessions[0].late_cross, engine::LateCrossPolicy::Reject);
  ASSERT_EQ(c->session_specs.size(), 1u);
  EXPECT_EQ(c->session_specs[0].gateway, 1);
  EXPECT_TRUE(c->session_specs[0].credential.verify("PW"));
  EXPECT_TRUE(c->session_specs[0].cancel_on_disconnect);
  ASSERT_EQ(c->risk.size(), 1u);
  EXPECT_EQ(c->risk[0].kind, engine::RiskKind::MaxOrderQty);
  // Early close without the 1 Hz clock: the standard timers plus one parameter entry.
  const auto sched = c->schedule_table();
  EXPECT_EQ(sched.back().arg, static_cast<std::uint16_t>(engine::Param::HaltPeriodSec));
  EXPECT_LT(sched.size(), 1000u);  // NOII and EOII cadences only; the 1 Hz clock adds 57,600
  // Local midnight at UTC-4: 2026-10-05 04:00 UTC.
  EXPECT_EQ(c->local_midnight(), 1'791'172'800'000'000'000);
  EXPECT_EQ(c->journal_dir(), "/tmp/x/journal/20261005");
}

// [ha] retransmission timers: the replication core's defaults unless set (the EPOCH_END
// fix makes a 5 ms rejoin retransmission safe at any round trip).
TEST(ExchangeConfig, HaRetransmissionDefaultsAreTheCoresAndCanBeSet) {
  auto d = parse_config(base());
  ASSERT_TRUE(d.has_value()) << d.error();
  EXPECT_EQ(d->rejoin_retry, repl::Config{}.rejoin_retry_ns);
  EXPECT_EQ(d->ha_rto, repl::Config{}.rto_ns);
  auto c = parse_config(base() + "[ha]\nrto_ms = 20\nrejoin_retry_ms = 7\n");
  ASSERT_TRUE(c.has_value()) << c.error();
  EXPECT_EQ(c->ha_rto, 20'000'000);
  EXPECT_EQ(c->rejoin_retry, 7'000'000);
  const auto z = parse_config(base() + "[ha]\nrto_ms = 0\n");
  ASSERT_FALSE(z.has_value());
  EXPECT_NE(z.error().find("rto_ms"), std::string::npos) << z.error();
}

// The primary takes a backup it has not heard from for T_ack for lost, so a heartbeat
// that is not below T_ack would lose a backup that is fine between two heartbeats.
TEST(ExchangeConfig, TheHaHeartbeatMustBeBelowTAck) {
  auto c = parse_config(base() + "[ha]\nheartbeat_ms = 2\nt_ack_ms = 5\n");
  ASSERT_TRUE(c.has_value()) << c.error();
  for (const char* hb : {"5", "8"}) {
    const auto z = parse_config(base() + "[ha]\nheartbeat_ms = " + hb + "\nt_ack_ms = 5\n");
    ASSERT_FALSE(z.has_value()) << hb;
    EXPECT_NE(z.error().find("heartbeat_ms"), std::string::npos) << z.error();
  }
}

// [gateway] close_linger_ms: how long a closing connection (gateway and GLIMPSE) may take
// to flush its last bytes; md::kDefaultCloseLinger unless set.
TEST(ExchangeConfig, CloseLingerDefaultsToASecondAndCanBeSet) {
  auto d = parse_config(base());
  ASSERT_TRUE(d.has_value()) << d.error();
  EXPECT_EQ(d->close_linger, md::kDefaultCloseLinger);
  auto c = parse_config(base() + "[gateway]\nclose_linger_ms = 25\n");
  ASSERT_TRUE(c.has_value()) << c.error();
  EXPECT_EQ(c->close_linger, 25'000'000);
  const auto z = parse_config(base() + "[gateway]\nclose_linger_ms = 0\n");
  ASSERT_FALSE(z.has_value());
  EXPECT_NE(z.error().find("close_linger_ms"), std::string::npos) << z.error();
}

// The keys a takeover trial needs (T25): the md heartbeat in microseconds (the later of
// heartbeat_ms / heartbeat_us wins) and the witness link's local address (default: the
// kernel's choice, so a dedicated A-B link the witness cannot reach is no obstacle).
TEST(ExchangeConfig, TakeoverTrialKeys) {
  auto d = parse_config(base());
  ASSERT_TRUE(d.has_value()) << d.error();
  EXPECT_EQ(d->md_heartbeat, kNsPerSec);
  EXPECT_EQ(d->witness_bind, 0u);
  auto c = parse_config(base() + "[md]\nheartbeat_ms = 200\nheartbeat_us = 20\n[ha]\nwitness_bind = 10.0.0.1\n");
  ASSERT_TRUE(c.has_value()) << c.error();
  EXPECT_EQ(c->md_heartbeat, 20'000);
  EXPECT_EQ(c->witness_bind, 0x0A000001u);
  auto later = parse_config(base() + "[md]\nheartbeat_us = 20\nheartbeat_ms = 3\n");
  ASSERT_TRUE(later.has_value()) << later.error();
  EXPECT_EQ(later->md_heartbeat, 3'000'000);
  EXPECT_EQ(d->restart_loop_limit, 3u);
  auto lim = parse_config(base() + "[ha]\nrestart_loop_limit = 0\n");
  ASSERT_TRUE(lim.has_value()) << lim.error();
  EXPECT_EQ(lim->restart_loop_limit, 0u);
  for (const char* bad : {"[md]\nheartbeat_us = 0\n", "[ha]\nwitness_bind = 10.0.0\n"}) {
    const auto z = parse_config(base() + bad);
    EXPECT_FALSE(z.has_value()) << bad;
  }
}

// The I/O variants (07 §1, METHODOLOGY §14): every backend from configuration, the
// IRQ-suspend sub-variant as busypoll plus its device setting, and [xsk] placements.
TEST(ExchangeConfig, VariantsAndTheirSettings) {
  for (const char* v : {"epoll", "busypoll", "uring", "uring-napi"}) {
    auto c = parse_config(base() + "[node]\nbackend = " + v + "\n");
    ASSERT_TRUE(c.has_value()) << v << ": " << c.error();
    EXPECT_EQ(c->variant(), v);
    EXPECT_FALSE(c->busypoll_irq_suspend);
  }
  auto s = parse_config(base() + "[node]\nbackend = busypoll-irq-suspend\n[net]\nifname = eth1\ndevice_setup = true\n");
  ASSERT_TRUE(s.has_value()) << s.error();
  EXPECT_EQ(s->backend, net::BackendKind::BusyPoll);
  EXPECT_TRUE(s->busypoll_irq_suspend);
  EXPECT_EQ(s->variant(), "busypoll-irq-suspend");
  EXPECT_EQ(s->net_ifname, "eth1");
  EXPECT_TRUE(s->device_setup);
  const std::string xsk = "[node]\nbackend = xsk\n[xsk]\ngw0 = veth0:1\ngw1 = veth0:2\nmd = veth1\nallow_copy = true\n"
                          "next_hop_mac = 02:00:5e:10:00:0a\nlocal_ip = 10.89.0.1\numem_frames = 4096\n"
                          "[control]\nbind = 10.89.0.1\n[admin]\nbind = 10.89.0.1\n";
  auto x = parse_config(base() + xsk);
  ASSERT_TRUE(x.has_value()) << x.error();
  EXPECT_EQ(x->variant(), "xsk");
  EXPECT_EQ(x->xsk.gw[0].ifname, "veth0");
  EXPECT_EQ(x->xsk.gw[0].queue, 1u);
  EXPECT_EQ(x->xsk.gw[1].queue, 2u);
  EXPECT_EQ(x->xsk.md.ifname, "veth1");
  EXPECT_EQ(x->xsk.md.queue, 0u);
  EXPECT_TRUE(x->xsk.allow_copy);
  ASSERT_TRUE(x->xsk.next_hop_mac.has_value());
  EXPECT_EQ((*x->xsk.next_hop_mac)[0], 0x02);
  EXPECT_EQ((*x->xsk.next_hop_mac)[5], 0x0a);
  EXPECT_EQ(x->xsk.local_ip, 0x0A59'0001u);
  EXPECT_EQ(x->control_bind, 0x0A59'0001u);
  EXPECT_EQ(x->admin_bind, 0x0A59'0001u);
  EXPECT_EQ(x->xsk.umem_frames, 4096u);
  auto bad = [](const std::string& text) {
    const auto c = parse_config(text);
    EXPECT_FALSE(c.has_value());
    return c.has_value() ? std::string() : c.error();
  };
  EXPECT_NE(bad(base() + "[node]\nbackend = xsk\n").find("needs [xsk] gw0, gw1 and md"), std::string::npos);
  EXPECT_NE(bad(base() + "[node]\nbackend = xsk\n[xsk]\ngw0 = v:1\ngw1 = v:1\nmd = v:3\n").find("distinct queues"),
            std::string::npos);
  EXPECT_NE(bad(base() + "[xsk]\nnext_hop_mac = 02:00\n").find("next_hop_mac"), std::string::npos);
  EXPECT_NE(bad(base() + "[control]\nbind = localhost\n").find("control.bind"), std::string::npos);
  EXPECT_NE(bad(base() + "[node]\nbackend = dpdk\n").find("node.backend"), std::string::npos);
}

// utcp's RFC 6528 ISN key on the production path comes from the OS CSPRNG at every start;
// the built-in constant stays for utcp's tests and the simulator.
TEST(ExchangeConfig, ProductionUtcpIsnKeyIsNotTheBuiltInConstant) {
  const std::uint64_t builtin = net::utcp::StackConfig{}.isn_secret;
  XskSettings x;
  const net::utcp::MacAddr mac{{0x02, 0, 0, 0, 0, 1}};
  const auto a = gateway_stack_config(x, net::TcpConfig{}, mac, 0x0A59'0001u, 0xFFFF'FF00u);
  const auto b = gateway_stack_config(x, net::TcpConfig{}, mac, 0x0A59'0001u, 0xFFFF'FF00u);
  EXPECT_NE(a.isn_secret, builtin);
  EXPECT_NE(b.isn_secret, builtin);
  EXPECT_NE(a.isn_secret, b.isn_secret) << "a fresh key per start (64 random bits)";
  // The rest of the server stack: the kernel answers ARP; a passive open replies to the
  // SYN's source MAC unless a static next hop is configured.
  EXPECT_FALSE(a.arp_reply);
  EXPECT_FALSE(a.static_next_hop.has_value());
  x.next_hop_mac = std::array<std::uint8_t, 6>{2, 0, 0, 0, 0, 9};
  const auto c = gateway_stack_config(x, net::TcpConfig{}, mac, 1, 0xFFFF'FF00u);
  ASSERT_TRUE(c.static_next_hop.has_value());
  EXPECT_EQ(c.static_next_hop->b[5], 9);
}

// lab/exchanged/variants: one configuration per variant, identical outside the variant
// block (so the pinning, queues and workload are the same), each parsing to its variant.
TEST(ExchangeConfig, OneConfigurationPerVariantWithIdenticalPinning) {
  const std::filesystem::path dir = std::filesystem::path(LLE_SOURCE_DIR) / "lab/exchanged/variants";
  const std::map<std::string, std::string> want = {{"epoll", "epoll"},
                                                   {"busypoll", "busypoll"},
                                                   {"busypoll-irq-suspend", "busypoll-irq-suspend"},
                                                   {"uring", "uring"},
                                                   {"uring-napi", "uring-napi"},
                                                   {"xsk", "xsk"}};
  std::string common;
  rt::CoreMap cores;
  bool first = true;
  for (const auto& [file, variant] : want) {
    std::ifstream in(dir / (file + ".conf"));
    ASSERT_TRUE(in) << file;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();
    auto c = parse_config(text);
    ASSERT_TRUE(c.has_value()) << file << ": " << c.error();
    EXPECT_EQ(c->variant(), variant) << file;
    // Outside the title line and the variant block, the files are byte-identical.
    const auto title_end = text.find('\n');
    const auto block = text.find("# --- variant");
    ASSERT_NE(block, std::string::npos) << file;
    const std::string rest = text.substr(title_end, block - title_end) + text.substr(text.find("# --- end of variant ---"));
    if (first) {
      common = rest;
      cores = c->cores;
      first = false;
    } else {
      EXPECT_EQ(rest, common) << file << " differs from the others outside its variant block";
      for (const char* stage : {"gw0", "gw1", "seq", "engine", "md", "io", "glimpse"})
        EXPECT_EQ(c->cores.cpu_for(stage), cores.cpu_for(stage)) << file << " " << stage;
    }
  }
}

TEST(ExchangeConfig, CoreMapAndEndpoints) {
  auto c = parse_config(base() + "[cores]\ngw0 = 8 gw1=9\nseq = 10  # comment\n[gateway]\ngw0 = 0.0.0.0:15000\n");
  ASSERT_TRUE(c.has_value()) << c.error();
  EXPECT_EQ(c->cores.cpu_for("gw0"), 8);
  EXPECT_EQ(c->cores.cpu_for("gw1"), 9);
  EXPECT_EQ(c->cores.cpu_for("seq"), 10);
  EXPECT_FALSE(c->cores.cpu_for("md").has_value());
  EXPECT_EQ(c->gw[0].port, 15000);
  EXPECT_EQ(c->gw[0].ipv4, 0u);
  EXPECT_FALSE(parse_config(base() + "[cores]\ngw0 = x\n").has_value());
}

TEST(ExchangeConfig, TheExampleFileParses) {
  auto c = load_config(std::string(LLE_SOURCE_DIR) + "/apps/exchanged/exchanged.example.conf");
  ASSERT_TRUE(c.has_value()) << c.error();
  EXPECT_EQ(c->session_specs.size(), 2u);
  EXPECT_TRUE(c->session_specs[0].credential.verify("alpha-pw"));
  EXPECT_TRUE(c->glimpse_credential.verify("glimpse-pw"));
  EXPECT_EQ(c->cores.size(), 7u);
}

TEST(ExchangeConfig, TheTablesAreWhatTheSequencerJournals) {
  auto c = parse_config(base());
  ASSERT_TRUE(c.has_value());
  const auto sched = c->schedule_table();
  const seq::EngineDay day(seq::EngineTables{c->symbols, c->accounts, c->sessions, c->risk, sched}, c->local_midnight());
  ASSERT_EQ(day.config().size(), 5u);  // Symbols, Accounts, Sessions, RiskLimits, Schedule
  EXPECT_EQ(day.config()[0].table, journal::ConfigTable::Symbols);
  EXPECT_EQ(day.config()[4].table, journal::ConfigTable::Schedule);
  EXPECT_FALSE(day.timers().empty());
}

TEST(ExchangeConfig, RefusesMistakesWithTheirLine) {
  auto bad = [](const std::string& text) {
    auto c = parse_config(text);
    EXPECT_FALSE(c.has_value());
    return c.has_value() ? std::string() : c.error();
  };
  EXPECT_NE(bad(base() + "[node]\nunknown = 1\n").find("unknown key node.unknown"), std::string::npos);
  EXPECT_NE(bad(base() + "[day]\nclock = sometimes\n").find("day.clock"), std::string::npos);
  EXPECT_NE(bad(base() + "[md]\nmax_packet_b = 60\n").find("out of range"), std::string::npos);
  EXPECT_NE(bad(base() + "[sessions]\n8 account=999 user=b password=" + cred() + "\n").find("unknown account"),
            std::string::npos);
  EXPECT_NE(bad(base() + "[sessions]\n9 account=100 user=c password=plain\n").find("sha256$"), std::string::npos);
  EXPECT_NE(bad("[node]\nname = x\n").find("no [symbols]"), std::string::npos);
  EXPECT_NE(bad(base() + "[node]\nmode = paired\n").find("paired mode needs"), std::string::npos);
  EXPECT_NE(bad(base() + "[ha]\nt_d_ms = 10\nt_ack_ms = 20\n").find("t_ack_ms"), std::string::npos);
  EXPECT_NE(bad(base() + "[journal]\nl2_mib = 3\n").find("power of two"), std::string::npos);
}

}  // namespace
}  // namespace lle::exch
