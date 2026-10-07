#pragma once
// exchanged configuration (07 §3 N-03, ADR-028). One text file describes the node
// (identity, data directory, runner and core map, network backend, ports, HA peer
// and witness) and the trading day (symbols, accounts and firms, sessions with
// salted credentials, risk limits, schedule parameters). The day part becomes the
// engine's tables, which the sequencer journals as Config records at day start: the
// engine never reads this file. Format: docs/design/exchange-node.md.
//
//   # comment
//   [section]             key/value sections: "key = value"
//   [symbols]             table sections: one entry per line, words and key=value options
//
// Cold path only.
#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "common/types.h"
#include "engine/records.h"
#include "env/concepts.h"
#include "gateway/session_table.h"
#include "net/common/port.h"
#include "runtime/launcher.h"

namespace lle::exch {

enum class ClockMode : std::uint8_t {
  Real,    // exchange time = CLOCK_REALTIME (production)
  Offset,  // CLOCK_REALTIME shifted so the process starts at `day.start` (demos)
  Manual,  // advanced only by the control port's `clock` command (tests: deterministic journals)
};
enum class RunnerMode : std::uint8_t { Threads, Inline };
enum class NodeMode : std::uint8_t { Solo, Paired };

struct Operator {
  std::uint32_t id = 0;
  std::vector<std::uint8_t> key;
};

// AF_XDP placement of one stage: its interface and NIC queue (07 §2.3). Production
// steers each stage's traffic to its queue with ethtool ntuple rules (lab/tune.sh).
struct XskStage {
  std::string ifname;
  std::uint32_t queue = 0;
  [[nodiscard]] bool set() const noexcept { return !ifname.empty(); }
};

// [xsk]: variant (iv), AF_XDP with utcp for the gateways and AF_XDP for market data.
struct XskSettings {
  XskStage gw[2];
  XskStage md;
  bool allow_copy = false;      // dev/test override (veth, virtio): accept copy mode; never for measurements
  bool skb_mode = false;        // dev/test: generic XDP if native attach fails
  std::string bpf_object;       // md_steer.bpf.o; empty: the build's
  bool busy_poll = true;        // socket busy polling (SO_PREFER_BUSY_POLL, needs CAP_NET_ADMIN)
  std::uint32_t umem_frames = 8192;
  std::uint32_t local_ip = 0;   // host order; 0: the interface's first IPv4 address
  std::optional<std::array<std::uint8_t, 6>> next_hop_mac;  // static next hop (direct cable)
  std::uint16_t md_source_port = 0;  // source port of the lines; 0: the re-request port
  bool checksum_offload = false;     // XDP_TXMD_FLAGS_CHECKSUM (mlx5 >= 6.8)
};

struct ExchangeConfig {
  // [node]
  std::string name = "lle";
  std::uint8_t node_id = 0;
  std::string data_dir = ".";
  NodeMode mode = NodeMode::Solo;
  RunnerMode runner = RunnerMode::Threads;
  // The I/O variant (07 §1, METHODOLOGY §14): one backend for the gateways and market
  // data, the same pinning for every variant. busypoll-irq-suspend is busypoll with the
  // IRQ-suspend device setting (a labelled sub-variant).
  net::BackendKind backend = net::BackendKind::Epoll;
  bool busypoll_irq_suspend = false;
  std::uint32_t idle_sleep_us = 50;  // inline runner: sleep after a run of idle passes
  std::uint64_t build_id = 0;        // 0: the binary's own
  bool metrics = true;
  bool nlog = true;
  rt::CoreMap cores;                 // [cores]

  // [day]
  std::uint32_t date = 20261001;
  std::string mold_session = "LLE0000001";
  std::string soup_session = "LLE0000001";
  std::string schedule = "standard";  // standard | early-close | none
  bool noii_clock = true;
  int utc_offset_hours = -4;
  ClockMode clock = ClockMode::Real;
  Nanos start = 0;  // ns since local midnight: offset / manual clock start
  bool auto_end = false;

  // [journal]
  std::uint64_t segment_bytes = std::uint64_t{64} << 20;
  std::size_t spares = 2;
  std::size_t l2_bytes = std::size_t{64} << 20;
  std::string l2_path;  // empty: anonymous memory
  std::size_t l2_page_bytes = 4096;  // L2 file control block: 4 KiB, or the huge-page size on hugetlbfs
  bool journal_io_uring = true;
  bool journal_iopoll = false;  // [journal] iopoll: IORING_SETUP_IOPOLL (NVMe with polled queues only)
  std::string snapshots;       // snapshotd's directory for the day (empty: <data>/snapshots/<date>)
  bool use_snapshots = true;   // recovery starts from the newest usable snapshot (06 §7 step 4)  // [journal] device = io_uring (POSIX fallback per segment) | posix
  std::uint64_t snapshot_every = 0;

  // [gateway]
  env::Endpoint gw[2] = {{0x7F000001u, 15000}, {0x7F000001u, 15001}};
  Nanos soup_heartbeat = kNsPerSec;
  Nanos soup_idle_timeout = 15 * kNsPerSec;
  Nanos soup_login_timeout = 30 * kNsPerSec;
  Nanos close_linger = kNsPerSec;  // a closing connection's flush bound (md::kDefaultCloseLinger)
  std::uint32_t max_conns = 64;
  std::size_t replay_ring_msgs = std::size_t{1} << 16;
  std::size_t replay_ring_bytes = std::size_t{8} << 20;

  // [md]
  env::Endpoint line_a{0x7F000001u, 30001};
  env::Endpoint line_b{0x7F000001u, 30002};
  env::Endpoint rerequest{0x7F000001u, 30003};
  std::size_t max_packet_a = 1472;
  std::size_t max_packet_b = 1000;
  Nanos md_heartbeat = kNsPerSec;
  Nanos md_eos_linger = 30 * kNsPerSec;
  std::string multicast_if;
  int ttl = 1;
  bool multicast_loop = false;

  // [glimpse]
  std::optional<env::Endpoint> glimpse;
  std::string glimpse_user = "GLIMPS";
  gw::Credential glimpse_credential;

  // [net]: the NIC port the variant's device settings apply to (busy-poll knobs), and
  // whether this process applies them (root) or only checks them.
  std::string net_ifname;
  bool device_setup = false;
  // [xsk]
  XskSettings xsk;

  // [admin], [control]
  int admin_port = -1;  // -1: off; 0: ephemeral
  std::uint32_t admin_bind = 0x7F000001u;  // host order; 127.0.0.1 unless a test sets another
  std::vector<Operator> operators;
  int control_port = -1;  // -1: off; 0: ephemeral; dev and test only
  std::uint32_t control_bind = 0x7F000001u;

  // [ha]
  env::Endpoint ha_bind{};
  env::Endpoint ha_peer{};
  env::Endpoint witness{};
  // The witness link's local address: 0 (default) lets the kernel pick the source by its
  // route to the witness. Binding it to ha.bind's address fails where the A-B link is a
  // network of its own that the witness cannot reach (the lab's F6 link).
  std::uint32_t witness_bind = 0;
  std::uint8_t initial_primary = 0;
  Nanos ha_heartbeat = 1'000'000;
  Nanos t_d = 50'000'000;
  Nanos t_ack = 25'000'000;
  // Rejoin handshake retransmission (EPOCH_END_QUERY, CATCHUP_REQ): the core's default
  // (repl::Config::rejoin_retry_ns). Retransmissions keep their query id and an answer to
  // any copy of the current question is accepted, so a round trip longer than this costs
  // retransmissions only.
  Nanos rejoin_retry = 5'000'000;
  // APPEND retransmission without ACK progress (repl::Config::rto_ns). Go-back-N: keep it
  // above the real A-B round trip, or every round trip retransmits the window.
  Nanos ha_rto = 2'000'000;
  // Starts from the same journal that each exited 5 at the same point before a start is
  // refused (restart_guard.h); 0: never.
  std::uint32_t restart_loop_limit = 3;
  std::size_t repl_log_bytes = std::size_t{256} << 20;
  bool repl_thread = false;  // the replica on its own thread ([ha] repl_thread, or a `repl` core-map entry)

  // The day's tables.
  std::vector<engine::SymbolEntry> symbols;
  std::vector<engine::AccountEntry> accounts;
  std::vector<engine::SessionEntry> sessions;
  std::vector<gw::SessionSpec> session_specs;  // credentials, gateway placement
  std::vector<engine::RiskEntry> risk;
  std::vector<engine::ScheduleEntry> params;   // schedule parameter entries

  // The variant's name: epoll, busypoll, busypoll-irq-suspend, uring, uring-napi, xsk.
  [[nodiscard]] std::string variant() const;

  // Derived paths.
  [[nodiscard]] std::string journal_dir() const;  // <data>/journal/<date>
  [[nodiscard]] std::string outlog_root() const;  // <data>/outlog
  [[nodiscard]] std::string snapshots_dir() const;  // [journal] snapshots, or <data>/snapshots/<date>
  [[nodiscard]] std::string log_path() const;     // <data>/logs/<name>-<date>.nlog
  [[nodiscard]] Nanos local_midnight() const;     // UNIX ns of local midnight of `date`
  // The engine Schedule table: the standard schedule (or none) plus the parameters.
  [[nodiscard]] std::vector<engine::ScheduleEntry> schedule_table() const;
};

[[nodiscard]] std::expected<ExchangeConfig, std::string> parse_config(const std::string& text);
[[nodiscard]] std::expected<ExchangeConfig, std::string> load_config(const std::string& path);

// UNIX ns of local midnight for YYYYMMDD at a fixed UTC offset (hours).
[[nodiscard]] Nanos local_midnight(std::uint32_t date, int utc_offset_hours);
// "HH:MM:SS[.fraction]" -> ns since midnight.
[[nodiscard]] std::expected<Nanos, std::string> parse_time_of_day(std::string_view s);

}  // namespace lle::exch
