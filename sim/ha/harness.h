#pragma once
// Shared state of the ha world that lives outside every process image: the data
// nodes' persistent media (journal, L2 storage), the ground truth the oracles check
// against, and the TLA+ trace recorder. Nothing here is visible to the production
// code under test; processes report into it through taps.
#include <array>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "common/prng.h"
#include "common/types.h"
#include "journal/record.h"
#include "journal/segment_dir.h"
#include "repl/types.h"
#include "sim/oracles/registry.h"
#include "sim/world.h"

namespace lle::sim::ha {

inline constexpr NodeId kA = 0;
inline constexpr NodeId kB = 1;
inline constexpr NodeId kW = 2;
inline constexpr NodeId kC = 3;
inline constexpr std::uint16_t kDataPort = 7000;
inline constexpr std::uint16_t kCtlPort = 7001;
inline constexpr std::uint16_t kClientPort = 7100;
inline constexpr std::uint16_t kWitnessPort = 7300;
inline constexpr std::uint32_t kDay = 20260930;
inline constexpr std::uint64_t kBuildId = 0x4C4C452D48410001ull;
inline constexpr std::uint64_t kSegmentBytes = 4096 + 256 * 1024;
inline constexpr std::size_t kL2Bytes = std::size_t{1} << 20;

using Bytes = std::vector<std::byte>;

// What survives a process crash of a data node (its disk and its hugetlbfs L2 file).
struct NodeStore {
  journal::MemSegmentDir dir;  // L3 segments
  std::unique_ptr<std::byte[]> l2;
  std::uint64_t l2_nonce = 0;
  Prng nonce_rng{1};  // segment and L2 nonces
  // Harness mirror of the node's log (L3 + L2), canonical records. Reconciled with
  // what recovery actually finds at every restart; used for log_read/catch-up.
  std::vector<Bytes> history;
  std::uint64_t boots = 0;
  bool host_crashed = false;  // since the last boot
};

[[nodiscard]] inline journal::RecordView view(const Bytes& b) { return journal::RecordView{std::span<const std::byte>(b)}; }
[[nodiscard]] inline std::uint32_t crc_of(const Bytes& b) { return view(b).crc(); }

// One NDJSON line per protocol event (verify/tla/trace/README.md).
class TlaTrace {
 public:
  void set(std::FILE* f) noexcept { f_ = f; }
  [[nodiscard]] bool on() const noexcept { return f_ != nullptr; }
  [[nodiscard]] std::uint64_t lines() const noexcept { return lines_; }
  template <class... KV>
  void emit(Nanos t, const char* ev, KV... kv) {
    if (f_ == nullptr) return;
    std::string s = "{\"t\":" + std::to_string(t) + ",\"ev\":\"" + ev + "\"";
    add(s, kv...);
    s += "}\n";
    std::fputs(s.c_str(), f_);
    ++lines_;
  }

 private:
  static void add(std::string&) {}
  template <class V, class... KV>
  static void add(std::string& s, const char* k, V v, KV... rest) {
    s += ",\"";
    s += k;
    s += "\":";
    if constexpr (std::is_same_v<V, const char*>) {
      s += "\"";
      s += v;
      s += "\"";
    } else if constexpr (std::is_same_v<V, std::string>) {
      s += "\"" + v + "\"";
    } else {
      s += std::to_string(v);
    }
    add(s, rest...);
  }
  std::FILE* f_ = nullptr;
  std::uint64_t lines_ = 0;
};

class HaNode;
struct WitnessProc;

struct Truth {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_prefix = 0;
  OracleId o_lost = 0;
  OracleId o_once = 0;
  OracleId o_commit = 0;
  OracleId o_one = 0;
  OracleId o_replay = 0;
  OracleId o_internal = 0;
  bool verbose = false;
  TlaTrace tla;

  std::array<NodeStore, 2> store;
  std::array<HaNode*, 2> node{};  // live process images (nullptr while down)
  WitnessProc* witness = nullptr;
  std::uint64_t witness_epoch_seen = 0;

  // Ground truth for the Output Rule and leader completeness.
  std::vector<std::uint32_t> released;                     // released[i - 1] = crc of the record released at i
  std::vector<std::uint64_t> released_epoch;               // the epoch of the primary that first released i
  std::map<std::uint64_t, NodeId> primary_of_epoch;        // epoch -> the node that became primary in it
  std::array<std::set<std::pair<std::uint64_t, std::uint32_t>>, 2> ever_held;  // (index, crc) ever in a node's log
  std::array<std::uint64_t, 2> l3_max{};                   // durable index reported by each node's writer

  // Clients: what any client received for (session, seq), first seen.
  std::map<std::uint32_t, std::map<std::uint64_t, Bytes>> seen;

  // A JOIN a solo primary relayed: the witness may still grant it (failure-model gating
  // must then hold for the paired configuration too).
  struct PendingJoin {
    bool valid = false;
    std::uint64_t epoch = 0;
    NodeId primary = 0;
    std::uint64_t joiner_inc = 0;
    std::uint64_t primary_inc = 0;  // the relaying process: the grant pairs W with it
  } pending_join;

  // The failure-model gate (01 §9): may node n fail now (crash, or abort on a disk error)?
  std::function<bool(NodeId, bool host)> may_fail;

  // Counters.
  std::uint64_t takeovers = 0;
  std::uint64_t solos = 0;
  std::uint64_t resumes = 0;
  std::uint64_t joins = 0;
  std::uint64_t deposed = 0;
  std::uint64_t truncations = 0;
  std::uint64_t crashes = 0;
  std::uint64_t host_crashes = 0;
  std::uint64_t crashes_gated = 0;
  std::uint64_t alarms = 0;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    if constexpr (sizeof...(A) == 0) {
      std::fputs(fmt, stderr);
    } else {
      std::fprintf(stderr, fmt, a...);
    }
    std::fputc('\n', stderr);
  }

  void fail(OracleId id, const std::string& msg) {
    log("ORACLE FAILURE: %s", msg.c_str());
    o->fail(id, msg);
  }

  // A node's log grew by one record (sequenced, replicated or caught up).
  void on_hold(NodeId n, std::uint64_t index, std::uint32_t crc) { ever_held[n].emplace(index, crc); }

  // A primary role's release watermark advanced to w (Output Rule ground truth).
  void on_release(NodeId n, std::uint64_t from, std::uint64_t upto, bool solo, std::uint64_t epoch,
                  std::uint64_t durable);
  // A node became primary of `epoch` (its EpochStart is in the log).
  void on_primary(NodeId n, std::uint64_t epoch);
};

}  // namespace lle::sim::ha
