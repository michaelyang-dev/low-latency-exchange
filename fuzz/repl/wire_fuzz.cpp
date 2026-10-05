// Replication data-plane fuzz target (10 §2, R-02). The input is a mode byte and a
// sequence of length-prefixed datagrams. Every datagram that decodes must re-encode
// to exactly the same bytes (one canonical form). Every decoded datagram is then fed
// to two replica cores, a backup and a primary of epoch 1, whose host checks that the
// backup's log stays a valid hash chain and that the Output Rule holds. In mode 1 the
// harness recomputes each datagram's CRC first, so mutations reach field validation
// and the state machines instead of dying at the checksum.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "common/assert.h"
#include "common/crc32c.h"
#include "common/endian.h"
#include "journal/record.h"
#include "repl/replica.h"
#include "repl/wire.h"

namespace {

using namespace lle;
using namespace lle::repl;
using Bytes = std::vector<std::byte>;

journal::Sealer& canonical() {
  static journal::Sealer s;
  return s;
}

struct FuzzHost {
  std::vector<Bytes> log;
  std::uint64_t durable = 0;
  std::uint64_t applied = 0;
  std::uint64_t tail_epoch = 1;

  [[nodiscard]] journal::ChainState log_tail() const {
    if (log.empty()) return {};
    const journal::RecordView v{std::span<const std::byte>(log.back())};
    return journal::ChainState{v.index(), v.crc(), v.ts_ns(), v.epoch()};
  }
  [[nodiscard]] std::uint64_t durable_index() const { return durable; }
  [[nodiscard]] std::uint64_t applied_index() const { return applied; }
  bool log_append(std::span<const std::byte> rec) {
    // The core must only append the next record of a valid chain, in canonical form.
    const auto v = journal::parse_record(rec);
    LLE_ASSERT(v.has_value() && v->len() == rec.size(), "appended a malformed record");
    const journal::ChainState t = log_tail();
    LLE_ASSERT(v->index() == t.last_index + 1, "appended out of order");
    LLE_ASSERT(v->prev_crc() == t.last_crc, "appended a record that does not chain");
    LLE_ASSERT(v->crc() == v->content(), "appended a record with a bad seal");
    LLE_ASSERT(v->epoch() >= t.epoch, "epoch went backwards");
    log.emplace_back(rec.begin(), rec.end());
    return log.size() < 4096;
  }
  std::uint32_t log_read(std::uint64_t idx, std::span<std::byte> out) const {
    if (idx == 0 || idx > log.size()) return 0;
    std::memcpy(out.data(), log[idx - 1].data(), log[idx - 1].size());
    return static_cast<std::uint32_t>(log[idx - 1].size());
  }
  EpochEndInfo log_epoch_end(std::uint64_t e) const {
    for (std::size_t i = log.size(); i > 0; --i) {
      const journal::RecordView v{std::span<const std::byte>(log[i - 1])};
      if (v.epoch() <= e) return EpochEndInfo{v.index(), v.crc(), v.epoch()};
    }
    return {};
  }
  EpochEndInfo log_epoch_start(std::uint64_t e) const {
    for (const Bytes& b : log) {
      const journal::RecordView v{std::span<const std::byte>(b)};
      if (v.epoch() == e) return EpochEndInfo{v.index(), v.crc(), v.epoch()};
    }
    return {};
  }
  bool log_truncate(std::uint64_t t) {
    if (t < log.size()) log.resize(t);
    if (durable > t) durable = t;
    return true;
  }
  void request_flush() { durable = log.size(); }
  void reload_state(std::uint64_t t) { applied = t; }
  bool inject_inbound(const wire::Forward& f) {
    // Only canonically decoded inbound reaches the sequencer: known record flags, and
    // none on session events.
    LLE_ASSERT((f.record_flags & ~journal::kFlagMalformedInput) == 0, "unknown record flags injected");
    LLE_ASSERT(f.kind == wire::ForwardKind::kOuch || f.record_flags == 0, "record flags on a session event");
    return !f.bytes.empty() || f.kind == wire::ForwardKind::kSessionEvent;
  }
  void on_role(Role, std::uint64_t) {}
  void instance_down(NodeId) {}
  void deposed() {}
  void alarm(Alarm, std::uint64_t) {}
  void send_peer(std::span<const std::byte> b) {
    // Everything the core sends must decode.
    LLE_ASSERT(wire::decode(b).has_value(), "the core sent an undecodable datagram");
  }
  void send_witness(std::span<const std::byte> b) {
    LLE_ASSERT(witness::decode(b).has_value(), "the core sent an undecodable control datagram");
  }
  [[nodiscard]] Nanos now_real() const { return 1'790'000'000'000'000'000; }
  void trace(const TraceEvent&) {}
  SnapshotOffer snapshot_offer() { return {}; }
  std::uint32_t snapshot_read(std::uint64_t, std::span<std::byte>) { return 0; }
  void snapshot_release() {}
  bool snapshot_receive(std::uint64_t, std::uint64_t, std::uint64_t, std::span<const std::byte>) { return true; }
  bool snapshot_install() { return false; }
};
static_assert(Host<FuzzHost>);

void day_start(FuzzHost& h) {
  journal::RecordBuilder b(canonical(), journal::ChainState{});
  b.set_epoch(1);
  Bytes buf(64);
  const auto r = b.append(std::span<std::byte>(buf), 1, journal::EpochStart{1, 0, 0});
  buf.resize(r.size());
  h.log.push_back(buf);
  h.durable = 1;
}

Config cfg(NodeId self) {
  Config c;
  c.self = self;
  c.build_id = 1;
  c.window_bytes = 64 * 1024;
  c.window_records = 256;
  c.forward_slots = 16;
  return c;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const bool fix_crc = (data[0] & 1) != 0;
  FuzzHost bh, ph;
  day_start(bh);
  day_start(ph);
  Replica<FuzzHost> backup(cfg(1), bh);
  Replica<FuzzHost> primary(cfg(0), ph);
  backup.start_paired(1, 0, 0, 0);
  primary.start_paired(1, 0, 0, 0);
  Nanos now = 0;
  Bytes dg;
  Bytes out(wire::kMaxDatagram);
  std::size_t pos = 1;
  while (pos + 2 <= size) {
    const std::size_t len = load_le16(data + pos) % (wire::kMaxDatagram + 1);
    pos += 2;
    if (pos + len > size) break;
    dg.assign(reinterpret_cast<const std::byte*>(data + pos), reinterpret_cast<const std::byte*>(data + pos + len));
    pos += len;
    if (fix_crc && dg.size() >= wire::kHeaderBytes + wire::kTrailerBytes) {
      const std::size_t n = dg.size() - wire::kTrailerBytes;
      store_le32(dg.data() + n, crc32c(dg.data(), n));
    }
    const auto m = wire::decode(dg);
    if (m) {
      const std::size_t n = wire::encode(*m, out);
      LLE_ASSERT(n == dg.size() && std::memcmp(out.data(), dg.data(), n) == 0, "decode accepted a non-canonical form");
    }
    now += 50'000;
    backup.on_peer(dg, now);
    primary.on_peer(dg, now);
    (void)backup.poll(now);
    (void)primary.poll(now);
    LLE_ASSERT(primary.release_watermark() <= ph.log.size(), "released beyond the log");
    LLE_ASSERT(backup.release_watermark() <= bh.log.size(), "mirror release beyond the log");
    LLE_ASSERT(backup.apply_limit() <= bh.log.size(), "apply limit beyond the log");
  }
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  // A valid APPEND carrying record 2 for the backup, an ACK, a HEARTBEAT and a FORWARD,
  // each length-prefixed, in CRC-fixing mode.
  FuzzHost h;
  day_start(h);
  journal::RecordBuilder b(canonical(), h.log_tail());
  b.set_epoch(1);
  Bytes rec(256);
  const std::byte msg[] = {std::byte{'O'}, std::byte{1}};
  const auto r = b.append(std::span<std::byte>(rec), 10, journal::OuchInbound{1, 2, 3, msg});
  rec.resize(r.size());
  wire::Append a;
  a.from = 0;
  a.epoch = 1;
  a.first_index = 2;
  a.first_len = static_cast<std::uint32_t>(rec.size());
  a.commit_index = 2;
  a.records = rec;
  wire::Heartbeat hb;
  hb.from = 1;
  hb.epoch = 1;
  hb.build_id = 1;
  hb.role = 4;
  hb.members = 3;
  wire::Forward f;
  f.from = 1;
  f.epoch = 1;
  f.seq = 1;
  f.bytes = msg;
  wire::Forward malformed = f;  // a truncated mirror-session packet, flagged by the gateway
  malformed.seq = 2;
  malformed.record_flags = journal::kFlagMalformedInput;
  wire::Heartbeat admitted = hb;  // a backup that W's copy of a JOIN grant admitted
  admitted.admitted = true;
  const wire::Message seeds[][2] = {
      {a, wire::Ack{1, false, 1, 2, 0, 0, 0}},
      {hb, f},
      {wire::Nack{1, false, 1, 2, 0}, wire::EpochEndQuery{1, 1, 0, 1, 1}},
      {admitted, malformed},
  };
  if (index >= std::size(seeds)) return 0;
  std::size_t n = 1;
  if (cap < 1) return 0;
  buf[0] = 1;
  for (const auto& m : seeds[index]) {
    Bytes out(wire::kMaxDatagram);
    const std::size_t len = wire::encode(m, out);
    if (n + 2 + len > cap) return 0;
    store_le16(buf + n, static_cast<std::uint16_t>(len));
    std::memcpy(buf + n + 2, out.data(), len);
    n += 2 + len;
  }
  return n;
}
