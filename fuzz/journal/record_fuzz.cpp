// Fuzz target for the journal record parser (06 §3: "A fuzz target covers the record
// parser"). On arbitrary bytes, parse_record, every payload decoder and the sealer
// must never crash or read out of bounds; whatever decodes must re-encode to exactly
// the same bytes (the canonical-form rule), and a record must still verify after being
// re-sealed for another medium.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <vector>

#include "fuzz_seeds.h"
#include "journal/record.h"

namespace {

using namespace lle::journal;

// Reports the failed invariant before aborting (the driver saves the input).
#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      std::fprintf(stderr, "%s:%d: invariant failed: %s\n", __FILE__, __LINE__, #cond); \
      std::abort();                                                          \
    }                                                                        \
  } while (0)

const Sealer& sealer() {
  static const Sealer s(0x1122334455667788ull);
  return s;
}
const Sealer& other() {
  static const Sealer s(0x8877665544332211ull);
  return s;
}

// Re-encodes `p` with the header of `v` and compares with the original bytes.
template <class P>
void roundtrip(const RecordView& v, const P& p) {
  CHECK(record_size(p) == v.len());
  std::vector<std::byte> out(v.len());
  const RecordHeader h = v.header();
  (void)build_record(out.data(), Stamp{h.index, h.ts_ns, h.epoch, h.prev_crc, h.flags}, p, sealer());
  // The header's reserved field is not produced by the builder; compare the rest.
  lle::store_le32(out.data() + hdr::kReserved, h.reserved);
  lle::store_le32(out.data() + hdr::kCrc, h.crc32c);
  CHECK(std::memcmp(out.data(), v.data(), v.len()) == 0);
}

template <class D>
void try_decode(const RecordView& v, D decode) {
  const auto d = decode(v);
  if (d) roundtrip(v, *d);
}

void build_seeds(lle::fuzz::Seeds& out) {
  const auto add = [&](const PayloadLike auto& p) {
    std::vector<std::byte> b(record_size(p));
    (void)build_record(b.data(), Stamp{42, 1'790'000'000'000'000'000, 3, 0xABCDEF01u, 0}, p, sealer());
    std::vector<std::uint8_t> u(b.size());
    std::memcpy(u.data(), b.data(), b.size());
    out.push_back(std::move(u));
  };
  static constexpr std::byte kBytes[64] = {std::byte{'E'}, std::byte{'n'}, std::byte{'t'}, std::byte{'e'}};
  DayStart ds;
  ds.trading_date = 20260930;
  add(ds);
  add(ConfigChunk{ConfigTable::Symbols, 0, 2, 100, std::span<const std::byte>(kBytes).first(50)});
  add(SessionEvent{7, 1, SessionEventKind::Disconnect, 99});
  add(OuchInbound{1, 2, 3, std::span<const std::byte>(kBytes).first(47)});
  add(Timer{5, TimerKind::Cross, 34'200'000'000'000});
  add(Admin{1, 1, 9, std::span<const std::byte>(kBytes).first(13)});
  add(SnapshotMark{3});
  add(EpochStart{2, 1, 77});
  add(DayEnd{100, 200, 300});
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> in(reinterpret_cast<const std::byte*>(data), size);
  const auto v = parse_record(in);
  if (!v) return 0;
  CHECK(v->len() <= size && v->len() % kRecordAlign == 0 && v->len() >= kHeaderBytes);
  // Seal checks never read outside the record; a record sealed for one medium
  // verifies after being re-sealed for another, and its content crc is preserved.
  std::vector<std::byte> copy(v->bytes().begin(), v->bytes().end());
  const std::uint32_t content = sealer().seal(copy.data());
  CHECK(sealer().verify(copy.data()) == std::optional<std::uint32_t>(content));
  CHECK(other().reseal(copy.data(), sealer()) == content);
  CHECK(other().verify(copy.data()) == std::optional<std::uint32_t>(content));
  CHECK(content == v->content());
  CHECK(same_content(*v, RecordView(copy)));
  (void)sealer().verify(v->data());

  try_decode(*v, decode_day_start);
  try_decode(*v, decode_config);
  try_decode(*v, decode_session_event);
  try_decode(*v, decode_ouch_inbound);
  try_decode(*v, decode_timer);
  try_decode(*v, decode_admin);
  try_decode(*v, decode_snapshot_mark);
  try_decode(*v, decode_epoch_start);
  try_decode(*v, decode_day_end);
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  return lle::fuzz::serve_seed(index, buf, cap, build_seeds);
}
