// Fuzz target for the snapshot loader (06 §9: "A fuzz target covers the
// loader"). Reader::open must never crash, assert, overflow or read out of
// bounds. For every image it accepts, the harness also checks:
//   - the payload cursor stays in bounds and typed reads equal the little-endian
//     bytes of the payload, across chunk boundaries;
//   - reading past the end fails;
//   - the format is canonical: re-encoding meta + sessions + payload with the
//     same chunk size reproduces the input byte for byte.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

#include "common/endian.h"
#include "common/prng.h"
#include "fuzz_seeds.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshot/writer.h"

namespace {

void check(bool cond) {
  if (!cond) std::abort();
}

std::vector<std::byte> seed_payload(std::size_t n, std::uint64_t seed) {
  lle::Prng rng(seed);
  std::vector<std::byte> v(n);
  for (auto& b : v) b = static_cast<std::byte>(rng.next_u64());
  return v;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lle::snap;
  const std::span<const std::byte> image = std::as_bytes(std::span<const std::uint8_t>(data, size));
  auto r = Reader::open(image);
  if (!r) return 0;

  check(r->layout().file_bytes == size);
  check(sessions_canonical(r->sessions()));
  check(r->sessions().size() == r->layout().session_count);

  Reader walker = *r;  // independent cursor over the same image
  std::vector<std::byte> payload(static_cast<std::size_t>(r->remaining()));
  check(r->read(payload));
  check(r->remaining() == 0);
  check(!r->skip(1));
  check(r->get_u8() == 0 && !r->ok());

  std::size_t pos = 0;
  for (std::uint64_t step = 0; walker.ok() && walker.remaining() > 0; ++step) {
    const std::size_t left = payload.size() - pos;
    switch (step % 5) {
      case 0: {
        const std::uint8_t v = walker.get_u8();
        if (walker.ok()) check(v == std::to_integer<std::uint8_t>(payload[pos]));
        if (walker.ok()) pos += 1;
        break;
      }
      case 1: {
        const std::uint16_t v = walker.get_u16();
        if (walker.ok()) check(v == lle::load_le16(payload.data() + pos));
        else check(left < 2 && v == 0);
        if (walker.ok()) pos += 2;
        break;
      }
      case 2: {
        const std::uint32_t v = walker.get_u32();
        if (walker.ok()) check(v == lle::load_le32(payload.data() + pos));
        else check(left < 4 && v == 0);
        if (walker.ok()) pos += 4;
        break;
      }
      case 3: {
        const std::uint64_t v = walker.get_u64();
        if (walker.ok()) check(v == lle::load_le64(payload.data() + pos));
        else check(left < 8 && v == 0);
        if (walker.ok()) pos += 8;
        break;
      }
      default: {
        std::byte buf[13];
        if (walker.read(buf)) {
          check(std::memcmp(buf, payload.data() + pos, sizeof(buf)) == 0);
          pos += sizeof(buf);
        } else {
          check(left < sizeof(buf));
        }
        break;
      }
    }
    check(walker.position() == pos);
  }

  auto again = encode_image(r->meta(), r->sessions(), payload, r->layout().chunk_bytes);
  check(again.has_value());
  check(again->size() == size && std::memcmp(again->data(), image.data(), size) == 0);
  return 0;
}

namespace {
void build_seeds(lle::fuzz::Seeds& out) {
  using namespace lle::snap;
  SnapshotMeta meta;
  meta.day = 20260930;
  meta.epoch = 1;
  meta.index = 10'000'000;
  meta.snapshot_id = 1;
  meta.mold_seq = 123'456;
  meta.state_hash = 0x0123456789ABCDEFull;
  meta.build_id = 7;
  const std::vector<SessionSeq> sessions = {{1, 100}, {2, 1}, {77, 5'000'000}};

  struct Seed {
    std::size_t payload_bytes;
    bool with_sessions;
    std::uint32_t chunk_bytes;
  };
  for (const Seed s : {Seed{0, false, kDefaultChunkBytes}, Seed{0, true, kMinChunkBytes},
                       Seed{37, true, kMinChunkBytes}, Seed{2 * kMinChunkBytes, false, kMinChunkBytes},
                       Seed{3 * kMinChunkBytes + 100, true, kMinChunkBytes}}) {
    const auto payload = seed_payload(s.payload_bytes, s.payload_bytes + 1);
    const std::span<const SessionSeq> table = s.with_sessions ? std::span<const SessionSeq>(sessions)
                                                              : std::span<const SessionSeq>();
    auto img = encode_image(meta, table, payload, s.chunk_bytes);
    check(img.has_value());
    std::vector<std::uint8_t> bytes(img->size());
    std::memcpy(bytes.data(), img->data(), img->size());
    out.push_back(std::move(bytes));
  }
}
}  // namespace

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  return lle::fuzz::serve_seed(index, buf, cap, build_seeds);
}
