// Fuzz target for journal recovery on hostile media (06 §7): recover() and the
// read-only reader must never crash, loop or read out of bounds, whatever the segment
// files contain, and their verdicts must be self-consistent:
//   - the reader walks exactly the chain recovery reports;
//   - after a repair, a second recovery is clean and reaches the same record;
//   - corruption is reported without modifying anything.
//
// Input: byte 0 selects the mode, the rest is mode data.
//   mode 0  raw: up to three segment files cut from the input verbatim;
//   mode 1  a valid assigned segment header (nonce from the input) followed by the
//           input bytes as the record area;
//   mode 2  a valid journal generated from an 8-byte seed (two small segments), then
//           an edit script from the input: XOR a byte, zero a range, copy a range,
//           truncate a file, rewrite a header field.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "common/prng.h"
#include "fuzz_seeds.h"
#include "journal/journal_writer.h"
#include "journal/mem_journal_device.h"
#include "journal/reader.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"

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

constexpr std::uint32_t kDay = 20260930;
constexpr std::uint64_t kSegBytes = kMinSegmentBytes;  // 4 KiB header + one 64 KiB batch
constexpr std::uint64_t kWindow = 2 * kBatchBytes;      // queue depth 2

struct Reader {
  const std::uint8_t* p;
  std::size_t n;
  std::size_t i = 0;
  bool more() const { return i < n; }
  std::uint8_t u8() { return i < n ? p[i++] : 0; }
  std::uint32_t u24() { return std::uint32_t{u8()} | (std::uint32_t{u8()} << 8) | (std::uint32_t{u8()} << 16); }
  std::uint64_t u64() {
    std::uint64_t v = 0;
    for (int k = 0; k < 8; ++k) v |= std::uint64_t{u8()} << (8 * k);
    return v;
  }
};

void write_header(MemJournalDevice& d, const SegmentHeader& h) {
  std::vector<std::byte> b(kSegmentHeaderBytes);
  encode_segment_header(std::span<std::byte, kSegmentHeaderBytes>(b.data(), kSegmentHeaderBytes), h);
  auto t = d.tamper();
  std::memcpy(t.data(), b.data(), std::min<std::size_t>(t.size(), b.size()));
  d.sync_tamper();
}

void generate(MemSegmentDir& dir, std::uint64_t seed) {
  lle::Prng rng(seed);
  JournalWriterOptions o;
  o.day = kDay;
  o.queue_depth = 2;
  o.buffers = 3;
  JournalWriter<MemJournalDevice> w(o);
  w.start(ChainState{});
  SegmentPreparer prep(dir, rng, kDay, kSegBytes);
  for (int i = 0; i < 2; ++i) {
    auto p = prep.create();
    CHECK(p.has_value());
    CHECK(w.add_prepared(dir.device(p->handle), p->handle, p->header));
  }
  const Sealer l2(0x5EED5EED5EED5EEDull);
  RecordBuilder b(l2);
  std::vector<std::byte> msg(140, std::byte{0x41});
  std::vector<std::byte> rec(kMaxRecordBytes);
  const std::uint64_t n = 50 + rng.below(700);
  for (std::uint64_t i = 0; i < n; ++i) {
    const OuchInbound oi{1, 2, 3, std::span<const std::byte>(msg).first(rng.below(141))};
    const auto r = b.append(rec, static_cast<lle::Nanos>(i + 1), oi);
    auto st = w.append(r, l2);
    while (st == JournalWriter<MemJournalDevice>::Status::Busy) {
      (void)w.flush();
      (void)w.poll();
      st = w.append(r, l2);
    }
    if (st != JournalWriter<MemJournalDevice>::Status::Ok) break;  // segments full
    if (rng.chance(1, 16)) (void)w.flush();
  }
  while (w.in_flight() != 0 || w.batch_used() != 0) {
    if (!w.flush() && w.in_flight() == 0) break;
    (void)w.poll();
  }
}

void edit(MemSegmentDir& dir, Reader& in) {
  while (in.more() && dir.count() != 0) {
    const std::uint8_t op = in.u8();
    auto& d = dir.device(in.u8() % dir.count());
    auto t = d.tamper();
    if (t.empty()) continue;
    const std::uint32_t off = in.u24() % static_cast<std::uint32_t>(t.size());
    switch (op % 5) {
      case 0:
        t[off] ^= static_cast<std::byte>(in.u8() | 1);
        break;
      case 1: {
        const std::size_t len = std::min<std::size_t>(in.u24() % 70000, t.size() - off);
        std::memset(t.data() + off, 0, len);
        break;
      }
      case 2: {
        const std::uint32_t src = in.u24() % static_cast<std::uint32_t>(t.size());
        const std::size_t len = std::min<std::size_t>({std::size_t{in.u8()} * 64, t.size() - off, t.size() - src});
        std::memmove(t.data() + off, t.data() + src, len);
        break;
      }
      case 3:
        (void)d.resize(off);
        break;
      default: {
        auto h = decode_segment_header(d.image());
        if (h) {
          const std::uint8_t field = in.u8();
          if (field % 3 == 0) h->first_index = in.u8();
          if (field % 3 == 1) h->prev_last_crc ^= 1;
          if (field % 3 == 2) h->nonce = in.u64();
          write_header(d, *h);
        }
        break;
      }
    }
    d.sync_tamper();
  }
}

void build_seeds(lle::fuzz::Seeds& out) {
  out.push_back({2, 1, 2, 3, 4, 5, 6, 7, 8});                                 // clean journal
  out.push_back({2, 9, 9, 9, 9, 9, 9, 9, 9, 0, 1, 0x80, 0x10, 0x00, 0x55});   // flip a byte
  out.push_back({2, 3, 3, 3, 3, 3, 3, 3, 3, 1, 0, 0x00, 0x20, 0x00, 0x00, 0x10, 0x00});  // zero a range
  out.push_back({2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 1, 0x00, 0x00, 0x00, 0x00});   // rewrite a header
  std::vector<std::uint8_t> m1{1, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE};
  for (int i = 0; i < 200; ++i) m1.push_back(static_cast<std::uint8_t>(i * 37));
  out.push_back(m1);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  Reader in{data + 1, size - 1};
  MemSegmentDir dir;
  switch (data[0] % 3) {
    case 0: {
      const std::size_t parts = 1 + in.u8() % 3;
      for (std::size_t k = 0; k < parts; ++k) {
        const std::size_t len = (in.n - in.i) / (parts - k);
        auto h = dir.create("raw-" + std::to_string(k) + ".seg", len);
        auto t = dir.device(*h).tamper();
        std::memcpy(t.data(), in.p + in.i, len);
        in.i += len;
        dir.device(*h).sync_tamper();
      }
      break;
    }
    case 1: {
      SegmentHeader h;
      h.day = kDay;
      h.first_index = 1 + in.u8() % 3;
      h.nonce = in.u64();
      if (!usable_nonce(h.nonce)) h.nonce = 0x0123456789ABCDEFull;
      h.segment_bytes = kSegBytes;
      auto hd = dir.create("a.seg", kSegmentHeaderBytes + (in.n - in.i));
      write_header(dir.device(*hd), h);
      auto t = dir.device(*hd).tamper();
      std::memcpy(t.data() + kSegmentHeaderBytes, in.p + in.i, in.n - in.i);
      dir.device(*hd).sync_tamper();
      break;
    }
    default:
      generate(dir, in.u64());
      edit(dir, in);
      break;
  }

  const RecoveryOptions report{0, kWindow, false};
  const RecoveryResult r0 = recover(dir, report);
  const MemSegmentDir before = dir.clone(false);
  const RecoveryResult r = recover(dir, RecoveryOptions{0, kWindow, true});
  if (r.status != r0.status || !(r.chain == r0.chain)) {
    std::fprintf(stderr, "report-only: %s (%s)\nrepair: %s (%s)\n", std::string(to_string(r0.status)).c_str(),
                 r0.detail.c_str(), std::string(to_string(r.status)).c_str(), r.detail.c_str());
  }
  CHECK(r.status == r0.status && r.chain == r0.chain);
  if (r.status == RecoveryStatus::Ok) {
    // The reader walks exactly the recovered chain.
    std::uint64_t n = 0;
    const ReadSummary s = read_journal(dir, ReadOptions{}, [&](const RecordView& v, const RecordLocation& loc) {
      CHECK(loc.sealer->verify(v.data()).has_value());
      ++n;
      return true;
    });
    CHECK(s.chain == r.chain && n == r.records);
    // After repair the journal recovers to the same point and the same resume offset,
    // and repairing again is idempotent.
    const RecoveryResult again = recover(dir, RecoveryOptions{0, kWindow, true});
    CHECK(again.status == RecoveryStatus::Ok && again.chain == r.chain);
    CHECK(again.resume_offset == r.resume_offset);
    const RecoveryResult third = recover(dir, report);
    CHECK(third.status == RecoveryStatus::Ok && third.chain == r.chain && third.resume_offset == r.resume_offset);
  } else if (r.status == RecoveryStatus::Corruption || r.status == RecoveryStatus::Empty) {
    // Refusal (and an empty journal) never writes.
    for (std::size_t i = 0; i < dir.count(); ++i) {
      const auto a = dir.device(i).image();
      const auto b = before.device(i).image();
      CHECK(a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0);
    }
  }
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  return lle::fuzz::serve_seed(index, buf, cap, build_seeds);
}
