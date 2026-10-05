// nlog-aware driver for nlog_decode_fuzz (in addition to the shared seeded driver):
// takes the harness's valid seed files, then feeds LLVMFuzzerTestOneInput
// deterministic (seeded) mutations: truncation, bit flips, byte overwrites with
// interesting values, range deletion/duplication, and CRC repair so that mutated
// payloads get past the checksums. Files given on the command line are replayed.
//
//   nlog_decode_structured_driver [--iterations N] [--seed S] [FILE...]
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "common/crc32c.h"
#include "common/endian.h"
#include "common/prng.h"
#include "log/file_format.h"
#include "log/level.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap);

namespace {

using namespace lle;
using namespace lle::nlog;
using Bytes = std::vector<std::byte>;

// Recomputes the header CRC and every chunk CRC along the (possibly mutated) chain.
void repair_crcs(Bytes& b) {
  if (b.size() < file::kFileHeaderBytes) return;
  store_le32(b.data() + 60, crc32c(b.data(), 60));
  std::size_t off = load_le32(b.data() + 12);
  while (off >= file::kFileHeaderBytes && off + file::kChunkHeaderBytes <= b.size()) {
    const std::uint32_t len = load_le32(b.data() + off + 8);
    if (len > b.size() - off - file::kChunkHeaderBytes) break;
    std::uint32_t crc = crc32c_extend(0, b.data() + off, 12);
    crc = crc32c_extend(crc, b.data() + off + file::kChunkHeaderBytes, len);
    store_le32(b.data() + off + 12, crc);
    off += file::kChunkHeaderBytes + len;
  }
}

void mutate(Bytes& b, Prng& rng) {
  const std::uint64_t ops = 1 + rng.below(4);
  for (std::uint64_t op = 0; op < ops && !b.empty(); ++op) {
    const std::size_t at = static_cast<std::size_t>(rng.below(b.size()));
    switch (rng.below(7)) {
      case 0: b.resize(at); break;  // truncate
      case 1: b[at] ^= static_cast<std::byte>(1u << rng.below(8)); break;
      case 2: {
        static constexpr std::uint8_t kInteresting[] = {0x00, 0x01, 0x7F, 0x80, 0xFF, 0xFE, 0x40, 0x3F};
        b[at] = static_cast<std::byte>(kInteresting[rng.below(sizeof kInteresting)]);
        break;
      }
      case 3: b[at] = static_cast<std::byte>(rng() & 0xFF); break;
      case 4: {  // delete a range
        const std::size_t n = static_cast<std::size_t>(rng.below(std::min<std::size_t>(64, b.size() - at) + 1));
        b.erase(b.begin() + static_cast<std::ptrdiff_t>(at), b.begin() + static_cast<std::ptrdiff_t>(at + n));
        break;
      }
      case 5: {  // duplicate a range
        const std::size_t n = static_cast<std::size_t>(rng.below(std::min<std::size_t>(128, b.size() - at) + 1));
        const Bytes chunk(b.begin() + static_cast<std::ptrdiff_t>(at), b.begin() + static_cast<std::ptrdiff_t>(at + n));
        b.insert(b.begin() + static_cast<std::ptrdiff_t>(rng.below(b.size() + 1)), chunk.begin(), chunk.end());
        break;
      }
      default: {  // 32-bit overwrite (lengths, counts, site IDs)
        if (b.size() - at >= 4) {
          static constexpr std::uint32_t kWords[] = {0, 1, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, 64, 65, 4096};
          store_le32(b.data() + at, kWords[rng.below(sizeof kWords / sizeof kWords[0])]);
        }
        break;
      }
    }
  }
  if (rng.below(2) == 0) repair_crcs(b);
}

int run_input(std::uint8_t mode, const Bytes& b) {
  std::vector<std::uint8_t> in(b.size() + 1);
  in[0] = mode;
  if (!b.empty()) std::memcpy(in.data() + 1, b.data(), b.size());
  return LLVMFuzzerTestOneInput(in.data(), in.size());
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t iterations = 20'000;
  std::uint64_t seed = 1;
  std::vector<std::string> files;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    if (a == "--iterations" && i + 1 < argc) {
      iterations = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--seed" && i + 1 < argc) {
      seed = std::strtoull(argv[++i], nullptr, 10);
    } else {
      files.emplace_back(a);
    }
  }
  for (const std::string& path : files) {  // corpus replay, like libFuzzer
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) continue;
    std::vector<std::uint8_t> data;
    std::uint8_t buf[4096];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof buf, f)) != 0) data.insert(data.end(), buf, buf + n);
    std::fclose(f);
    LLVMFuzzerTestOneInput(data.data(), data.size());
  }
  // The harness's valid seed files (every third seed; the mode byte is dropped).
  std::vector<Bytes> seeds;
  std::vector<std::uint8_t> buf(1 << 20);
  for (std::size_t i = 0;; i += 3) {
    const std::size_t n = lle_fuzz_seed(i, buf.data(), buf.size());
    if (n == 0) break;
    seeds.emplace_back(reinterpret_cast<const std::byte*>(buf.data()) + 1, reinterpret_cast<const std::byte*>(buf.data()) + n);
  }
  Prng rng(seed);
  std::uint64_t bytes = 0;
  // Every seed, every mode, unmutated and truncated at every length: the
  // "decode up to the last valid extent" path is covered exhaustively.
  for (const Bytes& s : seeds) {
    for (unsigned mode = 0; mode < 32; ++mode) run_input(static_cast<std::uint8_t>(mode), s);
    for (std::size_t cut = 0; cut <= s.size(); ++cut) {
      run_input(static_cast<std::uint8_t>(cut & 0x1F), Bytes(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(cut)));
    }
  }
  for (std::uint64_t it = 0; it < iterations; ++it) {
    Bytes b = seeds[rng.below(seeds.size())];
    mutate(b, rng);
    bytes += b.size();
    run_input(static_cast<std::uint8_t>(rng() & 0xFF), b);
  }
  std::printf("nlog_decode_structured_driver: seed %llu, %llu mutated inputs (%llu bytes), %zu replayed files: ok\n",
              static_cast<unsigned long long>(seed), static_cast<unsigned long long>(iterations),
              static_cast<unsigned long long>(bytes), files.size());
  return 0;
}
