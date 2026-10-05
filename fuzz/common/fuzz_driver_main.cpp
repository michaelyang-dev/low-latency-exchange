// Standalone driver for libFuzzer-style harnesses (docs/dev/conventions.md
// "Tests"): Apple clang ships no libFuzzer runtime, so every harness also links
// this main, which feeds seeded random inputs to LLVMFuzzerTestOneInput.
//
//   <name>_driver [--iterations N] [--seed S] [--max-len L] [FILE...]
//
// With FILE arguments each file is run once (corpus / crash replay). Otherwise
// inputs are generated: a third raw random bytes, the rest mutations (bit
// flips, byte sets, truncation, insertion, splicing) of the harness's seed
// inputs (lle_fuzz_seed). On abort the current input is written to
// crash-<driver>-<pid>.bin for replay.
#include <fcntl.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "common/prng.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);
// Harness-provided seed inputs: writes seed `index` into buf (capacity cap) and
// returns its size, or 0 when there are no more seeds.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap);

namespace {

const std::uint8_t* g_cur = nullptr;
std::size_t g_cur_len = 0;
char g_crash_path[512] = "crash-driver-input.bin";

void on_abort(int sig) {
  const int fd = ::open(g_crash_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    if (g_cur != nullptr && g_cur_len > 0) (void)!::write(fd, g_cur, g_cur_len);
    ::close(fd);
  }
  const char msg[] = "fuzz driver: input saved to ";
  (void)!::write(2, msg, sizeof msg - 1);
  (void)!::write(2, g_crash_path, std::strlen(g_crash_path));
  (void)!::write(2, "\n", 1);
  std::signal(sig, SIG_DFL);
  std::raise(sig);
}

int run_one(const std::vector<std::uint8_t>& in) {
  g_cur = in.data();
  g_cur_len = in.size();
  return LLVMFuzzerTestOneInput(in.data(), in.size());
}

void mutate(lle::Prng& rng, std::vector<std::uint8_t>& v, const std::vector<std::vector<std::uint8_t>>& seeds,
            std::size_t max_len) {
  const std::uint64_t rounds = 1 + rng.below(4);
  for (std::uint64_t r = 0; r < rounds; ++r) {
    switch (rng.below(7)) {
      case 0:  // flip a bit
        if (!v.empty()) v[rng.below(v.size())] ^= static_cast<std::uint8_t>(1u << rng.below(8));
        break;
      case 1:  // set a byte to an interesting value
        if (!v.empty()) {
          static constexpr std::uint8_t kInteresting[] = {0, 1, 0x7F, 0x80, 0xFF, ' ', 'A', 'G', 'S'};
          v[rng.below(v.size())] = kInteresting[rng.below(sizeof kInteresting)];
        }
        break;
      case 2:  // random byte
        if (!v.empty()) v[rng.below(v.size())] = static_cast<std::uint8_t>(rng.next_u64());
        break;
      case 3:  // truncate
        if (!v.empty()) v.resize(rng.below(v.size() + 1));
        break;
      case 4: {  // insert random bytes
        const std::size_t at = rng.below(v.size() + 1);
        const std::size_t n = 1 + rng.below(8);
        for (std::size_t i = 0; i < n && v.size() < max_len; ++i)
          v.insert(v.begin() + static_cast<std::ptrdiff_t>(at), static_cast<std::uint8_t>(rng.next_u64()));
        break;
      }
      case 5: {  // splice in part of another seed
        if (seeds.empty()) break;
        const auto& o = seeds[rng.below(seeds.size())];
        if (o.empty()) break;
        const std::size_t from = rng.below(o.size());
        const std::size_t n = 1 + rng.below(o.size() - from);
        const std::size_t at = rng.below(v.size() + 1);
        v.insert(v.begin() + static_cast<std::ptrdiff_t>(at), o.begin() + static_cast<std::ptrdiff_t>(from),
                 o.begin() + static_cast<std::ptrdiff_t>(from + n));
        break;
      }
      default: {  // overwrite a 2/4/8-byte big-endian integer with an edge value
        if (v.size() < 8) break;
        const std::size_t at = rng.below(v.size() - 7);
        const std::uint64_t edge[] = {0, 1, 0xFFFF, 0xFFFFFFFFull, ~0ull, rng.next_u64()};
        const std::uint64_t x = edge[rng.below(std::size(edge))];
        const std::size_t w = std::size_t{2} << rng.below(3);
        for (std::size_t i = 0; i < w; ++i) v[at + i] = static_cast<std::uint8_t>(x >> (8 * (w - 1 - i)));
        break;
      }
    }
  }
  if (v.size() > max_len) v.resize(max_len);
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t iterations = 100'000, seed = 1;
  std::size_t max_len = 4096;
  std::vector<std::string> files;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--iterations" && i + 1 < argc) {
      iterations = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--seed" && i + 1 < argc) {
      seed = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--max-len" && i + 1 < argc) {
      max_len = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
    } else {
      files.push_back(a);
    }
  }
  {
    std::string base = argv[0];
    if (const auto slash = base.rfind('/'); slash != std::string::npos) base = base.substr(slash + 1);
    std::snprintf(g_crash_path, sizeof g_crash_path, "crash-%s-%d.bin", base.c_str(), static_cast<int>(::getpid()));
  }
  std::signal(SIGABRT, on_abort);
  std::signal(SIGSEGV, on_abort);
  std::signal(SIGBUS, on_abort);

  if (!files.empty()) {
    for (const auto& f : files) {
      std::ifstream in(f, std::ios::binary);
      const std::vector<std::uint8_t> v((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      run_one(v);
      std::printf("ran %s (%zu bytes)\n", f.c_str(), v.size());
    }
    return 0;
  }

  std::vector<std::vector<std::uint8_t>> seeds;
  std::vector<std::uint8_t> buf(1 << 20);
  for (std::size_t i = 0;; ++i) {
    const std::size_t n = lle_fuzz_seed(i, buf.data(), buf.size());
    if (n == 0) break;
    seeds.emplace_back(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
  }

  lle::Prng rng(seed);
  std::uint64_t bytes = 0;
  for (const auto& s : seeds) run_one(s);
  std::vector<std::uint8_t> in;
  for (std::uint64_t it = 0; it < iterations; ++it) {
    if (seeds.empty() || rng.below(3) == 0) {
      in.resize(rng.below(max_len + 1));
      for (auto& b : in) b = static_cast<std::uint8_t>(rng.next_u64());
    } else {
      in = seeds[rng.below(seeds.size())];
      mutate(rng, in, seeds, max_len);
    }
    bytes += in.size();
    run_one(in);
  }
  std::printf("fuzz driver: %llu seeds + %llu generated inputs (%llu bytes), seed %llu: OK\n",
              static_cast<unsigned long long>(seeds.size()), static_cast<unsigned long long>(iterations),
              static_cast<unsigned long long>(bytes), static_cast<unsigned long long>(seed));
  return 0;
}
