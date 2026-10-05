// Differential-test generator (03-protocols s4 "Independent check"): emits N
// random valid and invalid OUCH messages with the C++ codec's canonical
// verdicts, one per line: "D<TAB>hex<TAB>verdict" (D = I inbound, O outbound).
// tools/spec/ouch50_diff.py pipes this into the independent Python decoder.
//
//   ouch50_diffgen --seed S --count N
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>

#include "canonical.h"
#include "msggen.h"

namespace {

std::uint64_t arg_u64(int argc, char** argv, const char* name, std::uint64_t def) {
  for (int i = 1; i + 1 < argc; ++i)
    if (std::strcmp(argv[i], name) == 0) return std::strtoull(argv[i + 1], nullptr, 10);
  return def;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace lle::ouch50;
  const std::uint64_t seed = arg_u64(argc, argv, "--seed", 1);
  const std::uint64_t count = arg_u64(argc, argv, "--count", 1000);
  gen::Generator g(seed);
  std::string line;
  std::string out;
  out.reserve(1 << 20);
  for (std::uint64_t i = 0; i < count; ++i) {
    const Direction dir = g.rng().chance(1, 2) ? Direction::Inbound : Direction::Outbound;
    const gen::Bytes msg = g.any(dir);
    const std::span<const std::byte> b(msg.data(), msg.size());
    line.clear();
    line += dir == Direction::Inbound ? 'I' : 'O';
    line += '\t';
    canon::append_hex(line, b);
    line += '\t';
    line += dir == Direction::Inbound ? canon::inbound_verdict(b) : canon::outbound_verdict(b);
    line += '\n';
    out += line;
    if (out.size() > (1u << 20) - 4096) {
      std::fwrite(out.data(), 1, out.size(), stdout);
      out.clear();
    }
  }
  std::fwrite(out.data(), 1, out.size(), stdout);
  return 0;
}
