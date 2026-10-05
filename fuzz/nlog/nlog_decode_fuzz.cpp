// Fuzz target for the nlog decoder (11-logging-observability §1: "the decoder is
// fuzzed"). The first input byte selects options so one corpus covers them all:
//   bit 0  skip CRC checks (lets mutations reach the dictionary/extent parsers)
//   bit 1  JSONL instead of text
//   bits 2-3  time mode: wall, tsc, none
//   bit 4  apply filters (level, thread, site, time ranges)
// Everything else is the file. Declared with lle_fuzz: a libFuzzer binary with
// LLE_LIBFUZZER, and always nlog_decode_fuzz_driver (the shared seeded mutation
// driver). nlog_decode_structured_driver adds nlog-aware mutations (CRC repair,
// exhaustive truncation).
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "log/decoder.h"
#include "log/file_format.h"

namespace {

using namespace lle;
using namespace lle::nlog;
using Bytes = std::vector<std::byte>;

// A valid file exercising every argument kind, specs, calibrations, threads,
// drops, a thread end and a clean END chunk.
Bytes make_seed(std::uint64_t variant) {
  Bytes b;
  file::append_file_header(b, file::FileHeader{1'700'000'000'000'000'000, 24'000'000, "fuzz", 0});
  std::vector<file::DictEntry> dict;
  const ArgKind all[] = {ArgKind::kU8,  ArgKind::kU16,  ArgKind::kU32, ArgKind::kU64,
                         ArgKind::kI8,  ArgKind::kI16,  ArgKind::kI32, ArgKind::kI64,
                         ArgKind::kBool, ArgKind::kChar, ArgKind::kF64, ArgKind::kStr};
  ArgKinds k0{};
  for (std::size_t i = 0; i < 8; ++i) k0[i] = all[i];
  ArgKinds k1{};
  for (std::size_t i = 0; i < 4; ++i) k1[i] = all[8 + i];
  dict.push_back({0, 1, 8, k0, 11, "fuzz/a.cpp", "u {} {} {} {} i {} {:x} {:>6} {:+}"});
  dict.push_back({1, 2, 4, k1, 22, "fuzz/b.cpp", "b {} c {:c} f {:.3f} s [{:<5}]"});
  dict.push_back({2, 3, 0, {}, 33, "fuzz/c.cpp", "plain {{}}"});
  file::append_dict_chunk(b, dict);
  file::append_calib_chunk(b, file::Calibration{1000, 1'700'000'000'000'000'000, 24'000'000, 3});
  for (std::uint32_t t = 1; t <= 2 + variant % 3; ++t) file::append_thread_chunk(b, t, 1 << 20, "worker");
  Prng rng(variant + 17);
  for (int e = 0; e < 4; ++e) {
    for (std::uint32_t t = 1; t <= 2; ++t) {
      file::ExtentBuilder eb;
      eb.reset(t);
      for (int r = 0; r < 6; ++r) {
        const std::uint64_t tsc = 1000 + static_cast<std::uint64_t>(e * 100 + r * 10) + t;
        switch (rng.below(3)) {
          case 0: {
            const ArgValue a[] = {ArgValue::of_unsigned(ArgKind::kU8, rng() & 0xFF),
                                  ArgValue::of_unsigned(ArgKind::kU16, rng() & 0xFFFF),
                                  ArgValue::of_unsigned(ArgKind::kU32, rng() & 0xFFFFFFFF),
                                  ArgValue::of_unsigned(ArgKind::kU64, rng()),
                                  ArgValue::of_signed(ArgKind::kI8, -5),
                                  ArgValue::of_signed(ArgKind::kI16, -300),
                                  ArgValue::of_signed(ArgKind::kI32, -70000),
                                  ArgValue::of_signed(ArgKind::kI64, static_cast<std::int64_t>(rng()))};
            eb.add_values(0, 0, tsc, a);
            break;
          }
          case 1: {
            const ArgValue a[] = {ArgValue::of_unsigned(ArgKind::kBool, 1), ArgValue::of_unsigned(ArgKind::kChar, 'q'),
                                  ArgValue::of_double(static_cast<double>(rng() % 1000) / 7.0),
                                  ArgValue::of_string(std::string_view{"hello world, a long string"}.substr(0, rng() % 27),
                                                      rng.below(2) == 0)};
            eb.add_values(1, 1, tsc, a);
            break;
          }
          default: eb.add_values(2, 2, tsc, {}); break;
        }
      }
      eb.finish_into(b);
    }
    file::append_calib_chunk(b, file::Calibration{2000 + static_cast<std::uint64_t>(e) * 1000,
                                                  1'700'000'000'000'041'000 + e * 41'000, 24'000'000, 2});
  }
  file::append_drops_chunk(b, 1, 5000, 3);
  file::append_thread_end_chunk(b, 2, 5001);
  file::append_end_chunk(b, 6000, 48, 3, 0);
  return b;
}

}  // namespace

// Seeds: three valid files, each with mode bytes 0x00 (CRC checked), 0x01 (CRC
// skipped, so mutations reach the dictionary and extent parsers) and 0x16
// (JSONL, filters on).
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  static constexpr std::uint8_t kModes[] = {0x00, 0x01, 0x16};
  if (index >= 9) return 0;
  const Bytes file = make_seed(index / 3);
  if (file.size() + 1 > cap) return 0;
  buf[0] = kModes[index % 3];
  std::memcpy(buf + 1, file.data(), file.size());
  return file.size() + 1;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lle::nlog::decode;
  if (size == 0) return 0;
  const std::uint8_t mode = data[0];
  const std::span<const std::byte> bytes{reinterpret_cast<const std::byte*>(data + 1), size - 1};
  ParseOptions po;
  po.verify_crc = (mode & 1) == 0;
  const LogFile f = LogFile::parse(bytes, po);
  RenderOptions ro;
  ro.format = (mode & 2) != 0 ? OutputFormat::kJsonl : OutputFormat::kText;
  switch ((mode >> 2) & 3) {
    case 0: ro.time = TimeMode::kWall; break;
    case 1: ro.time = TimeMode::kTsc; break;
    default: ro.time = TimeMode::kNone; break;
  }
  if ((mode & 0x10) != 0) {
    ro.filter.min_level = static_cast<std::uint8_t>(mode >> 6);
    ro.filter.threads = {1, 2};
    ro.filter.sites = {0, 1, 2, 3};
    ro.filter.from_tsc = 1;
    ro.filter.to_tsc = ~std::uint64_t{0} >> 1;
    ro.filter.from_ns = -1;
    ro.filter.to_ns = INT64_MAX;
  }
  std::size_t total = 0;
  render(f, ro, [&total](std::string_view line) { total += line.size(); });
  total += describe(f).size();
  total += dictionary_text(f).size();
  for (const auto& c : f.calibrations()) total += f.to_wall_ns(c.tsc + 1).has_value() ? 1u : 0u;
  return total == static_cast<std::size_t>(-1) ? 1 : 0;
}
