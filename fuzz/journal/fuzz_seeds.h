#pragma once
// Adapter from "build a list of seed inputs" to the driver's lle_fuzz_seed(index, buf,
// cap) protocol (fuzz/common/fuzz_driver_main.cpp): the seeds are built once.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace lle::fuzz {

using Seeds = std::vector<std::vector<std::uint8_t>>;

template <class Build>
std::size_t serve_seed(std::size_t index, std::uint8_t* buf, std::size_t cap, Build&& build) {
  static const Seeds seeds = [&] {
    Seeds s;
    build(s);
    return s;
  }();
  if (index >= seeds.size() || seeds[index].size() > cap) return 0;
  if (!seeds[index].empty()) std::memcpy(buf, seeds[index].data(), seeds[index].size());
  return seeds[index].size();
}

}  // namespace lle::fuzz
