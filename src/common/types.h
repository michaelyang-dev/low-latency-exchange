#pragma once
// Project-wide vocabulary types (01-architecture §8).
#include <cstdint>
#include <limits>

namespace lle {

using Nanos = std::int64_t;      // nanoseconds (signed: differences are common)
using PxE4 = std::int64_t;       // price in 1/10,000 USD (ITCH Price(4), OUCH Price)
using Qty = std::uint32_t;       // shares
using Locate = std::uint16_t;    // ITCH stock locate (day-scoped array index)
using OrderRef = std::uint64_t;  // ITCH order reference / exchange order reference
using MatchNo = std::uint64_t;   // match number
using SeqNo = std::uint64_t;     // MoldUDP64 / SoupBinTCP / journal sequence
using UserRefNum = std::uint32_t;

enum class Side : char { Buy = 'B', Sell = 'S' };

constexpr Side opposite(Side s) noexcept { return s == Side::Buy ? Side::Sell : Side::Buy; }

inline constexpr PxE4 kPxScale = 10'000;                      // $1.0000
inline constexpr PxE4 kPxMaxLimit = 1'999'999'900;            // $199,999.9900 (OUCH max limit)
inline constexpr PxE4 kPxMarketAlt = 2'000'000'000;           // $200,000.0000 treated as market
inline constexpr PxE4 kPxMarket = 0x7FFF'FFFF;                // OUCH market price sentinel
inline constexpr Nanos kNsPerSec = 1'000'000'000;
inline constexpr Nanos kNsPerDay = 86'400 * kNsPerSec;

}  // namespace lle
