#pragma once
// Seeded random OUCH message generator: valid messages built from the
// descriptor tables, structured mutations of them, and noise. Used by the
// differential generator (ouch50_diffgen) and the standalone fuzz drivers.
// Test tooling: allocation is fine here.
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "common/endian.h"
#include "common/prng.h"
#include "proto/ouch50/ouch50.h"

namespace lle::ouch50::gen {

using Bytes = std::vector<std::byte>;

class Generator {
 public:
  explicit Generator(std::uint64_t seed) : r_(seed) {}

  Prng& rng() { return r_; }

  // A message that passes the strict validator of its direction.
  Bytes valid(Direction dir) {
    const MsgDesc& d = pick_desc(dir);
    return valid_of(d);
  }

  // 1..3 structured mutations of a valid message.
  Bytes mutated(Direction dir) {
    Bytes b = valid(dir);
    const std::uint64_t n = 1 + r_.below(3);
    for (std::uint64_t i = 0; i < n; ++i) mutate(b, dir);
    return b;
  }

  // Noise, usually starting with a type letter of the direction.
  Bytes noise(Direction dir) {
    Bytes b(static_cast<std::size_t>(r_.below(170)));
    for (auto& x : b) x = static_cast<std::byte>(r_.below(256));
    if (!b.empty() && r_.chance(7, 10)) b[0] = static_cast<std::byte>(pick_desc(dir).type);
    return b;
  }

  // The mix used by the differential test.
  Bytes any(Direction dir) {
    const std::uint64_t k = r_.below(100);
    if (k < 35) return valid(dir);
    if (k < 92) return mutated(dir);
    return noise(dir);
  }

 private:
  static constexpr char kAlphaChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -.";

  const MsgDesc& pick_desc(Direction dir) {
    if (dir == Direction::Inbound) return kInboundMessages[static_cast<std::size_t>(r_.below(kInboundMessages.size()))];
    return kOutboundMessages[static_cast<std::size_t>(r_.below(kOutboundMessages.size()))];
  }

  std::uint8_t pick_member(const ByteSet& s) {
    std::array<std::uint8_t, 256> m{};
    std::size_t n = 0;
    for (unsigned c = 0; c < 256; ++c)
      if (s.contains(static_cast<std::uint8_t>(c))) m[n++] = static_cast<std::uint8_t>(c);
    return m[static_cast<std::size_t>(r_.below(n))];
  }

  std::uint64_t biased(std::uint64_t lo, std::uint64_t hi) {
    switch (r_.below(4)) {
      case 0: return lo;
      case 1: return hi;
      default: return lo + r_.below(hi - lo + 1);
    }
  }

  std::uint64_t valid_price() {
    switch (r_.below(6)) {
      case 0: return 1;
      case 1: return kMaxLimitPrice;
      case 2: return kMarketPrice;
      case 3: return kMarketPriceAlt;
      default: return 1 + r_.below(kMaxLimitPrice);
    }
  }

  std::uint64_t interesting_price() {
    static constexpr std::uint64_t k[] = {0,          1,          kMaxLimitPrice, kMaxLimitPrice + 1, kMarketPriceAlt - 1,
                                          kMarketPriceAlt, kMarketPriceAlt + 1, kMarketPrice, kMarketPrice + 1,
                                          0xFFFFFFFFull, 0x100000001ull, 0xFFFFFFFFFFFFFFFFull};
    if (r_.chance(1, 4)) return r_.next_u64();
    return k[r_.below(std::size(k))];
  }

  std::uint64_t random_width(std::size_t len) {
    const std::uint64_t v = r_.chance(1, 2) ? r_.below(1000) : r_.next_u64();
    return len >= 8 ? v : (v & ((1ull << (8 * len)) - 1));
  }

  void put_uint(std::byte* p, std::size_t len, std::uint64_t v) {
    switch (len) {
      case 1: p[0] = static_cast<std::byte>(v); break;
      case 2: store_be16(p, static_cast<std::uint16_t>(v)); break;
      case 4: store_be32(p, static_cast<std::uint32_t>(v)); break;
      case 8: store_be64(p, v); break;
      default: break;
    }
  }

  void fill_alpha(std::byte* p, std::size_t len) {
    const std::size_t used = static_cast<std::size_t>(r_.below(len + 1));
    for (std::size_t i = 0; i < len; ++i)
      p[i] = static_cast<std::byte>(i < used ? kAlphaChars[r_.below(sizeof(kAlphaChars) - 1)] : ' ');
  }

  void fill_field(std::byte* p, const FieldDesc& f) {
    switch (f.check) {
      case CheckKind::Enum:
        if (f.type == FieldType::Char) {
          p[0] = static_cast<std::byte>(pick_member(*f.chars));
        } else {
          store_be16(p, f.codes[r_.below(f.code_count)]);
        }
        return;
      case CheckKind::LimitOrMarket: store_be64(p, valid_price()); return;
      case CheckKind::ZeroOrLimit: store_be64(p, r_.chance(1, 3) ? 0 : 1 + r_.below(kMaxLimitPrice)); return;
      case CheckKind::Range: put_uint(p, f.len, biased(f.lo, f.hi)); return;
      case CheckKind::None: break;
    }
    if (f.type == FieldType::Alpha) {
      fill_alpha(p, f.len);
    } else {
      put_uint(p, f.len, random_width(f.len));
    }
  }

  void put_tag_value(Bytes& b, const TagDesc& t, bool force_nonzero_idx) {
    const std::size_t at = b.size();
    b.resize(at + 2 + t.value_len);
    b[at] = static_cast<std::byte>(t.value_len + 1);
    b[at + 1] = static_cast<std::byte>(t.tag);
    std::byte* p = b.data() + at + 2;
    switch (t.check) {
      case CheckKind::Enum: p[0] = static_cast<std::byte>(pick_member(*t.chars)); return;
      case CheckKind::Range: put_uint(p, t.value_len, biased(t.lo, t.hi)); return;
      case CheckKind::ZeroOrLimit: store_be64(p, r_.chance(1, 3) ? 0 : 1 + r_.below(kMaxLimitPrice)); return;
      case CheckKind::LimitOrMarket: store_be64(p, valid_price()); return;
      case CheckKind::None: break;
    }
    if (t.type == FieldType::Alpha) {
      fill_alpha(p, t.value_len);
    } else if (t.tag == std::to_underlying(Tag::UserRefIdx)) {
      p[0] = static_cast<std::byte>(force_nonzero_idx ? 1 + r_.below(255) : r_.below(256));
    } else {
      put_uint(p, t.value_len, random_width(t.value_len));
    }
  }

  Bytes valid_of(const MsgDesc& d) {
    Bytes b(d.base_len);
    b[0] = static_cast<std::byte>(d.type);
    for (std::size_t i = 1; i < d.field_count; ++i) {
      const FieldDesc& f = d.fields[i];
      if (f.type == FieldType::AppLen) continue;
      fill_field(b.data() + f.offset, f);
    }
    if (d.rule == AppendageRule::None) return b;
    std::array<std::uint8_t, 32> tags{};
    std::size_t n = 0;
    const std::uint64_t density = r_.below(4);  // none / sparse / half / all
    for (std::uint8_t t = 0; t < 32; ++t) {
      if ((d.allowed_tags & (1u << t)) == 0) continue;
      const bool take = density == 3 || (density == 2 && r_.chance(1, 2)) || (density == 1 && r_.chance(1, 5));
      if (take) tags[n++] = t;
    }
    if (d.rule == AppendageRule::OptionalUnlessUserRefIdx) {
      if (n == 0) return b;
      bool has_idx = false;
      for (std::size_t i = 0; i < n; ++i) has_idx |= tags[i] == std::to_underlying(Tag::UserRefIdx);
      if (!has_idx) tags[n++] = std::to_underlying(Tag::UserRefIdx);
    }
    if (d.rule == AppendageRule::Optional && n == 0 && r_.chance(1, 2)) return b;
    for (std::size_t i = n; i > 1; --i) std::swap(tags[i - 1], tags[static_cast<std::size_t>(r_.below(i))]);
    b.resize(d.fixed_len);
    for (std::size_t i = 0; i < n; ++i)
      put_tag_value(b, kTags[tags[i]], d.rule == AppendageRule::OptionalUnlessUserRefIdx);
    store_be16(b.data() + d.base_len, static_cast<std::uint16_t>(b.size() - d.fixed_len));
    return b;
  }

  // Element starts of a well-formed appendage beginning at `from`.
  static std::vector<std::size_t> elements(const Bytes& b, std::size_t from) {
    std::vector<std::size_t> out;
    std::size_t pos = from;
    while (pos < b.size()) {
      const std::size_t len = std::to_integer<std::size_t>(b[pos]);
      if (len == 0 || pos + 1 + len > b.size()) break;
      out.push_back(pos);
      pos += 1 + len;
    }
    return out;
  }

  const MsgDesc* desc_of(const Bytes& b, Direction dir) {
    if (b.empty()) return nullptr;
    const auto t = std::to_integer<std::uint8_t>(b[0]);
    return dir == Direction::Inbound ? find_inbound(t) : find_outbound(t);
  }

  void fix_applen(Bytes& b, const MsgDesc& d) {
    if (b.size() >= d.fixed_len)
      store_be16(b.data() + d.base_len, static_cast<std::uint16_t>(b.size() - d.fixed_len));
  }

  void mutate(Bytes& b, Direction dir) {
    const MsgDesc* d = desc_of(b, dir);
    const bool has_app = d != nullptr && d->rule != AppendageRule::None && b.size() >= d->fixed_len;
    switch (r_.below(16)) {
      case 0:  // bit flip
        if (!b.empty()) b[r_.below(b.size())] ^= static_cast<std::byte>(1u << r_.below(8));
        return;
      case 1:  // random byte
        if (!b.empty()) b[r_.below(b.size())] = static_cast<std::byte>(r_.below(256));
        return;
      case 2: {  // interesting byte
        static constexpr unsigned k[] = {0x00, 0x20, 0x7F, 0xFF, 'A', 'Z', 'N', 'Y', '0', '*', 'Q', 'e'};
        if (!b.empty()) b[r_.below(b.size())] = static_cast<std::byte>(k[r_.below(std::size(k))]);
        return;
      }
      case 3:  // truncate
        if (!b.empty()) b.resize(static_cast<std::size_t>(r_.below(b.size())));
        return;
      case 4:  // trailing garbage
        for (std::uint64_t i = 0, n = 1 + r_.below(8); i < n; ++i) b.push_back(static_cast<std::byte>(r_.below(256)));
        return;
      case 5:  // insert an element with a random tag and size
        if (has_app) {
          const auto els = elements(b, d->fixed_len);
          std::size_t at = b.size();
          if (!els.empty() && r_.chance(1, 2)) at = els[r_.below(els.size())];
          const auto tag = static_cast<std::uint8_t>(r_.chance(1, 2) ? r_.below(34) : r_.below(256));
          std::size_t size = static_cast<std::size_t>(r_.below(10));
          if (const TagDesc* td = find_tag(tag); td != nullptr && r_.chance(3, 4)) size = td->value_len;
          Bytes el{static_cast<std::byte>(size + 1), static_cast<std::byte>(tag)};
          for (std::size_t i = 0; i < size; ++i) el.push_back(static_cast<std::byte>(r_.below(256)));
          b.insert(b.begin() + static_cast<std::ptrdiff_t>(at), el.begin(), el.end());
          fix_applen(b, *d);
        }
        return;
      case 6:  // duplicate an element
        if (has_app) {
          const auto els = elements(b, d->fixed_len);
          if (!els.empty()) {
            const std::size_t at = els[r_.below(els.size())];
            const std::size_t len = 1 + std::to_integer<std::size_t>(b[at]);
            Bytes el(b.begin() + static_cast<std::ptrdiff_t>(at), b.begin() + static_cast<std::ptrdiff_t>(at + len));
            b.insert(b.end(), el.begin(), el.end());
            fix_applen(b, *d);
          }
        }
        return;
      case 7:  // corrupt Appendage Length
        if (has_app) {
          const std::uint16_t cur = load_be16(b.data() + d->base_len);
          static constexpr int deltas[] = {-2, -1, 1, 2};
          const auto v = r_.chance(1, 4) ? static_cast<std::uint16_t>(r_.below(65536))
                                         : static_cast<std::uint16_t>(cur + deltas[r_.below(4)]);
          store_be16(b.data() + d->base_len, v);
        }
        return;
      case 8:  // change the type letter
        if (!b.empty()) {
          if (r_.chance(1, 2)) {
            // A letter of the other direction (letters overlap: U C D E M X Q).
            const MsgDesc& other = dir == Direction::Inbound
                                       ? kOutboundMessages[r_.below(kOutboundMessages.size())]
                                       : kInboundMessages[r_.below(kInboundMessages.size())];
            b[0] = static_cast<std::byte>(other.type);
          } else {
            b[0] = static_cast<std::byte>(r_.below(256));
          }
        }
        return;
      case 9:  // random value in an enumerated field
      case 10:  // interesting price
      case 11:  // interesting quantity
        if (d != nullptr) mutate_field(b, *d, r_.below(3));
        return;
      case 12:  // drop or add the Appendage Length
        if (d != nullptr && d->rule != AppendageRule::None) {
          if (b.size() >= d->fixed_len) {
            b.resize(d->base_len);
          } else if (b.size() == d->base_len) {
            b.push_back(std::byte{0});
            b.push_back(std::byte{0});
          }
        }
        return;
      case 13:  // wrong-size value for a known tag
        if (has_app) {
          const auto els = elements(b, d->fixed_len);
          if (!els.empty()) {
            const std::size_t at = els[r_.below(els.size())];
            const std::size_t len = std::to_integer<std::size_t>(b[at]);
            if (r_.chance(1, 2) && len > 1) {
              b.erase(b.begin() + static_cast<std::ptrdiff_t>(at + len));
              b[at] = static_cast<std::byte>(len - 1);
            } else {
              b.insert(b.begin() + static_cast<std::ptrdiff_t>(at + 1 + len), std::byte{0x41});
              b[at] = static_cast<std::byte>(len + 1);
            }
            fix_applen(b, *d);
          }
        }
        return;
      case 14:  // corrupt an element length byte
        if (has_app) {
          const auto els = elements(b, d->fixed_len);
          if (!els.empty()) b[els[r_.below(els.size())]] = static_cast<std::byte>(r_.chance(1, 2) ? 0 : r_.below(256));
        }
        return;
      default:  // UserRefIdx edits on Opt* messages (AppendageRule paths)
        if (has_app && d->rule == AppendageRule::OptionalUnlessUserRefIdx) {
          for (std::size_t at : elements(b, d->fixed_len))
            if (std::to_integer<std::uint8_t>(b[at + 1]) == std::to_underlying(Tag::UserRefIdx) &&
                std::to_integer<std::size_t>(b[at]) == 2)
              b[at + 2] = std::byte{0};
        }
        return;
    }
  }

  void mutate_field(Bytes& b, const MsgDesc& d, std::uint64_t which) {
    std::array<const FieldDesc*, 32> cand{};
    std::size_t n = 0;
    for (std::size_t i = 0; i < d.field_count; ++i) {
      const FieldDesc& f = d.fields[i];
      if (f.offset + f.len > b.size()) continue;
      const bool match = (which == 0 && f.check == CheckKind::Enum) ||
                         (which == 1 && f.type == FieldType::Price) ||
                         (which == 2 && (f.check == CheckKind::Range || f.type == FieldType::U32));
      if (match) cand[n++] = &f;
    }
    if (n == 0) return;
    const FieldDesc& f = *cand[r_.below(n)];
    std::byte* p = b.data() + f.offset;
    if (which == 0) {
      if (f.type == FieldType::Char) {
        p[0] = static_cast<std::byte>(r_.below(256));
      } else {
        store_be16(p, static_cast<std::uint16_t>(r_.chance(1, 2) ? r_.below(0x50) : r_.below(65536)));
      }
    } else if (which == 1) {
      store_be64(p, interesting_price());
    } else {
      static constexpr std::uint32_t k[] = {0, 1, 999'999, 1'000'000, 0xFFFFFFFFu};
      store_be32(p, r_.chance(1, 4) ? static_cast<std::uint32_t>(r_.next_u64()) : k[r_.below(std::size(k))]);
    }
  }

  Prng r_;
};

}  // namespace lle::ouch50::gen
