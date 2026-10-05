#pragma once
// Field-level views of OUCH 5.0 outbound and ITCH 5.0 messages for the end-to-end
// assertions, read at the spec offsets directly (an independent reading of the bytes
// the node sent, not the encoder that produced them).
#include <cstdint>
#include <span>
#include <string>

#include "common/endian.h"

namespace lle::exch::test {

inline char type_of(std::span<const std::byte> m) { return m.empty() ? '?' : static_cast<char>(m[0]); }

inline std::uint64_t ts48(const std::byte* p) {
  return (std::uint64_t{load_be16(p)} << 32) | load_be32(p + 2);
}

inline std::string sym(const std::byte* p, std::size_t n) {
  std::string s(reinterpret_cast<const char*>(p), n);
  while (!s.empty() && s.back() == ' ') s.pop_back();
  return s;
}

// OUCH 5.0 outbound (exchange -> client).
struct Ouch {
  std::span<const std::byte> b;
  [[nodiscard]] char type() const { return type_of(b); }
  [[nodiscard]] std::uint64_t ts() const { return load_be64(b.data() + 1); }
  [[nodiscard]] std::uint32_t urn() const { return load_be32(b.data() + 9); }
  // Accepted 'A'
  [[nodiscard]] char a_side() const { return static_cast<char>(b[13]); }
  [[nodiscard]] std::uint32_t a_qty() const { return load_be32(b.data() + 14); }
  [[nodiscard]] std::string a_symbol() const { return sym(b.data() + 18, 8); }
  [[nodiscard]] std::uint64_t a_price() const { return load_be64(b.data() + 26); }
  [[nodiscard]] std::uint64_t a_ref() const { return load_be64(b.data() + 36); }
  [[nodiscard]] char a_cross() const { return static_cast<char>(b[46]); }
  [[nodiscard]] char a_state() const { return static_cast<char>(b[47]); }
  // Replaced 'U'
  [[nodiscard]] std::uint32_t u_orig() const { return load_be32(b.data() + 9); }
  [[nodiscard]] std::uint32_t u_urn() const { return load_be32(b.data() + 13); }
  [[nodiscard]] std::uint32_t u_qty() const { return load_be32(b.data() + 18); }
  [[nodiscard]] std::uint64_t u_price() const { return load_be64(b.data() + 30); }
  [[nodiscard]] std::uint64_t u_ref() const { return load_be64(b.data() + 40); }
  [[nodiscard]] char u_state() const { return static_cast<char>(b[51]); }
  // Canceled 'C'
  [[nodiscard]] std::uint32_t c_qty() const { return load_be32(b.data() + 13); }
  [[nodiscard]] char c_reason() const { return static_cast<char>(b[17]); }
  // Executed 'E'
  [[nodiscard]] std::uint32_t e_qty() const { return load_be32(b.data() + 13); }
  [[nodiscard]] std::uint64_t e_price() const { return load_be64(b.data() + 17); }
  [[nodiscard]] char e_liq() const { return static_cast<char>(b[25]); }
  [[nodiscard]] std::uint64_t e_match() const { return load_be64(b.data() + 26); }
  // Rejected 'J'
  [[nodiscard]] std::uint16_t j_reason() const { return load_be16(b.data() + 13); }
  // System event 'S'
  [[nodiscard]] char s_event() const { return static_cast<char>(b[9]); }

  [[nodiscard]] std::string str() const {
    std::string s(1, type());
    switch (type()) {
      case 'S': return s + " event=" + s_event();
      case 'A':
        return s + " urn=" + std::to_string(urn()) + " " + a_side() + " " + std::to_string(a_qty()) + " " + a_symbol() +
               " @" + std::to_string(a_price()) + " ref=" + std::to_string(a_ref()) + " cross=" + a_cross() +
               " state=" + a_state();
      case 'U':
        return s + " orig=" + std::to_string(u_orig()) + " urn=" + std::to_string(u_urn()) + " qty=" +
               std::to_string(u_qty()) + " @" + std::to_string(u_price()) + " ref=" + std::to_string(u_ref()) +
               " state=" + u_state();
      case 'C': return s + " urn=" + std::to_string(urn()) + " qty=" + std::to_string(c_qty()) + " reason=" + c_reason();
      case 'E':
        return s + " urn=" + std::to_string(urn()) + " qty=" + std::to_string(e_qty()) + " @" +
               std::to_string(e_price()) + " liq=" + e_liq() + " match=" + std::to_string(e_match());
      case 'J': return s + " urn=" + std::to_string(urn()) + " reason=" + std::to_string(j_reason());
      default: return s + " urn=" + std::to_string(urn());
    }
  }
};

// ITCH 5.0.
struct Itch {
  std::span<const std::byte> b;
  [[nodiscard]] char type() const { return type_of(b); }
  [[nodiscard]] std::uint16_t locate() const { return load_be16(b.data() + 1); }
  [[nodiscard]] std::uint64_t ts() const { return ts48(b.data() + 5); }
  [[nodiscard]] std::string str() const {
    std::string s = std::string(1, type()) + " loc=" + std::to_string(locate());
    const std::byte* p = b.data();
    switch (type()) {
      case 'S': return s + " event=" + static_cast<char>(p[11]);
      case 'R': return s + " " + sym(p + 11, 8);
      case 'H': return s + " " + sym(p + 11, 8) + " state=" + static_cast<char>(p[19]) + " reason=" + sym(p + 21, 4);
      case 'A':
      case 'F':
        return s + " ref=" + std::to_string(load_be64(p + 11)) + " " + static_cast<char>(p[19]) + " " +
               std::to_string(load_be32(p + 20)) + " " + sym(p + 24, 8) + " @" + std::to_string(load_be32(p + 32));
      case 'E':
        return s + " ref=" + std::to_string(load_be64(p + 11)) + " shares=" + std::to_string(load_be32(p + 19)) +
               " match=" + std::to_string(load_be64(p + 23));
      case 'C':
        return s + " ref=" + std::to_string(load_be64(p + 11)) + " shares=" + std::to_string(load_be32(p + 19)) +
               " match=" + std::to_string(load_be64(p + 23)) + " printable=" + static_cast<char>(p[31]) + " @" +
               std::to_string(load_be32(p + 32));
      case 'X':
        return s + " ref=" + std::to_string(load_be64(p + 11)) + " cancelled=" + std::to_string(load_be32(p + 19));
      case 'D': return s + " ref=" + std::to_string(load_be64(p + 11));
      case 'U':
        return s + " orig=" + std::to_string(load_be64(p + 11)) + " new=" + std::to_string(load_be64(p + 19)) +
               " shares=" + std::to_string(load_be32(p + 27)) + " @" + std::to_string(load_be32(p + 31));
      case 'P':
        return s + " " + static_cast<char>(p[19]) + " shares=" + std::to_string(load_be32(p + 20)) + " @" +
               std::to_string(load_be32(p + 32)) + " match=" + std::to_string(load_be64(p + 36));
      case 'Q':
        return s + " shares=" + std::to_string(load_be64(p + 11)) + " " + sym(p + 19, 8) + " @" +
               std::to_string(load_be32(p + 27)) + " match=" + std::to_string(load_be64(p + 31)) +
               " type=" + static_cast<char>(p[39]);
      case 'I':
        return s + " paired=" + std::to_string(load_be64(p + 11)) + " imbalance=" + std::to_string(load_be64(p + 19)) +
               " dir=" + static_cast<char>(p[27]) + " cross=" + static_cast<char>(p[48]);
      default: return s;
    }
  }
  // Cross Trade 'Q'
  [[nodiscard]] std::uint64_t q_shares() const { return load_be64(b.data() + 11); }
  [[nodiscard]] std::uint32_t q_price() const { return load_be32(b.data() + 27); }
  [[nodiscard]] char q_type() const { return static_cast<char>(b[39]); }
  [[nodiscard]] std::string symbol_at(std::size_t off) const { return sym(b.data() + off, 8); }
};

}  // namespace lle::exch::test
