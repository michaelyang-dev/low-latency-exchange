#include "admin/protocol.h"

#include <algorithm>
#include <cstring>

#include "common/endian.h"
#include "common/sha256.h"
#include "engine/records.h"

namespace lle::admin {

Mac hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::byte> msg) noexcept {
  std::array<std::uint8_t, 64> k{};
  if (key.size() > k.size()) {
    const auto d = Sha256::of(key.data(), key.size());
    std::copy(d.begin(), d.end(), k.begin());
  } else if (!key.empty()) {
    std::copy(key.begin(), key.end(), k.begin());
  }
  std::array<std::uint8_t, 64> ipad{}, opad{};
  for (std::size_t i = 0; i < 64; ++i) {
    ipad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36u);
    opad[i] = static_cast<std::uint8_t>(k[i] ^ 0x5Cu);
  }
  Sha256 in;
  in.update(ipad.data(), ipad.size());
  in.update(msg.data(), msg.size());
  const auto inner = in.finish();
  Sha256 out;
  out.update(opad.data(), opad.size());
  out.update(inner.data(), inner.size());
  return out.finish();
}

bool equal_ct(const Mac& a, std::span<const std::byte> b) noexcept {
  if (b.size() != a.size()) return false;
  unsigned diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ std::to_integer<unsigned>(b[i]);
  return diff == 0;
}

std::string_view to_string(NackReason r) noexcept {
  switch (r) {
    case NackReason::None: return "accepted";
    case NackReason::Malformed: return "malformed frame";
    case NackReason::UnknownOperator: return "unknown operator";
    case NackReason::BadMac: return "bad MAC";
    case NackReason::Replay: return "sequence not above the last accepted";
    case NackReason::UnknownCommand: return "unknown command";
    case NackReason::BadArgs: return "bad TLV arguments";
    case NackReason::Busy: return "sequencer busy, send again";
  }
  return "?";
}

std::vector<std::byte> encode_request(const Request& r, std::span<const std::uint8_t> key) {
  const std::size_t n = std::min(r.args.size(), kMaxArgs);
  std::vector<std::byte> f(kRequestHead + n + kMacBytes);
  store_be16(f.data(), static_cast<std::uint16_t>(f.size() - 2));
  f[2] = static_cast<std::byte>(kVersion);
  f[3] = static_cast<std::byte>('R');
  store_be32(f.data() + 4, r.operator_id);
  store_be64(f.data() + 8, r.sequence);
  store_be16(f.data() + 16, r.command);
  store_be16(f.data() + 18, r.tlv_version);
  store_be16(f.data() + 20, static_cast<std::uint16_t>(n));
  if (n != 0) std::memcpy(f.data() + kRequestHead, r.args.data(), n);
  const Mac mac = hmac_sha256(key, std::span<const std::byte>(f.data() + 2, kRequestHead - 2 + n));
  std::memcpy(f.data() + kRequestHead + n, mac.data(), kMacBytes);
  return f;
}

std::expected<Response, NackReason> decode_response(std::span<const std::byte> f, std::span<const std::uint8_t> key,
                                                    bool allow_unsigned) {
  if (f.size() != kResponseBytes || load_be16(f.data()) != kResponseBytes - 2 ||
      std::to_integer<std::uint8_t>(f[2]) != kVersion)
    return std::unexpected(NackReason::Malformed);
  const char type = std::to_integer<char>(f[3]);
  if (type != 'A' && type != 'N') return std::unexpected(NackReason::Malformed);
  Response r;
  r.accepted = type == 'A';
  r.operator_id = load_be32(f.data() + 4);
  r.sequence = load_be64(f.data() + 8);
  r.reason = static_cast<NackReason>(std::to_integer<std::uint8_t>(f[16]));
  const auto mac = f.subspan(17, kMacBytes);
  const bool unsigned_nack =
      !r.accepted && std::all_of(mac.begin(), mac.end(), [](std::byte b) { return b == std::byte{0}; });
  if (unsigned_nack && allow_unsigned) return r;
  if (!equal_ct(hmac_sha256(key, f.subspan(2, 15)), mac)) return std::unexpected(NackReason::BadMac);
  return r;
}

std::expected<Request, NackReason> Verifier::verify(std::span<const std::byte> f) const noexcept {
  if (f.size() < kRequestHead + kMacBytes || load_be16(f.data()) != f.size() - 2 ||
      std::to_integer<std::uint8_t>(f[2]) != kVersion || std::to_integer<char>(f[3]) != 'R')
    return std::unexpected(NackReason::Malformed);
  const std::size_t n = load_be16(f.data() + 20);
  if (n > kMaxArgs || f.size() != kRequestHead + n + kMacBytes) return std::unexpected(NackReason::Malformed);
  Request r;
  r.operator_id = load_be32(f.data() + 4);
  r.sequence = load_be64(f.data() + 8);
  r.command = load_be16(f.data() + 16);
  r.tlv_version = load_be16(f.data() + 18);
  r.args = f.subspan(kRequestHead, n);
  const auto it = ops_.find(r.operator_id);
  if (it == ops_.end()) return std::unexpected(NackReason::UnknownOperator);
  if (!equal_ct(hmac_sha256(it->second.key, f.subspan(2, kRequestHead - 2 + n)), f.subspan(kRequestHead + n)))
    return std::unexpected(NackReason::BadMac);
  if (r.sequence <= it->second.last) return std::unexpected(NackReason::Replay);
  if (r.command < static_cast<std::uint16_t>(engine::AdminCommand::Halt) ||
      r.command > static_cast<std::uint16_t>(engine::AdminCommand::RegSho))
    return std::unexpected(NackReason::UnknownCommand);
  if (!engine::parse_admin_args(r.args, r.tlv_version).has_value()) return std::unexpected(NackReason::BadArgs);
  return r;
}

void Verifier::commit(const Request& r) noexcept {
  const auto it = ops_.find(r.operator_id);
  if (it != ops_.end() && r.sequence > it->second.last) it->second.last = r.sequence;
}

std::array<std::byte, kResponseBytes> Verifier::respond(const Response& r) const noexcept {
  std::array<std::byte, kResponseBytes> f{};
  store_be16(f.data(), static_cast<std::uint16_t>(kResponseBytes - 2));
  f[2] = static_cast<std::byte>(kVersion);
  f[3] = static_cast<std::byte>(r.accepted ? 'A' : 'N');
  store_be32(f.data() + 4, r.operator_id);
  store_be64(f.data() + 8, r.sequence);
  f[16] = static_cast<std::byte>(r.accepted ? 0 : static_cast<std::uint8_t>(r.reason));
  const auto it = ops_.find(r.operator_id);
  if (it != ops_.end()) {
    const Mac mac = hmac_sha256(it->second.key, std::span<const std::byte>(f.data() + 2, 15));
    std::memcpy(f.data() + 17, mac.data(), kMacBytes);
  }
  return f;
}

std::span<const std::byte> FrameAssembler::next() {
  if (poisoned_ || buf_.size() < 2) return {};
  const std::size_t len = load_be16(buf_.data());
  if (len < kRequestHead - 2 + kMacBytes || len + 2 > kMaxFrame) {
    poisoned_ = true;
    return {};
  }
  if (buf_.size() < len + 2) return {};
  frame_.assign(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(len + 2));
  buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(len + 2));
  return frame_;
}

}  // namespace lle::admin
