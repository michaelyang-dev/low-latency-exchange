#pragma once
// refclient's per-order timestamp log: the client side of T18 (TTT_client, METHODOLOGY
// §13; 07 §4 "T18").
//
// One record per order the strategy sent:
//   trigger_seq   the trigger's MoldUDP64 sequence number (= the order's ClOrdID);
//   rx_*          the receive timestamps of the packet the client acted on: the
//                 "winning" copy of the trigger (line A, line B or a re-request reply);
//   tx_*          the TX timestamp of the frame that carried the order's last byte;
//   phc           the PHC index of the port both stamps come from (-1: none).
// TTT_client = tx_hw - rx_hw, computed only when both are hardware stamps of the same
// PHC (hwts::IntervalAccounting); anything else is counted, never computed.
//
// File: "LLEHWTS1", u32 version (1), u32 record size (48), u64 count, then the records
// as stored in memory (little-endian hosts: x86-64, arm64). Written once at the end of
// a run from a preallocated array (no I/O on the hot path).
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "common/types.h"
#include "net/hwts/clock_domain.h"

namespace lle::client {

struct OrderStampRecord {
  std::uint64_t trigger_seq = 0;
  std::int64_t rx_hw = 0, rx_sw = 0;
  std::int64_t tx_hw = 0, tx_sw = 0;
  std::int32_t phc = -1;
  std::uint8_t line = 0;   // 0 line A, 1 line B, 2 request reply
  std::uint8_t flags = 0;
  std::uint16_t reserved = 0;

  static constexpr std::uint8_t kInPacket = 1;  // the trigger message was in the packet stamped by rx_*
  static constexpr std::uint8_t kUntagged = 2;  // the order was not written at once (no TX attribution)
  static constexpr std::uint8_t kTxSeen = 4;    // a TX stamp (of any kind) was matched

  [[nodiscard]] net::hwts::PhcStamp rx_stamp() const noexcept {
    return rx_hw != 0 ? net::hwts::PhcStamp{phc, rx_hw}
                      : net::hwts::PhcStamp{-1, rx_sw};  // software (phc -1) or missing (0)
  }
  [[nodiscard]] net::hwts::PhcStamp tx_stamp() const noexcept {
    return tx_hw != 0 ? net::hwts::PhcStamp{phc, tx_hw} : net::hwts::PhcStamp{-1, tx_sw};
  }
};
static_assert(sizeof(OrderStampRecord) == 48);

inline constexpr char kHwtsMagic[8] = {'L', 'L', 'E', 'H', 'W', 'T', 'S', '1'};

inline bool write_hwts_log(const std::string& path, std::span<const OrderStampRecord> recs) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) return false;
  const std::uint32_t ver = 1, size = sizeof(OrderStampRecord);
  const std::uint64_t n = recs.size();
  bool ok = std::fwrite(kHwtsMagic, 1, 8, f) == 8 && std::fwrite(&ver, 4, 1, f) == 1 && std::fwrite(&size, 4, 1, f) == 1 &&
            std::fwrite(&n, 8, 1, f) == 1;
  if (ok && n != 0) ok = std::fwrite(recs.data(), sizeof(OrderStampRecord), recs.size(), f) == recs.size();
  ok = std::fclose(f) == 0 && ok;
  return ok;
}

inline bool read_hwts_log(const std::string& path, std::vector<OrderStampRecord>& out, std::string* err) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    if (err) *err = "cannot open " + path;
    return false;
  }
  char magic[8];
  std::uint32_t ver = 0, size = 0;
  std::uint64_t n = 0;
  bool ok = std::fread(magic, 1, 8, f) == 8 && std::memcmp(magic, kHwtsMagic, 8) == 0 && std::fread(&ver, 4, 1, f) == 1 &&
            std::fread(&size, 4, 1, f) == 1 && std::fread(&n, 8, 1, f) == 1 && ver == 1 &&
            size == sizeof(OrderStampRecord) && n < (std::uint64_t{1} << 32);
  if (ok) {
    out.resize(n);
    ok = n == 0 || std::fread(out.data(), sizeof(OrderStampRecord), n, f) == n;
  }
  std::fclose(f);
  if (!ok && err) *err = path + ": not an LLEHWTS1 log (or truncated)";
  return ok;
}

}  // namespace lle::client
