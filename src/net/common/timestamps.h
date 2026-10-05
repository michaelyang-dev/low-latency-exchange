#pragma once
// Timestamp vocabulary shared by the socket, io_uring and hwts code (07 §2.5).
#include <cstdint>

#include "common/types.h"

namespace lle::net {

// What a port asks the kernel for. Hardware needs the device configured first
// (hwts::enable_hw_timestamping); without it the kernel silently reports nothing.
enum class TsMode : std::uint8_t { Off, Software, Hardware };

// One packet's timestamps as reported by SO_TIMESTAMPING (scm_timestamping ts[0] and
// ts[2]). Both are ns; sw is CLOCK_REALTIME, hw is the raw PHC time of the NIC. 0 means
// "not reported".
struct RxTimestamps {
  Nanos sw_ns = 0;
  Nanos hw_ns = 0;
};

enum class TsKind : std::uint8_t { None, Software, Hardware };

[[nodiscard]] constexpr TsKind classify(const RxTimestamps& t) noexcept {
  return t.hw_ns != 0 ? TsKind::Hardware : (t.sw_ns != 0 ? TsKind::Software : TsKind::None);
}

[[nodiscard]] constexpr const char* to_string(TsKind k) noexcept {
  switch (k) {
    case TsKind::Hardware: return "hardware";
    case TsKind::Software: return "software";
    case TsKind::None: break;
  }
  return "none";
}

// A transmit timestamp read back from the kernel (error queue or io_uring), keyed by the
// SOF_TIMESTAMPING_OPT_ID counter: per datagram for UDP, last-byte offset for TCP.
struct TxStamp {
  std::uint32_t id = 0;     // sock_extended_err.ee_data (OPT_ID key)
  std::uint32_t type = 0;   // SCM_TSTAMP_SND / SCHED / ACK / COMPLETION
  RxTimestamps ts;          // same layout as RX: sw in sw_ns, hw in hw_ns
  [[nodiscard]] TsKind kind() const noexcept { return classify(ts); }
};

// Timestamp accounting per 07 §2.5: a run is valid only if ≥99.9% of measured items carry
// hardware timestamps and no software timestamp appears. Integer arithmetic only.
struct TsValidity {
  std::uint64_t hw = 0;
  std::uint64_t sw = 0;
  std::uint64_t missing = 0;

  void record(TsKind k) noexcept {
    if (k == TsKind::Hardware) {
      ++hw;
    } else if (k == TsKind::Software) {
      ++sw;
    } else {
      ++missing;
    }
  }
  [[nodiscard]] std::uint64_t total() const noexcept { return hw + sw + missing; }
  // Hardware share in parts per million (0 when nothing was measured).
  [[nodiscard]] std::uint64_t hw_ppm() const noexcept { return total() == 0 ? 0 : hw * 1'000'000 / total(); }
  [[nodiscard]] bool valid() const noexcept { return total() > 0 && sw == 0 && hw * 1000 >= total() * 999; }
  void merge(const TsValidity& o) noexcept {
    hw += o.hw;
    sw += o.sw;
    missing += o.missing;
  }
};

}  // namespace lle::net
