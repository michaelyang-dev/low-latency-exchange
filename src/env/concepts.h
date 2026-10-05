#pragma once
// Environment concepts (ADR-003, 01-architecture §5, §8).
//
// Every component that touches time, network, disk or randomness is a
// `template <class Env>`; production binds ProdEnv, the simulator binds SimEnv.
// Polling APIs take callbacks so no batch storage is allocated on hot paths.
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

#include "common/types.h"

namespace lle::env {

struct Endpoint {
  std::uint32_t ipv4 = 0;  // host byte order
  std::uint16_t port = 0;
  friend constexpr auto operator<=>(const Endpoint&, const Endpoint&) = default;
};

struct RxDatagram {
  std::span<const std::byte> data;
  Endpoint src;
  Endpoint dst;          // multicast group or local address
  Nanos hw_rx_ns = 0;    // NIC hardware RX timestamp (0 if unavailable)
};

using ConnId = std::uint32_t;
inline constexpr ConnId kNoConn = 0xFFFF'FFFFu;

enum class StreamEventKind : std::uint8_t { Accepted, Connected, Data, Closed };

struct StreamEvent {
  StreamEventKind kind = StreamEventKind::Data;
  ConnId conn = kNoConn;
  std::span<const std::byte> data;  // valid only during the callback (Data)
  Nanos hw_rx_ns = 0;
};

struct DiskCompletion {
  std::uint64_t tag = 0;
  std::int32_t result = 0;  // bytes written / 0 on sync success, -errno on failure
};

struct NoopCallback {
  template <class... A>
  void operator()(A&&...) const noexcept {}
};

template <class C>
concept ClockLike = requires(C& c) {
  { c.now_mono() } -> std::same_as<Nanos>;           // monotonic: timeouts
  { c.now_real() } -> std::same_as<Nanos>;           // realtime ns since UNIX epoch: sequencer only
  { c.tsc() } -> std::same_as<std::uint64_t>;        // cycle counter: probes and logging
};

template <class R>
concept RngLike = requires(R& r) {
  { r.next_u64() } -> std::same_as<std::uint64_t>;
};

// Typed callback probes: each poll() is called with a callback taking exactly
// the event type it delivers (spans inside are valid only during the call).
struct RxDatagramSink {
  void operator()(const RxDatagram&) const noexcept {}
};
struct StreamEventSink {
  void operator()(const StreamEvent&) const noexcept {}
};
struct DiskCompletionSink {
  void operator()(const DiskCompletion&) const noexcept {}
};

template <class P>
concept DatagramPortLike = requires(P& p, Endpoint e, std::span<const std::byte> b) {
  { p.send(e, b) } -> std::same_as<bool>;
  { p.poll_rx(RxDatagramSink{}) } -> std::same_as<std::size_t>;  // cb(const RxDatagram&)
};

template <class S>
concept StreamPortLike = requires(S& s, ConnId c, std::span<const std::byte> b) {
  { s.write(c, b) } -> std::same_as<std::size_t>;  // bytes accepted (may be < size: flow control)
  { s.poll(StreamEventSink{}) } -> std::same_as<std::size_t>;  // cb(const StreamEvent&)
  s.close(c);
};

// A stream port that also opens connections. listen() and connect() return an
// expected- or optional-like value: false on failure, otherwise dereferencing to
// the bound endpoint (port 0 binds an ephemeral port) or the new connection.
template <class S>
concept StreamEndpointLike = StreamPortLike<S> && requires(S& s, Endpoint e) {
  { static_cast<bool>(s.listen(e)) };
  { *s.listen(e) } -> std::convertible_to<Endpoint>;
  { static_cast<bool>(s.connect(e)) };
  { *s.connect(e) } -> std::convertible_to<ConnId>;
};

template <class D>
concept DiskFileLike = requires(D& d, std::uint64_t off, std::span<const std::byte> b) {
  { d.submit_write(off, b, true, std::uint64_t{}) } -> std::same_as<bool>;
  { d.submit_sync(std::uint64_t{}) } -> std::same_as<bool>;
  { d.poll(DiskCompletionSink{}) } -> std::same_as<std::size_t>;  // cb(const DiskCompletion&)
};

// A disk file that recovery can also read back (bytes the OS would return,
// including unsynced page-cache contents).
template <class D>
concept DiskFileReadLike = DiskFileLike<D> && requires(const D& d, std::uint64_t off, std::span<std::byte> out) {
  { d.read(off, out) } -> std::same_as<std::size_t>;
  { d.size() } -> std::same_as<std::uint64_t>;
};

}  // namespace lle::env
