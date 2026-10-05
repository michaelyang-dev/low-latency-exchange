#pragma once
// POSIX TCP plumbing for the admin channel (cold path: operator tools and the
// admin listener). The protocol itself is sans-I/O (protocol.h, admin_port.h);
// this is the thin socket layer around it. Not used by deterministic code.
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <string>
#include <vector>

#include "admin/protocol.h"

namespace lle::admin {

// Reads a key file: hex digits (whitespace ignored), at least 16 bytes.
[[nodiscard]] std::expected<Key, std::string> load_key_file(const std::string& path);
[[nodiscard]] std::expected<Key, std::string> parse_key_hex(std::string_view hex);

// Connects, sends one request frame, reads the response frame (timeout in ms).
[[nodiscard]] std::expected<std::vector<std::byte>, std::string> exchange(const std::string& host, std::uint16_t port,
                                                                          std::span<const std::byte> frame,
                                                                          int timeout_ms = 5'000);

// A non-blocking TCP listener for the admin port. step() accepts connections,
// reads bytes and writes back what `on_bytes` produces; `on_bytes` returns
// false to close the connection. Single-threaded; call step() from the admin
// thread (or a test) in a loop.
class TcpListener {
 public:
  using OnBytes = std::function<bool(std::size_t conn, std::span<const std::byte> in, std::vector<std::byte>& out)>;
  using OnClose = std::function<void(std::size_t conn)>;

  // Binds 127.0.0.1:`port` (0: any free port; see port()).
  [[nodiscard]] static std::expected<TcpListener, std::string> open(std::uint16_t port, OnBytes on_bytes,
                                                                    OnClose on_close = {});
  // Binds `ipv4` (host order):`port`. Loopback is the default everywhere; another
  // address exists for tests that reach a node in another network namespace.
  [[nodiscard]] static std::expected<TcpListener, std::string> open(std::uint32_t ipv4, std::uint16_t port,
                                                                    OnBytes on_bytes, OnClose on_close = {});
  TcpListener(TcpListener&& o) noexcept;
  TcpListener& operator=(TcpListener&&) = delete;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;
  ~TcpListener();

  // Waits up to `timeout_ms` for activity and handles it; returns the number of events handled.
  int step(int timeout_ms);
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] std::size_t connections() const noexcept;

 private:
  TcpListener() = default;
  struct Conn {
    int fd = -1;
    std::size_t id = 0;
    std::vector<std::byte> pending;  // bytes to write
  };
  void close_conn(Conn& c);

  int fd_ = -1;
  std::uint16_t port_ = 0;
  std::size_t next_id_ = 1;
  std::vector<Conn> conns_;
  OnBytes on_bytes_;
  OnClose on_close_;
};

}  // namespace lle::admin
