#include "net/busypoll/busypoll.h"

#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netdev.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <string>

#include "net/common/fd.h"

namespace lle::net::busypoll {

namespace {

// struct epoll_params and its ioctls (6.9). Defined locally so older headers build; the
// numbers are _IOW/_IOR(0x8A, nr, 8 bytes) on asm-generic ioctl encoding.
struct RawEpollParams {
  std::uint32_t busy_poll_usecs;
  std::uint16_t busy_poll_budget;
  std::uint8_t prefer_busy_poll;
  std::uint8_t pad;
};
static_assert(sizeof(RawEpollParams) == 8);
constexpr unsigned long kEpiocsparams = (1ul << 30) | (8ul << 16) | (0x8Aul << 8) | 0x01ul;
constexpr unsigned long kEpiocgparams = (2ul << 30) | (8ul << 16) | (0x8Aul << 8) | 0x02ul;
#if defined(EPIOCSPARAMS)
static_assert(kEpiocsparams == EPIOCSPARAMS && kEpiocgparams == EPIOCGPARAMS);
static_assert(sizeof(epoll_params) == sizeof(RawEpollParams));
#endif

#ifndef SO_PREFER_BUSY_POLL
constexpr int SO_PREFER_BUSY_POLL = 69;
#endif
#ifndef SO_BUSY_POLL_BUDGET
constexpr int SO_BUSY_POLL_BUDGET = 70;
#endif
#ifndef SO_INCOMING_NAPI_ID
constexpr int SO_INCOMING_NAPI_ID = 56;
#endif

Result<int> get_sockopt(int fd, int name, const char* op) {
  int v = 0;
  socklen_t len = sizeof(v);
  if (::getsockopt(fd, SOL_SOCKET, name, &v, &len) != 0) return fail_errno(op);
  return v;
}

Result<std::string> sysfs_path(std::string_view ifname, std::string_view attr) {
  if (ifname.empty() || ifname.size() >= IFNAMSIZ || ifname.find('/') != std::string_view::npos || ifname == "." ||
      ifname == "..")
    return fail("sysfs", EINVAL);
  std::string p = "/sys/class/net/";
  p += ifname;
  p += '/';
  p += attr;
  return p;
}

Result<void> write_sysfs(std::string_view ifname, std::string_view attr, std::uint64_t v) {
  auto path = sysfs_path(ifname, attr);
  if (!path) return std::unexpected(path.error());
  UniqueFd fd(::open(path->c_str(), O_WRONLY | O_CLOEXEC));
  if (!fd) return fail_errno("open(sysfs)");
  std::array<char, 24> buf{};
  auto [end, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), v);
  (void)ec;
  const auto n = static_cast<std::size_t>(end - buf.data());
  if (::write(fd.get(), buf.data(), n) != static_cast<ssize_t>(n)) return fail_errno("write(sysfs)");
  return {};
}

Result<std::uint64_t> read_sysfs(std::string_view ifname, std::string_view attr) {
  auto path = sysfs_path(ifname, attr);
  if (!path) return std::unexpected(path.error());
  UniqueFd fd(::open(path->c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd) return fail_errno("open(sysfs)");
  std::array<char, 32> buf{};
  const ssize_t n = ::read(fd.get(), buf.data(), buf.size() - 1);
  if (n <= 0) return fail(n < 0 ? "read(sysfs)" : "read(sysfs): empty", n < 0 ? errno : EIO);
  std::uint64_t v = 0;
  auto [end, ec] = std::from_chars(buf.data(), buf.data() + n, v);
  if (ec != std::errc{}) return fail("parse(sysfs)", EINVAL);
  (void)end;
  return v;
}

// ---- minimal generic-netlink client (cold path) ----

constexpr std::size_t nl_align(std::size_t n) noexcept { return (n + 3u) & ~std::size_t{3}; }

class NlMsg {
 public:
  void begin(std::uint16_t type, std::uint16_t flags, std::uint32_t seq, std::uint8_t cmd) noexcept {
    len_ = 0;
    nlmsghdr h{};
    h.nlmsg_type = type;
    h.nlmsg_flags = flags;
    h.nlmsg_seq = seq;
    std::memcpy(buf_.data(), &h, sizeof(h));
    len_ = nl_align(sizeof(h));
    genlmsghdr g{};
    g.cmd = cmd;
    g.version = 1;
    std::memcpy(buf_.data() + len_, &g, sizeof(g));
    len_ += nl_align(sizeof(g));
  }
  void put(std::uint16_t type, const void* data, std::size_t n) noexcept {
    nlattr a{};
    a.nla_type = type;
    a.nla_len = static_cast<std::uint16_t>(sizeof(nlattr) + n);
    std::memcpy(buf_.data() + len_, &a, sizeof(a));
    std::memcpy(buf_.data() + len_ + sizeof(nlattr), data, n);
    len_ += nl_align(sizeof(nlattr) + n);
  }
  template <class T>
  void put(std::uint16_t type, T v) noexcept {
    put(type, &v, sizeof(v));
  }
  std::span<const std::byte> finish() noexcept {
    const auto l = static_cast<std::uint32_t>(len_);
    std::memcpy(buf_.data(), &l, sizeof(l));  // nlmsg_len is the first field
    return {buf_.data(), len_};
  }

 private:
  std::array<std::byte, 256> buf_{};
  std::size_t len_ = 0;
};

// Calls fn(type, payload) for each attribute in [p, p + n).
template <class F>
void for_each_attr(const std::byte* p, std::size_t n, F&& fn) {
  std::size_t off = 0;
  while (off + sizeof(nlattr) <= n) {
    nlattr a{};
    std::memcpy(&a, p + off, sizeof(a));
    if (a.nla_len < sizeof(nlattr) || off + a.nla_len > n) break;
    fn(static_cast<std::uint16_t>(a.nla_type & NLA_TYPE_MASK),
       std::span<const std::byte>(p + off + sizeof(nlattr), a.nla_len - sizeof(nlattr)));
    off += nl_align(a.nla_len);
  }
}

std::uint64_t attr_uint(std::span<const std::byte> v) noexcept {
  if (v.size() >= 8) {
    std::uint64_t x = 0;
    std::memcpy(&x, v.data(), 8);
    return x;
  }
  std::uint32_t x = 0;
  std::memcpy(&x, v.data(), v.size() < 4 ? v.size() : 4);
  return x;
}

class Genl {
 public:
  Result<void> open() {
    fd_.reset(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC));
    if (!fd_) return fail_errno("socket(NETLINK_GENERIC)");
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (::bind(fd_.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) != 0) return fail_errno("bind(netlink)");
    return {};
  }
  std::uint32_t next_seq() noexcept { return ++seq_; }

  Result<void> send(std::span<const std::byte> m) {
    sockaddr_nl to{};
    to.nl_family = AF_NETLINK;
    if (::sendto(fd_.get(), m.data(), m.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to)) < 0)
      return fail_errno("sendto(netlink)");
    return {};
  }

  // Receives replies to `seq` until NLMSG_DONE (dump) or an ACK/error (do). Calls
  // fn(attrs, len) for every genl payload message. Returns the kernel's error, if any.
  template <class F>
  Result<void> recv(std::uint32_t seq, bool dump, F&& fn) {
    for (;;) {
      const ssize_t n = ::recv(fd_.get(), buf_.data(), buf_.size(), 0);
      if (n < 0) {
        if (errno == EINTR) continue;
        return fail_errno("recv(netlink)");
      }
      std::size_t off = 0;
      const auto total = static_cast<std::size_t>(n);
      while (off + sizeof(nlmsghdr) <= total) {
        nlmsghdr h{};
        std::memcpy(&h, buf_.data() + off, sizeof(h));
        if (h.nlmsg_len < sizeof(nlmsghdr) || off + h.nlmsg_len > total) break;
        const std::byte* body = buf_.data() + off + nl_align(sizeof(nlmsghdr));
        const std::size_t body_len = h.nlmsg_len - nl_align(sizeof(nlmsghdr));
        if (h.nlmsg_seq == seq) {
          if (h.nlmsg_type == NLMSG_DONE) return {};
          if (h.nlmsg_type == NLMSG_ERROR) {
            int err = 0;
            std::memcpy(&err, body, sizeof(err));
            if (err != 0) return fail("netlink", -err);
            if (!dump) return {};
          } else if (body_len >= nl_align(sizeof(genlmsghdr))) {
            const std::size_t g = nl_align(sizeof(genlmsghdr));
            fn(body + g, body_len - g);
            if (!dump) return {};
          }
        }
        off += nl_align(h.nlmsg_len);
      }
    }
  }

 private:
  UniqueFd fd_;
  std::uint32_t seq_ = 0;
  alignas(8) std::array<std::byte, 16384> buf_{};
};

Result<std::uint16_t> resolve_family(Genl& nl, const char* name) {
  NlMsg m;
  const std::uint32_t seq = nl.next_seq();
  m.begin(GENL_ID_CTRL, NLM_F_REQUEST, seq, CTRL_CMD_GETFAMILY);
  m.put(CTRL_ATTR_FAMILY_NAME, name, std::strlen(name) + 1);
  if (auto r = nl.send(m.finish()); !r) return std::unexpected(r.error());
  std::uint16_t id = 0;
  auto r = nl.recv(seq, false, [&](const std::byte* p, std::size_t n) {
    for_each_attr(p, n, [&](std::uint16_t t, std::span<const std::byte> v) {
      if (t == CTRL_ATTR_FAMILY_ID && v.size() >= 2) std::memcpy(&id, v.data(), 2);
    });
  });
  if (!r) return std::unexpected(r.error());
  if (id == 0) return fail("genl family", ENOENT);
  return id;
}

}  // namespace

Result<void> set_epoll_params(int epfd, const EpollParams& p) {
  RawEpollParams raw{p.busy_poll_usecs, p.budget, static_cast<std::uint8_t>(p.prefer ? 1 : 0), 0};
  if (::ioctl(epfd, kEpiocsparams, &raw) != 0) return fail_errno("ioctl(EPIOCSPARAMS)");
  return {};
}

Result<EpollParams> get_epoll_params(int epfd) {
  RawEpollParams raw{};
  if (::ioctl(epfd, kEpiocgparams, &raw) != 0) return fail_errno("ioctl(EPIOCGPARAMS)");
  return EpollParams{raw.busy_poll_usecs, raw.busy_poll_budget, raw.prefer_busy_poll != 0};
}

Result<BusyPollOptions> read_socket_options(int fd) {
  auto us = get_sockopt(fd, SO_BUSY_POLL, "getsockopt(SO_BUSY_POLL)");
  if (!us) return std::unexpected(us.error());
  auto pref = get_sockopt(fd, SO_PREFER_BUSY_POLL, "getsockopt(SO_PREFER_BUSY_POLL)");
  if (!pref) return std::unexpected(pref.error());
  // SO_BUSY_POLL_BUDGET has no getsockopt handler (ENOPROTOOPT): reported as 0.
  auto budget = get_sockopt(fd, SO_BUSY_POLL_BUDGET, "getsockopt(SO_BUSY_POLL_BUDGET)");
  if (!budget && budget.error().code != ENOPROTOOPT) return std::unexpected(budget.error());
  return BusyPollOptions{static_cast<std::uint32_t>(*us), *pref != 0, static_cast<std::uint16_t>(budget.value_or(0))};
}

Result<std::uint32_t> incoming_napi_id(int fd) {
  auto v = get_sockopt(fd, SO_INCOMING_NAPI_ID, "getsockopt(SO_INCOMING_NAPI_ID)");
  if (!v) return std::unexpected(v.error());
  return static_cast<std::uint32_t>(*v);
}

Result<std::uint64_t> busy_poll_rx_packets() {
  UniqueFd fd(::open("/proc/net/netstat", O_RDONLY | O_CLOEXEC));
  if (!fd) return fail_errno("open(/proc/net/netstat)");
  std::string text;
  std::array<char, 4096> buf{};
  for (;;) {
    const ssize_t n = ::read(fd.get(), buf.data(), buf.size());
    if (n < 0) return fail_errno("read(/proc/net/netstat)");
    if (n == 0) break;
    text.append(buf.data(), static_cast<std::size_t>(n));
  }
  // "TcpExt: name name ...\nTcpExt: value value ...\n": find the column, read the value.
  const std::string_view all(text);
  const auto h = all.find("TcpExt:");
  if (h == std::string_view::npos) return fail("BusyPollRxPackets", ENOENT);
  const auto h_end = all.find('\n', h);
  const auto v = all.find("TcpExt:", h_end);
  if (h_end == std::string_view::npos || v == std::string_view::npos) return fail("BusyPollRxPackets", ENOENT);
  std::string_view names = all.substr(h + 7, h_end - h - 7);
  std::string_view values = all.substr(v + 7, all.find('\n', v) - v - 7);
  auto next = [](std::string_view& sv) {
    while (!sv.empty() && sv.front() == ' ') sv.remove_prefix(1);
    const auto e = sv.find(' ');
    const std::string_view tok = sv.substr(0, e);
    sv.remove_prefix(e == std::string_view::npos ? sv.size() : e);
    return tok;
  };
  for (;;) {
    const std::string_view name = next(names);
    const std::string_view value = next(values);
    if (name.empty() || value.empty()) break;
    if (name == "BusyPollRxPackets") {
      std::uint64_t x = 0;
      std::from_chars(value.data(), value.data() + value.size(), x);
      return x;
    }
  }
  return fail("BusyPollRxPackets", ENOENT);
}

Result<void> set_napi_defer_hard_irqs(std::string_view ifname, std::uint32_t n) {
  return write_sysfs(ifname, "napi_defer_hard_irqs", n);
}
Result<void> set_gro_flush_timeout(std::string_view ifname, std::uint64_t ns) {
  return write_sysfs(ifname, "gro_flush_timeout", ns);
}
Result<std::uint64_t> napi_defer_hard_irqs(std::string_view ifname) { return read_sysfs(ifname, "napi_defer_hard_irqs"); }
Result<std::uint64_t> gro_flush_timeout(std::string_view ifname) { return read_sysfs(ifname, "gro_flush_timeout"); }

Result<std::size_t> list_napi(std::uint32_t ifindex, std::span<NapiInfo> out) {
  Genl nl;
  if (auto r = nl.open(); !r) return std::unexpected(r.error());
  auto fam = resolve_family(nl, NETDEV_FAMILY_NAME);
  if (!fam) return std::unexpected(fam.error());
  NlMsg m;
  const std::uint32_t seq = nl.next_seq();
  m.begin(*fam, NLM_F_REQUEST | NLM_F_DUMP, seq, NETDEV_CMD_NAPI_GET);
  m.put<std::uint32_t>(NETDEV_A_NAPI_IFINDEX, ifindex);
  if (auto r = nl.send(m.finish()); !r) return std::unexpected(r.error());
  std::size_t count = 0;
  auto r = nl.recv(seq, true, [&](const std::byte* p, std::size_t n) {
    NapiInfo info{};
    for_each_attr(p, n, [&](std::uint16_t t, std::span<const std::byte> v) {
      const std::uint64_t x = attr_uint(v);
      switch (t) {
        case NETDEV_A_NAPI_IFINDEX: info.ifindex = static_cast<std::uint32_t>(x); break;
        case NETDEV_A_NAPI_ID: info.id = static_cast<std::uint32_t>(x); break;
        case NETDEV_A_NAPI_IRQ: info.irq = static_cast<std::int32_t>(x); break;
        case NETDEV_A_NAPI_PID: info.pid = static_cast<std::int32_t>(x); break;
        case NETDEV_A_NAPI_DEFER_HARD_IRQS: info.defer_hard_irqs = static_cast<std::uint32_t>(x); break;
        case NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT: info.gro_flush_timeout_ns = x; break;
        case NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT: info.irq_suspend_timeout_ns = x; break;
        default: break;
      }
    });
    if (ifindex != 0 && info.ifindex != ifindex) return;
    if (count < out.size()) out[count] = info;
    ++count;
  });
  if (!r) return std::unexpected(r.error());
  return count;
}

Result<void> set_napi(const NapiSettings& s) {
  Genl nl;
  if (auto r = nl.open(); !r) return r;
  auto fam = resolve_family(nl, NETDEV_FAMILY_NAME);
  if (!fam) return std::unexpected(fam.error());
  NlMsg m;
  const std::uint32_t seq = nl.next_seq();
  m.begin(*fam, NLM_F_REQUEST | NLM_F_ACK, seq, NETDEV_CMD_NAPI_SET);
  m.put<std::uint32_t>(NETDEV_A_NAPI_ID, s.napi_id);
  if (s.defer_hard_irqs) m.put<std::uint32_t>(NETDEV_A_NAPI_DEFER_HARD_IRQS, *s.defer_hard_irqs);
  if (s.gro_flush_timeout_ns) m.put<std::uint64_t>(NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT, *s.gro_flush_timeout_ns);
  if (s.irq_suspend_timeout_ns) m.put<std::uint64_t>(NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT, *s.irq_suspend_timeout_ns);
  if (auto r = nl.send(m.finish()); !r) return r;
  return nl.recv(seq, false, [](const std::byte*, std::size_t) {});
}

Result<void> configure_reactor(sock::Poller& poller, const Config& c) {
  if (!poller.is_open()) return fail("configure_reactor", EBADF);
  return set_epoll_params(poller.fd(), c.epoll);
}

void apply_to(UdpConfig& u, const Config& c) noexcept { u.busy_poll = c.socket; }
void apply_to(TcpConfig& t, const Config& c) noexcept { t.busy_poll = c.socket; }

Result<void> configure_device(std::string_view ifname, const Config& c) {
  if (auto r = set_napi_defer_hard_irqs(ifname, c.napi_defer_hard_irqs); !r) return r;
  if (auto r = set_gro_flush_timeout(ifname, c.gro_flush_timeout_ns); !r) return r;
  if (c.mode != Mode::IrqSuspend) return {};
  const std::string name(ifname);
  const unsigned idx = ::if_nametoindex(name.c_str());
  if (idx == 0) return fail("if_nametoindex", ENODEV);
  std::array<NapiInfo, 64> napis{};
  auto n = list_napi(idx, napis);
  if (!n) return std::unexpected(n.error());
  if (*n == 0) return fail("list_napi", ENOENT);
  for (std::size_t i = 0; i < *n && i < napis.size(); ++i) {
    NapiSettings s;
    s.napi_id = napis[i].id;
    s.defer_hard_irqs = c.napi_defer_hard_irqs;
    s.gro_flush_timeout_ns = c.gro_flush_timeout_ns;
    s.irq_suspend_timeout_ns = c.irq_suspend_timeout_ns;
    if (auto r = set_napi(s); !r) return r;
  }
  return {};
}

}  // namespace lle::net::busypoll
