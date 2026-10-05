#include "net/xsk/napi.h"

#include <linux/genetlink.h>
#include <linux/netdev.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>

namespace lle::net::xsk {
namespace {

constexpr std::size_t align4(std::size_t n) { return (n + 3) & ~std::size_t{3}; }

// Minimal generic-netlink request/response helper (explicit offsets, no NLMSG macros).
class Genl {
 public:
  Genl() { fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC); }
  ~Genl() {
    if (fd_ >= 0) ::close(fd_);
  }
  Genl(const Genl&) = delete;
  Genl& operator=(const Genl&) = delete;
  [[nodiscard]] bool ok() const { return fd_ >= 0; }

  void begin(std::uint16_t family, std::uint8_t cmd, std::uint16_t flags) {
    len_ = align4(sizeof(nlmsghdr)) + align4(sizeof(genlmsghdr));
    std::memset(buf_, 0, len_);
    nlmsghdr nh{};
    nh.nlmsg_type = family;
    nh.nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST | flags);
    nh.nlmsg_seq = ++seq_;
    std::memcpy(buf_, &nh, sizeof(nh));
    genlmsghdr gh{};
    gh.cmd = cmd;
    gh.version = 1;
    std::memcpy(buf_ + align4(sizeof(nlmsghdr)), &gh, sizeof(gh));
  }
  void attr(std::uint16_t type, const void* data, std::size_t n) {
    nlattr a{};
    a.nla_type = type;
    a.nla_len = static_cast<std::uint16_t>(sizeof(nlattr) + n);
    std::memcpy(buf_ + len_, &a, sizeof(a));
    std::memcpy(buf_ + len_ + sizeof(nlattr), data, n);
    len_ += align4(sizeof(nlattr) + n);
  }
  void attr_u32(std::uint16_t type, std::uint32_t v) { attr(type, &v, sizeof(v)); }
  void attr_str(std::uint16_t type, const char* s) { attr(type, s, std::strlen(s) + 1); }

  // Sends and walks the replies; cb(attr_type, data, len) for each top-level attribute of
  // each data message. Returns 0 or errno (from NLMSG_ERROR).
  template <class Cb>
  int transact(Cb&& cb) {
    nlmsghdr nh;
    std::memcpy(&nh, buf_, sizeof(nh));
    nh.nlmsg_len = static_cast<std::uint32_t>(len_);
    std::memcpy(buf_, &nh, sizeof(nh));
    sockaddr_nl k{};
    k.nl_family = AF_NETLINK;
    if (::sendto(fd_, buf_, len_, 0, reinterpret_cast<const sockaddr*>(&k), sizeof(k)) < 0) return errno;
    while (true) {
      const ssize_t got = ::recv(fd_, rbuf_, sizeof(rbuf_), 0);
      if (got < 0) return errno;
      const auto n = static_cast<std::size_t>(got);
      std::size_t off = 0;
      bool more = false;
      while (off + sizeof(nlmsghdr) <= n) {
        nlmsghdr h;
        std::memcpy(&h, rbuf_ + off, sizeof(h));
        if (h.nlmsg_len < sizeof(nlmsghdr) || off + h.nlmsg_len > n) break;
        const unsigned char* p = rbuf_ + off + align4(sizeof(nlmsghdr));
        const std::size_t plen = h.nlmsg_len - align4(sizeof(nlmsghdr));
        off += align4(h.nlmsg_len);
        if (h.nlmsg_type == NLMSG_ERROR) {
          nlmsgerr e{};
          std::memcpy(&e, p, plen < sizeof(e) ? plen : sizeof(e));
          return -e.error;  // 0 = ACK
        }
        if (h.nlmsg_type == NLMSG_DONE) return 0;
        if ((h.nlmsg_flags & NLM_F_MULTI) != 0) more = true;
        std::size_t a = align4(sizeof(genlmsghdr));
        while (a + sizeof(nlattr) <= plen) {
          nlattr na;
          std::memcpy(&na, p + a, sizeof(na));
          if (na.nla_len < sizeof(nlattr) || a + na.nla_len > plen) break;
          cb(static_cast<std::uint16_t>(na.nla_type & NLA_TYPE_MASK), p + a + sizeof(nlattr), na.nla_len - sizeof(nlattr));
          a += align4(na.nla_len);
        }
      }
      if (!more) return 0;
    }
  }

 private:
  int fd_ = -1;
  std::uint32_t seq_ = 0;
  std::size_t len_ = 0;
  alignas(8) unsigned char buf_[512]{};
  alignas(8) unsigned char rbuf_[16384]{};
};

std::uint32_t read_u32(const unsigned char* p) {
  std::uint32_t v;
  std::memcpy(&v, p, 4);
  return v;
}

std::expected<std::uint16_t, int> netdev_family(Genl& g) {
  g.begin(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0);
  g.attr_str(CTRL_ATTR_FAMILY_NAME, NETDEV_FAMILY_NAME);
  std::uint16_t id = 0;
  const int rc = g.transact([&](std::uint16_t t, const unsigned char* d, std::size_t n) {
    if (t == CTRL_ATTR_FAMILY_ID && n >= 2) std::memcpy(&id, d, 2);
  });
  if (rc != 0) return std::unexpected(rc);
  if (id == 0) return std::unexpected(ENOENT);
  return id;
}

}  // namespace

std::expected<std::uint32_t, int> napi_id_for_rx_queue(int ifindex, std::uint32_t queue) {
  Genl g;
  if (!g.ok()) return std::unexpected(errno);
  auto fam = netdev_family(g);
  if (!fam) return std::unexpected(fam.error());
  g.begin(*fam, NETDEV_CMD_QUEUE_GET, NLM_F_ACK);
  g.attr_u32(NETDEV_A_QUEUE_IFINDEX, static_cast<std::uint32_t>(ifindex));
  g.attr_u32(NETDEV_A_QUEUE_TYPE, NETDEV_QUEUE_TYPE_RX);
  g.attr_u32(NETDEV_A_QUEUE_ID, queue);
  std::uint32_t napi = 0;
  const int rc = g.transact([&](std::uint16_t t, const unsigned char* d, std::size_t n) {
    if (t == NETDEV_A_QUEUE_NAPI_ID && n >= 4) napi = read_u32(d);
  });
  if (rc != 0) return std::unexpected(rc);
  if (napi == 0) return std::unexpected(ENOENT);
  return napi;
}

std::expected<NapiInfo, int> napi_get(std::uint32_t napi_id) {
  Genl g;
  if (!g.ok()) return std::unexpected(errno);
  auto fam = netdev_family(g);
  if (!fam) return std::unexpected(fam.error());
  g.begin(*fam, NETDEV_CMD_NAPI_GET, NLM_F_ACK);
  g.attr_u32(NETDEV_A_NAPI_ID, napi_id);
  NapiInfo info;
  const int rc = g.transact([&](std::uint16_t t, const unsigned char* d, std::size_t n) {
    if (n < 4) return;
    const std::uint32_t v = read_u32(d);
    switch (t) {
      case NETDEV_A_NAPI_ID: info.id = v; break;
      case NETDEV_A_NAPI_IFINDEX: info.ifindex = static_cast<std::int32_t>(v); break;
      case NETDEV_A_NAPI_IRQ: info.irq = static_cast<std::int32_t>(v); break;
      case NETDEV_A_NAPI_PID: info.pid = static_cast<std::int32_t>(v); break;
      case NETDEV_A_NAPI_THREADED: info.threaded = static_cast<std::int32_t>(v); break;
      default: break;
    }
  });
  if (rc != 0) return std::unexpected(rc);
  return info;
}

std::expected<void, int> napi_set_threaded(std::uint32_t napi_id, NapiThreaded mode) {
  Genl g;
  if (!g.ok()) return std::unexpected(errno);
  auto fam = netdev_family(g);
  if (!fam) return std::unexpected(fam.error());
  g.begin(*fam, NETDEV_CMD_NAPI_SET, NLM_F_ACK);
  g.attr_u32(NETDEV_A_NAPI_ID, napi_id);
  g.attr_u32(NETDEV_A_NAPI_THREADED, static_cast<std::uint32_t>(mode));
  const int rc = g.transact([](std::uint16_t, const unsigned char*, std::size_t) {});
  if (rc != 0) return std::unexpected(rc);
  return {};
}

}  // namespace lle::net::xsk
