// witnessd: the durable witness W (10 §1–§2) on host C.
//
//   witnessd --state FILE --init --primary 0|1 [--epoch N] [--inc0 N] [--inc1 N] [--force]
//   witnessd --state FILE --reinit --epoch N --primary 0|1 [--members 0|1|01] [--inc0 N] [--inc1 N]
//   witnessd --state FILE --show
//   witnessd --state FILE --listen IP:PORT [--tie-break-ms 5]
//
// The state file holds the two 4 KiB slots (offsets 0 and 4096) written with
// O_DSYNC. W refuses to start without a valid slot. Repair is a manual
// --reinit with an epoch above anything either node has seen, after
// inspecting both nodes (10 §2). Every reply leaves only after the state it
// reflects is on disk (the core enforces this; a failed write stops W).
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>

#include "witness/control.h"
#include "witness/witness.h"

namespace {

using namespace lle::witness;

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

lle::Nanos mono_now() {
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<lle::Nanos>(ts.tv_sec) * lle::kNsPerSec + ts.tv_nsec;
}

[[noreturn]] void die(const std::string& msg) {
  std::fprintf(stderr, "witnessd: %s\n", msg.c_str());
  std::exit(1);
}

struct Args {
  std::string state;
  std::string mode;  // init | reinit | show | listen
  std::string listen;
  std::optional<unsigned> primary;
  std::optional<std::uint64_t> epoch;
  std::string members;
  std::uint64_t inc[kNodes] = {0, 0};
  bool force = false;
  long tie_break_ms = 5;
};

Args parse(int argc, char** argv) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    const std::string_view k = argv[i];
    auto val = [&]() -> std::string {
      if (i + 1 >= argc) die("missing value for " + std::string(k));
      return argv[++i];
    };
    auto num = [&]() -> std::uint64_t {
      const std::string v = val();
      char* end = nullptr;
      const std::uint64_t x = std::strtoull(v.c_str(), &end, 10);
      if (end == v.c_str() || *end != '\0') die("bad number " + v);
      return x;
    };
    if (k == "--state") a.state = val();
    else if (k == "--init") a.mode = "init";
    else if (k == "--reinit") a.mode = "reinit";
    else if (k == "--show") a.mode = "show";
    else if (k == "--listen") {
      a.mode = "listen";
      a.listen = val();
    } else if (k == "--primary") a.primary = static_cast<unsigned>(num());
    else if (k == "--epoch") a.epoch = num();
    else if (k == "--members") a.members = val();
    else if (k == "--inc0") a.inc[0] = num();
    else if (k == "--inc1") a.inc[1] = num();
    else if (k == "--force") a.force = true;
    else if (k == "--tie-break-ms") a.tie_break_ms = static_cast<long>(num());
    else die("unknown option " + std::string(k));
  }
  if (a.state.empty() || a.mode.empty())
    die("usage: witnessd --state FILE (--init --primary P | --reinit --epoch N --primary P | --show | --listen IP:PORT)");
  return a;
}

struct Slots {
  SlotImage s[kSlots]{};
};

bool read_slots(int fd, Slots& out) {
  for (std::size_t i = 0; i < kSlots; ++i)
    if (pread(fd, out.s[i].data(), kSlotBytes, static_cast<off_t>(i * kSlotBytes)) != static_cast<ssize_t>(kSlotBytes))
      return false;
  return true;
}

void write_slot_or_die(int fd, std::size_t slot, const SlotImage& img) {
  const ssize_t n = pwrite(fd, img.data(), kSlotBytes, static_cast<off_t>(slot * kSlotBytes));
  if (n != static_cast<ssize_t>(kSlotBytes)) die(std::string("slot write failed: ") + std::strerror(errno));
}

void fsync_dir_of(const std::string& path) {
  const auto slash = path.find_last_of('/');
  const std::string dir = slash == std::string::npos ? "." : path.substr(0, slash == 0 ? 1 : slash);
  const int d = ::open(dir.c_str(), O_RDONLY);
  if (d >= 0) {
    ::fsync(d);
    ::close(d);
  }
}

std::string describe(const State& s) {
  char b[256];
  std::snprintf(b, sizeof b, "epoch %llu primary %u members {%s%s%s} inc [%llu, %llu]",
                static_cast<unsigned long long>(s.epoch), s.primary, is_member(s.members, 0) ? "0" : "",
                s.members == 0b11 ? "," : "", is_member(s.members, 1) ? "1" : "",
                static_cast<unsigned long long>(s.inc[0]), static_cast<unsigned long long>(s.inc[1]));
  return b;
}

Members parse_members(const std::string& m, unsigned primary) {
  if (m.empty()) return 0b11;
  Members out = 0;
  for (char c : m) {
    if (c == '0') out = static_cast<Members>(out | member_bit(0));
    else if (c == '1') out = static_cast<Members>(out | member_bit(1));
    else if (c != ',') die("bad --members " + m);
  }
  if (!is_member(out, static_cast<NodeId>(primary))) die("--members must include the primary");
  return out;
}

int cmd_init(const Args& a) {
  if (!a.primary || *a.primary >= kNodes) die("--init needs --primary 0|1");
  struct stat st{};
  if (::stat(a.state.c_str(), &st) == 0 && !a.force) die(a.state + " exists (use --force to overwrite)");
  State s;
  s.epoch = a.epoch.value_or(1);
  s.primary = static_cast<NodeId>(*a.primary);
  s.members = parse_members(a.members, *a.primary);
  s.inc = {a.inc[0], a.inc[1]};
  if (!valid_state(s)) die("invalid initial state");
  const int fd = ::open(a.state.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_DSYNC, 0644);
  if (fd < 0) die(a.state + ": " + std::strerror(errno));
  write_slot_or_die(fd, 0, encode_slot(s, 1));
  write_slot_or_die(fd, 1, SlotImage{});
  ::fsync(fd);
  ::close(fd);
  fsync_dir_of(a.state);
  std::printf("initialized: %s\n", describe(s).c_str());
  return 0;
}

int cmd_reinit(const Args& a) {
  if (!a.primary || *a.primary >= kNodes || !a.epoch) die("--reinit needs --epoch N and --primary 0|1");
  const int fd = ::open(a.state.c_str(), O_RDWR | O_DSYNC);
  if (fd < 0) die(a.state + ": " + std::strerror(errno));
  Slots sl;
  std::uint64_t gen = 1;
  std::size_t slot = 0;
  if (read_slots(fd, sl)) {
    if (const auto d = choose(sl.s[0], sl.s[1])) {
      if (*a.epoch <= d->state.epoch) die("--epoch must exceed the current epoch " + std::to_string(d->state.epoch));
      gen = d->generation + 1;
      slot = 1 - d->slot;
    }
  }
  State s;
  s.epoch = *a.epoch;
  s.primary = static_cast<NodeId>(*a.primary);
  s.members = parse_members(a.members, *a.primary);
  s.inc = {a.inc[0], a.inc[1]};
  if (!valid_state(s)) die("invalid state");
  write_slot_or_die(fd, slot, encode_slot(s, gen));
  ::fsync(fd);
  ::close(fd);
  std::printf("reinitialized: %s (generation %llu)\n", describe(s).c_str(), static_cast<unsigned long long>(gen));
  return 0;
}

int cmd_show(const Args& a) {
  const int fd = ::open(a.state.c_str(), O_RDONLY);
  if (fd < 0) die(a.state + ": " + std::strerror(errno));
  Slots sl;
  const bool ok = read_slots(fd, sl);
  ::close(fd);
  if (!ok) die("short state file");
  for (std::size_t i = 0; i < kSlots; ++i) {
    if (const auto d = decode_slot(sl.s[i], i))
      std::printf("slot %zu: generation %llu, %s\n", i, static_cast<unsigned long long>(d->generation),
                  describe(d->state).c_str());
    else std::printf("slot %zu: invalid\n", i);
  }
  const auto d = choose(sl.s[0], sl.s[1]);
  if (!d) die("no valid slot: W refuses to start");
  std::printf("current: slot %zu\n", d->slot);
  return 0;
}

int cmd_listen(const Args& a) {
  const int fd = ::open(a.state.c_str(), O_RDWR | O_DSYNC);
  if (fd < 0) die(a.state + ": " + std::strerror(errno));
  Slots sl;
  if (!read_slots(fd, sl)) die("short state file");
  const auto durable = choose(sl.s[0], sl.s[1]);
  if (!durable) die("no valid state slot: refusing to start (repair with --reinit after inspecting both nodes)");

  const auto colon = a.listen.rfind(':');
  if (colon == std::string::npos) die("--listen needs IP:PORT");
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(std::stoul(a.listen.substr(colon + 1))));
  if (inet_pton(AF_INET, a.listen.substr(0, colon).c_str(), &addr.sin_addr) != 1) die("bad address " + a.listen);
  const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) die(std::string("socket: ") + std::strerror(errno));
  if (::bind(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0)
    die(std::string("bind: ") + std::strerror(errno));
  sockaddr_in bound{};
  socklen_t blen = sizeof bound;
  ::getsockname(sock, reinterpret_cast<sockaddr*>(&bound), &blen);

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  Witness w(Config{static_cast<lle::Nanos>(a.tie_break_ms) * 1'000'000}, *durable, mono_now());
  std::printf("witnessd: listening on port %u, %s\n", ntohs(bound.sin_port), describe(w.state()).c_str());
  std::fflush(stdout);

  std::byte buf[2048];
  while (!g_stop) {
    pollfd p{sock, POLLIN, 0};
    if (::poll(&p, 1, 10) <= 0) continue;
    sockaddr_in from{};
    socklen_t flen = sizeof from;
    const ssize_t n = ::recvfrom(sock, buf, sizeof buf, 0, reinterpret_cast<sockaddr*>(&from), &flen);
    if (n <= 0) continue;
    const auto m = decode(std::span<const std::byte>(buf, static_cast<std::size_t>(n)));
    if (!m) continue;  // not ours or damaged: drop silently
    const lle::env::Endpoint ep{ntohl(from.sin_addr.s_addr), ntohs(from.sin_port)};
    const std::uint64_t before = w.state().epoch;
    w.handle(*m, ep, mono_now());
    while (auto job = w.begin_write()) {
      if (pwrite(fd, job->image.data(), kSlotBytes, static_cast<off_t>(job->slot * kSlotBytes)) !=
          static_cast<ssize_t>(kSlotBytes)) {
        w.on_write_failed();
        die(std::string("state write failed (W stops; restart after checking the disk): ") + std::strerror(errno));
      }
      w.on_persisted(job->generation);
    }
    if (w.state().epoch != before)
      std::printf("witnessd: %s granted: %s\n", to_string(type_of(*m)), describe(w.state()).c_str());
    w.drain([&](const lle::env::Endpoint& to, std::span<const std::byte> b) {
      sockaddr_in dst{};
      dst.sin_family = AF_INET;
      dst.sin_addr.s_addr = htonl(to.ipv4);
      dst.sin_port = htons(to.port);
      ::sendto(sock, b.data(), b.size(), 0, reinterpret_cast<const sockaddr*>(&dst), sizeof dst);
    });
    std::fflush(stdout);
  }
  ::close(sock);
  ::close(fd);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const Args a = parse(argc, argv);
  if (a.mode == "init") return cmd_init(a);
  if (a.mode == "reinit") return cmd_reinit(a);
  if (a.mode == "show") return cmd_show(a);
  return cmd_listen(a);
}
