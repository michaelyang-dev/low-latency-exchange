// witnessd as a process: init, grant over UDP, SIGKILL, restart from the state
// file, and a retransmitted request answered with the identical GRANT.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "common/assert.h"
#include "witness/control.h"

extern char** environ;

namespace lle::witness {
namespace {

std::string run(const std::vector<std::string>& args) {
  std::string cmd;
  for (const auto& a : args) cmd += "'" + a + "' ";
  std::string out;
  if (FILE* p = ::popen((cmd + "2>&1").c_str(), "r")) {
    char buf[256];
    while (std::fgets(buf, sizeof buf, p)) out += buf;
    ::pclose(p);
  }
  return out;
}

class Daemon {
 public:
  explicit Daemon(const std::string& state) {
    int fds[2];
    LLE_ASSERT(::pipe(fds) == 0, "pipe");
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    std::vector<std::string> args = {LLE_WITNESSD, "--state", state, "--listen", "127.0.0.1:0", "--tie-break-ms", "0"};
    std::vector<char*> argv;
    for (auto& s : args) argv.push_back(s.data());
    argv.push_back(nullptr);
    LLE_ASSERT(posix_spawn(&pid_, LLE_WITNESSD, &fa, nullptr, argv.data(), environ) == 0, "spawn");
    posix_spawn_file_actions_destroy(&fa);
    ::close(fds[1]);
    // First line: "witnessd: listening on port N, ..."
    std::string line;
    char c;
    while (::read(fds[0], &c, 1) == 1 && c != '\n') line += c;
    out_ = fds[0];
    const auto at = line.find("port ");
    LLE_ASSERT(at != std::string::npos, "no port line");
    port_ = static_cast<std::uint16_t>(std::stoul(line.substr(at + 5)));
  }
  ~Daemon() { kill9(); }
  void kill9() {
    if (pid_ > 0) {
      ::kill(pid_, SIGKILL);
      int st = 0;
      ::waitpid(pid_, &st, 0);
      pid_ = -1;
      ::close(out_);
    }
  }
  [[nodiscard]] std::uint16_t port() const { return port_; }

 private:
  pid_t pid_ = -1;
  int out_ = -1;
  std::uint16_t port_ = 0;
};

std::optional<Message> ask(std::uint16_t port, const Message& req) {
  const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in to{};
  to.sin_family = AF_INET;
  to.sin_port = htons(port);
  to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const Encoded e = encode(req);
  ::sendto(s, e.bytes.data(), e.size, 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
  pollfd p{s, POLLIN, 0};
  std::optional<Message> out;
  if (::poll(&p, 1, 5000) == 1) {
    std::byte buf[128];
    const ssize_t n = ::recv(s, buf, sizeof buf, 0);
    if (n > 0) {
      auto d = decode(std::span<const std::byte>(buf, static_cast<std::size_t>(n)));
      if (d) out = *d;
    }
  }
  ::close(s);
  return out;
}

TEST(Witnessd, GrantSurvivesSigkillAndRestart) {
  const auto dir = std::filesystem::temp_directory_path() / ("witnessd-test-" + std::to_string(::getpid()));
  std::filesystem::create_directories(dir);
  const std::string state = (dir / "witness.state").string();
  ASSERT_NE(run({LLE_WITNESSD, "--state", state, "--init", "--primary", "0"}).find("initialized"), std::string::npos);
  // A second --init without --force must refuse.
  EXPECT_NE(run({LLE_WITNESSD, "--state", state, "--init", "--primary", "1"}).find("exists"), std::string::npos);

  Grant first;
  {
    Daemon d(state);
    const auto r = ask(d.port(), Promote{1, 1, 0, 42});
    ASSERT_TRUE(r.has_value());
    ASSERT_TRUE(std::holds_alternative<Grant>(*r));
    first = std::get<Grant>(*r);
    EXPECT_EQ(first.epoch, 2u);
    EXPECT_EQ(first.primary, 1);
    d.kill9();  // no clean shutdown
  }
  {
    Daemon d(state);
    // The node lost the GRANT and retransmits: same grant, no new epoch.
    const auto again = ask(d.port(), Promote{1, 1, 0, 42});
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(std::get<Grant>(*again), first);
    // The old primary's SOLO for epoch 1 is stale.
    const auto stale = ask(d.port(), Solo{1, 0, 0});
    ASSERT_TRUE(stale.has_value());
    EXPECT_EQ(std::get<Reject>(*stale).reason, RejectReason::kStaleEpoch);
    EXPECT_EQ(std::get<Reject>(*stale).primary, 1);
  }
  const std::string shown = run({LLE_WITNESSD, "--state", state, "--show"});
  EXPECT_NE(shown.find("epoch 2 primary 1 members {1}"), std::string::npos) << shown;
  // Repair must move the epoch forward.
  EXPECT_NE(run({LLE_WITNESSD, "--state", state, "--reinit", "--epoch", "2", "--primary", "0"}).find("must exceed"),
            std::string::npos);
  EXPECT_NE(run({LLE_WITNESSD, "--state", state, "--reinit", "--epoch", "7", "--primary", "0"}).find("reinitialized"),
            std::string::npos);
  EXPECT_NE(run({LLE_WITNESSD, "--state", state, "--show"}).find("epoch 7 primary 0 members {0,1}"), std::string::npos);
  std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace lle::witness
