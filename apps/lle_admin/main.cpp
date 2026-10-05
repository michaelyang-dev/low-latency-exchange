// lle-admin: the operator's client for the authenticated admin port (05 §10
// E-15; ADR-028). Each invocation sends one command and prints the port's
// answer; accepted commands are journaled by the sequencer as Admin records
// and acted on by the engine at their journal position.
//
//   lle-admin [--host H] [--port P] --operator ID --key-file F [--seq N] [--dry-run] COMMAND ARGS...
//
// COMMAND is one of (admin/commands.h):
//   halt SYMBOL [REASON]                 quote-only SYMBOL [--price P] [--reason R]
//   resume SYMBOL                        ipo-schedule SYMBOL PRICE HH:MM:SS [--qualifier A|C]
//   ipo-quote SYMBOL                     ipo-release SYMBOL [--band B]
//   luld-bands SYMBOL LOWER UPPER        mwcb-levels L1 L2 L3          mwcb-breach 1|2|3
//   kill-switch ACCOUNT                  kill-reset ACCOUNT
//   risk-limit ACCOUNT KIND VALUE [SYMBOL]                             cross-cancel-permit ACCOUNT
//   regsho SYMBOL 0|1|2
// Prices are decimal dollars ("100.25"), index levels decimal with up to 8
// places. The sequence defaults to the current UNIX time in nanoseconds, which
// increases across invocations; --seq sets it explicitly (it must exceed the
// operator's last accepted one).
//
// Day start is not an admin command: the sequencer journals the day's tables
// (seq::EngineDay, src/sequencer/engine_day.h) in start_day; after that, every
// change goes through this tool.
//
// Exit status: 0 accepted, 1 rejected by the port, 2 usage, I/O or key error.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "admin/commands.h"
#include "admin/net.h"
#include "admin/protocol.h"

namespace {

int usage(const std::string& why = {}) {
  if (!why.empty()) std::fprintf(stderr, "lle-admin: %s\n", why.c_str());
  std::fprintf(stderr,
               "usage: lle-admin [--host H] [--port P] --operator ID --key-file F [--seq N] [--dry-run] COMMAND ARGS...\n"
               "  commands: halt quote-only resume ipo-schedule ipo-quote ipo-release luld-bands mwcb-levels\n"
               "            mwcb-breach kill-switch kill-reset risk-limit cross-cancel-permit regsho\n");
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  std::string host = "127.0.0.1", key_file;
  std::uint16_t port = 7500;
  std::uint32_t op = 0;
  std::uint64_t seq = 0;
  bool dry = false;
  int i = 1;
  for (; i < argc; ++i) {
    const std::string_view a(argv[i]);
    if (!a.starts_with("--")) break;
    if (a == "--dry-run") {
      dry = true;
      continue;
    }
    if (i + 1 >= argc) return usage("missing value for " + std::string(a));
    const std::string_view v(argv[++i]);
    if (a == "--host") {
      host = std::string(v);
    } else if (a == "--port") {
      const auto p = lle::admin::parse_uint(v);
      if (!p || *p == 0 || *p > 65535) return usage("bad port");
      port = static_cast<std::uint16_t>(*p);
    } else if (a == "--operator") {
      const auto p = lle::admin::parse_uint(v);
      if (!p || *p > 0xFFFFFFFFu) return usage("bad operator id");
      op = static_cast<std::uint32_t>(*p);
    } else if (a == "--key-file") {
      key_file = std::string(v);
    } else if (a == "--seq") {
      const auto p = lle::admin::parse_uint(v);
      if (!p) return usage("bad sequence");
      seq = *p;
    } else {
      return usage("unknown option " + std::string(a));
    }
  }
  if (i >= argc) return usage("no command");
  std::vector<std::string_view> words;
  for (; i < argc; ++i) words.emplace_back(argv[i]);
  const auto cmd = lle::admin::parse_command(words);
  if (!cmd) return usage(cmd.error());
  if (key_file.empty() && !dry) return usage("--key-file is required");
  lle::admin::Key key;
  if (!key_file.empty()) {
    auto k = lle::admin::load_key_file(key_file);
    if (!k) return usage(k.error());
    key = std::move(*k);
  }
  if (seq == 0) {
    seq = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
  }
  const auto frame = lle::admin::encode_request(lle::admin::Request{op, seq, cmd->command, 1, cmd->args}, key);
  if (dry) {
    std::printf("command %u, %zu argument bytes, frame:", static_cast<unsigned>(cmd->command), cmd->args.size());
    for (std::byte b : frame) std::printf(" %02x", std::to_integer<unsigned>(b));
    std::printf("\n");
    return 0;
  }
  const auto resp = lle::admin::exchange(host, port, frame);
  if (!resp) {
    std::fprintf(stderr, "lle-admin: %s\n", resp.error().c_str());
    return 2;
  }
  const auto r = lle::admin::decode_response(*resp, key);
  if (!r) {
    std::fprintf(stderr, "lle-admin: bad response: %s\n", std::string(lle::admin::to_string(r.error())).c_str());
    return 2;
  }
  if (r->accepted) {
    std::printf("accepted (operator %u, sequence %llu)\n", r->operator_id,
                static_cast<unsigned long long>(r->sequence));
    return 0;
  }
  std::printf("rejected: %s\n", std::string(lle::admin::to_string(r->reason)).c_str());
  return 1;
}
