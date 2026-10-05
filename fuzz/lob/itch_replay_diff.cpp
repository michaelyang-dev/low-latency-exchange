// itch_replay_diff: real NASDAQ ITCH 5.0 days into every book variant and into
// RefBook, compared message by message (04-order-book §8 "Harnesses").
//
//   itch_replay_diff --file data/itch/01302019.NASDAQ_ITCH50.gz [--variant NAME|all]
//                    [--max-records N] [--full-check-every K] [--jobs J]
//                    [--ledger fuzz/ledger/runs.jsonl]
//
// Every book message (R, A, F, E, C, X, D, U) goes through the same adapter
// as lob_replay (book/itch_adapter.h) and becomes one operation applied to
// both books. After each operation the harness compares the result codes, the
// presence and content of the BBO-change event, and the running stream
// digest. Every K operations and at the end of the file it also compares the
// final-books digest and live counts and runs both invariant checkers.
//
// Ledger records carry harness "itch_replay_diff". Real-file operations are
// reported separately and never counted toward the random-fuzzing headline
// (T14). The plain-file SHA-256 identifies the replayed bytes.
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "book/itch_adapter.h"
#include "book/variants.h"
#include "common/endian.h"
#include "common/sha256.h"
#include "diff.hpp"
#include "proto/itch50/binary_file.h"
#include "provenance.hpp"

namespace {

using lle::lobfuzz::DiffPair;
using lle::lobfuzz::Op;
namespace book = lle::book;

struct Args {
  std::string file;
  std::string variant = "all";
  std::uint64_t max_records = 0;
  std::uint64_t full_every = std::uint64_t{1} << 22;
  unsigned jobs = 1;
  std::string ledger;
};

struct Stats {
  std::uint64_t messages = 0;  // every record read
  std::uint64_t ops = 0;       // book operations applied to both books and compared
  std::uint64_t full_checks = 0;
  std::uint64_t events = 0;
  std::uint64_t divergences = 0;
  std::string first_divergence;
  std::string sha256;
};

bool to_op(const book::ItchEvent& e, Op& op) {
  op = Op{};
  op.loc = e.loc;
  switch (e.kind) {
    case book::ItchKind::kDirectory: op.kind = Op::Kind::kDeclare; return true;
    case book::ItchKind::kAdd:
      op.kind = Op::Kind::kAdd;
      op.side = e.side;
      op.ref = e.ref;
      op.px = e.px;
      op.qty = e.qty;
      return true;
    case book::ItchKind::kExecute:
    case book::ItchKind::kExecPrice:
    case book::ItchKind::kCancel:
      op.kind = Op::Kind::kReduce;
      op.ref = e.ref;
      op.qty = e.qty;
      return true;
    case book::ItchKind::kDelete:
      op.kind = Op::Kind::kRemove;
      op.ref = e.ref;
      return true;
    case book::ItchKind::kReplace:
      op.kind = Op::Kind::kReplace;
      op.ref = e.ref;
      op.new_ref = e.new_ref;
      op.px = e.px;
      op.qty = e.qty;
      return true;
    case book::ItchKind::kOther:
    case book::ItchKind::kMalformed: return false;
  }
  return false;
}

template <class V>
Stats run_variant(const Args& a) {
  Stats st;
  lle::itch50::BinaryFileReader rd;
  if (auto r = rd.open(a.file); !r) {
    st.divergences = 1;
    st.first_divergence = "cannot open input: " + r.error();
    return st;
  }
  book::BookConfig cfg;
  cfg.reserve_orders = std::size_t{1} << 21;
  cfg.reserve_levels = std::size_t{1} << 16;
  auto pair = std::make_unique<DiffPair<V>>(cfg);
  lle::Sha256 sha;
  std::string why;
  auto diverge = [&](const std::string& what) {
    ++st.divergences;
    st.first_divergence = "message " + std::to_string(st.messages) + ": " + what;
  };
  for (;;) {
    if (a.max_records != 0 && st.messages == a.max_records) break;
    const lle::itch50::Record rec = rd.next();
    if (rec.status == lle::itch50::RecordStatus::EndOfFile) break;
    if (rec.status == lle::itch50::RecordStatus::Truncated || rec.status == lle::itch50::RecordStatus::IoError) {
      diverge(rec.status == lle::itch50::RecordStatus::Truncated ? "input truncated" : "read error: " + rd.error());
      return st;
    }
    std::byte len[2];
    lle::store_be16(len, static_cast<std::uint16_t>(rec.data.size()));
    sha.update(len, 2);
    sha.update(rec.data.data(), rec.data.size());
    if (rec.status != lle::itch50::RecordStatus::Message) continue;
    ++st.messages;
    const book::ItchEvent e = book::decode_book_event(rec.data.data(), rec.data.size());
    if (e.kind == book::ItchKind::kMalformed) {
      diverge("malformed message type " + std::to_string(static_cast<int>(rec.data[0])));
      return st;
    }
    Op op;
    if (!to_op(e, op)) continue;
    ++st.ops;
    if (!pair->step(op, &why)) {
      diverge(lle::lobfuzz::to_string(op) + ": " + why);
      return st;
    }
    if (a.full_every != 0 && st.ops % a.full_every == 0) {
      ++st.full_checks;
      if (!pair->full_check(&why)) {
        diverge("full check: " + why);
        return st;
      }
    }
  }
  ++st.full_checks;
  if (!pair->full_check(&why)) diverge("final full check: " + why);
  st.events = pair->ref().event_count();
  st.sha256 = a.max_records == 0 ? lle::Sha256::hex(sha.finish()) : "prefix";
  return st;
}

void append_ledger(const Args& a, const lle::lobfuzz::Provenance& pv, std::string_view variant, const Stats& st,
                   double wall_s) {
  if (a.ledger.empty()) return;
  if (!pv.fresh) {
    std::fprintf(stderr, "%s: not writing the ledger: %s is newer than this binary (rebuild first)\n", "itch_replay_diff",
                 pv.stale_file.c_str());
    return;
  }
  using lle::lobfuzz::json_escape;
  std::filesystem::create_directories(std::filesystem::path(a.ledger).parent_path());
  FILE* f = std::fopen(a.ledger.c_str(), "a");
  if (f == nullptr) {
    std::fprintf(stderr, "itch_replay_diff: cannot open ledger %s\n", a.ledger.c_str());
    return;
  }
  const std::string file = std::filesystem::path(a.file).filename().string();
  std::fprintf(f,
               "{\"run_id\":\"itch_replay_diff-%s-%d-%s\",\"harness\":\"itch_replay_diff\",\"sha\":\"%s\","
               "\"dirty\":%s,\"tree\":\"%s\",\"build\":\"%s\",\"variant\":\"%s\",\"file\":\"%s\","
               "\"file_sha256\":\"%s\",\"max_records\":%" PRIu64 ",\"messages\":%" PRIu64 ",\"ops\":%" PRIu64
               ",\"full_checks\":%" PRIu64 ",\"bbo_events\":%" PRIu64 ",\"divergences\":%" PRIu64
               ",\"wall_s\":%.3f,\"host\":\"%s\",\"date\":\"%s\"%s%s%s}\n",
               pv.date.c_str(), static_cast<int>(::getpid()), json_escape(variant).c_str(), json_escape(pv.sha).c_str(),
               pv.dirty ? "true" : "false", pv.tree.c_str(), json_escape(pv.build).c_str(),
               json_escape(variant).c_str(), json_escape(file).c_str(), st.sha256.c_str(), a.max_records, st.messages,
               st.ops, st.full_checks, st.events, st.divergences, wall_s, json_escape(pv.host).c_str(),
               pv.date.c_str(), st.divergences != 0 ? ",\"first_divergence\":\"" : "",
               st.divergences != 0 ? json_escape(st.first_divergence).c_str() : "", st.divergences != 0 ? "\"" : "");
  std::fclose(f);
}

template <class V>
int run_and_report(const Args& a, const lle::lobfuzz::Provenance& pv) {
  const auto t0 = std::chrono::steady_clock::now();
  const Stats st = run_variant<V>(a);
  const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  append_ledger(a, pv, V::kName, st, wall);
  std::fprintf(stderr, "%-14s messages %12" PRIu64 "  ops %12" PRIu64 "  full checks %6" PRIu64 "  events %11" PRIu64
               "  divergences %" PRIu64 "  %.1f s%s%s\n",
               std::string(V::kName).c_str(), st.messages, st.ops, st.full_checks, st.events, st.divergences, wall,
               st.divergences ? "\n  first: " : "", st.first_divergence.c_str());
  return st.divergences == 0 ? 0 : 1;
}

[[noreturn]] void usage(const char* msg) {
  if (msg) std::fprintf(stderr, "itch_replay_diff: %s\n", msg);
  std::fprintf(stderr,
               "usage: itch_replay_diff --file PATH [--variant NAME|all] [--max-records N] [--full-check-every K]\n"
               "                        [--jobs J] [--ledger FILE]\n");
  std::exit(2);
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    const std::string_view k = argv[i];
    auto val = [&]() -> std::string {
      if (i + 1 >= argc) usage("missing value");
      return argv[++i];
    };
    if (k == "--file") a.file = val();
    else if (k == "--variant") a.variant = val();
    else if (k == "--max-records") a.max_records = std::strtoull(val().c_str(), nullptr, 0);
    else if (k == "--full-check-every") a.full_every = std::strtoull(val().c_str(), nullptr, 0);
    else if (k == "--jobs") a.jobs = static_cast<unsigned>(std::strtoul(val().c_str(), nullptr, 0));
    else if (k == "--ledger") a.ledger = val();
    else usage(("unknown option " + std::string(k)).c_str());
  }
  if (a.file.empty()) usage("--file is required");
  if (a.jobs == 0) a.jobs = 1;
  const lle::lobfuzz::Provenance pv = lle::lobfuzz::provenance();

  // One forked worker per variant, at most --jobs at a time; each streams the
  // file itself, so memory is one RefBook plus one book per worker.
  std::vector<std::string_view> names;
  if (a.variant == "all") {
    book::for_each_variant([&]<class V>() { names.push_back(V::kName); });
  } else {
    if (!book::visit_variant(a.variant, []<class V>() {})) usage("unknown variant");
    names.push_back(a.variant);
  }
  int rc = 0;
  std::vector<pid_t> live;
  auto reap = [&]() {
    int status = 0;
    const pid_t p = ::wait(&status);
    if (p <= 0) return;
    std::erase(live, p);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) rc = 1;
  };
  for (std::string_view n : names) {
    while (live.size() >= a.jobs) reap();
    std::fflush(nullptr);
    const pid_t pid = ::fork();
    if (pid < 0) {
      std::perror("fork");
      return 1;
    }
    if (pid == 0) {
      int child_rc = 1;
      book::visit_variant(n, [&]<class V>() { child_rc = run_and_report<V>(a, pv); });
      std::_Exit(child_rc);
    }
    live.push_back(pid);
  }
  while (!live.empty()) reap();
  return rc;
}
