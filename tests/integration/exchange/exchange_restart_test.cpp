// exchanged killed and restarted mid-day (06 §7, §8; T05).
//
// KillAndRestartByteIdentical: the scripted day runs twice in two processes, once
// uninterrupted and once with a SIGKILL after two of its steps. Each restart recovers
// the day from the journal (torn tail handling, replay through the engine, output-log
// regeneration), the clients log in again asking for their next expected sequence
// number and the subscriber fills what it missed by re-request. Every byte the clients
// and the feed received is identical between the two runs (cross-process output
// equality), and equal to journal_replay --emit of the restarted run's journal.
//
// KillMidFlowExactlyOnce: SIGKILL while orders are in flight (no barrier). Whatever
// the node released was durable (solo mode releases at durable_index, ADR-005), so
// after the restart the clients re-send only the orders they never saw accepted, in
// their original order (OUCH 5.0 §1.2: UserRefNum dedupe makes the resend safe), and
// the ledger shows every order accepted exactly once and every execution reported
// exactly once to each side.
//
// OutputLogRegeneratedFromTheJournal and TornOutputLogTailReplaysByteExact: the output
// log is derived data; damaged files (lost tail, changed bytes, a torn tail whose
// length prefixes survived) are found by comparison with the journal's regeneration
// at restart and rewritten before any replay is served.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <map>
#include <optional>
#include <set>

#include "journal/posix_segment_dir.h"
#include "dead_instances.h"
#include "journal/reader.h"
#include "scripted_day.h"

namespace lle::exch::test {
namespace {

TEST(ExchangeRestart, KillAndRestartByteIdentical) {
  ScriptedDay ref(ScriptedDay::Options::named("rst-ref"));
  ref.run();
  if (::testing::Test::HasFatalFailure()) return;
  EXPECT_EQ(ref.ex().stop(), 0);  // one node at a time (the AF_XDP variant owns the queues)
  // Kill after the opening cross (step 2) and after CHARL disconnected (step 10): the
  // node dies with sessions logged in; recovery journals InstanceDown for them, which
  // produces no output here (CHARL, the cancel-on-disconnect session, has no open order
  // at the first point and is logged out at the second), so the outputs must match the
  // uninterrupted run byte for byte.
  ScriptedDay::Options ko = ScriptedDay::Options::named("rst-kill");
  ko.kill_after = {2, 10};
  ScriptedDay crash(ko);
  crash.run();
  if (::testing::Test::HasFatalFailure()) return;
  EXPECT_EQ(crash.restarts(), 2);

  ASSERT_EQ(ref.sub().messages().size(), crash.sub().messages().size());
  EXPECT_TRUE(ref.sub().messages() == crash.sub().messages()) << "the ITCH feed differs after the restarts";
  for (const auto& [user, id] : ref.session_ids()) {
    EXPECT_TRUE(ref.c(user).stream() == crash.c(user).stream()) << user << ": OUCH stream differs after the restarts";
    EXPECT_EQ(crash.c(user).duplicates(), 0u) << user;
    EXPECT_EQ(crash.c(user).gaps(), 0u) << user;
  }
  // The restarted day's own journal regenerates exactly what was sent.
  check_regeneration(crash, "restarted");
  check_regeneration(ref, "reference");
  // The restarts are visible in the journal (InstanceDown and new logins), not in the
  // outputs: the two journals differ, their outputs do not.
  const std::string out = crash.ex().output();
  EXPECT_NE(out.find("records recovered"), std::string::npos);
  EXPECT_EQ(crash.ex().stop(), 0);
}

struct Ledger {
  std::map<std::uint32_t, int> accepted;    // urn -> 'A' count
  std::map<std::uint64_t, int> executions;  // match number -> 'E' count (both sides)
  std::map<std::uint32_t, std::uint64_t> filled;
  int rejects = 0;
  void add(const Ouch& m) {
    if (m.type() == 'A') ++accepted[m.urn()];
    if (m.type() == 'J') ++rejects;
    if (m.type() == 'E') {
      ++executions[m.e_match()];
      filled[m.urn()] += m.e_qty();
    }
  }
};

TEST(ExchangeRestart, KillMidFlowExactlyOnce) {
  const auto dir = fresh_dir("rst-flow");
  const ScopedDir cleanup(dir);
  MoldSubscriber sub;
  NodeSpec spec;
  spec.name = "flow";
  spec.data_dir = (dir / "data").string();
  spec.line_a = sub.port_a();
  spec.line_b = sub.port_b();
  Exchange ex(spec, dir);
  ASSERT_TRUE(ex.start()) << ex.output();
  ex.clock("09:31:00");
  OuchClient a("ALPHA", "alpha-pw"), b("BRAVO", "bravo-pw");
  ASSERT_EQ(a.login(ex.port("gw0")), 'A');
  ASSERT_EQ(b.login(ex.port("gw1")), 'A');
  ex.sync();

  // ALPHA sells, BRAVO buys at the same price: every pair trades.
  constexpr std::uint32_t kOrders = 400;
  auto enter = [](std::uint32_t urn, char side) {
    engine::EnterArgs e;
    e.urn = urn;
    e.side = static_cast<ouch50::Side>(side);
    e.qty = 100;
    e.symbol = "AAPL";
    e.price = 1'500'000;
    return engine::enter_msg(e);
  };
  for (std::uint32_t u = 1; u <= kOrders; ++u) {
    a.send(enter(u, 'S'));
    b.send(enter(u, 'B'));
    if (u % 50 == 0) {
      a.poll(0);
      b.poll(0);
    }
  }
  // Kill while the flow is still being processed.
  a.poll(1);
  ex.kill9();
  a.drop();
  b.drop();
  const std::size_t seen_a = a.received().size(), seen_b = b.received().size();

  ASSERT_TRUE(ex.start()) << ex.output();
  ASSERT_EQ(a.login(ex.port("gw0")), 'A');
  ASSERT_EQ(b.login(ex.port("gw1")), 'A');
  ex.sync();
  a.settle(200ms);
  b.settle(200ms);
  // Re-send, in order, what was never seen accepted (OUCH 5.0 §1.2 client rule).
  auto resend = [&](OuchClient& c, char side) {
    std::set<std::uint32_t> acked;
    for (const Received& r : c.received())
      if (Ouch{r.msg}.type() == 'A') acked.insert(Ouch{r.msg}.urn());
    std::uint32_t n = 0;
    for (std::uint32_t u = 1; u <= kOrders; ++u) {
      if (acked.count(u) == 0) {
        c.send(enter(u, side));
        ++n;
      }
    }
    return n;
  };
  const std::uint32_t resent_a = resend(a, 'S');
  const std::uint32_t resent_b = resend(b, 'B');
  ex.sync();
  a.settle(300ms);
  b.settle(300ms);

  Ledger la, lb;
  for (const Received& r : a.received()) la.add(Ouch{r.msg});
  for (const Received& r : b.received()) lb.add(Ouch{r.msg});
  for (std::uint32_t u = 1; u <= kOrders; ++u) {
    EXPECT_EQ(la.accepted[u], 1) << "ALPHA urn " << u;
    EXPECT_EQ(lb.accepted[u], 1) << "BRAVO urn " << u;
  }
  EXPECT_EQ(la.rejects + lb.rejects, 0);
  // Every execution is reported once to each side; nothing is filled twice.
  std::map<std::uint64_t, int> both = la.executions;
  for (const auto& [m, n] : lb.executions) both[m] += n;
  for (const auto& [m, n] : both) EXPECT_EQ(n, 2) << "match " << m;
  std::uint64_t total_a = 0, total_b = 0;
  for (const auto& [u, q] : la.filled) {
    EXPECT_LE(q, 100u) << "ALPHA urn " << u;
    total_a += q;
  }
  for (const auto& [u, q] : lb.filled) {
    EXPECT_LE(q, 100u) << "BRAVO urn " << u;
    total_b += q;
  }
  EXPECT_EQ(total_a, total_b);
  EXPECT_EQ(total_a, std::uint64_t{kOrders} * 100);
  EXPECT_EQ(a.duplicates() + b.duplicates() + a.gaps() + b.gaps(), 0u);
  RecordProperty("seen_before_kill", std::to_string(seen_a + seen_b));
  RecordProperty("resent", std::to_string(resent_a + resent_b));
  std::printf("kill mid-flow: %zu/%zu responses seen before the kill, %u/%u orders re-sent\n", seen_a, seen_b, resent_a,
              resent_b);

  // The streams equal the restarted journal's regeneration.
  const Regenerated r = regenerate(ex.journal_dir(), dir / "regen");
  ASSERT_EQ(r.exit_code, 0) << r.report;
  EXPECT_TRUE(a.stream() == r.ouch.at(1));
  EXPECT_TRUE(b.stream() == r.ouch.at(2));
  EXPECT_EQ(ex.stop(), 0);
}

// Outlog.RegeneratesFromJournal (06 §8, §12): the output log is derived data. With the
// node stopped, one file loses its tail, one has a byte changed in the middle and one
// is deleted with its index; at restart recovery compares every file with the journal's
// regeneration, cuts the damaged ones back to the first difference and rewrites them,
// and the files equal journal_replay --emit again.
TEST(ExchangeRestart, OutputLogRegeneratedFromTheJournal) {
  ScriptedDay day(ScriptedDay::Options::named("rst-outlog"));
  day.run();
  if (::testing::Test::HasFatalFailure()) return;
  day.ex().kill9();
  const std::string dir = day.ex().outlog_dir();
  const Bytes soup1 = slurp(dir + "/soup-000001.bin");
  ASSERT_GT(soup1.size(), 100u);
  {
    std::filesystem::resize_file(dir + "/soup-000001.bin", soup1.size() / 2);  // lost tail
    Bytes s2 = slurp(dir + "/soup-000002.bin");
    ASSERT_GT(s2.size(), 40u);
    s2[s2.size() / 2] = static_cast<std::byte>(std::to_integer<unsigned>(s2[s2.size() / 2]) ^ 0x5Au);  // corrupt
    std::ofstream(dir + "/soup-000002.bin", std::ios::binary | std::ios::trunc)
        .write(reinterpret_cast<const char*>(s2.data()), static_cast<std::streamsize>(s2.size()));
    std::filesystem::remove(dir + "/itch.bin");  // gone
    std::filesystem::remove(dir + "/itch.bin.idx");
  }
  ASSERT_TRUE(day.ex().start()) << day.ex().output();
  const std::string out = day.ex().output();
  EXPECT_NE(out.find("files rewritten"), std::string::npos) << out;
  EXPECT_EQ(out.find(" 0 regenerated"), std::string::npos) << out;
  EXPECT_EQ(day.ex().stop(), 0);
  const Regenerated r = regenerate(day.ex().journal_dir(), day.dir() / "regen-outlog");
  ASSERT_EQ(r.exit_code, 0) << r.report;
  EXPECT_TRUE(slurp(dir + "/itch.bin") == framed(r.itch));
  EXPECT_TRUE(slurp(dir + "/soup-000001.bin") == r.ouch.at(1));
  EXPECT_TRUE(slurp(dir + "/soup-000002.bin") == r.ouch.at(2));
  EXPECT_TRUE(slurp(dir + "/soup-000003.bin") == r.ouch.at(3));
}

// A torn output-log tail (06 §8, ADR-029). The output log has no per-record checksum,
// so after a power cut repair() can keep a record whose length prefix survived but whose
// payload sectors did not. A recovery that only repaired and appended from count() + 1
// would then serve wrong bytes on SoupBinTCP replay and MoldUDP64 re-request. Here,
// with the node killed after step 10, the payloads of the last records of every output
// log file are zeroed (length prefixes kept). Recovery compares each file with the
// journal's regeneration before any port opens, cuts it back to the first difference
// and rewrites it; the replays the node then serves from the output log are byte-exact:
// a MoldUDP64 re-request of the damaged ITCH range right after the restart, and
// SoupBinTCP logins from sequence 1 at the end of the day.
struct TornTail {
  std::string file;
  SeqNo first = 0;              // first damaged sequence
  std::vector<Bytes> original;  // the payloads before the damage
};

// Zeroes the payloads of the last `k` complete records of an output-log file.
std::optional<TornTail> tear_tail(const std::string& path, std::size_t k) {
  Bytes f = slurp(path);
  std::vector<std::pair<std::size_t, std::size_t>> recs;  // payload offset, length
  std::size_t at = 0;
  while (at + 2 <= f.size()) {
    const std::size_t len = load_be16(f.data() + at);
    if (len == 0 || at + 2 + len > f.size()) break;
    recs.emplace_back(at + 2, len);
    at += 2 + len;
  }
  if (recs.empty()) return std::nullopt;
  const std::size_t n = std::min(k, recs.size());
  TornTail t;
  t.file = path;
  t.first = static_cast<SeqNo>(recs.size() - n + 1);
  for (std::size_t i = recs.size() - n; i < recs.size(); ++i) {
    const auto [off, len] = recs[i];
    t.original.emplace_back(f.data() + off, f.data() + off + len);
    std::memset(f.data() + off, 0, len);
  }
  std::ofstream(path, std::ios::binary | std::ios::trunc)
      .write(reinterpret_cast<const char*>(f.data()), static_cast<std::streamsize>(f.size()));
  return t;
}

TEST(ExchangeRestart, TornOutputLogTailReplaysByteExact) {
  std::vector<TornTail> torn;
  std::string restart_output;
  ScriptedDay::Options o = ScriptedDay::Options::named("rst-torn");
  o.kill_after = {10};
  o.before_restart = [&](ScriptedDay& d) {
    for (const auto& e : std::filesystem::directory_iterator(d.ex().outlog_dir())) {
      const std::string p = e.path().string();
      if (!p.ends_with(".bin")) continue;
      if (auto t = tear_tail(p, 3)) torn.push_back(std::move(*t));
    }
    ASSERT_GE(torn.size(), 3u) << "itch.bin and at least two session files";
  };
  o.after_restart = [&](ScriptedDay& d) {
    restart_output = d.ex().output();
    for (const TornTail& t : torn) {
      if (!t.file.ends_with("/itch.bin")) continue;
      // Served from itch.bin (the re-request ring starts empty after a restart).
      const std::vector<Bytes> got = mold_rerequest(d.ex().port("rerequest"), d.sub().session(), t.first,
                                                    static_cast<std::uint16_t>(t.original.size()));
      ASSERT_EQ(got.size(), t.original.size()) << "re-request of " << t.first << " not served";
      EXPECT_TRUE(got == t.original) << "re-request served damaged ITCH bytes";
    }
  };
  ScriptedDay day(o);
  day.run();
  if (::testing::Test::HasFatalFailure()) return;
  ASSERT_EQ(day.restarts(), 1);
  ASSERT_FALSE(restart_output.empty());
  const std::size_t rec = restart_output.rfind("recovery replayed");
  ASSERT_NE(rec, std::string::npos) << restart_output;
  const std::string line = restart_output.substr(rec, restart_output.find('\n', rec) - rec);
  EXPECT_NE(line.find(", " + std::to_string(torn.size()) + " files rewritten"), std::string::npos) << line;

  // End of day: every session logs in again from sequence 1 and gets its whole stream,
  // replayed from the output log (the records before the restart) and the ring.
  for (const SessionDef& s : day.spec().sessions) {
    SCOPED_TRACE(s.user);
    OuchClient fresh(s.user, s.password);
    ASSERT_EQ(fresh.login(day.ex().port(s.gw == 0 ? "gw0" : "gw1"), SeqNo{1}), 'A');
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!fresh.ended() && std::chrono::steady_clock::now() < deadline) fresh.poll(5);
    ASSERT_TRUE(fresh.ended()) << "no End of Session after the replay";
    EXPECT_TRUE(fresh.stream() == day.c(s.user).stream()) << "replay differs from the live stream";
    char name[32];
    std::snprintf(name, sizeof name, "/soup-%06u.bin", s.id);
    for (const TornTail& t : torn) {
      if (!t.file.ends_with(name)) continue;
      ASSERT_GE(fresh.received().size(), t.first - 1 + t.original.size());
      for (std::size_t i = 0; i < t.original.size(); ++i)
        EXPECT_TRUE(fresh.received()[t.first - 1 + i].msg == t.original[i]) << "replayed damaged record " << t.first + i;
    }
  }
  check_regeneration(day, "torn");
  EXPECT_EQ(day.ex().stop(), 0);
}

// 06 §7 step 4, §9, ADR-007: recovery from a snapshot. The node journals a SnapshotMark
// every 3,000 records; snapshotd (its own process) replays the journal and writes the
// engine state at each mark. The scripted day is SIGKILLed after step 10; before the
// restart snapshotd catches up, so recovery loads the newest snapshot and replays only
// the journal after it. Snapshot equivalence: the restarted engine's state hash equals a
// full replay's at the same index (journal_replay from record 1), and every output byte
// of the day equals the uninterrupted reference run and the journal's regeneration.
std::uint64_t replay_state_hash(const std::string& journal_dir, std::uint64_t to, const std::string& snap_dir = {}) {
  std::vector<std::string> args{LLE_JOURNAL_REPLAY, journal_dir, "--to", std::to_string(to), "--emit", "/dev/null"};
  if (!snap_dir.empty()) {
    args.push_back("--snapshot-dir");
    args.push_back(snap_dir);
  }
  int code = 0;
  const std::string out = run_capture(args, &code);
  const auto at = out.rfind("state hash ");
  if (code != 0 || at == std::string::npos) return 0;
  return std::stoull(out.substr(at + 11, 16), nullptr, 16);
}

TEST(ExchangeRestart, RecoveryFromASnapshotIsEquivalentToFullReplay) {
  ScriptedDay ref(ScriptedDay::Options::named("rst-snapref"));
  ref.run();
  if (::testing::Test::HasFatalFailure()) return;
  EXPECT_EQ(ref.ex().stop(), 0);  // one node at a time (the AF_XDP variant owns the queues)
  std::string snap_dir, restart_out, snapshotd_out;
  ScriptedDay::Options o = ScriptedDay::Options::named("rst-snap");
  o.kill_after = {10};
  o.extra = {"[journal]", "snapshot_every = 3000"};
  o.before_restart = [&](ScriptedDay& d) {
    snap_dir = d.spec().data_dir + "/snapshots/20261001";
    int code = 0;
    snapshotd_out = run_capture({LLE_SNAPSHOTD, "--journal", d.ex().journal_dir(), "--snapshots", snap_dir, "--day",
                                 "20261001"},
                                &code);
    ASSERT_EQ(code, 0) << snapshotd_out;
  };
  o.after_restart = [&](ScriptedDay& d) { restart_out = d.ex().output(); };
  ScriptedDay day(o);
  day.run();
  if (::testing::Test::HasFatalFailure()) return;
  ASSERT_EQ(day.restarts(), 1);
  EXPECT_NE(snapshotd_out.find("snapshotd: snapshot "), std::string::npos) << snapshotd_out;
  // The restart started from a snapshot.
  const auto from = restart_out.rfind("recovery from the snapshot at ");
  ASSERT_NE(from, std::string::npos) << restart_out;
  const std::uint64_t p = std::stoull(restart_out.substr(from + 30));
  EXPECT_GT(p, 0u);
  // Snapshot equivalence at the recovered index.
  const auto rep = restart_out.rfind("recovery replayed ");
  ASSERT_NE(rep, std::string::npos);
  const std::uint64_t n = std::stoull(restart_out.substr(rep + 18));
  const auto hat = restart_out.find("engine state hash ", rep);
  ASSERT_NE(hat, std::string::npos);
  const std::uint64_t node_hash = std::stoull(restart_out.substr(hat + 18, 16), nullptr, 16);
  EXPECT_GT(n, p);
  const std::uint64_t full = replay_state_hash(day.ex().journal_dir(), n);
  ASSERT_NE(full, 0u);
  EXPECT_EQ(node_hash, full) << "the engine recovered from the snapshot at " << p
                             << " differs from a full replay to " << n;
  EXPECT_EQ(replay_state_hash(day.ex().journal_dir(), n, snap_dir), full) << "journal_replay from the snapshot";
  RecordProperty("snapshot_index", std::to_string(p));
  std::printf("recovered from the snapshot at %llu; state hash %016llx at %llu equals a full replay's\n",
              static_cast<unsigned long long>(p), static_cast<unsigned long long>(node_hash),
              static_cast<unsigned long long>(n));
  // Every output byte as in the uninterrupted day.
  ASSERT_EQ(ref.sub().messages().size(), day.sub().messages().size());
  EXPECT_TRUE(ref.sub().messages() == day.sub().messages()) << "feed";
  for (const auto& [user, id] : ref.session_ids())
    EXPECT_TRUE(ref.c(user).stream() == day.c(user).stream()) << user;
  check_regeneration(day, "snapshot");
  EXPECT_EQ(day.ex().stop(), 0);
}

// A torn record below a snapshot (ADR-029 with 06 §9): recovery from a snapshot at P
// regenerates only the outputs after P, so the output log up to P is checked against
// the digests snapshotd wrote next to the snapshot (snapshotd/out_digest.h). Here, with
// the node down after step 10 and snapshotd caught up, one ITCH record and one of
// ALPHA's records at or below the snapshot's positions lose their payload (length
// prefixes kept). Recovery must refuse that snapshot, fall back to an older one or a full
// replay, and rewrite both records; a re-request and a re-login replay then return the
// original bytes, and every file equals journal_replay --emit.
// Zeroes the payload of record `seq` (1-based) of an output-log file; its old bytes.
Bytes tear_record(const std::string& path, std::uint64_t seq) {
  Bytes f = slurp(path);
  std::size_t at = 0;
  for (std::uint64_t n = 1; at + 2 <= f.size(); ++n) {
    const std::size_t len = load_be16(f.data() + at);
    if (n == seq) {
      Bytes old(f.data() + at + 2, f.data() + at + 2 + len);
      std::memset(f.data() + at + 2, 0, len);
      std::ofstream(path, std::ios::binary | std::ios::trunc)
          .write(reinterpret_cast<const char*>(f.data()), static_cast<std::streamsize>(f.size()));
      return old;
    }
    at += 2 + len;
  }
  return {};
}

TEST(ExchangeRestart, TornRecordBelowASnapshotIsFoundAndRewritten) {
  std::string restart_out, snapshotd_out;
  std::uint64_t itch_seq = 0;
  Bytes itch_orig, alpha_orig;
  const std::uint64_t alpha_seq = 2;
  ScriptedDay::Options o = ScriptedDay::Options::named("rst-tornsnap");
  o.kill_after = {10};
  o.extra = {"[journal]", "snapshot_every = 3000"};
  o.before_restart = [&](ScriptedDay& d) {
    const std::string snap_dir = d.spec().data_dir + "/snapshots/20261001";
    int code = 0;
    snapshotd_out = run_capture({LLE_SNAPSHOTD, "--journal", d.ex().journal_dir(), "--snapshots", snap_dir, "--day",
                                 "20261001"},
                                &code);
    ASSERT_EQ(code, 0) << snapshotd_out;
    // The newest snapshot's S(P): damage an ITCH record a little below it.
    const auto at = snapshotd_out.rfind("(S(P) ");
    ASSERT_NE(at, std::string::npos) << snapshotd_out;
    const std::uint64_t m = std::stoull(snapshotd_out.substr(at + 6));
    ASSERT_GT(m, 10u);
    itch_seq = m - 5;
    itch_orig = tear_record(d.ex().outlog_dir() + "/itch.bin", itch_seq);
    alpha_orig = tear_record(d.ex().outlog_dir() + "/soup-000001.bin", alpha_seq);
    ASSERT_FALSE(itch_orig.empty());
    ASSERT_FALSE(alpha_orig.empty());
  };
  o.after_restart = [&](ScriptedDay& d) {
    restart_out = d.ex().output();
    // Served from itch.bin: the original bytes.
    const std::vector<Bytes> got = mold_rerequest(d.ex().port("rerequest"), d.sub().session(), itch_seq, 1);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_TRUE(got[0] == itch_orig) << "re-request served the torn ITCH record";
  };
  ScriptedDay day(o);
  day.run();
  if (::testing::Test::HasFatalFailure()) return;
  // The snapshot whose prefix no longer matches was refused, and the damage rewritten.
  EXPECT_NE(restart_out.find("not used: "), std::string::npos) << restart_out;
  const auto rec = restart_out.rfind("recovery replayed");
  ASSERT_NE(rec, std::string::npos);
  const std::string line = restart_out.substr(rec, restart_out.find('\n', rec) - rec);
  EXPECT_NE(line.find(", 2 files rewritten"), std::string::npos) << line;
  // ALPHA logs in again from sequence 1: its stream, the repaired record included.
  OuchClient fresh("ALPHA", "alpha-pw");
  ASSERT_EQ(fresh.login(day.ex().port("gw0"), SeqNo{1}), 'A');
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!fresh.ended() && std::chrono::steady_clock::now() < deadline) fresh.poll(5);
  ASSERT_GE(fresh.received().size(), alpha_seq);
  EXPECT_TRUE(fresh.received()[alpha_seq - 1].msg == alpha_orig) << "re-login replayed the torn record";
  EXPECT_TRUE(fresh.stream() == day.c("ALPHA").stream());
  check_regeneration(day, "tornsnap");
  EXPECT_EQ(day.ex().stop(), 0);
}

// 06 §5: L2 in a file (hugetlbfs in production, a regular file here) outlives a
// process crash. With the io stage held (control `io-hold on`), orders are sequenced into
// L2 but not journaled, so solo mode releases none of them; then the node is SIGKILLed.
// At restart the records the L2 file holds beyond L3 are journaled first, and the orders
// the clients never saw answered are accepted without being sent again. With anonymous
// L2 the same crash loses them, and the clients re-send them (exactly once either way).
struct L2CrashRun {
  std::string output;
  std::set<std::uint32_t> answered_after_restart;  // urns accepted before any re-send
  std::uint64_t sequenced_while_held = 0;
};
L2CrashRun l2_crash(bool l2_file) {
  L2CrashRun run;
  const auto dir = fresh_dir(l2_file ? "rst-l2file" : "rst-l2anon");
  const ScopedDir cleanup(dir);
  NodeSpec spec;
  spec.name = l2_file ? "l2f" : "l2a";
  spec.data_dir = (dir / "data").string();
  if (l2_file) spec.extra = {"[journal]", "l2_path = " + (dir / "l2").string()};
  Exchange ex(spec, dir);
  EXPECT_TRUE(ex.start()) << ex.output();
  ex.clock("09:31:00");
  OuchClient a("ALPHA", "alpha-pw"), b("BRAVO", "bravo-pw");
  EXPECT_EQ(a.login(ex.port("gw0")), 'A');
  EXPECT_EQ(b.login(ex.port("gw1")), 'A');
  auto enter = [](std::uint32_t urn, char side) {
    engine::EnterArgs e;
    e.urn = urn;
    e.side = static_cast<ouch50::Side>(side);
    e.qty = 100;
    e.symbol = "AAPL";
    e.price = 1'500'000;
    return engine::enter_msg(e);
  };
  a.send(enter(1, 'S'));
  b.send(enter(1, 'B'));
  (void)ex.sync();
  a.settle(100ms);
  b.settle(100ms);
  const std::size_t seen_a = a.received().size();
  EXPECT_EQ(ex.cmd("io-hold on"), "ok on");
  const std::uint64_t seq0 = Control::field(ex.status(), "seq");
  for (std::uint32_t u = 2; u <= 6; ++u) {
    a.send(enter(u, 'S'));
    b.send(enter(u, 'B'));
  }
  const auto end = std::chrono::steady_clock::now() + 5s;
  while (Control::field(ex.status(), "seq") < seq0 + 10 && std::chrono::steady_clock::now() < end)
    std::this_thread::sleep_for(5ms);
  run.sequenced_while_held = Control::field(ex.status(), "seq") - seq0;
  a.settle(200ms);
  EXPECT_EQ(a.received().size(), seen_a) << "nothing is released while it is not durable (solo)";
  ex.kill9();
  a.drop();
  b.drop();
  EXPECT_TRUE(ex.start()) << ex.output();
  run.output = ex.output();
  EXPECT_EQ(a.login(ex.port("gw0")), 'A');
  EXPECT_EQ(b.login(ex.port("gw1")), 'A');
  (void)ex.sync();
  a.settle(200ms);
  b.settle(200ms);
  for (const Received& r : a.received())
    if (Ouch{r.msg}.type() == 'A') run.answered_after_restart.insert(Ouch{r.msg}.urn());
  // Re-send what was never answered (the OUCH client rule); every order ends up accepted
  // exactly once and filled.
  std::set<std::uint32_t> acked_b;
  for (const Received& r : b.received())
    if (Ouch{r.msg}.type() == 'A') acked_b.insert(Ouch{r.msg}.urn());
  for (std::uint32_t u = 2; u <= 6; ++u) {
    if (run.answered_after_restart.count(u) == 0) a.send(enter(u, 'S'));
    if (acked_b.count(u) == 0) b.send(enter(u, 'B'));
  }
  (void)ex.sync();
  a.settle(200ms);
  b.settle(200ms);
  Ledger la, lb;
  for (const Received& r : a.received()) la.add(Ouch{r.msg});
  for (const Received& r : b.received()) lb.add(Ouch{r.msg});
  for (std::uint32_t u = 1; u <= 6; ++u) {
    EXPECT_EQ(la.accepted[u], 1) << "ALPHA urn " << u;
    EXPECT_EQ(lb.accepted[u], 1) << "BRAVO urn " << u;
    EXPECT_EQ(la.filled[u], 100u) << "ALPHA urn " << u;
  }
  EXPECT_EQ(a.duplicates() + a.gaps() + b.duplicates() + b.gaps(), 0u);
  EXPECT_EQ(ex.stop(), 0);
  return run;
}

// ADR-032: a cross that came due while the node was down must not execute the
// cancel-on-disconnect orders of instances that died with the old process. Their
// InstanceDown records are the first after the recovered prefix, ahead of every overdue
// Timer. CHARL (cancel-on-disconnect) and BRAVO rest crossing orders for the open; the
// node is SIGKILLed at 09:00 and restarts with its clock at 09:31, so the opening cross
// and every timer before it are overdue at the first poll.
TEST(ExchangeRestart, DeadCodInstancesGoDownBeforeAnOverdueCross) {
  const auto dir = fresh_dir("rst-adr32");
  const ScopedDir cleanup(dir);
  MoldSubscriber sub;
  NodeSpec spec;
  spec.name = "adr32";
  spec.data_dir = (dir / "data").string();
  spec.line_a = sub.port_a();
  spec.line_b = sub.port_b();
  auto ex = std::make_unique<Exchange>(spec, dir);
  ASSERT_TRUE(ex->start()) << ex->output();
  ex->clock("09:00:00");
  OuchClient charl("CHARL", "charl-pw"), bravo("BRAVO", "bravo-pw");
  ASSERT_EQ(charl.login(ex->port("gw0")), 'A');
  ASSERT_EQ(bravo.login(ex->port("gw1")), 'A');
  auto enter = [](char side) {
    engine::EnterArgs e;
    e.urn = 1;
    e.side = static_cast<ouch50::Side>(side);
    e.qty = 100;
    e.symbol = "AAPL";
    e.price = 1'500'000;
    return engine::enter_msg(e);
  };
  charl.send(enter('B'));
  bravo.send(enter('S'));
  ex->sync();
  auto accepted = [](OuchClient& c) {
    for (int i = 0; i < 200; ++i) {
      c.poll(5);
      for (const Received& r : c.received())
        if (Ouch{r.msg}.type() == 'A') return true;
    }
    return false;
  };
  ASSERT_TRUE(accepted(charl));
  ASSERT_TRUE(accepted(bravo));
  ex->kill9();
  charl.drop();
  bravo.drop();
  ex.reset();

  spec.start = "09:31:00";  // the restarted node finds 09:28 ... 09:30 overdue
  spec.name = "adr32r";     // its own configuration and output files; the same data directory
  ex = std::make_unique<Exchange>(spec, dir);
  ASSERT_TRUE(ex->start()) << ex->output();
  ex->sync();
  // The recovered prefix, then the InstanceDown records, then the overdue timers.
  const std::string out = ex->output();
  const auto at = out.find(" records recovered");
  ASSERT_NE(at, std::string::npos) << out;
  const std::uint64_t recovered = std::stoull(out.substr(out.rfind(' ', at - 1) + 1));
  ASSERT_GT(recovered, 0u);
  expect_dead_instances_first(journal_records(ex->journal_dir()), recovered, 0, 3);  // node 0's instance, CHARL
  const Regenerated r = regenerate(ex->journal_dir(), dir / "regen");
  ASSERT_EQ(r.exit_code, 0) << r.report;
  expect_cod_order_cancelled_before_the_cross(r, 3, 2);  // CHARL, BRAVO
  EXPECT_EQ(ex->stop(), 0);
}

// snapshotd --follow next to the running node (06 §9): it applies the journal as the
// node writes it, across segment switches, and writes a snapshot at every SnapshotMark,
// each equal to a full replay to its index. It keeps its place in the journal between
// passes (journal/follow_cursor.h): it walks every record once and reads at most one
// chunk of read-ahead per pass, never the segment so far.
TEST(ExchangeRestart, SnapshotdFollowsTheRunningNode) {
  ScriptedDay::Options o = ScriptedDay::Options::named("rst-follow");
  o.extra = {"[journal]", "snapshot_every = 1000", "segment_mib = 1"};
  ScriptedDay day(o);
  // Started before the node (it waits for the journal directory) and before any client
  // connects: a child spawned later would inherit the clients' TCP sockets and keep a
  // dropped connection open.
  auto snapd = std::make_unique<Process>(
      LLE_SNAPSHOTD,
      std::vector<std::string>{"--journal", day.spec().data_dir + "/journal/20261001", "--snapshots",
                               day.spec().data_dir + "/snapshots/20261001", "--day", "20261001", "--follow",
                               "--poll-ms", "5"},
      (day.dir() / "snapshotd.log").string());
  ASSERT_GT(snapd->pid(), 0);
  day.run();
  if (::testing::Test::HasFatalFailure()) return;
  // The journal as the node left it: its SnapshotMarks, records and segments.
  auto dir = journal::PosixSegmentDir::open(day.ex().journal_dir(), false, journal::PosixDeviceOptions{.read_only = true});
  ASSERT_TRUE(dir.has_value()) << dir.error();
  std::vector<std::uint64_t> marks;
  const journal::ReadSummary sum =
      journal::read_journal(*dir, journal::ReadOptions{}, [&](const journal::RecordView& r, const journal::RecordLocation&) {
        if (r.type() == journal::RecordType::SnapshotMark) marks.push_back(r.index());
        return true;
      });
  ASSERT_GE(sum.segments, 2u) << "the day must span segments for this test";
  ASSERT_GE(marks.size(), 2u);
  ASSERT_TRUE(snapd->wait_output("at index " + std::to_string(marks.back()) + " ", 60s)) << snapd->output();
  snapd->kill(SIGTERM);
  const std::string out = snapd->output();
  // A snapshot at every mark, each the engine state of a full replay to its index.
  for (const std::uint64_t m : marks) {
    const auto at = out.find("at index " + std::to_string(m) + " (S(P) ");
    ASSERT_NE(at, std::string::npos) << "no snapshot at " << m << "\n" << out;
    const auto h = out.find("state hash ", at);
    ASSERT_NE(h, std::string::npos);
    EXPECT_EQ(std::stoull(out.substr(h + 11, 16), nullptr, 16), replay_state_hash(day.ex().journal_dir(), m)) << m;
  }
  // How it read: every record once, every segment entered once, about one chunk per poll.
  const auto rd = out.rfind("snapshotd: read ");
  ASSERT_NE(rd, std::string::npos) << out;
  unsigned long long bytes = 0, polls = 0, records = 0, segments = 0, listings = 0, positionings = 0;
  ASSERT_EQ(std::sscanf(out.c_str() + rd,
                        "snapshotd: read %llu journal bytes in %llu polls: %llu records, %llu segments, %llu directory "
                        "listings, %llu positionings",
                        &bytes, &polls, &records, &segments, &listings, &positionings),
            6)
      << out.substr(rd);
  EXPECT_GE(records, sum.records) << "every record walked (the node may have journaled more since)";
  EXPECT_LE(records, sum.records + 64);
  EXPECT_GE(segments, sum.segments);
  EXPECT_LE(segments, sum.segments + 1);
  const unsigned long long on_disk = sum.segments * (std::uint64_t{1} << 20);
  EXPECT_LT(bytes, 2 * on_disk + polls * (2 * journal::kMaxRecordBytes + journal::kHeaderBytes)) << out.substr(rd);
  // A listing only to position (each attempt, also before the node made the directory)
  // or after at least two idle polls at the tail.
  EXPECT_LE(listings, positionings + polls / 2) << "the directory is listed only when idle, with back-off";
  RecordProperty("snapshotd_read", out.substr(rd, out.find('\n', rd) - rd));
  std::printf("%s\n", out.substr(rd, out.find('\n', rd) - rd).c_str());
  EXPECT_EQ(day.ex().stop(), 0);
}

TEST(ExchangeRestart, L2FileSurvivesAProcessCrash) {
  const L2CrashRun file = l2_crash(true);
  if (::testing::Test::HasFatalFailure()) return;
  EXPECT_GE(file.sequenced_while_held, 10u);
  EXPECT_NE(file.output.find("exchanged: L2: restored "), std::string::npos) << file.output;
  EXPECT_EQ(file.answered_after_restart, (std::set<std::uint32_t>{1, 2, 3, 4, 5, 6}))
      << "the held orders are accepted from the restored L2, without a re-send";
  // The counterfactual: anonymous L2 loses them.
  const L2CrashRun anon = l2_crash(false);
  EXPECT_EQ(anon.output.find("exchanged: L2: restored "), std::string::npos);
  EXPECT_EQ(anon.answered_after_restart, (std::set<std::uint32_t>{1})) << "lost with the process; re-sent";
}

}  // namespace
}  // namespace lle::exch::test
