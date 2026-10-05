// engine_fuzz: coverage-guided harness feeding arbitrary bytes to the engine
// as OUCH inbound payloads (plus session events, timers and admin records),
// differentially against RefEngine (05-matching-engine §9; conventions
// "Anything that parses untrusted bytes gets a fuzz harness").
//
// Input format: a sequence of chunks [selector u8][length u8][bytes...].
//   selector & 0x03 : session index (3 sessions over 2 accounts; 3 = wrong account)
//   selector >> 2   : 0-47 OUCH inbound, 48-50 session event, 51-56 timer (the
//                     first body byte picks the schedule entry), 57-61 admin (the
//                     body is the TLV argument list, the first byte the command),
//                     62 gateway-truncated OUCH, 63 day roll
// The engine is configured with a fixed day (3 symbols, 2 accounts, the
// generator's timer table). After every record the full OUCH/ITCH output must
// equal RefEngine's; invariants and state hashes are checked at the end. Any
// difference aborts.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "engine/engine.h"
#include "engine/scenario.h"
#include "gen.hpp"
#include "ref_engine.hpp"

namespace {

using namespace lle::engine;

std::vector<ScheduleEntry> fuzz_schedule() {
  std::vector<ScheduleEntry> v = params_only('P');
  const std::array<std::pair<TimerKind, std::uint16_t>, 20> kT = {{
      {TimerKind::SystemEvent, 'O'}, {TimerKind::SystemEvent, 'C'}, {TimerKind::StateChange, 'P'},
      {TimerKind::StateChange, 'F'}, {TimerKind::StateChange, 'M'}, {TimerKind::StateChange, 'L'},
      {TimerKind::StateChange, 'f'}, {TimerKind::StateChange, 'm'}, {TimerKind::StateChange, 'l'},
      {TimerKind::StateChange, 'X'}, {TimerKind::Eoii, 'O'},        {TimerKind::Noii, 'O'},
      {TimerKind::Eoii, 'C'},        {TimerKind::Noii, 'C'},        {TimerKind::Noii, 'H'},
      {TimerKind::Cross, 'O'},       {TimerKind::Cross, 'C'},       {TimerKind::ExpirySweep, 'D'},
      {TimerKind::ExpirySweep, 'X'}, {TimerKind::DayEnd, 0},
  }};
  for (std::size_t i = 0; i < kT.size(); ++i)
    v.push_back(ScheduleEntry{static_cast<std::uint32_t>(i + 1), kT[i].first, kT[i].second, lle::hms_ns(4, 0, 0)});
  ScheduleEntry p;
  p.kind = static_cast<TimerKind>(0);
  p.arg = static_cast<std::uint16_t>(Param::HaltPeriodSec);
  p.time_ns = 3;
  v.push_back(p);
  p.arg = static_cast<std::uint16_t>(Param::LimitStateSec);
  p.time_ns = 2;
  v.push_back(p);
  p.arg = static_cast<std::uint16_t>(Param::ExtensionSec);
  p.time_ns = 2;
  v.push_back(p);
  return v;
}

void configure(Scenario& sc) {
  sc.day_start();
  std::array<SymbolEntry, 3> syms{};
  syms[0].symbol = lle::Symbol8("AAPL");
  syms[0].prior_close = 1'000'000;
  syms[1].symbol = lle::Symbol8("PENY");
  syms[1].tick = 1;
  syms[1].prior_close = 5'000;
  syms[1].regsho = '2';
  syms[2].symbol = lle::Symbol8("HALF");
  syms[2].tick = 50;
  syms[2].flags = SymbolEntry::kFlagEtp;
  std::array<AccountEntry, 2> accts{};
  accts[0].account_id = 100;
  accts[0].firms[0] = lle::Mpid4("FA01");
  accts[0].firms[1] = lle::Mpid4("SHRD");
  accts[1].account_id = 200;
  accts[1].firms[0] = lle::Mpid4("FB01");
  accts[1].firms[1] = lle::Mpid4("SHRD");
  std::array<SessionEntry, 3> sess{};
  sess[0] = SessionEntry{1, 100, SessionEntry::kCancelOnDisconnect | SessionEntry::kMarketOrders, 'N',
                         LateCrossPolicy::Reprice};
  sess[1] = SessionEntry{2, 200, SessionEntry::kCancelOnDisconnect | SessionEntry::kMarketOrders, 'D',
                         LateCrossPolicy::Reject};
  sess[2] = SessionEntry{3, 100, SessionEntry::kPostOnlyCancel, '1', LateCrossPolicy::Accept};
  sc.symbols(syms);
  sc.accounts(accts);
  sc.sessions(sess);
  sc.schedule(fuzz_schedule());
  for (std::uint32_t s = 1; s <= 3; ++s) sc.session_event(s, 0, SessionEventKind::Login);
}

std::string hex(std::span<const std::byte> b) {
  static constexpr char k[] = "0123456789abcdef";
  std::string s;
  for (std::byte x : b) {
    s += k[std::to_integer<unsigned>(x) >> 4];
    s += k[std::to_integer<unsigned>(x) & 15];
  }
  return s;
}

[[noreturn]] void fail(const char* what, std::uint64_t index) {
  std::fprintf(stderr, "engine_fuzz: %s at record %llu\n", what, static_cast<unsigned long long>(index));
  std::abort();
}

// Prints the record and both output streams before aborting.
[[noreturn]] void diverged(const InputRecord& rec, const BufferSink& sink, const std::vector<ref::ROut>& want) {
  std::fprintf(stderr, "record %llu type %u payload %s\n  engine:\n", static_cast<unsigned long long>(rec.index),
               rec.type, hex(rec.payload).c_str());
  for (const auto& en : sink.entries())
    if (en.dest != Dest::Audit)
      std::fprintf(stderr, "    %s s=%u %s\n", en.dest == Dest::Itch ? "ITCH" : "OUCH", en.session,
                   hex(sink.bytes(en)).c_str());
  std::fprintf(stderr, "  ref:\n");
  for (const ref::ROut& o : want)
    std::fprintf(stderr, "    %s s=%u %s\n", o.itch ? "ITCH" : "OUCH", o.session, hex(o.bytes).c_str());
  fail("output differs from RefEngine", rec.index);
}

void apply_both(Engine& e, ref::RefEngine& r, const InputRecord& rec, BufferSink& sink, std::vector<ref::ROut>& want) {
  sink.clear();
  e.apply(rec, sink);
  want.clear();
  r.apply(rec, want);
  std::size_t k = 0;
  for (const auto& en : sink.entries()) {
    if (en.dest == Dest::Audit) continue;
    const auto b = sink.bytes(en);
    if (k >= want.size() || want[k].itch != (en.dest == Dest::Itch) || want[k].session != en.session ||
        want[k].bytes.size() != b.size() || std::memcmp(want[k].bytes.data(), b.data(), b.size()) != 0)
      diverged(rec, sink, want);
    if (en.dest == Dest::Ouch && !lle::ouch50::validate_outbound(b)) fail("invalid OUCH output", rec.index);
    ++k;
  }
  if (k != want.size()) diverged(rec, sink, want);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  EngineConfig cfg;
  cfg.book = BookConfig{256, 64, 8};
  cfg.urn_capacity = 256;
  cfg.scratch = 256;
  Engine e(cfg);
  ref::RefEngine r;
  BufferSink sink;
  std::vector<ref::ROut> want;
  Scenario sc(Scenario::kMidnight, lle::hms_ns(4, 0, 0));
  configure(sc);
  for (const InputRecord& rec : sc.records()) apply_both(e, r, rec, sink, want);
  const std::size_t setup = sc.size();
  static const std::vector<ScheduleEntry> kSched = fuzz_schedule();
  std::size_t i = 0;
  while (i + 2 <= size) {
    const std::uint8_t sel = data[i];
    const std::size_t len = std::min<std::size_t>(data[i + 1], size - i - 2);
    const auto* p = reinterpret_cast<const std::byte*>(data + i + 2);
    const std::span<const std::byte> body(p, len);
    i += 2 + len;
    const std::uint32_t s = (sel & 3u) == 3 ? 1u : (sel & 3u) + 1u;
    const std::uint32_t acct = (sel & 3u) == 3 || s == 2 ? 200u : 100u;
    const unsigned kind = sel >> 2;
    const unsigned b0 = len != 0 ? std::to_integer<unsigned>(body[0]) : 0;
    if (kind < 48) {
      sc.ouch(s, acct, body);
    } else if (kind < 51) {
      sc.session_event(s, static_cast<std::uint16_t>(b0 >> 6), static_cast<SessionEventKind>(1 + b0 % 5));
    } else if (kind < 57) {
      const ScheduleEntry& t = kSched[1 + b0 % (kSched.size() - 4)];
      sc.set_step(b0 >= 128 ? lle::kNsPerSec : 1'000);  // let halt periods and LULD states elapse
      sc.fire(t);
      sc.set_step(1'000);
    } else if (kind < 62) {
      const auto cmd = static_cast<AdminCommand>(1 + b0 % 14);
      AdminArgsBuilder args;
      args.raw(AdminTag::Symbol, "AAPL    ", 8);
      if (len > 1) args.i64(AdminTag::Price, 990'000 + 100 * static_cast<std::int64_t>(std::to_integer<unsigned>(body[1]) % 21));
      if (len > 2) {
        const std::int64_t m = 990'000 + 100 * static_cast<std::int64_t>(std::to_integer<unsigned>(body[2]) % 21);
        args.i64(AdminTag::Lower, m - 50'000).i64(AdminTag::Upper, m + 50'000);
      }
      if (len > 3) args.u8(AdminTag::Level, static_cast<std::uint8_t>(1 + std::to_integer<unsigned>(body[3]) % 3));
      if (len > 4) args.u8(AdminTag::Action, static_cast<std::uint8_t>("012"[std::to_integer<unsigned>(body[4]) % 3]));
      sc.admin(cmd, args);
    } else if (kind == 62) {
      sc.ouch(s, acct, body, 0, kFlagMalformedInput);
    } else {
      configure(sc);
    }
  }
  for (std::size_t k = setup; k < sc.size(); ++k) apply_both(e, r, sc[k], sink, want);
  std::string err;
  if (!e.check(&err)) fail(err.c_str(), 0);
  if (e.state_hash() != r.state_hash()) fail("state hash differs from RefEngine", 0);
  return 0;
}

// Seeds: well-formed OUCH order flow from the enginediff generator, re-encoded as chunks.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 256) return 0;
  gen::Generator g(lle::mix64(index + 1));
  std::size_t n = 0;
  for (int k = 0; k < 400 && n + 2 < cap; ++k) {
    const InputRecord& rec = g.next();
    if (rec.type != static_cast<std::uint16_t>(RecordType::OuchInbound)) {
      if (rec.type == static_cast<std::uint16_t>(RecordType::Timer) && n + 3 < cap) {
        buf[n++] = static_cast<std::uint8_t>(51 << 2);
        buf[n++] = 1;
        buf[n++] = static_cast<std::uint8_t>(k);
      }
      continue;
    }
    const auto in = parse_ouch_inbound(rec.payload);
    if (!in || in->msg.size() > 255 || n + 2 + in->msg.size() > cap) continue;
    buf[n++] = static_cast<std::uint8_t>((k % 3) | ((k % 7) << 2));
    buf[n++] = static_cast<std::uint8_t>(in->msg.size());
    std::memcpy(buf + n, in->msg.data(), in->msg.size());
    n += in->msg.size();
  }
  return n;
}
