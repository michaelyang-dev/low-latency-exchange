#include "sim/fault/injector.h"

#include <algorithm>
#include <charconv>
#include <cstdio>

#include "common/hash.h"
#include "sim/dist.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/world.h"

namespace lle::sim {

namespace {

constexpr std::uint64_t kSubCrash = 1;
constexpr std::uint64_t kSubPause = 2;
constexpr std::uint64_t kSubPartition = 1000;
constexpr std::uint64_t kSubClock = 1000;

bool parse_u64(std::string_view tok, std::uint64_t& out) {
  const auto* first = tok.data();
  const auto* last = tok.data() + tok.size();
  const auto r = std::from_chars(first, last, out);
  return r.ec == std::errc{} && r.ptr == last;
}

bool parse_i64(std::string_view tok, std::int64_t& out) {
  const auto* first = tok.data();
  const auto* last = tok.data() + tok.size();
  const auto r = std::from_chars(first, last, out);
  return r.ec == std::errc{} && r.ptr == last;
}

}  // namespace

std::string_view fault_kind_name(FaultKind k) noexcept {
  switch (k) {
    case FaultKind::Crash:
      return "crash";
    case FaultKind::Pause:
      return "pause";
    case FaultKind::Partition:
      return "partition";
    case FaultKind::ClockStep:
      return "clock_step";
  }
  return "?";
}

std::string FaultSchedule::format(std::string_view prefix) const {
  std::string out;
  char buf[160];
  for (const FaultEvent& e : events) {
    std::snprintf(buf, sizeof buf, "%lld %u %u %llu %llu %lld", static_cast<long long>(e.at),
                  static_cast<unsigned>(e.kind), static_cast<unsigned>(e.node), static_cast<unsigned long long>(e.a),
                  static_cast<unsigned long long>(e.b), static_cast<long long>(e.dur));
    if (!prefix.empty()) {
      out += prefix;
      out += ' ';
    }
    out += buf;
    out += '\n';
  }
  return out;
}

bool FaultSchedule::parse(std::string_view text, std::string_view prefix) {
  while (!text.empty()) {
    const std::size_t nl = text.find('\n');
    std::string_view line = text.substr(0, nl);
    text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
    if (const std::size_t hash = line.find('#'); hash != std::string_view::npos) line = line.substr(0, hash);
    std::string_view toks[8];
    std::size_t n = 0;
    while (!line.empty() && n < 8) {
      const std::size_t s = line.find_first_not_of(" \t\r");
      if (s == std::string_view::npos) break;
      line.remove_prefix(s);
      const std::size_t e = line.find_first_of(" \t\r");
      toks[n++] = line.substr(0, e);
      line = e == std::string_view::npos ? std::string_view{} : line.substr(e);
    }
    if (n == 0) continue;
    std::size_t base = 0;
    if (!prefix.empty()) {
      if (toks[0] != prefix) continue;
      base = 1;
    }
    if (n != base + 6) return false;
    FaultEvent e;
    std::int64_t at = 0;
    std::uint64_t kind = 0;
    std::uint64_t node = 0;
    std::int64_t dur = 0;
    if (!parse_i64(toks[base], at) || !parse_u64(toks[base + 1], kind) || !parse_u64(toks[base + 2], node) ||
        !parse_u64(toks[base + 3], e.a) || !parse_u64(toks[base + 4], e.b) || !parse_i64(toks[base + 5], dur) ||
        kind > 3) {
      return false;
    }
    e.at = at;
    e.kind = static_cast<FaultKind>(kind);
    e.node = static_cast<NodeId>(node);
    e.dur = dur;
    events.push_back(e);
  }
  std::stable_sort(events.begin(), events.end(), [](const FaultEvent& x, const FaultEvent& y) { return x.at < y.at; });
  return true;
}

FaultInjector::FaultInjector(World& w) : w_(w) { handler_ = w.register_handler(this, &FaultInjector::on_event, "fault"); }

FaultSchedule FaultInjector::generate(Nanos start, Nanos end) const {
  FaultSchedule s;
  const FaultConfig& f = w_.faults();
  const std::size_t n = std::min<std::size_t>(w_.node_count(), 64);
  std::vector<NodeId> crashable;
  std::vector<NodeId> pausable;
  for (NodeId i = 0; i < w_.node_count(); ++i) {
    const Node& nd = w_.node(i);
    if (nd.crashable()) crashable.push_back(i);
    if (nd.pausable()) pausable.push_back(i);
  }

  // Crashes (process stream).
  if (const Nanos mean = f[Param::CrashIntervalNs]; mean > 0 && !crashable.empty()) {
    Rng r = w_.stream(Stream::Process, kSubCrash);
    for (Nanos t = start + 1 + exp_ns(r, mean); t < end; t += 1 + exp_ns(r, mean)) {
      FaultEvent e;
      e.at = t;
      e.kind = FaultKind::Crash;
      e.node = crashable[r.below(crashable.size())];
      e.a = chance_ppm(r, f.u(Param::CrashHostPpm)) ? 1u : 0u;
      e.dur = uniform(r, 0, f[Param::CrashRestartMaxNs]);
      s.events.push_back(e);
    }
  }
  // Pauses (process stream, own sub-stream).
  if (const Nanos mean = f[Param::PauseIntervalNs]; mean > 0 && !pausable.empty()) {
    Rng r = w_.stream(Stream::Process, kSubPause);
    for (Nanos t = start + 1 + exp_ns(r, mean); t < end; t += 1 + exp_ns(r, mean)) {
      FaultEvent e;
      e.at = t;
      e.kind = FaultKind::Pause;
      e.node = pausable[r.below(pausable.size())];
      e.dur = uniform(r, 10 * kMs, std::max<Nanos>(10 * kMs, f[Param::PauseMaxNs]));
      s.events.push_back(e);
    }
  }
  // Partitions (network stream): random split, isolate one node, or one
  // directed pair; symmetric or asymmetric; optionally flapping.
  if (const Nanos mean = f[Param::PartIntervalNs]; mean > 0 && n >= 2) {
    Rng r = w_.stream(Stream::Network, (std::uint64_t{0xFFFF} << 40) | kSubPartition);
    const std::uint64_t all = n >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << n) - 1);
    for (Nanos t = start + 1 + exp_ns(r, mean); t < end; t += 1 + exp_ns(r, mean)) {
      const std::uint64_t shape = r.below(3);
      std::uint64_t a = 0;
      std::uint64_t b = 0;
      const std::uint64_t pick = r.next_u64();
      const auto x = static_cast<NodeId>(r.below(n));
      auto y = static_cast<NodeId>(r.below(n - 1));
      if (y >= x) ++y;
      if (shape == 0) {
        a = pick & all;
        if (a == 0 || a == all) a = std::uint64_t{1} << x;
        b = all & ~a;
      } else if (shape == 1) {
        a = std::uint64_t{1} << x;
        b = all & ~a;
      } else {
        a = std::uint64_t{1} << x;
        b = std::uint64_t{1} << y;
      }
      const bool asym = chance_ppm(r, f.u(Param::PartAsymPpm));
      const bool flap = chance_ppm(r, f.u(Param::PartFlapPpm));
      const Nanos lo = std::max<Nanos>(kMs, f[Param::PartMinNs]);
      const Nanos dur = log_uniform(r, lo, std::max(lo, f[Param::PartMaxNs]));
      const Nanos seg = std::max<Nanos>(kMs, dur / 8);
      if (!flap) {
        s.events.push_back(FaultEvent{t, FaultKind::Partition, asym ? 0u : 1u, a, b, dur});
      } else {
        // Flapping: alternating cut / heal segments across the duration.
        for (Nanos u = t; u < t + dur && u < end; u += 2 * seg) {
          s.events.push_back(FaultEvent{u, FaultKind::Partition, asym ? 0u : 1u, a, b, seg});
        }
      }
    }
  }
  // Clock steps (clock stream).
  if (const Nanos mean = f[Param::ClockStepIntervalNs]; mean > 0 && w_.node_count() > 0) {
    Rng r = w_.stream(Stream::Clock, (std::uint64_t{0xFFFF} << 40) | kSubClock);
    const Nanos mx = f[Param::ClockStepMaxNs];
    for (Nanos t = start + 1 + exp_ns(r, mean); t < end; t += 1 + exp_ns(r, mean)) {
      FaultEvent e;
      e.at = t;
      e.kind = FaultKind::ClockStep;
      e.node = static_cast<NodeId>(r.below(w_.node_count()));
      e.a = static_cast<std::uint64_t>(uniform(r, -mx, mx));
      s.events.push_back(e);
    }
  }
  std::stable_sort(s.events.begin(), s.events.end(),
                   [](const FaultEvent& x, const FaultEvent& y) { return x.at < y.at; });
  return s;
}

void FaultInjector::install(const FaultSchedule& s) {
  schedule_ = s;
  for (std::size_t i = 0; i < schedule_.events.size(); ++i) {
    const FaultEvent& e = schedule_.events[i];
    Fnv1a64 h;
    h.u(static_cast<std::uint8_t>(e.kind));
    h.u(e.a);
    h.u(e.b);
    h.u(e.dur);
    w_.schedule(std::max(e.at, w_.now()), handler_, static_cast<std::uint16_t>(e.kind), e.node, i, 0, h.value());
  }
}

Dispatch FaultInjector::on_event(void* ctx, const Event& ev) {
  auto* self = static_cast<FaultInjector*>(ctx);
  if (ev.a >= self->schedule_.events.size()) return {false, 0};
  return self->fire(self->schedule_.events[ev.a]);
}

Dispatch FaultInjector::fire(const FaultEvent& f) {
  // Faults only fire in the safety phase; healing cancels what remains.
  if (w_.phase() != Phase::Safety) {
    ++skipped_;
    return {true, 0};
  }
  switch (f.kind) {
    case FaultKind::Crash: {
      if (f.node >= w_.node_count()) break;
      Node& n = w_.node(f.node);
      if (!n.alive() || !n.crashable()) break;
      if (crash_guard_ && !crash_guard_(f.node)) break;
      n.crash(f.a != 0 && n.host() == nullptr ? CrashKind::Host : CrashKind::Process);
      n.restart_after(f.dur);
      ++fired_;
      return {true, 1};
    }
    case FaultKind::Pause: {
      if (f.node >= w_.node_count()) break;
      Node& n = w_.node(f.node);
      if (!n.alive() || n.paused() || !n.pausable()) break;
      n.pause(f.dur);
      ++fired_;
      return {true, 1};
    }
    case FaultKind::Partition: {
      w_.net().partition(f.a, f.b, f.node != 0, f.dur);
      ++fired_;
      return {true, 1};
    }
    case FaultKind::ClockStep: {
      if (f.node >= w_.node_count()) break;
      w_.node(f.node).clock().step(static_cast<Nanos>(f.a));
      ++w_.stats().clock_steps;
      ++fired_;
      return {true, 1};
    }
  }
  ++skipped_;
  return {true, 0};
}

}  // namespace lle::sim
