// itch2ouch (07 §3, WP N-19): NASDAQ ITCH 5.0 day -> OUCH 5.0 order-flow script,
// and the divergence report of that script run through the real sequencer and
// engine in-process. Mapping and file format: src/client/itch2ouch.h.
//
//   itch2ouch convert --itch DAY[.gz] --out SCRIPT[.gz] [--sessions K] [--max-messages N]
//                     [--date YYYYMMDD] [--synthetic]
//   itch2ouch diverge --itch DAY[.gz] [--sessions K] [--max-messages N] [--date YYYYMMDD]
//                     [--checkpoint-times HH:MM:SS,...] [--checkpoint-every N]
//                     [--script-out SCRIPT[.gz]] [--synthetic] [--progress N] [--report FILE]
//   itch2ouch dump SCRIPT [--records N]      header, per-type counts, the first N records
//
// Synthetic order-flow days for CI: itch_synth --out day.bin ... then
// itch2ouch convert --itch day.bin --out day.ofs --synthetic.
#include <cinttypes>
#include <cstdio>
#include <string>
#include <vector>

#include "client/cli.h"
#include "client/divergence.h"
#include "client/itch2ouch.h"
#include "client/report.h"
#include "common/time.h"
#include "proto/itch50/binary_file.h"

namespace {

using namespace lle;
using namespace lle::client::i2o;
using client::cli::Args;

std::vector<Nanos> parse_times(Args& a, const std::string& v) {
  std::vector<Nanos> out;
  std::size_t start = 0;
  while (start < v.size()) {
    const std::size_t comma = v.find(',', start);
    const std::string item = v.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
    int h = 0, m = 0, s = 0;
    if (std::sscanf(item.c_str(), "%d:%d:%d", &h, &m, &s) != 3) a.die("bad time " + item);
    out.push_back(hms_ns(h, m, s));
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  return out;
}

int convert(int argc, char** argv) {
  Args a(argc, argv, "itch2ouch convert");
  std::string itch, out;
  ConvertConfig cc;
  std::uint64_t max = 0;
  ScriptHeader h;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--itch") itch = a.value();
    else if (f == "--out") out = a.value();
    else if (f == "--sessions") cc.sessions = static_cast<std::uint16_t>(a.u64());
    else if (f == "--max-messages") max = a.u64();
    else if (f == "--date") h.date = static_cast<std::uint32_t>(a.u64());
    else if (f == "--synthetic") h.flags |= 1;
    else a.die("unknown flag " + f);
  }
  if (itch.empty() || out.empty()) a.die("--itch and --out are required");
  std::string err;
  if (!scan_symbols(itch, max, h.symbols, &err)) a.die(err);
  h.sessions = cc.sessions;
  itch50::BinaryFileReader rd;
  if (auto r = rd.open(itch); !r) a.die(r.error());
  ScriptWriter w;
  if (!w.open(out, h, &err)) a.die(err);
  Converter conv(cc);
  SeqNo seq = 0;
  bool ok = true;
  for (;;) {
    const itch50::Record r = rd.next();
    if (r.status != itch50::RecordStatus::Message) {
      if (r.status == itch50::RecordStatus::IoError || r.status == itch50::RecordStatus::Truncated) a.die(rd.error());
      break;
    }
    conv.on_itch(++seq, r.data, [&](Nanos t, std::uint16_t s, std::span<const std::byte> ouch, const Origin&) {
      ok = ok && w.write(t, s, ouch);
    });
    if (max != 0 && seq >= max) break;
  }
  ok = w.close() && ok;
  const ConvertStats& st = conv.stats();
  client::JsonObject j;
  j.str("mode", "convert").str("itch", itch).str("script", out).num("source_messages", st.source);
  j.num("records", w.records()).num("sessions", cc.sessions).num("symbols", h.symbols.size());
  j.num("enter", st.ops[0]).num("cancel", st.ops[1]).num("replace", st.ops[2]).num("ioc", st.ops[3]);
  j.num("partial_cancels", st.partial_cancels).num("ioc_from_e", st.ioc_from_e).num("ioc_from_c", st.ioc_from_c);
  j.num("hidden_trades_P", st.hidden_trades).num("cross_prints_Q", st.cross_prints);
  j.num("unknown_ref", st.unknown_ref).num("duplicate_ref", st.duplicate_ref).num("live_at_end", conv.live());
  std::fputs(j.done().c_str(), stdout);
  return ok ? 0 : 1;
}

int diverge(int argc, char** argv) {
  Args a(argc, argv, "itch2ouch diverge");
  DivergenceConfig c;
  std::string report;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--itch") c.itch_path = a.value();
    else if (f == "--sessions") c.sessions = static_cast<std::uint16_t>(a.u64());
    else if (f == "--max-messages") c.max_messages = a.u64();
    else if (f == "--date") c.date = static_cast<std::uint32_t>(a.u64());
    else if (f == "--checkpoint-times") c.checkpoint_times = parse_times(a, a.value());
    else if (f == "--checkpoint-every") c.checkpoint_every = a.u64();
    else if (f == "--script-out") c.script_out = a.value();
    else if (f == "--synthetic") c.synthetic = true;
    else if (f == "--progress") c.progress_every = a.u64();
    else if (f == "--reserve-orders") c.reserve_orders = a.u64();
    else if (f == "--report") report = a.value();
    else a.die("unknown flag " + f);
  }
  if (c.itch_path.empty()) a.die("--itch is required");
  DivergenceReport r;
  std::string err;
  if (!run_divergence(c, r, &err)) a.die(err);
  const std::string j = divergence_json(c, r);
  std::fputs(j.c_str(), stdout);
  if (!report.empty()) {
    if (std::FILE* f = std::fopen(report.c_str(), "w")) {
      std::fputs(j.c_str(), f);
      std::fclose(f);
    }
  }
  return 0;
}

int dump(int argc, char** argv) {
  Args a(argc, argv, "itch2ouch dump");
  if (a.done()) a.die("dump SCRIPT [--records N]");
  const std::string path = a.flag();
  std::uint64_t show = 0;
  while (!a.done()) {
    const std::string f = a.flag();
    if (f == "--records") show = a.u64();
    else a.die("unknown flag " + f);
  }
  ScriptReader rd;
  std::string err;
  if (!rd.open(path, &err)) a.die(err);
  const ScriptHeader& h = rd.header();
  std::printf("script %s: date %u sessions %u flags %u symbols %zu\n", path.c_str(), h.date, h.sessions, h.flags,
              h.symbols.size());
  std::uint64_t n = 0, by[256] = {}, bad = 0;
  Nanos last = 0;
  std::uint64_t decreasing = 0;
  ScriptRecord rec;
  while (rd.next(rec)) {
    ++n;
    ++by[static_cast<unsigned char>(rec.ouch[0])];
    if (rec.t < last) ++decreasing;
    last = rec.t;
    if (!ouch50::validate_inbound(rec.ouch)) ++bad;
    if (n <= show) {
      std::printf("%" PRIu64 " t=%lld s=%u %c len=%zu\n", n, static_cast<long long>(rec.t), rec.session,
                  static_cast<char>(rec.ouch[0]), rec.ouch.size());
    }
  }
  if (!rd.error().empty()) a.die(rd.error());
  std::printf("records %" PRIu64 " O %" PRIu64 " X %" PRIu64 " U %" PRIu64 " invalid %" PRIu64 " time_decreases %" PRIu64 "\n",
              n, by[static_cast<unsigned char>('O')], by[static_cast<unsigned char>('X')], by[static_cast<unsigned char>('U')], bad,
              decreasing);
  return bad == 0 && decreasing == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: itch2ouch convert|diverge|dump ... (see apps/itch2ouch/main.cpp)\n");
    return 2;
  }
  const std::string mode = argv[1];
  if (mode == "convert") return convert(argc - 1, argv + 1);
  if (mode == "diverge") return diverge(argc - 1, argv + 1);
  if (mode == "dump") return dump(argc - 1, argv + 1);
  std::fprintf(stderr, "itch2ouch: unknown mode %s\n", mode.c_str());
  return 2;
}
