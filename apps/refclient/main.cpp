// refclient v1: the reference trading client (07 §3, WP N-04; T10, T18).
//
// Network mode (feed handler, optional strategy and order entry):
//   refclient --line-a IP:PORT --line-b IP:PORT [--rerequest-a IP:PORT --rerequest-b IP:PORT]
//             [--glimpse IP:PORT [--glimpse-user U --glimpse-password P]] [--checkpoint-every N] [--checkpoints-out FILE] [--bbo] [--line-compare WINDOW]
//             [--trade --symbol SYM (--sell-at PX | --buy-at PX) [--qty N] [--max-orders N]
//              --primary IP:PORT [--backup IP:PORT] [--user U --password P]]
//             [--gap-timeout DUR] [--request-timeout DUR] [--snapshot-gap N] [--reorder-capacity N]
//             [--stamp-log FILE [--stamp-log-capacity N]] [--max-runtime DUR] [--report FILE] [--nlog FILE]
//             [--metrics NAME]
//             [variant flags: --variant V --ifname IF --timestamps M --wait W --cpu N ...; client/variant.h]
// Direct replay of a file (the reference of the T10 comparison):
//   refclient --direct FILE [--book opt|b0] [--checkpoint-every N] [--extra-checkpoints A,B,...]
//             [--checkpoints-out FILE] [--max-messages N]
//
// --variant names the I/O variant (epoll, busypoll, busypoll-irq-suspend, uring,
// uring-napi, xsk, xsk-threaded); for compatibility, a book variant name there (opt, b0,
// ...) selects the book of --direct, like --book. --backend is an alias of --variant.
// --stamp-log writes the T18 order-stamp log (client/hwts_log.h) at the end of the run.
// Comparison:
//   refclient --compare CLIENT_CHECKPOINTS REFERENCE_CHECKPOINTS
#include <atomic>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "book/digested_book.h"
#include "book/itch_adapter.h"
#include "book/variants.h"
#include "client/checkpoints.h"
#include "client/cli.h"
#include "client/histogram.h"
#include "client/refclient.h"
#include "client/report.h"
#include "client/variant.h"
#include "env/prod_clock.h"
#include "log/backend.h"
#include "log/nlog.h"
#include "proto/itch50/binary_file.h"
#include "runtime/pinning.h"

namespace {

using namespace lle;
using client::cli::Args;

std::atomic<bool> g_stop{false};
extern "C" void on_signal(int) { g_stop.store(true); }

struct Options {
  client::RefClientConfig rc;
  client::VariantConfig vc;
  std::string direct;
  std::string variant = "opt";  // the book of --direct
  std::string compare_a, compare_b;
  std::string checkpoints_out;
  std::string report;
  std::string stamp_log;
  std::string nlog;  // the client's event log (11 §3), decoded offline by nlog_decode
  std::string metrics;  // the client's metrics segment /lle-stats-<name> (11 §3), read by lle-top
  std::uint64_t max_messages = 0;
  bool bbo = false;
};

Options parse(int argc, char** argv) {
  Options o;
  auto& rc = o.rc;
  rc.feed.book.reserve_orders = std::size_t{1} << 21;
  rc.feed.book.reserve_levels = std::size_t{1} << 20;
  // X27: level vectors reserved per book at its directory message, so a level
  // insert does not reallocate below this depth (real days: p90 101, p99 311).
  rc.feed.book.levels_per_side = 128;
  rc.feed.arbiter.reorder_capacity = std::size_t{1} << 20;
  rc.feed.arbiter.gap_timeout = 200'000;
  rc.feed.arbiter.request_timeout = 2'000'000;
  rc.glimpse_login.username = Alpha<6>("GLIMPS");
  rc.orders.session.username = Alpha<6>("U00099");
  rc.orders.session.password = Alpha<10>("password");
  Args a(argc, argv, "refclient");
  while (!a.done()) {
    const std::string f = a.flag();
    auto dur = [&]() {
      const std::string v = a.value();
      const auto d = client::cli::parse_duration(v);
      if (!d) a.die("bad duration: " + v);
      return *d;
    };
    auto price = [&]() {
      const std::string v = a.value();
      const auto p = client::cli::parse_price(v);
      if (!p) a.die("bad price: " + v);
      return *p;
    };
    if (f == "--variant") {
      const std::string v = a.value();
      if (const auto p = client::parse_variant(v)) o.vc.variant = *p;
      else o.variant = v;  // a book variant (--direct)
      continue;
    }
    if (client::parse_variant_flag(a, f, o.vc)) continue;
    if (f == "--line-a") rc.line_a = a.endpoint();
    else if (f == "--line-b") rc.line_b = a.endpoint();
    else if (f == "--book") o.variant = a.value();
    else if (f == "--rerequest-a") rc.rerequest_a = a.endpoint();
    else if (f == "--rerequest-b") rc.rerequest_b = a.endpoint();
    else if (f == "--glimpse") rc.glimpse = a.endpoint();
    else if (f == "--glimpse-user") rc.glimpse_login.username = Alpha<6>(a.value());
    else if (f == "--glimpse-password") rc.glimpse_login.password = Alpha<10>(a.value());
    else if (f == "--checkpoint-every") rc.feed.checkpoints.every = a.u64();
    else if (f == "--extra-checkpoints") {
      for (auto v : client::cli::parse_u64_list(a, a.value())) rc.feed.checkpoints.extra.push_back(v);
    } else if (f == "--checkpoints-out") o.checkpoints_out = a.value();
    else if (f == "--bbo") o.bbo = true;
    else if (f == "--line-compare") rc.line_compare_window = a.u64();
    else if (f == "--trade") rc.trade = true;
    else if (f == "--symbol") rc.strategy.symbol = Symbol8(a.value());
    else if (f == "--sell-at") {
      rc.strategy.on_sell = true;
      rc.strategy.sell_threshold = price();
    } else if (f == "--buy-at") {
      rc.strategy.on_buy = true;
      rc.strategy.buy_threshold = price();
    } else if (f == "--no-sell") rc.strategy.on_sell = false;
    else if (f == "--qty") rc.strategy.quantity = static_cast<Qty>(a.u64());
    else if (f == "--max-orders") rc.strategy.max_orders = a.u64();
    else if (f == "--primary") rc.primary = a.endpoint();
    else if (f == "--backup") rc.backup = a.endpoint();
    else if (f == "--user") rc.orders.session.username = Alpha<6>(a.value());
    else if (f == "--password") rc.orders.session.password = Alpha<10>(a.value());
    else if (f == "--reconnect") rc.reconnect_interval = dur();
    else if (f == "--linger") rc.linger_after_end = dur();
    else if (f == "--gap-timeout") rc.feed.arbiter.gap_timeout = dur();
    else if (f == "--request-timeout") rc.feed.arbiter.request_timeout = dur();
    else if (f == "--snapshot-gap") rc.feed.arbiter.snapshot_gap_messages = a.u64();
    else if (f == "--reorder-capacity") rc.feed.arbiter.reorder_capacity = a.u64();
    else if (f == "--reserve-orders") rc.feed.book.reserve_orders = a.u64();
    else if (f == "--levels-per-side") rc.feed.book.levels_per_side = a.u64();
    else if (f == "--block") o.vc.wait = net::WaitPolicy::Block;
    else if (f == "--stamp-log") o.stamp_log = a.value();
    else if (f == "--nlog") o.nlog = a.value();
    else if (f == "--metrics") o.metrics = a.value();
    else if (f == "--stamp-log-capacity") rc.stamp_log_capacity = a.u64();
    else if (f == "--max-runtime") rc.max_runtime = dur();
    else if (f == "--report") o.report = a.value();
    else if (f == "--verbose") rc.verbose = true;
    else if (f == "--direct") o.direct = a.value();
    else if (f == "--max-messages") o.max_messages = a.u64();
    else if (f == "--compare") {
      o.compare_a = a.value();
      o.compare_b = a.value();
    } else a.die("unknown flag " + f);
  }
  rc.feed.checkpoints.max_checkpoints = 1 << 16;
  if (!o.stamp_log.empty() && rc.stamp_log_capacity == 0) rc.stamp_log_capacity = std::size_t{1} << 22;
  return o;
}

void emit(const Options& o, const std::string& json) {
  std::fputs(json.c_str(), stdout);
  if (!o.report.empty()) {
    if (std::FILE* f = std::fopen(o.report.c_str(), "w")) {
      std::fputs(json.c_str(), f);
      std::fclose(f);
    }
  }
}

// --- direct replay ------------------------------------------------------------------
template <class V>
int direct(const Options& o) {
  itch50::BinaryFileReader rd;
  if (auto r = rd.open(o.direct); !r) {
    std::fprintf(stderr, "refclient: %s\n", r.error().c_str());
    return 1;
  }
  book::BookConfig bc;
  bc.reserve_orders = o.rc.feed.book.reserve_orders;
  bc.reserve_levels = o.rc.feed.book.reserve_levels;
  auto db = std::make_unique<book::DigestedBook<V>>(bc);
  client::CheckpointRecorder ck(o.rc.feed.checkpoints);
  client::StreamHasher whole;
  env::ProdClock clock;
  const Nanos t0 = clock.now_mono();
  SeqNo seq = 0;
  std::uint64_t malformed = 0;
  for (;;) {
    const itch50::Record r = rd.next();
    if (r.status != itch50::RecordStatus::Message) {
      if (r.status == itch50::RecordStatus::Truncated || r.status == itch50::RecordStatus::IoError) {
        std::fprintf(stderr, "refclient: read error: %s\n", rd.error().c_str());
        return 1;
      }
      break;
    }
    ++seq;
    const auto res = book::apply_itch(db->book(), r.data.data(), r.data.size());
    if (res.kind == book::ItchKind::kMalformed) ++malformed;
    ck.on_message(seq, r.data, db->book(), db->recorder().digest.value);
    whole.add(seq, r.data);
    if (o.max_messages != 0 && seq >= o.max_messages) break;
  }
  ck.finish(seq, db->book(), db->recorder().digest.value);
  if (!o.checkpoints_out.empty() && !client::write_checkpoints(o.checkpoints_out, ck.list())) {
    std::fprintf(stderr, "refclient: cannot write %s\n", o.checkpoints_out.c_str());
    return 1;
  }
  client::JsonObject j;
  j.str("mode", "direct").str("file", o.direct).str("variant", o.variant).num("messages", seq);
  j.num("elapsed_ns", static_cast<std::uint64_t>(clock.now_mono() - t0)).num("malformed", malformed);
  j.hex("final_books_digest", db->book().books_digest()).num("final_live_orders", db->book().live_orders());
  j.hex("bbo_digest", db->recorder().digest.value).num("bbo_events", db->recorder().digest.events);
  j.hex("stream_hash_all", whole.value()).num("checkpoints", ck.list().size());
  emit(o, j.done());
  return 0;
}

// --- network mode ---------------------------------------------------------------------
// TTT_client over the order-stamp log (METHODOLOGY §13): TX_hw(order frame) -
// RX_hw(winning trigger frame), both on the port's PHC; only records whose trigger was
// in the stamped packet. The harness-side analysis (ttt_harness analyze) restricts it
// to the measured triggers; this is the whole-run view.
void ttt_client_json(client::JsonObject& j, std::span<const client::OrderStampRecord> log, std::uint64_t overflow,
                     const net::TsValidity& txv) {
  net::hwts::IntervalAccounting acc;
  client::Histogram h;
  std::uint64_t not_in_packet = 0, untagged = 0;
  for (const client::OrderStampRecord& r : log) {
    if ((r.flags & client::OrderStampRecord::kUntagged) != 0) ++untagged;
    if ((r.flags & client::OrderStampRecord::kInPacket) == 0) {
      ++not_in_packet;
      continue;
    }
    if (const auto d = acc.record(r.tx_stamp(), r.rx_stamp())) h.record(*d);
  }
  j.num("stamp_log_records", log.size()).num("stamp_log_overflow", overflow);
  j.num("stamp_log_not_in_packet", not_in_packet).num("stamp_log_untagged", untagged);
  j.num("tx_stamps_hw", txv.hw).num("tx_stamps_sw", txv.sw).num("tx_stamps_missing", txv.missing);
  j.num("ttt_client_pairs_ok", acc.ok).num("ttt_client_pairs_missing", acc.missing);
  j.num("ttt_client_pairs_software", acc.software).num("ttt_client_pairs_cross_phc", acc.cross_phc);
  j.boolean("ttt_client_valid", acc.valid());
  h.json(j, "ttt_client_");
}

template <class Io, class L>
int network(Options& o) {
  client::DeviceReport dev;
  std::string err;
  if (!client::prepare_variant(o.vc, dev, err)) {
    std::fprintf(stderr, "refclient: %s\n", err.c_str());
    return 2;
  }
  o.rc.phc_index = dev.phc_index;
  auto c = std::make_unique<client::RefClient<Io, L>>(o.rc, o.vc);
  if (auto r = c->open(); !r) {
    std::fprintf(stderr, "refclient: open: %s\n", r.error().c_str());
    return 1;
  }
  std::optional<metrics::Segment> seg;
  if (!o.metrics.empty()) {
    auto s = metrics::Segment::create_shm(o.metrics, client::client_metrics_schema());
    if (!s) {
      std::fprintf(stderr, "refclient: metrics: %s\n", s.error().c_str());
      return 2;
    }
    seg.emplace(std::move(*s));
    c->set_metrics(&*seg);
  }
  if (o.vc.cpu >= 0) {
    const auto st = rt::pin_current_thread(o.vc.cpu);
    std::fprintf(stderr, "refclient: pin cpu %d: %s\n", o.vc.cpu, rt::to_string(st));
  }
  const client::RefClientResult res = c->run(&g_stop);
  const auto& fs = c->feed().stats();
  if (!o.checkpoints_out.empty() && !client::write_checkpoints(o.checkpoints_out, c->feed().checkpoints().list())) {
    std::fprintf(stderr, "refclient: cannot write %s\n", o.checkpoints_out.c_str());
  }
  if (!o.stamp_log.empty() && !client::write_hwts_log(o.stamp_log, c->stamp_log())) {
    std::fprintf(stderr, "refclient: cannot write %s\n", o.stamp_log.c_str());
  }
  client::JsonObject j;
  j.str("mode", "network").str("backend", client::to_string(o.vc.variant)).boolean("feed_ended", res.feed_ended);
  client::variant_json(j, o.vc, dev);
  j.num("elapsed_ns", static_cast<std::uint64_t>(res.elapsed)).num("delivered", fs.delivered);
  j.num("last_seq", fs.last_seq).num("book_seq", fs.book_seq).num("end_seq", fs.end_seq);
  j.num("snapshots_requested", fs.snapshots_requested).num("snapshots_applied", fs.snapshots_applied);
  j.num("snapshots_rejected", fs.snapshots_rejected).num("snapshots_aborted", fs.snapshots_aborted);
  j.num("snapshot_messages", fs.snapshot_messages);
  j.num("snapshot_covered", fs.snapshot_covered).num("snapshot_sessions", res.snapshot_sessions);
  j.num("snapshot_failures", res.snapshot_failures);
  for (std::size_t s = 0; s < fs.book_status.size(); ++s)
    j.num(std::string("book_status_") + book::to_string(static_cast<book::Status>(s)), fs.book_status[s]);
  j.hex("final_books_digest", c->feed().book().books_digest()).num("final_live_orders", c->feed().book().live_orders());
  j.hex("bbo_digest", c->feed().bbo_value());
  j.num("checkpoints", c->feed().checkpoints().list().size()).num("checkpoints_skipped", c->feed().checkpoints().skipped());
  std::string splices;
  for (const auto& ck : c->feed().checkpoints().list())
    if (ck.splice) splices += (splices.empty() ? "" : ",") + std::to_string(ck.seq);
  j.str("splice_checkpoints", splices);
  client::add_arbiter_metrics(j, c->feed().arbiter().metrics());
  // A latency run needs a gap-free feed (plan 12 §4): nothing re-requested, no snapshot.
  const auto& am = c->feed().arbiter().metrics();
  j.boolean("feed_gap_free", am.requests_sent[0] + am.requests_sent[1] == 0 && fs.snapshots_requested == 0);
  if (mold::LineComparator* lc = c->line_comparator()) {
    // T10 HA line consistency (03 §5): line A and line B, message by message.
    lc->finish();
    const mold::LineComparatorStats& ls = lc->stats();
    j.boolean("lines_consistent", lc->consistent()).num("lines_compared", ls.compared);
    j.num("lines_mismatches", ls.mismatches).num("lines_first_mismatch", ls.first_mismatch);
    j.num("lines_session_mismatches", ls.session_mismatches);
    j.num("lines_unmatched_a", ls.unmatched[0]).num("lines_unmatched_b", ls.unmatched[1]);
    j.num("lines_stale_a", ls.stale[0]).num("lines_stale_b", ls.stale[1]);
    j.num("lines_duplicates_a", ls.duplicates[0]).num("lines_duplicates_b", ls.duplicates[1]);
    j.num("lines_malformed_a", ls.malformed[0]).num("lines_malformed_b", ls.malformed[1]);
  }
  c->io().stats_json(j);
  if (o.rc.trade) {
    const auto& ss = c->strategy().stats();
    const auto& os = c->orders().stats();
    j.num("strategy_adds_seen", ss.adds_seen).num("strategy_triggers", ss.triggers).num("strategy_orders", ss.orders);
    j.num("strategy_suppressed", ss.suppressed).num("strategy_send_failed", ss.send_failed);
    j.num("strategy_locate_known", c->strategy().locate_known() ? 1 : 0);
    j.num("oe_sent", os.sent).num("oe_resent", os.resent).num("oe_acked", os.acked);
    j.num("oe_responses", os.responses).num("oe_duplicate_responses", os.duplicate_responses);
    j.num("oe_takeovers", os.takeovers).num("oe_logins", os.logins).num("oe_login_rejects", os.login_rejects);
    j.num("oe_instance_failures", os.instance_failures).num("oe_pending", c->orders().pending());
    j.num("oe_pending_full", os.pending_full).num("oe_sequence_jumps", os.sequence_jumps);
    if (o.rc.stamp_log_capacity != 0) ttt_client_json(j, c->stamp_log(), c->stamp_log_overflow(), c->tx_stamp_validity());
  }
  emit(o, j.done());
  return res.ok && res.feed_ended ? 0 : 1;
}

int compare(const Options& o) {
  std::vector<client::Checkpoint> a, b;
  std::string err;
  if (!client::read_checkpoints(o.compare_a, a, &err) || !client::read_checkpoints(o.compare_b, b, &err)) {
    std::fprintf(stderr, "refclient: %s\n", err.c_str());
    return 2;
  }
  const client::CompareResult r = client::compare_checkpoints(a, b);
  client::JsonObject j;
  j.str("mode", "compare").boolean("match", r.ok).num("client_checkpoints", a.size());
  j.num("reference_checkpoints", b.size()).num("compared_books", r.compared_books);
  j.num("compared_streams", r.compared_streams).num("compared_bbo", r.compared_bbo);
  j.num("missing_in_reference", r.missing_in_reference).num("mismatches", r.mismatches);
  j.boolean("reached_end", r.reached_end);
  std::string d;
  for (const auto& s : r.details) d += (d.empty() ? "" : "; ") + s;
  j.str("details", d);
  emit(o, j.done());
  return r.ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  Options o = parse(argc, argv);
  if (!o.compare_a.empty()) return compare(o);
  if (!o.direct.empty()) {
    int rc = 2;
    if (!book::visit_variant(o.variant, [&]<class V>() { rc = direct<V>(o); })) {
      std::fprintf(stderr, "refclient: unknown --variant %s\n", o.variant.c_str());
      return 2;
    }
    return rc;
  }
  if (o.rc.line_a.port == 0 || o.rc.line_b.port == 0) {
    std::fprintf(stderr, "refclient: --line-a and --line-b are required (or --direct / --compare)\n");
    return 2;
  }
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  // --nlog: order sends and responses, gap fills and first arrivals per line, written by
  // a backend thread; without it the log calls are dropped.
  nlog::Backend log;
  if (!o.nlog.empty()) {
    nlog::BackendOptions bo;
    bo.path = o.nlog;
    bo.node = "refclient";
    if (auto r = log.start(bo); !r) {
      std::fprintf(stderr, "refclient: nlog: %s\n", r.error().c_str());
      return 2;
    }
    nlog::ThreadOptions to;
    to.name = "refclient";
    (void)nlog::register_thread(to);
  }
  int rc = 2;
  const bool ok = client::with_variant_io(o.vc, [&]<class Io>() {
    rc = o.bbo ? network<Io, book::BboRecorder>(o) : network<Io, book::NullListener>(o);
  });
  if (!ok) {
    std::fprintf(stderr, "refclient: variant %s not compiled in\n", client::to_string(o.vc.variant));
    return 2;
  }
  return rc;
}
