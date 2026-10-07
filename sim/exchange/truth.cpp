#include "sim/exchange/truth.h"

#include <algorithm>
#include <span>

#include "engine/journal_adapter.h"
#include "engine/scenario.h"
#include "journal/reader.h"
#include "journal/replay.h"
#include "journal/segment.h"
#include "proto/ouch50/ouch50.h"
#include "sim/exchange/sim_storage.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"

namespace lle::sim::exch {

namespace en = lle::engine;
namespace jr = lle::journal;
namespace oo = lle::ouch50::out;

Truth regenerate(Node& n, const std::string& journal_prefix, std::uint32_t date,
                 const std::vector<en::ScheduleEntry>& schedule) {
  Truth t;
  SimReadOnlySegmentDir dir(n, journal_prefix);
  en::Engine eng;
  struct Sink {
    Truth* t;
    std::uint64_t idx = 0;
    Nanos ts = 0;
    void itch(std::uint64_t i, std::span<const std::byte> b) {
      t->itch.push_back(Out{i, std::vector<std::byte>(b.begin(), b.end())});
    }
    void ouch(std::uint64_t i, std::uint32_t session, std::span<const std::byte> b) {
      t->ouch[session].push_back(Out{i, std::vector<std::byte>(b.begin(), b.end())});
      if (b.empty()) return;
      auto life = [&](std::uint32_t urn) -> OrderLife* {
        const auto it = t->orders.find({session, urn});
        return it == t->orders.end() ? nullptr : &it->second;
      };
      auto close_if_done = [&](OrderLife& ol) {
        if (ol.open <= 0 && ol.closed == 0) ol.closed = i;
      };
      switch (static_cast<char>(b[0])) {
        case 'A': {
          const auto m = oo::OrderAccepted::decode_base(b.data());
          t->consumed[{session, m.user_ref_num}].push_back(i);
          OrderLife ol{session, m.user_ref_num, i, 0, static_cast<std::int64_t>(m.quantity), {}, {}, m.cross_type};
          if (m.order_state == ouch50::OrderState::Dead) {
            ol.open = 0;
            ol.closed = i;
          }
          t->orders[{session, m.user_ref_num}] = ol;
          break;
        }
        case 'U': {
          const auto m = oo::OrderReplaced::decode_base(b.data());
          t->consumed[{session, m.user_ref_num}].push_back(i);
          if (OrderLife* old = life(m.orig_user_ref_num)) {
            old->open = 0;
            close_if_done(*old);
          }
          OrderLife ol{session, m.user_ref_num, i, 0, static_cast<std::int64_t>(m.quantity), {}, {}, m.cross_type};
          if (m.order_state == ouch50::OrderState::Dead) {
            ol.open = 0;
            ol.closed = i;
          }
          t->orders[{session, m.user_ref_num}] = ol;
          break;
        }
        case 'J': {
          const auto m = oo::Rejected::decode_base(b.data());
          t->consumed[{session, m.user_ref_num}].push_back(i);
          break;
        }
        case 'E': {
          const auto m = oo::OrderExecuted::decode_base(b.data());
          if (OrderLife* ol = life(m.user_ref_num)) {
            ol->open -= m.quantity;
            ol->executions.push_back(i);
            ol->execution_ts.push_back(ts);
            close_if_done(*ol);
          }
          break;
        }
        case 'C': {
          const auto m = oo::OrderCanceled::decode_base(b.data());
          if (OrderLife* ol = life(m.user_ref_num)) {
            ol->open -= m.quantity;
            close_if_done(*ol);
          }
          break;
        }
        case 'D': {
          const auto m = oo::AiqCanceled::decode_base(b.data());
          if (OrderLife* ol = life(m.user_ref_num)) {
            ol->open -= m.decrement_shares;
            close_if_done(*ol);
          }
          break;
        }
        case 'M': {  // Order Modified: the order's leaves after a Modify
          const auto m = oo::OrderModified::decode_base(b.data());
          if (OrderLife* ol = life(m.user_ref_num)) {
            ol->open = static_cast<std::int64_t>(m.quantity);
            close_if_done(*ol);
          }
          break;
        }
        case 'X':    // Mass Cancel Response
        case 'G':    // Disable Order Entry Response
        case 'K': {  // Enable Order Entry Response: each consumed its request's UserRefNum
          t->consumed[{session, load_be32(b.data() + 9)}].push_back(i);
          break;
        }
        default:
          break;
      }
    }
    void audit(std::uint64_t, const en::AuditEvent&) {}
  };
  struct Replay {
    Truth* t;
    en::Engine* eng;
    Sink* sink;
    const std::vector<en::ScheduleEntry>* schedule;
    std::uint64_t expect = 1;
    bool gap = false;
    bool on_record(const jr::RecordView& r) {
      if (r.index() != expect) {
        gap = true;
        return false;
      }
      ++expect;
      Rec rec;
      rec.type = r.type();
      rec.ts = r.ts_ns();
      rec.epoch = r.epoch();
      if (r.type() == jr::RecordType::OuchInbound) {
        if (const auto x = jr::decode_ouch_inbound(r)) {
          rec.session = x->session_id;
          rec.instance = x->instance;
          rec.payload.assign(x->msg.begin(), x->msg.end());
        }
        rec.flags = r.flags();
      } else if (r.type() == jr::RecordType::SessionEvent) {
        if (const auto e = jr::decode_session_event(r)) {
          rec.session = e->session_id;
          rec.event = e->event;
          rec.instance = e->instance;
          rec.requested = e->requested_seq;
        }
      } else if (r.type() == jr::RecordType::Admin) {
        if (const auto a = jr::decode_admin(r)) rec.admin = a->command;
      } else if (r.type() == jr::RecordType::EpochStart) {
        if (const auto e = jr::decode_epoch_start(r)) rec.primary = e->primary_node;
      } else if (r.type() == jr::RecordType::DayEnd) {
        t->day_end = r.index();
      } else if (r.type() == jr::RecordType::Timer) {
        if (const auto tm = jr::decode_timer(r)) {
          for (const en::ScheduleEntry& e : *schedule) {
            if (e.timer_id != tm->timer_id) continue;
            if (e.kind == en::TimerKind::StateChange &&
                e.arg == static_cast<std::uint16_t>(en::Milestone::OpenFreeze) && t->open_freeze == 0)
              t->open_freeze = r.index();
            if (e.kind == en::TimerKind::Cross && e.arg == 'O' && t->open_cross == 0) t->open_cross = r.index();
            if (e.kind == en::TimerKind::StateChange &&
                e.arg == static_cast<std::uint16_t>(en::Milestone::CloseFreeze) && t->close_freeze == 0)
              t->close_freeze = r.index();
          }
        }
      }
      t->recs.push_back(std::move(rec));
      sink->idx = r.index();
      sink->ts = r.ts_ns();
      eng->apply(en::to_input(r), *sink);
      if (r.type() == jr::RecordType::SnapshotMark) t->mark_hash[r.index()] = eng->state_hash();
      return true;
    }
  };
  Sink sink{&t};
  Replay rp{&t, &eng, &sink, &schedule};
  (void)jr::replay(dir, jr::ReplayRange{1, ~std::uint64_t{0}}, rp, date);
  if (rp.gap) {
    t.error = "journal replay found a gap at " + std::to_string(rp.expect);
    return t;
  }
  t.crc = canonical_crcs(n, journal_prefix, date);
  t.state_hash = eng.state_hash();
  t.ok = true;
  return t;
}

std::string check_snapshots(Node& n, const std::string& dir, const Truth& t) {
  SimSnapStorage st(n);
  for (const std::string& name : st.list(dir)) {
    const auto idx = snap::parse_snapshot_file_name(name);
    if (!idx || *idx > t.recs.size()) continue;
    const std::string path = dir + "/" + name;
    const auto loaded = snap::LoadedSnapshot::open(st, path);
    if (!loaded || loaded->meta().index != *idx) continue;
    const auto it = t.mark_hash.find(*idx);
    if (it == t.mark_hash.end())
      return n.name() + ": " + path + ": the final journal has no SnapshotMark at " + std::to_string(*idx);
    if (loaded->meta().state_hash != it->second)
      return n.name() + ": " + path + ": the snapshot's state differs from the final journal's at " +
             std::to_string(*idx);
  }
  return {};
}

std::vector<std::uint32_t> canonical_crcs(Node& n, const std::string& journal_prefix, std::uint32_t date) {
  std::vector<std::uint32_t> out;
  SimReadOnlySegmentDir dir(n, journal_prefix);
  jr::ReadOptions ro;
  ro.day = date;
  ro.from_index = 1;
  ro.to_index = ~std::uint64_t{0};
  (void)jr::read_journal(dir, ro, [&](const jr::RecordView& r, const jr::RecordLocation& loc) {
    if (r.index() != out.size() + 1) return false;
    out.push_back(loc.sealer->content_of(r.data()));
    return true;
  });
  return out;
}

std::uint64_t DurableTap::parse(std::span<const std::byte> img, std::uint64_t from, std::uint64_t to,
                                const jr::Sealer& sealer, Nanos now) {
  std::uint64_t cur = from;
  while (cur + jr::kHeaderBytes <= to) {
    const auto r = jr::parse_record(img.subspan(static_cast<std::size_t>(cur), static_cast<std::size_t>(to - cur)));
    if (!r) break;
    const auto content = sealer.verify(r->data());
    if (!content) break;
    if (r->type() != jr::RecordType::Pad) {
      const auto [it, fresh] = durable_at_.emplace(std::pair{r->index(), *content}, now);
      if (!fresh && now < it->second) it->second = now;
    }
    cur += r->bytes().size();
  }
  return cur;
}

void DurableTap::on_durable(Disk& disk, std::uint32_t fidx, std::uint64_t off, std::uint32_t len) {
  const std::span<const std::byte> img = disk.durable_image(fidx);
  if (img.size() < jr::kSegmentHeaderBytes) return;
  const auto h = jr::decode_segment_header(img.first(jr::kSegmentHeaderBytes));
  if (!h) return;
  std::unique_ptr<jr::Sealer>& sealer = sealers_[fidx];
  if (!sealer || sealer->nonce() != h->nonce) sealer = std::make_unique<jr::Sealer>(h->nonce);
  const Nanos now = w_.now();
  if (len != 0 && off >= jr::kSegmentHeaderBytes) {
    (void)parse(img, off, std::min<std::uint64_t>(off + len, img.size()), *sealer, now);
    return;
  }
  for (std::uint64_t b = jr::kSegmentHeaderBytes; b < img.size();) {
    const std::uint64_t end = parse(img, b, img.size(), *sealer, now);
    b = std::max(b + jr::kBlockBytes, (end + jr::kBlockBytes - 1) / jr::kBlockBytes * jr::kBlockBytes);
  }
}

// An auction is collecting interest: the opening or closing cross is frozen and not
// done for some symbol, or a symbol is halted (its halt cross is pending).
bool auction_in_progress(const en::Engine& e) {
  const std::uint8_t ms = e.milestones();
  for (Locate l = 1; l <= e.symbols(); ++l) {
    const en::SymbolInfo& s = e.symbol(l);
    if ((ms & en::kOpenFreeze) != 0 && !s.opened) return true;
    if ((ms & en::kCloseFreeze) != 0 && !s.closed) return true;
    if (s.halt == en::HaltPhase::Halted || s.halt == en::HaltPhase::QuoteOnly || s.halt == en::HaltPhase::Paused)
      return true;
  }
  return false;
}

}  // namespace lle::sim::exch
