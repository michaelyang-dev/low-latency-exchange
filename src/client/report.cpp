#include "client/report.h"

#include <cinttypes>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>

namespace lle::client {

void JsonObject::key(std::string_view k) {
  s_ += s_.empty() ? "{\n  \"" : ",\n  \"";
  s_ += k;
  s_ += "\": ";
}

JsonObject& JsonObject::num(std::string_view k, std::uint64_t v) {
  key(k);
  s_ += std::to_string(v);
  return *this;
}

JsonObject& JsonObject::inum(std::string_view k, std::int64_t v) {
  key(k);
  s_ += std::to_string(v);
  return *this;
}

JsonObject& JsonObject::str(std::string_view k, std::string_view v) {
  key(k);
  s_ += '"';
  for (char c : v) {
    if (c == '"' || c == '\\') {
      s_ += '\\';
      s_ += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      char b[8];
      std::snprintf(b, sizeof b, "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
      s_ += b;
    } else {
      s_ += c;
    }
  }
  s_ += '"';
  return *this;
}

JsonObject& JsonObject::hex(std::string_view k, std::uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "%016" PRIx64, v);
  return str(k, b);
}

JsonObject& JsonObject::boolean(std::string_view k, bool v) {
  key(k);
  s_ += v ? "true" : "false";
  return *this;
}

JsonObject& JsonObject::raw(std::string_view k, std::string_view json) {
  key(k);
  s_ += json;
  return *this;
}

std::string JsonObject::done() const { return s_.empty() ? std::string("{}\n") : s_ + "\n}\n"; }

void add_arbiter_metrics(JsonObject& j, const mold::LineArbiterMetrics& m) {
  static constexpr const char* kSrc[mold::kNumSources] = {"line_a", "line_b", "rerequest_a", "rerequest_b"};
  for (std::size_t i = 0; i < mold::kNumSources; ++i) {
    const std::string p = std::string("arb_") + kSrc[i] + "_";
    j.num(p + "packets", m.packets[i]);
    j.num(p + "first_arrivals", m.first_arrivals[i]);
    j.num(p + "duplicate_packets", m.duplicate_packets[i]);
    j.num(p + "partial_overlaps", m.partial_overlaps[i]);
    j.num(p + "malformed", m.malformed[i]);
  }
  j.num("arb_first_arrival_ppm_line_a", m.first_arrival_ppm(mold::Source::LineA));
  j.num("arb_first_arrival_ppm_line_b", m.first_arrival_ppm(mold::Source::LineB));
  j.num("arb_delivered", m.delivered);
  j.num("arb_wrong_session", m.wrong_session);
  j.num("arb_heartbeats", m.heartbeats);
  j.num("arb_end_of_session_packets", m.end_of_session_packets);
  j.num("arb_gaps_opened", m.gaps_opened);
  j.num("arb_gaps_filled_by_line_a", m.gaps_filled_by_line[0]);
  j.num("arb_gaps_filled_by_line_b", m.gaps_filled_by_line[1]);
  j.num("arb_gaps_filled_by_rerequest", m.gaps_filled_by_rerequest);
  j.num("arb_gaps_filled_by_snapshot", m.gaps_filled_by_snapshot);
  j.num("arb_requests_sent_a", m.requests_sent[0]);
  j.num("arb_requests_sent_b", m.requests_sent[1]);
  j.num("arb_request_timeouts_a", m.request_timeouts[0]);
  j.num("arb_request_timeouts_b", m.request_timeouts[1]);
  j.num("arb_failovers", m.failovers);
  j.num("arb_recovered_messages", m.recovered_messages);
  j.num("arb_snapshot_signals", m.snapshot_signals);
  j.num("arb_reorder_high_water", m.reorder_high_water);
  j.num("arb_buffer_overflows", m.buffer_overflows);
  j.num("arb_snapshot_window_drops", m.snapshot_window_drops);
  j.num("arb_skew_samples", m.skew_ns.count());
  j.num("arb_skew_a_ahead", m.skew_a_ahead);
  j.num("arb_skew_b_ahead", m.skew_b_ahead);
  j.num("arb_skew_p50_ns_upper", m.skew_ns.quantile_upper(500'000));
  j.num("arb_skew_p999_ns_upper", m.skew_ns.quantile_upper(999'000));
  j.num("arb_skew_max_ns", m.skew_ns.max());
  j.num("arb_rtt_samples", m.rtt_ns.count());
  j.num("arb_rtt_p99_ns_upper", m.rtt_ns.quantile_upper(990'000));
  j.num("arb_rtt_max_ns", m.rtt_ns.max());
}

bool write_checkpoints(const std::string& path, const std::vector<Checkpoint>& list) {
  std::FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr) return false;
  std::fprintf(f, "# seq books_digest live_orders stream_hash bbo_digest tainted splice\n");
  for (const Checkpoint& c : list) {
    std::fprintf(f, "%" PRIu64 " %016" PRIx64 " %" PRIu64 " %016" PRIx64 " %016" PRIx64 " %d %d\n", c.seq,
                 c.books_digest, c.live_orders, c.stream_hash, c.bbo_digest, c.tainted ? 1 : 0, c.splice ? 1 : 0);
  }
  return std::fclose(f) == 0;
}

bool read_checkpoints(const std::string& path, std::vector<Checkpoint>& out, std::string* err) {
  std::ifstream in(path);
  if (!in) {
    if (err) *err = "cannot open " + path;
    return false;
  }
  std::string line;
  int ln = 0;
  while (std::getline(in, line)) {
    ++ln;
    if (line.empty() || line[0] == '#') continue;
    std::istringstream s(line);
    Checkpoint c;
    std::string bd, sh, bb;
    int t = 0, sp = 0;
    if (!(s >> c.seq >> bd >> c.live_orders >> sh >> bb >> t >> sp)) {
      if (err) *err = path + ":" + std::to_string(ln) + ": malformed checkpoint";
      return false;
    }
    c.books_digest = std::stoull(bd, nullptr, 16);
    c.stream_hash = std::stoull(sh, nullptr, 16);
    c.bbo_digest = std::stoull(bb, nullptr, 16);
    c.tainted = t != 0;
    c.splice = sp != 0;
    out.push_back(c);
  }
  return true;
}

CompareResult compare_checkpoints(const std::vector<Checkpoint>& client, const std::vector<Checkpoint>& reference) {
  CompareResult r;
  std::map<SeqNo, const Checkpoint*> ref;
  for (const Checkpoint& c : reference) ref[c.seq] = &c;
  bool spliced = false;
  auto note = [&](const std::string& s) {
    ++r.mismatches;
    if (r.details.size() < 20) r.details.push_back(s);
  };
  for (const Checkpoint& c : client) {
    if (c.tainted || c.splice) spliced = true;
    const auto it = ref.find(c.seq);
    if (it == ref.end()) {
      ++r.missing_in_reference;
      continue;
    }
    const Checkpoint& d = *it->second;
    ++r.compared_books;
    if (c.books_digest != d.books_digest || c.live_orders != d.live_orders)
      note("seq " + std::to_string(c.seq) + ": books digest/live orders differ");
    // The client's interval since its previous checkpoint is the reference's only
    // when no splice intervened and the reference has the same previous checkpoint.
    if (!c.tainted && !c.splice) {
      ++r.compared_streams;
      if (c.stream_hash != d.stream_hash) note("seq " + std::to_string(c.seq) + ": stream hash differs");
    }
    if (!spliced && c.bbo_digest != 0) {
      ++r.compared_bbo;
      if (c.bbo_digest != d.bbo_digest) note("seq " + std::to_string(c.seq) + ": BBO digest differs");
    }
  }
  r.reached_end = !client.empty() && !reference.empty() && client.back().seq == reference.back().seq;
  if (!r.reached_end && r.details.size() < 20)
    r.details.push_back("the client's last checkpoint (" + (client.empty() ? std::string("none") : std::to_string(client.back().seq)) +
                        ") is not the end of the stream (" + (reference.empty() ? std::string("none") : std::to_string(reference.back().seq)) + ")");
  r.ok = r.mismatches == 0 && r.missing_in_reference == 0 && r.compared_books > 0 && r.reached_end;
  return r;
}

std::optional<std::map<std::string, std::string>> parse_flat_json(std::string_view t) {
  std::map<std::string, std::string> out;
  std::size_t i = 0;
  auto ws = [&]() {
    while (i < t.size() && (t[i] == ' ' || t[i] == '\n' || t[i] == '\r' || t[i] == '\t')) ++i;
  };
  auto str = [&](std::string& s) -> bool {
    if (i >= t.size() || t[i] != '"') return false;
    ++i;
    while (i < t.size() && t[i] != '"') {
      if (t[i] == '\\' && i + 1 < t.size()) {
        ++i;
        const char c = t[i];
        s += c == 'n' ? '\n' : c == 't' ? '\t' : c;
      } else {
        s += t[i];
      }
      ++i;
    }
    if (i >= t.size()) return false;
    ++i;
    return true;
  };
  ws();
  if (i >= t.size() || t[i] != '{') return std::nullopt;
  ++i;
  for (;;) {
    ws();
    if (i < t.size() && t[i] == '}') return out;
    std::string key;
    if (!str(key)) return std::nullopt;
    ws();
    if (i >= t.size() || t[i] != ':') return std::nullopt;
    ++i;
    ws();
    if (i >= t.size()) return std::nullopt;
    if (t[i] == '"') {
      std::string v;
      if (!str(v)) return std::nullopt;
      out[key] = v;
    } else if (t[i] == '{' || t[i] == '[') {
      int depth = 0;
      bool in_str = false;
      for (; i < t.size(); ++i) {
        const char c = t[i];
        if (in_str) {
          if (c == '\\') ++i;
          else if (c == '"') in_str = false;
          continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{' || c == '[') ++depth;
        else if ((c == '}' || c == ']') && --depth == 0) {
          ++i;
          break;
        }
      }
    } else {
      const std::size_t b = i;
      while (i < t.size() && t[i] != ',' && t[i] != '}' && t[i] != '\n' && t[i] != ' ') ++i;
      out[key] = std::string(t.substr(b, i - b));
    }
    ws();
    if (i < t.size() && t[i] == ',') {
      ++i;
      continue;
    }
    ws();
    if (i < t.size() && t[i] == '}') return out;
    return std::nullopt;
  }
}

std::optional<std::map<std::string, std::string>> read_flat_json(const std::string& path) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) return std::nullopt;
  std::string text;
  char buf[65536];
  for (;;) {
    const std::size_t n = std::fread(buf, 1, sizeof buf, f);
    if (n == 0) break;
    text.append(buf, n);
  }
  std::fclose(f);
  return parse_flat_json(text);
}

}  // namespace lle::client
