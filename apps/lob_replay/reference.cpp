#include "reference.h"

#include <fstream>
#include <map>

#include "common/endian.h"
#include "ref_book.hpp"

namespace lle::replay {
namespace {

// RefBook behind the ItchEventSink interface, so the reference pass uses the
// same adapter as the timed runs.
struct RefSink {
  lobfuzz::RefBook& r;
  std::uint64_t peak = 0;

  static book::Status st(lobfuzz::RefResult x) noexcept {
    switch (x) {
      case lobfuzz::RefResult::kOk: return book::Status::kOk;
      case lobfuzz::RefResult::kUnknownRef: return book::Status::kUnknownRef;
      case lobfuzz::RefResult::kDuplicateRef: return book::Status::kDuplicateRef;
      case lobfuzz::RefResult::kBadQty: return book::Status::kBadQty;
      case lobfuzz::RefResult::kBadPrice: return book::Status::kBadPrice;
      case lobfuzz::RefResult::kBadSide: return book::Status::kBadSide;
      case lobfuzz::RefResult::kOverReduce: return book::Status::kOverReduce;
    }
    return book::Status::kOk;
  }
  void stock_directory(Locate l) { r.declare(l); }
  book::Status add(OrderRef ref, Locate l, Side s, PxE4 px, Qty q) {
    const book::Status x = st(r.add(ref, l, s, px, q));
    peak = std::max<std::uint64_t>(peak, r.live());
    return x;
  }
  book::Status reduce(OrderRef ref, Qty q) { return st(r.reduce(ref, q)); }
  book::Status remove(OrderRef ref) { return st(r.remove(ref)); }
  book::Status replace(OrderRef o, OrderRef n, PxE4 px, Qty q) {
    const book::Status x = st(r.replace(o, n, px, q));
    peak = std::max<std::uint64_t>(peak, r.live());
    return x;
  }
};

}  // namespace

Reference compute_reference(const std::byte* p, std::size_t n) {
  lobfuzz::RefBook rb;
  RefSink sink{rb};
  Reference out;
  std::size_t pos = 0;
  while (pos + 2 <= n) {
    const std::size_t len = load_be16(p + pos);
    if (pos + 2 + len > n) break;
    if (len != 0) {
      const book::ItchResult r = book::apply_itch(sink, p + pos + 2, len);
      ++out.kinds[static_cast<std::size_t>(r.kind)];
      if (r.status != book::Status::kOk) ++out.bad_status;
      ++out.records;
    }
    pos += 2 + len;
  }
  out.bbo_digest = rb.event_digest();
  out.bbo_events = rb.event_count();
  out.books_digest = rb.books_digest();
  out.live_end = rb.live();
  out.peak_live = sink.peak;
  return out;
}

std::optional<Reference> load_reference(const std::string& path, const std::string& sha256,
                                        std::uint64_t max_records) {
  std::ifstream f(path);
  if (!f) return std::nullopt;
  std::map<std::string, std::string> kv;
  std::string line;
  while (std::getline(f, line)) {
    const auto eq = line.find('=');
    if (eq != std::string::npos) kv[line.substr(0, eq)] = line.substr(eq + 1);
  }
  if (kv["sha256"] != sha256 || kv["max_records"] != std::to_string(max_records)) return std::nullopt;
  try {
    Reference r;
    r.sha256 = sha256;
    r.max_records = max_records;
    r.records = std::stoull(kv.at("records"));
    r.bbo_digest = std::stoull(kv.at("bbo_digest"), nullptr, 16);
    r.bbo_events = std::stoull(kv.at("bbo_events"));
    r.books_digest = std::stoull(kv.at("books_digest"), nullptr, 16);
    r.live_end = std::stoull(kv.at("live_end"));
    r.peak_live = std::stoull(kv.at("peak_live"));
    r.bad_status = std::stoull(kv.at("bad_status"));
    for (std::size_t k = 0; k < book::kItchKinds; ++k)
      r.kinds[k] = std::stoull(kv.at(std::string("kind_") + book::to_string(static_cast<book::ItchKind>(k))));
    return r;
  } catch (...) {
    return std::nullopt;
  }
}

bool save_reference(const std::string& path, const Reference& r) {
  std::ofstream f(path, std::ios::trunc);
  if (!f) return false;
  char hex[32];
  f << "sha256=" << r.sha256 << "\nmax_records=" << r.max_records << "\nrecords=" << r.records << '\n';
  std::snprintf(hex, sizeof hex, "%016llx", static_cast<unsigned long long>(r.bbo_digest));
  f << "bbo_digest=" << hex << "\nbbo_events=" << r.bbo_events << '\n';
  std::snprintf(hex, sizeof hex, "%016llx", static_cast<unsigned long long>(r.books_digest));
  f << "books_digest=" << hex << "\nlive_end=" << r.live_end << "\npeak_live=" << r.peak_live
    << "\nbad_status=" << r.bad_status << '\n';
  for (std::size_t k = 0; k < book::kItchKinds; ++k)
    f << "kind_" << book::to_string(static_cast<book::ItchKind>(k)) << '=' << r.kinds[k] << '\n';
  return static_cast<bool>(f);
}

}  // namespace lle::replay
