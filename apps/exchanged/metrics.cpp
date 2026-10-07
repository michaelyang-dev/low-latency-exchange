#include "exchanged/metrics.h"

namespace lle::exch {

std::expected<std::unique_ptr<NodeMetrics>, std::string> NodeMetrics::create(std::string_view node, bool shared) {
  metrics::Schema schema;
#define LLE_EXCH_SPEC(name, kind) schema.counters.push_back(metrics::CounterSpec{#name, metrics::CounterKind::kind});
  LLE_EXCH_COUNTERS(LLE_EXCH_SPEC)
#undef LLE_EXCH_SPEC
  schema.histograms.push_back(metrics::HistogramSpec{"md_packet_messages", 1, 65'535, 2, "msgs"});
  schema.histograms.push_back(metrics::HistogramSpec{"repl_ack_rtt", 1, 10'000'000'000, 3, "ns"});
  schema.histograms.push_back(metrics::HistogramSpec{"journal_commit", 1, 60'000'000'000, 3, "ns"});
  schema.histograms.push_back(metrics::HistogramSpec{"engine_reject_codes", 1, 255, 3, "code"});
  std::unique_ptr<NodeMetrics> m(new NodeMetrics());
  if (shared) {
    auto seg = metrics::Segment::create_shm(node, schema);
    if (!seg) return std::unexpected("metrics segment: " + seg.error());
    m->seg_ = std::make_unique<metrics::Segment>(std::move(*seg));
  } else {
    const auto bytes = metrics::Segment::required_bytes(schema);
    if (!bytes) return std::unexpected("metrics schema: " + bytes.error());
    m->mem_.reset(new std::byte[*bytes + 64]);
    // 64-byte alignment for the segment's cache-line layout.
    auto* base = m->mem_.get();
    const auto mis = reinterpret_cast<std::uintptr_t>(base) % 64;
    std::span<std::byte> mem(base + (mis == 0 ? 0 : 64 - mis), *bytes);
    auto seg = metrics::Segment::create_in(mem, node, schema);
    if (!seg) return std::unexpected("metrics segment: " + seg.error());
    m->seg_ = std::make_unique<metrics::Segment>(std::move(*seg));
  }
  return m;
}

}  // namespace lle::exch
