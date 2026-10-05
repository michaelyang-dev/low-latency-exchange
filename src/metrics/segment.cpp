#include "metrics/segment.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <format>

#include <hdr/hdr_histogram.h>

namespace lle::metrics {
namespace {

constexpr std::size_t kAlign = 64;
constexpr std::size_t round_up(std::size_t v) noexcept { return (v + kAlign - 1) & ~(kAlign - 1); }
constexpr std::size_t kHeaderBytes = round_up(sizeof(SegmentHeader));
constexpr std::size_t kHistSlotBytes = round_up(sizeof(HistogramSlot));

template <class T>
T* at(std::byte* base, std::size_t off) noexcept {
  return static_cast<T*>(static_cast<void*>(base + off));
}
template <class T>
const T* at(const std::byte* base, std::size_t off) noexcept {
  return static_cast<const T*>(static_cast<const void*>(base + off));
}

void copy_name(char* dst, std::size_t cap, std::string_view s) noexcept {
  const std::size_t n = s.size() < cap - 1 ? s.size() : cap - 1;
  std::memcpy(dst, s.data(), n);
  dst[n] = '\0';
}

std::string_view name_view(const char* s, std::size_t cap) noexcept { return {s, strnlen(s, cap)}; }

struct Layout {
  std::size_t counters_offset = 0;
  std::size_t histograms_offset = 0;
  std::vector<std::size_t> counts_offsets;
  std::vector<hdr_histogram_bucket_config> configs;
  std::size_t total = 0;
};

std::expected<Layout, std::string> layout_for(const Schema& s) {
  Layout l;
  l.counters_offset = kHeaderBytes;
  l.histograms_offset = round_up(l.counters_offset + s.counters.size() * sizeof(CounterSlot));
  std::size_t off = round_up(l.histograms_offset + s.histograms.size() * kHistSlotBytes);
  for (const HistogramSpec& h : s.histograms) {
    hdr_histogram_bucket_config cfg{};
    if (h.name.empty() ||
        hdr_calculate_bucket_config(h.lowest, h.highest, h.significant_figures, &cfg) != 0) {
      return std::unexpected(std::format("invalid histogram spec '{}'", h.name));
    }
    l.configs.push_back(cfg);
    l.counts_offsets.push_back(off);
    off = round_up(off + static_cast<std::size_t>(cfg.counts_len) * sizeof(std::int64_t));
  }
  for (const CounterSpec& c : s.counters) {
    if (c.name.empty()) return std::unexpected(std::string("empty counter name"));
  }
  l.total = off;
  return l;
}

bool valid_node(std::string_view node) noexcept {
  if (node.empty() || node.size() > kMaxNodeName) return false;
  for (const char c : node) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                    c == '_' || c == '.';
    if (!ok) return false;
  }
  return true;
}

std::int64_t realtime_ns() noexcept {
  timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  return static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec;
}

void initialize(std::byte* base, const Layout& l, std::string_view node, const Schema& s) {
  std::memset(base, 0, l.total);
  auto* h = at<SegmentHeader>(base, 0);
  h->version = kVersion;
  h->header_bytes = static_cast<std::uint32_t>(kHeaderBytes);
  h->total_bytes = l.total;
  copy_name(h->node, kNodeBytes, node);
  h->counter_count = static_cast<std::uint32_t>(s.counters.size());
  h->histogram_count = static_cast<std::uint32_t>(s.histograms.size());
  h->counters_offset = l.counters_offset;
  h->histograms_offset = l.histograms_offset;
  h->created_realtime_ns = realtime_ns();
  h->writer_pid = static_cast<std::uint32_t>(::getpid());
  for (std::size_t i = 0; i < s.counters.size(); ++i) {
    auto* c = at<CounterSlot>(base, l.counters_offset + i * sizeof(CounterSlot));
    copy_name(c->name, kNameBytes, s.counters[i].name);
    c->kind = s.counters[i].kind;
  }
  for (std::size_t i = 0; i < s.histograms.size(); ++i) {
    auto* hs = at<HistogramSlot>(base, l.histograms_offset + i * kHistSlotBytes);
    const hdr_histogram_bucket_config& cfg = l.configs[i];
    copy_name(hs->name, kNameBytes, s.histograms[i].name);
    copy_name(hs->unit, kUnitBytes, s.histograms[i].unit);
    hs->lowest = cfg.lowest_discernible_value;
    hs->highest = cfg.highest_trackable_value;
    hs->significant_figures = static_cast<std::int32_t>(cfg.significant_figures);
    hs->counts_len = cfg.counts_len;
    hs->unit_magnitude = static_cast<std::int32_t>(cfg.unit_magnitude);
    hs->sub_bucket_half_count_magnitude = cfg.sub_bucket_half_count_magnitude;
    hs->sub_bucket_half_count = cfg.sub_bucket_half_count;
    hs->sub_bucket_mask = cfg.sub_bucket_mask;
    hs->counts_offset = l.counts_offsets[i];
  }
  // Publish: readers check the magic with acquire before reading anything else.
  h->magic.store(kMagic, std::memory_order_release);
}

}  // namespace

// ---- Histogram ---------------------------------------------------------------------

Histogram::Histogram(HistogramSlot* slot, std::int64_t* counts) noexcept
    : slot_(slot),
      counts_(counts),
      highest_(slot->highest),
      sub_bucket_mask_(slot->sub_bucket_mask),
      unit_magnitude_(slot->unit_magnitude),
      sub_bucket_half_count_magnitude_(slot->sub_bucket_half_count_magnitude),
      sub_bucket_half_count_(slot->sub_bucket_half_count) {}

// ---- Segment -----------------------------------------------------------------------

std::expected<std::size_t, std::string> Segment::required_bytes(const Schema& schema) {
  auto l = layout_for(schema);
  if (!l) return std::unexpected(l.error());
  return l->total;
}

std::expected<Segment, std::string> Segment::create_in(std::span<std::byte> mem, std::string_view node,
                                                       const Schema& schema) {
  auto l = layout_for(schema);
  if (!l) return std::unexpected(l.error());
  if (mem.size() < l->total) return std::unexpected(std::format("need {} bytes, have {}", l->total, mem.size()));
  if ((reinterpret_cast<std::uintptr_t>(mem.data()) & (kAlign - 1)) != 0) {
    return std::unexpected(std::string("memory must be 64-byte aligned"));
  }
  initialize(mem.data(), *l, node, schema);
  Segment s;
  s.base_ = mem.data();
  s.size_ = l->total;
  return s;
}

std::string Segment::shm_name(std::string_view node) { return "/lle-stats-" + std::string(node); }

std::expected<Segment, std::string> Segment::create_shm(std::string_view node, const Schema& schema) {
  if (!valid_node(node)) return std::unexpected(std::format("bad node name '{}'", node));
  auto l = layout_for(schema);
  if (!l) return std::unexpected(l.error());
  const std::string name = shm_name(node);
  ::shm_unlink(name.c_str());  // a stale segment from a crashed run is replaced
  const int fd = ::shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
  if (fd < 0) return std::unexpected(std::format("shm_open {}: {}", name, std::strerror(errno)));
  if (::ftruncate(fd, static_cast<off_t>(l->total)) != 0) {
    const std::string err = std::format("ftruncate {}: {}", name, std::strerror(errno));
    ::close(fd);
    ::shm_unlink(name.c_str());
    return std::unexpected(err);
  }
  void* p = ::mmap(nullptr, l->total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  ::close(fd);
  if (p == MAP_FAILED) {
    ::shm_unlink(name.c_str());
    return std::unexpected(std::format("mmap {}: {}", name, std::strerror(errno)));
  }
  initialize(static_cast<std::byte*>(p), *l, node, schema);
  Segment s;
  s.base_ = static_cast<std::byte*>(p);
  s.size_ = l->total;
  s.mapped_ = true;
  s.shm_name_ = name;
  return s;
}

Segment::Segment(Segment&& o) noexcept
    : base_(o.base_), size_(o.size_), mapped_(o.mapped_), shm_name_(std::move(o.shm_name_)) {
  o.base_ = nullptr;
  o.mapped_ = false;
}

Segment& Segment::operator=(Segment&& o) noexcept {
  if (this != &o) {
    if (mapped_ && base_ != nullptr) ::munmap(base_, size_);
    base_ = o.base_;
    size_ = o.size_;
    mapped_ = o.mapped_;
    shm_name_ = std::move(o.shm_name_);
    o.base_ = nullptr;
    o.mapped_ = false;
  }
  return *this;
}

Segment::~Segment() {
  if (mapped_ && base_ != nullptr) ::munmap(base_, size_);
}

Counter Segment::counter(std::size_t i) const noexcept {
  const auto* h = at<SegmentHeader>(base_, 0);
  if (i >= h->counter_count) return Counter{};
  return Counter{at<CounterSlot>(base_, h->counters_offset + i * sizeof(CounterSlot))};
}

Histogram Segment::histogram(std::size_t i) const noexcept {
  const auto* h = at<SegmentHeader>(base_, 0);
  if (i >= h->histogram_count) return Histogram{};
  auto* slot = at<HistogramSlot>(base_, h->histograms_offset + i * kHistSlotBytes);
  return Histogram{slot, at<std::int64_t>(base_, slot->counts_offset)};
}

Counter Segment::counter(std::string_view name) const noexcept {
  const auto* h = at<SegmentHeader>(base_, 0);
  for (std::size_t i = 0; i < h->counter_count; ++i) {
    const auto* c = at<CounterSlot>(base_, h->counters_offset + i * sizeof(CounterSlot));
    if (name_view(c->name, kNameBytes) == name) return counter(i);
  }
  return Counter{};
}

Histogram Segment::histogram(std::string_view name) const noexcept {
  const auto* h = at<SegmentHeader>(base_, 0);
  for (std::size_t i = 0; i < h->histogram_count; ++i) {
    const auto* s = at<HistogramSlot>(base_, h->histograms_offset + i * kHistSlotBytes);
    if (name_view(s->name, kNameBytes) == name) return histogram(i);
  }
  return Histogram{};
}

void Segment::heartbeat() noexcept {
  auto* h = at<SegmentHeader>(base_, 0);
  h->heartbeat.store(h->heartbeat.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
}

bool Segment::unlink() noexcept { return !shm_name_.empty() && ::shm_unlink(shm_name_.c_str()) == 0; }

// ---- Reader ------------------------------------------------------------------------

void HdrDeleter::operator()(hdr_histogram* h) const noexcept { hdr_close(h); }

std::int64_t HistogramSnapshot::value_at_percentile(double p) const noexcept {
  return hdr ? hdr_value_at_percentile(hdr.get(), p) : 0;
}

std::expected<Reader, std::string> Reader::attach(std::span<const std::byte> mem) {
  if (mem.size() < kHeaderBytes) return std::unexpected(std::string("segment too small"));
  const auto* h = at<SegmentHeader>(mem.data(), 0);
  if (h->magic.load(std::memory_order_acquire) != kMagic) {
    return std::unexpected(std::string("not an lle stats segment (or not initialized yet)"));
  }
  if (h->version != kVersion) return std::unexpected(std::format("unsupported segment version {}", h->version));
  const std::uint64_t total = h->total_bytes;
  const bool sizes_ok =
      total <= mem.size() && h->header_bytes >= sizeof(SegmentHeader) && h->counters_offset >= h->header_bytes &&
      h->counters_offset + std::uint64_t{h->counter_count} * sizeof(CounterSlot) <= total &&
      h->histograms_offset + std::uint64_t{h->histogram_count} * kHistSlotBytes <= total &&
      h->counters_offset % kAlign == 0 && h->histograms_offset % kAlign == 0;
  if (!sizes_ok) return std::unexpected(std::string("inconsistent segment header"));
  for (std::size_t i = 0; i < h->histogram_count; ++i) {
    const auto* s = at<HistogramSlot>(mem.data(), h->histograms_offset + i * kHistSlotBytes);
    if (s->counts_len <= 0 || s->counts_offset % kAlign != 0 ||
        s->counts_offset + static_cast<std::uint64_t>(s->counts_len) * sizeof(std::int64_t) > total) {
      return std::unexpected(std::format("inconsistent histogram slot {}", i));
    }
  }
  Reader r;
  r.base_ = mem.data();
  r.size_ = mem.size();
  return r;
}

std::expected<Reader, std::string> Reader::open_shm(std::string_view node) {
  if (!valid_node(node)) return std::unexpected(std::format("bad node name '{}'", node));
  const std::string name = Segment::shm_name(node);
  const int fd = ::shm_open(name.c_str(), O_RDONLY, 0);
  if (fd < 0) return std::unexpected(std::format("shm_open {}: {}", name, std::strerror(errno)));
  struct stat st {};
  if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
    ::close(fd);
    return std::unexpected(std::format("fstat {}: bad size", name));
  }
  const auto size = static_cast<std::size_t>(st.st_size);
  void* p = ::mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
  ::close(fd);
  if (p == MAP_FAILED) return std::unexpected(std::format("mmap {}: {}", name, std::strerror(errno)));
  auto r = attach({static_cast<const std::byte*>(p), size});
  if (!r) {
    ::munmap(p, size);
    return r;
  }
  r->mapped_ = true;
  return r;
}

Reader::Reader(Reader&& o) noexcept : base_(o.base_), size_(o.size_), mapped_(o.mapped_) {
  o.base_ = nullptr;
  o.mapped_ = false;
}

Reader& Reader::operator=(Reader&& o) noexcept {
  if (this != &o) {
    if (mapped_ && base_ != nullptr) ::munmap(const_cast<std::byte*>(base_), size_);
    base_ = o.base_;
    size_ = o.size_;
    mapped_ = o.mapped_;
    o.base_ = nullptr;
    o.mapped_ = false;
  }
  return *this;
}

Reader::~Reader() {
  if (mapped_ && base_ != nullptr) ::munmap(const_cast<std::byte*>(base_), size_);
}

std::string_view Reader::node() const noexcept { return name_view(at<SegmentHeader>(base_, 0)->node, kNodeBytes); }
std::uint32_t Reader::writer_pid() const noexcept { return at<SegmentHeader>(base_, 0)->writer_pid; }
std::uint64_t Reader::heartbeat() const noexcept {
  return at<SegmentHeader>(base_, 0)->heartbeat.load(std::memory_order_relaxed);
}
std::size_t Reader::counter_count() const noexcept { return at<SegmentHeader>(base_, 0)->counter_count; }
std::size_t Reader::histogram_count() const noexcept { return at<SegmentHeader>(base_, 0)->histogram_count; }

CounterValue Reader::counter(std::size_t i) const noexcept {
  const auto* h = at<SegmentHeader>(base_, 0);
  if (i >= h->counter_count) return CounterValue{};
  const auto* c = at<CounterSlot>(base_, h->counters_offset + i * sizeof(CounterSlot));
  return CounterValue{name_view(c->name, kNameBytes), c->kind, c->value.load(std::memory_order_relaxed)};
}

std::optional<std::size_t> Reader::find_counter(std::string_view name) const noexcept {
  for (std::size_t i = 0; i < counter_count(); ++i)
    if (counter(i).name == name) return i;
  return std::nullopt;
}

std::optional<std::size_t> Reader::find_histogram(std::string_view name) const noexcept {
  const auto* h = at<SegmentHeader>(base_, 0);
  for (std::size_t i = 0; i < h->histogram_count; ++i) {
    const auto* s = at<HistogramSlot>(base_, h->histograms_offset + i * kHistSlotBytes);
    if (name_view(s->name, kNameBytes) == name) return i;
  }
  return std::nullopt;
}

std::expected<HistogramSnapshot, std::string> Reader::histogram(std::size_t i) const {
  const auto* h = at<SegmentHeader>(base_, 0);
  if (i >= h->histogram_count) return std::unexpected(std::string("no such histogram"));
  const auto* s = at<HistogramSlot>(base_, h->histograms_offset + i * kHistSlotBytes);
  hdr_histogram* raw = nullptr;
  if (hdr_init(s->lowest, s->highest, s->significant_figures, &raw) != 0 || raw == nullptr) {
    return std::unexpected(std::format("hdr_init failed for '{}'", name_view(s->name, kNameBytes)));
  }
  HistogramSnapshot snap;
  snap.hdr.reset(raw);
  if (raw->counts_len != s->counts_len) return std::unexpected(std::string("histogram layout mismatch"));
  const std::int64_t* counts = at<std::int64_t>(base_, s->counts_offset);
  for (std::int32_t k = 0; k < s->counts_len; ++k) raw->counts[k] = __atomic_load_n(&counts[k], __ATOMIC_RELAXED);
  hdr_reset_internal_counters(raw);  // recomputes total, min and max from the counts
  snap.name = std::string(name_view(s->name, kNameBytes));
  snap.unit = std::string(name_view(s->unit, kUnitBytes));
  snap.count = raw->total_count;
  snap.overflow = s->overflow.load(std::memory_order_relaxed);
  snap.min = snap.count != 0 ? hdr_min(raw) : 0;
  snap.max = hdr_max(raw);
  const std::int64_t total = s->total_count.load(std::memory_order_relaxed);
  snap.mean = total != 0 ? static_cast<double>(s->sum.load(std::memory_order_relaxed)) / static_cast<double>(total)
                         : 0.0;
  return snap;
}

std::string dump_text(const Reader& r) {
  std::string out = std::format("lle-stats node={} pid={} heartbeat={} counters={} histograms={}\n", r.node(),
                                r.writer_pid(), r.heartbeat(), r.counter_count(), r.histogram_count());
  if (r.counter_count() != 0) {
    out += std::format("{:<40} {:>6} {:>20}\n", "COUNTER", "KIND", "VALUE");
    for (std::size_t i = 0; i < r.counter_count(); ++i) {
      const CounterValue c = r.counter(i);
      out += std::format("{:<40} {:>6} {:>20}\n", c.name, c.kind == CounterKind::kGauge ? "gauge" : "count", c.value);
    }
  }
  if (r.histogram_count() != 0) {
    out += std::format("{:<28} {:>4} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>12} {:>8}\n", "HISTOGRAM",
                       "UNIT", "COUNT", "MIN", "P50", "P90", "P99", "P99.9", "MAX", "MEAN", "OVERFLOW");
    for (std::size_t i = 0; i < r.histogram_count(); ++i) {
      const auto s = r.histogram(i);
      if (!s) {
        out += std::format("histogram {}: {}\n", i, s.error());
        continue;
      }
      out += std::format("{:<28} {:>4} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>12.1f} {:>8}\n", s->name,
                         s->unit, s->count, s->min, s->value_at_percentile(50.0), s->value_at_percentile(90.0),
                         s->value_at_percentile(99.0), s->value_at_percentile(99.9), s->max, s->mean, s->overflow);
    }
  }
  return out;
}

}  // namespace lle::metrics
