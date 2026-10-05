#include "log/backend.h"

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <map>
#include <thread>
#include <vector>

#include "common/int128.h"
#include "env/prod_clock.h"
#include "log/file_format.h"
#include "log/record.h"
#include "log/registry.h"
#include "log/site.h"
#include "log/tsc.h"

#if defined(__APPLE__)
#include <pthread/qos.h>
#endif

namespace lle::nlog {

struct Backend::Impl {
  BackendOptions opts;
  int fd = -1;
  std::thread thread;
  std::atomic<bool> stop_requested{false};
  std::atomic<bool> running{false};

  // Backend-thread state.
  std::vector<std::byte> out;
  std::map<std::uint32_t, file::ExtentBuilder> extents;  // by thread id (stable node addresses)
  std::map<std::uint32_t, std::uint64_t> drop_totals;
  std::uint32_t cur_thread = 0;
  file::ExtentBuilder* cur = nullptr;

  struct AtomicStats {
    std::atomic<std::uint64_t> records{0}, bad_records{0}, extents{0}, bytes_written{0}, write_errors{0},
        calibrations{0}, drops_seen{0}, threads_seen{0};
    void reset() noexcept {
      for (auto* a : {&records, &bad_records, &extents, &bytes_written, &write_errors, &calibrations, &drops_seen,
                      &threads_seen}) {
        a->store(0, std::memory_order_relaxed);
      }
    }
  } st;

  static void bump(std::atomic<std::uint64_t>& c, std::uint64_t n = 1) noexcept {
    c.store(c.load(std::memory_order_relaxed) + n, std::memory_order_relaxed);
  }

  // ---- output --------------------------------------------------------------------
  bool write_out() noexcept {
    std::size_t done = 0;
    bool ok = true;
    while (done < out.size()) {
      const ssize_t n = ::write(fd, out.data() + done, out.size() - done);
      if (n < 0) {
        if (errno == EINTR) continue;
        bump(st.write_errors);
        ok = false;
        break;
      }
      done += static_cast<std::size_t>(n);
    }
    bump(st.bytes_written, done);
    out.clear();
    return ok;
  }

  void write_calibration() {
    const CalibrationSample s = take_calibration_sample();
    file::append_calib_chunk(out, file::Calibration{s.tsc, s.realtime_ns, tsc_hz(), s.window_ticks});
    bump(st.calibrations);
  }

  void write_dictionary() {
    std::vector<file::DictEntry> entries;
    const std::uint32_t n = site_count();
    entries.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
      const LogSite* s = site_at(i);
      if (s == nullptr) continue;
      entries.push_back(file::DictEntry{i, static_cast<std::uint8_t>(s->level), s->nargs, s->kinds, s->line,
                                        s->file, s->fmt});
    }
    file::append_dict_chunk(out, entries);
  }

  // ---- extents -------------------------------------------------------------------
  file::ExtentBuilder& builder(std::uint32_t thread_id) {
    if (cur == nullptr || cur_thread != thread_id) {
      auto [it, inserted] = extents.try_emplace(thread_id);
      if (inserted) {
        it->second.reset(thread_id);
        it->second.reserve(opts.extent_flush_bytes + kMaxRecordBytes * 2);
      }
      cur = &it->second;
      cur_thread = thread_id;
    }
    return *cur;
  }

  void flush_extent(file::ExtentBuilder& b) {
    if (b.empty()) return;
    b.finish_into(out);
    bump(st.extents);
  }

  void flush_all_extents() {
    for (auto& [id, b] : extents) flush_extent(b);
  }

  // ---- poll_rings handler --------------------------------------------------------
  void on_thread(const detail::ThreadBuffer& b) {
    file::append_thread_chunk(out, b.thread_id, b.storage_bytes, b.name);
    bump(st.threads_seen);
  }

  void on_record(const detail::ThreadBuffer& b, const std::byte* p, std::uint32_t len) {
    if (len < kRecordHeaderBytes) {
      bump(st.bad_records);
      return;
    }
    const RawHeader h = read_raw_header(p);
    const std::uint32_t idx = canonical_site(h.site_idx);
    const LogSite* site = site_at(idx);
    if (h.len < kRecordHeaderBytes || h.len > len || site == nullptr) {
      bump(st.bad_records);
      return;
    }
    file::ExtentBuilder& eb = builder(b.thread_id);
    if (!eb.add_raw(idx, h.flags, h.tsc, site->kinds, site->nargs, p + kRecordHeaderBytes, p + h.len)) {
      bump(st.bad_records);
      return;
    }
    bump(st.records);
    if (eb.bytes() >= opts.extent_flush_bytes) flush_extent(eb);
  }

  void on_drops(const detail::ThreadBuffer& b, std::uint64_t total) {
    flush_extent(builder(b.thread_id));  // records before the report stay before it
    file::append_drops_chunk(out, b.thread_id, env::read_tsc(), total);
    std::uint64_t& prev = drop_totals[b.thread_id];
    bump(st.drops_seen, total - prev);
    prev = total;
  }

  void on_thread_end(const detail::ThreadBuffer& b) {
    auto it = extents.find(b.thread_id);
    if (it != extents.end()) {
      flush_extent(it->second);
      extents.erase(it);
    }
    cur = nullptr;
    file::append_thread_end_chunk(out, b.thread_id, env::read_tsc());
  }

  // ---- thread --------------------------------------------------------------------
  void pin() noexcept {
#if defined(__linux__)
    if (opts.pin_cpu >= 0) {
      cpu_set_t set;
      CPU_ZERO(&set);
      CPU_SET(static_cast<unsigned>(opts.pin_cpu), &set);
      pthread_setaffinity_np(pthread_self(), sizeof set, &set);
    }
    pthread_setname_np(pthread_self(), "nlog-backend");
#elif defined(__APPLE__)
    // macOS cannot pin; keep the drain on performance cores.
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    pthread_setname_np("nlog-backend");
#endif
  }

  void run() {
    pin();
    const std::uint64_t hz = tsc_hz();
    const auto calib_ticks = static_cast<std::uint64_t>(
        static_cast<lle::u128>(opts.calibration_interval_ns) * hz / 1'000'000'000u);
    const auto poll_ticks =
        static_cast<std::uint64_t>(static_cast<lle::u128>(opts.poll_interval_ns) * hz / 1'000'000'000u);
    std::uint64_t last_calib = env::read_tsc();
    for (;;) {
      const std::uint64_t round_start = env::read_tsc();
      const bool stopping = stop_requested.load(std::memory_order_acquire);
      const std::size_t n = detail::poll_rings(*this, opts.drain_batch);
      if (out.size() >= opts.write_buffer_bytes) write_out();
      const std::uint64_t now = env::read_tsc();
      if (now - last_calib >= calib_ticks) {
        flush_all_extents();
        write_calibration();
        last_calib = now;
      }
      if (stopping) {
        // Everything committed before stop() is visible since the acquire above;
        // keep draining until a round comes back empty (bounded for live producers).
        for (int round = 0; round < 100'000 && detail::poll_rings(*this, opts.drain_batch) != 0; ++round) {
          if (out.size() >= opts.write_buffer_bytes) write_out();
        }
        break;
      }
      if (n == 0) {
        flush_all_extents();
        if (!out.empty()) write_out();
        if (opts.idle_sleep_us != 0) {
          std::this_thread::sleep_for(std::chrono::microseconds(opts.idle_sleep_us));
          continue;
        }
      }
      if (n < opts.drain_batch) {
        // Caught up. A consumer re-polling right behind the producer pulls the
        // ring's lines and the write index to its core after every record, so each
        // producer commit then misses (measured: +20-28 ns per call on the dev
        // laptop). Wait out the poll interval on the local clock, touching no
        // shared line, so producers fill whole lines between visits.
        while (env::read_tsc() - round_start < poll_ticks && !stop_requested.load(std::memory_order_relaxed)) {
        }
      }
    }
    flush_all_extents();
    write_calibration();
    std::uint64_t drops = 0;
    for (const auto& [id, total] : drop_totals) drops += total;
    file::append_end_chunk(out, env::read_tsc(), st.records.load(std::memory_order_relaxed), drops,
                           unregistered_drops());
    write_out();
  }
};

Backend::Backend() : impl_(std::make_unique<Impl>()) {}

Backend::~Backend() { stop(); }

std::expected<void, std::string> Backend::start(BackendOptions opts) {
  Impl& m = *impl_;
  if (m.running.load(std::memory_order_acquire)) return std::unexpected(std::string("backend already running"));
  if (!detail::acquire_consumer()) return std::unexpected(std::string("another nlog consumer is active"));
  if (opts.calibration_interval_ns == 0) opts.calibration_interval_ns = 1'000'000'000;
  if (opts.drain_batch == 0) opts.drain_batch = 1;
  m.opts = std::move(opts);
  m.fd = ::open(m.opts.path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (m.fd < 0) {
    std::string err = "open " + m.opts.path + ": " + std::strerror(errno);
    detail::release_consumer();
    return std::unexpected(std::move(err));
  }
  m.stop_requested.store(false, std::memory_order_relaxed);
  m.st.reset();
  m.extents.clear();
  m.drop_totals.clear();
  m.cur = nullptr;
  m.out.clear();
  m.out.reserve(m.opts.write_buffer_bytes + 2 * m.opts.extent_flush_bytes + 4096);

  const CalibrationSample s = take_calibration_sample();
  file::append_file_header(m.out, file::FileHeader{s.realtime_ns, tsc_hz(), m.opts.node, 0});
  m.write_dictionary();
  file::append_calib_chunk(m.out, file::Calibration{s.tsc, s.realtime_ns, tsc_hz(), s.window_ticks});
  Impl::bump(m.st.calibrations);
  if (!m.write_out()) {
    std::string err = "write " + m.opts.path + ": " + std::strerror(errno);
    ::close(m.fd);
    m.fd = -1;
    detail::release_consumer();
    return std::unexpected(std::move(err));
  }
  m.running.store(true, std::memory_order_release);
  m.thread = std::thread([&m] { m.run(); });
  return {};
}

void Backend::stop() {
  Impl& m = *impl_;
  if (!m.running.load(std::memory_order_acquire)) return;
  m.stop_requested.store(true, std::memory_order_release);
  m.thread.join();
  ::close(m.fd);
  m.fd = -1;
  m.running.store(false, std::memory_order_release);
  detail::release_consumer();
}

bool Backend::running() const noexcept { return impl_->running.load(std::memory_order_acquire); }

BackendStats Backend::stats() const noexcept {
  const auto& s = impl_->st;
  auto ld = [](const std::atomic<std::uint64_t>& a) { return a.load(std::memory_order_relaxed); };
  return BackendStats{ld(s.records),       ld(s.bad_records),  ld(s.extents),    ld(s.bytes_written),
                      ld(s.write_errors),  ld(s.calibrations), ld(s.drops_seen), ld(s.threads_seen)};
}

}  // namespace lle::nlog
