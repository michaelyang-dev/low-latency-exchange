#include "runtime/launcher.h"

#include <charconv>
#include <string>
#include <system_error>

#include "common/assert.h"
#include "concurrent/wait.h"

namespace lle::rt {
namespace {

bool is_name_char(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ||
         c == '.';
}
bool is_separator(char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';'; }

constexpr int kMaxCpuId = 4095;

}  // namespace

// ---- CoreMap ---------------------------------------------------------------------

std::expected<CoreMap, std::string> CoreMap::parse(std::string_view text) {
  CoreMap map;
  std::size_t i = 0;
  while (i < text.size()) {
    const char c = text[i];
    if (is_separator(c)) {
      ++i;
      continue;
    }
    if (c == '#') {  // comment to end of line
      while (i < text.size() && text[i] != '\n') ++i;
      continue;
    }
    if (c == '[') {  // section header such as [cores]
      const std::size_t close = text.find(']', i);
      if (close == std::string_view::npos) return std::unexpected("core map: unterminated section header");
      i = close + 1;
      continue;
    }
    std::size_t j = i;
    while (j < text.size() && !is_separator(text[j]) && text[j] != '#') ++j;
    const std::string_view tok = text.substr(i, j - i);
    i = j;
    const std::size_t eq = tok.find('=');
    if (eq == std::string_view::npos || eq == 0) {
      return std::unexpected("core map: expected name=cpu, got '" + std::string(tok) + "'");
    }
    const std::string_view name = tok.substr(0, eq);
    const std::string_view num = tok.substr(eq + 1);
    for (const char nc : name) {
      if (!is_name_char(nc)) return std::unexpected("core map: bad stage name '" + std::string(name) + "'");
    }
    int cpu = -1;
    const auto [ptr, ec] = std::from_chars(num.data(), num.data() + num.size(), cpu);
    if (ec != std::errc{} || ptr != num.data() + num.size() || num.empty() || cpu < 0 || cpu > kMaxCpuId) {
      return std::unexpected("core map: bad cpu id '" + std::string(num) + "' for '" + std::string(name) + "'");
    }
    if (map.cpu_for(name).has_value()) {
      return std::unexpected("core map: duplicate stage '" + std::string(name) + "'");
    }
    map.entries_.emplace_back(std::string(name), cpu);
  }
  return map;
}

void CoreMap::set(std::string_view name, int cpu) {
  for (auto& [n, c] : entries_) {
    if (n == name) {
      c = cpu;
      return;
    }
  }
  entries_.emplace_back(std::string(name), cpu);
}

std::optional<int> CoreMap::cpu_for(std::string_view name) const {
  for (const auto& [n, c] : entries_) {
    if (n == name) return c;
  }
  return std::nullopt;
}

// ---- Launcher --------------------------------------------------------------------

Launcher::Launcher(CoreMap cores, LaunchOptions opts) : cores_(std::move(cores)), opts_(opts) {}

Launcher::~Launcher() {
  request_stop();
  join();
}

void Launcher::add(std::string_view name, StageRef stage) {
  LLE_ASSERT(!started_, "Launcher::add after start()");
  auto slot = std::make_unique<Slot>(std::string(name), stage);
  if (auto cpu = cores_.cpu_for(name)) slot->cpu = *cpu;
  stages_.push_back(std::move(slot));
}

Launcher::Slot* Launcher::find(std::string_view name) {
  for (auto& s : stages_) {
    if (s->name == name) return s.get();
  }
  return nullptr;
}

void Launcher::add_pretouch(std::string_view stage, void* p, std::size_t bytes) {
  if (Slot* s = find(stage)) s->pretouch.push_back(Region{p, bytes});
}

std::expected<void, std::string> Launcher::start() {
  if (started_) return std::unexpected("launcher: already started");
  for (std::size_t i = 0; i < stages_.size(); ++i) {
    for (std::size_t j = i + 1; j < stages_.size(); ++j) {
      if (stages_[i]->name == stages_[j]->name) return std::unexpected("launcher: duplicate stage " + stages_[i]->name);
    }
    if (opts_.require_core_map_entry && stages_[i]->cpu < 0) {
      return std::unexpected("launcher: no core-map entry for stage " + stages_[i]->name);
    }
  }
  if (opts_.lock_memory) {
    mlock_ = lock_all_memory();
    if (mlock_ != PinStatus::Ok) return std::unexpected(std::string("launcher: mlockall ") + to_string(mlock_));
  }

  started_ = true;
  for (auto& s : stages_) {
    Slot& slot = *s;
    slot.thread = std::thread([this, &slot] { thread_main(slot); });
  }
  // Startup barrier: every thread is named, pinned and has pre-touched its memory.
  // Acquire pairs with each thread's release increment, so its `pin` is visible.
  conc::spin_until([this] { return ready_.load(std::memory_order_acquire) == stages_.size(); }, conc::Backoff{});

  std::string error;
  if (opts_.require_pinning) {
    for (const auto& s : stages_) {
      if (s->pin != PinStatus::Ok) {
        error = "launcher: stage " + s->name + " not pinned (" + to_string(s->pin) + ")";
        break;
      }
    }
  }
  if (!error.empty()) {
    phase_.store(Phase::Aborted, std::memory_order_release);
    join();
    return std::unexpected(error);
  }
  phase_.store(Phase::Running, std::memory_order_release);
  return {};
}

void Launcher::thread_main(Slot& s) {
  set_current_thread_name(s.name);
  s.pin = s.cpu >= 0 ? pin_current_thread(s.cpu) : PinStatus::NotRequested;
  for (const Region& r : s.pretouch) prefault(r.p, r.bytes);
  ready_.fetch_add(1, std::memory_order_release);

  conc::spin_until([this] { return phase_.load(std::memory_order_acquire) != Phase::Starting; }, conc::Backoff{});
  if (phase_.load(std::memory_order_acquire) == Phase::Aborted) return;

  switch (opts_.idle) {
    case IdlePolicy::Spin:
      poll_loop(s, conc::Spin{});
      break;
    case IdlePolicy::SpinPause:
      poll_loop(s, conc::SpinPause{});
      break;
    case IdlePolicy::Backoff:
      poll_loop(s, conc::Backoff{});
      break;
  }
}

template <class Policy>
void Launcher::poll_loop(Slot& s, Policy policy) {
  std::uint64_t polls = 0, busy = 0;
  // Relaxed is enough for the stop flag: it carries no data, and join() provides the
  // happens-before edge for everything the stage did.
  while (!stop_.load(std::memory_order_relaxed)) {
    ++polls;
    if (s.stage.poll()) {
      ++busy;
      policy.reset();
    } else {
      policy.wait();
    }
  }
  s.polls = polls;
  s.busy_polls = busy;
}

void Launcher::request_stop() noexcept { stop_.store(true, std::memory_order_relaxed); }

void Launcher::join() {
  if (!started_ || joined_) return;
  for (auto& s : stages_) {
    if (s->thread.joinable()) s->thread.join();
  }
  joined_ = true;
}

std::vector<StageReport> Launcher::reports() const {
  std::vector<StageReport> out;
  out.reserve(stages_.size());
  for (const auto& s : stages_) out.push_back(StageReport{s->name, s->cpu, s->pin, s->polls, s->busy_polls});
  return out;
}

}  // namespace lle::rt
