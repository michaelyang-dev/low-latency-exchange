#pragma once
// A stage as the runner sees it: the concrete stage (polled directly, no virtual call
// on the poll path), its thread's nlog registration on the first poll, and the
// periodic publication of its stats into the metrics segment from its own thread
// (single writer per counter, 11 §3): every 1,024 polls and whenever it goes idle after
// doing work.
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "log/nlog.h"
#include "runtime/stage.h"

namespace lle::exch {

struct HostedBase {
  explicit HostedBase(std::string n) : name(std::move(n)) {}
  virtual ~HostedBase() = default;  // destruction only (cold)
  [[nodiscard]] virtual rt::StageRef ref() = 0;
  std::string name;
};

template <class S, class Pub>
class Hosted final : public HostedBase {
 public:
  Hosted(std::string n, S& stage, Pub pub) : HostedBase(std::move(n)), s_(&stage), pub_(std::move(pub)) {}

  bool poll() {
    if (!registered_) [[unlikely]] {
      registered_ = true;
      nlog::ThreadOptions o;
      o.name = name;
      (void)nlog::register_thread(o);  // already registered (inline runner): harmless
    }
    const bool did = s_->poll();
    // Every 1,024 polls, and when the stage goes idle after work, so readers see
    // settled values soon after a burst.
    if ((++polls_ & 1023u) == 0 || (!did && busy_)) pub_();
    busy_ = did;
    return did;
  }
  void publish() { pub_(); }
  [[nodiscard]] rt::StageRef ref() override { return rt::StageRef(*this); }

 private:
  S* s_;
  Pub pub_;
  bool registered_ = false;
  bool busy_ = false;
  std::uint32_t polls_ = 0;
};

template <class S, class Pub>
std::unique_ptr<HostedBase> host(std::string name, S& stage, Pub pub) {
  return std::make_unique<Hosted<S, Pub>>(std::move(name), stage, std::move(pub));
}

}  // namespace lle::exch
