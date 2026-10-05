#pragma once
// Stages (01-architecture §5): every pinned-thread body is a type with
// `bool poll()` returning true if it did work. Production runs one stage per
// pinned core; dev mode and the simulator poll stages from one thread.
#include <concepts>
#include <cstddef>
#include <functional>
#include <tuple>
#include <type_traits>
#include <utility>

namespace lle::rt {

template <class S>
concept StageLike = requires(S& s) {
  { s.poll() } -> std::same_as<bool>;
};

// Non-owning, type-erased reference to a stage (cold paths: launcher, tests).
class StageRef {
 public:
  // StageRef is itself StageLike; the constraint keeps copies of a non-const StageRef
  // on the copy constructor instead of wrapping a pointer to the source object.
  template <StageLike S>
    requires(!std::same_as<std::remove_cv_t<S>, StageRef>)
  explicit StageRef(S& s) noexcept : obj_(&s), fn_([](void* o) { return static_cast<S*>(o)->poll(); }) {}
  bool poll() const { return fn_(obj_); }

 private:
  void* obj_;
  bool (*fn_)(void*);
};

// Polls a fixed set of stages round-robin on the calling thread.
template <StageLike... S>
class InlineRunner {
 public:
  explicit InlineRunner(S&... stages) noexcept : stages_(stages...) {}

  // One pass over every stage. Returns true if any stage did work.
  bool poll_once() {
    return std::apply([](auto&... s) { return (static_cast<int>(s.poll()) | ... | 0) != 0; }, stages_);
  }

  // Runs passes until `done()` is true or `max_idle_passes` consecutive passes did no work.
  template <class Pred>
  std::size_t run_until(Pred&& done, std::size_t max_idle_passes = 1'000'000) {
    std::size_t passes = 0, idle = 0;
    while (!done() && idle < max_idle_passes) {
      idle = poll_once() ? 0 : idle + 1;
      ++passes;
    }
    return passes;
  }

 private:
  std::tuple<S&...> stages_;
};

}  // namespace lle::rt
