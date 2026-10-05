#pragma once
// Shared helpers for bench/concurrent: a background thread that runs a body until
// stopped (producers, consumers, echo servers).
#include <atomic>
#include <thread>
#include <utility>

#if defined(__APPLE__)
#include <pthread.h>
#include <sys/qos.h>
#endif

namespace lle::conc::bench {

// macOS cannot pin; the closest substitute is asking for the highest QoS class, which
// steers threads to performance cores (research R6 used the same).
inline void prefer_fast_cores() {
#if defined(__APPLE__)
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
}

class Background {
 public:
  template <class F>
  explicit Background(F&& body)
      : thread_([this, f = std::forward<F>(body)]() mutable {
          prefer_fast_cores();
          f(stop_);
        }) {
    prefer_fast_cores();  // the benchmark (measuring) thread too
  }
  ~Background() { stop(); }
  Background(const Background&) = delete;
  Background& operator=(const Background&) = delete;
  void stop() {
    stop_.store(true, std::memory_order_relaxed);
    if (thread_.joinable()) thread_.join();
  }

 private:
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

inline bool stopped(const std::atomic<bool>& s) { return s.load(std::memory_order_relaxed); }

}  // namespace lle::conc::bench
