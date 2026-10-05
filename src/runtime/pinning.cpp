#include "runtime/pinning.h"

#include <pthread.h>
#include <unistd.h>

#include <algorithm>
#include <thread>

#if defined(__linux__)
#include <sched.h>
#include <sys/mman.h>
#endif

namespace lle::rt {

const char* to_string(PinStatus s) noexcept {
  switch (s) {
    case PinStatus::Ok:
      return "ok";
    case PinStatus::NotRequested:
      return "not-requested";
    case PinStatus::Unsupported:
      return "unsupported";
    case PinStatus::Failed:
      return "failed";
  }
  return "?";
}

PinStatus pin_current_thread(int cpu) noexcept {
  if (cpu < 0) return PinStatus::Failed;
#if defined(__linux__)
  if (cpu >= CPU_SETSIZE) return PinStatus::Failed;
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(static_cast<std::size_t>(cpu), &set);
  return pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0 ? PinStatus::Ok : PinStatus::Failed;
#else
  return PinStatus::Unsupported;
#endif
}

bool set_current_thread_name(std::string_view name) noexcept {
#if defined(__linux__)
  char buf[16];  // TASK_COMM_LEN including the terminator
#else
  char buf[64];  // MAXTHREADNAMESIZE on macOS
#endif
  const std::size_t n = std::min(name.size(), sizeof(buf) - 1);
  std::copy_n(name.data(), n, buf);
  buf[n] = '\0';
#if defined(__APPLE__)
  return pthread_setname_np(buf) == 0;
#else
  return pthread_setname_np(pthread_self(), buf) == 0;
#endif
}

std::string current_thread_name() {
  char buf[64] = {};
  if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) != 0) return {};
  return std::string(buf);
}

PinStatus lock_all_memory() noexcept {
#if defined(__linux__)
  return mlockall(MCL_CURRENT | MCL_FUTURE) == 0 ? PinStatus::Ok : PinStatus::Failed;
#else
  return PinStatus::Unsupported;
#endif
}

int current_cpu() noexcept {
#if defined(__linux__)
  return sched_getcpu();
#else
  return -1;
#endif
}

unsigned online_cpus() noexcept { return std::max(1u, std::thread::hardware_concurrency()); }

void prefault(void* p, std::size_t bytes) noexcept {
  if (p == nullptr || bytes == 0) return;
  const long page = sysconf(_SC_PAGESIZE);
  const std::size_t step = page > 0 ? static_cast<std::size_t>(page) : 4096;
  auto* b = static_cast<volatile unsigned char*>(p);
  // Read and write back each page's first byte (and the last byte of the range):
  // faults the page in writable without changing its contents.
  for (std::size_t off = 0; off < bytes; off += step) b[off] = b[off];
  b[bytes - 1] = b[bytes - 1];
}

}  // namespace lle::rt
