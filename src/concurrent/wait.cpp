#include "concurrent/wait.h"

#include <thread>

namespace lle::conc::detail {

void yield_thread() noexcept { std::this_thread::yield(); }

}  // namespace lle::conc::detail
