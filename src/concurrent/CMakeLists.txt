# Lock-free queues (08-concurrency-runtime). Headers include only <atomic>, <cstddef>,
# <cstdint>, <type_traits> (GenMC compiles them directly; see
# tools/genmc/check_includes.sh). wait.cpp holds the out-of-line yield.
lle_library(lle_concurrent SOURCES wait.cpp DEPS lle_common)
