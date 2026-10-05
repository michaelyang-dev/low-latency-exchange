cmake_minimum_required(VERSION 3.28)
project(lle VERSION 0.1.0 LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(LLE_BUILD_TESTS "Build unit/integration tests" ON)
option(LLE_BUILD_BENCH "Build benchmarks" ON)
option(LLE_BUILD_APPS "Build applications" ON)
option(LLE_BUILD_FUZZ "Build fuzz/differential harnesses" ON)
option(LLE_SIM "Build for the deterministic simulator (exsim)" OFF)
option(LLE_WERROR "Treat warnings as errors" ON)
option(LLE_LIBFUZZER "Also build libFuzzer binaries for fuzz targets (Linux clang)" OFF)
set(LLE_ONLY "" CACHE STRING "Optional list of path prefixes to restrict subdirectory discovery")
set(LLE_FALSE_SHARING_BYTES 128 CACHE STRING "False-sharing padding in bytes (power of two >= 64)")
set(LLE_SANITIZE "" CACHE STRING "Sanitizers: address;undefined | thread | memory | fuzzer")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)  # no C++ modules; avoids GCC module scanning under CMake 4
set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(Warnings)
include(Sanitizers)
include(Lle)

# Interface target carrying project-wide settings; every lle target links it.
add_library(lle_options INTERFACE)
target_include_directories(lle_options INTERFACE "${CMAKE_SOURCE_DIR}/src")
target_compile_features(lle_options INTERFACE cxx_std_23)
target_compile_definitions(lle_options INTERFACE
  LLE_FALSE_SHARING_BYTES=${LLE_FALSE_SHARING_BYTES}
  $<$<BOOL:${LLE_SIM}>:LLE_SIM=1>)
lle_apply_warnings(lle_options)
lle_apply_sanitizers(lle_options)
if(LLE_SIM)
  target_compile_options(lle_options INTERFACE -ffp-contract=off -ftrivial-auto-var-init=pattern)
endif()

include(Deps)  # HdrHistogram always; GoogleTest and Benchmark with tests or benchmarks
if(LLE_BUILD_TESTS)
  enable_testing()
endif()

# ---------------------------------------------------------------------------
# Auto-discovered subprojects: any directory with its own CMakeLists.txt.
# Target references across directories are resolved at generate time, so
# discovery order does not matter.
# ---------------------------------------------------------------------------
# Components that use SIM_BUGGIFY/SIM_PROBE (env/buggify.h) add ${LLE_SIM_HOOKS}
# to their DEPS: it links the simulator's hook implementation in LLE_SIM builds
# and is empty otherwise.
if(LLE_SIM)
  set(LLE_SIM_HOOKS lle_sim)
else()
  set(LLE_SIM_HOOKS "")
endif()

lle_add_subdirs("${CMAKE_SOURCE_DIR}/src")
lle_add_subdirs("${CMAKE_SOURCE_DIR}/src/proto")
lle_add_subdirs("${CMAKE_SOURCE_DIR}/src/net")
if(LLE_BUILD_TESTS)
  lle_add_subdirs("${CMAKE_SOURCE_DIR}/tests/unit")
  lle_add_subdirs("${CMAKE_SOURCE_DIR}/tests/integration")
  lle_add_subdirs("${CMAKE_SOURCE_DIR}/tests/golden")
  lle_add_subdirs("${CMAKE_SOURCE_DIR}/tests/sim_regressions")  # DST-NNN_* (verify_bugs.py)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/sim/CMakeLists.txt")
  lle_add_dir("${CMAKE_SOURCE_DIR}/sim")
endif()
if(LLE_BUILD_APPS)
  lle_add_subdirs("${CMAKE_SOURCE_DIR}/apps")
endif()
if(LLE_BUILD_FUZZ)
  lle_add_subdirs("${CMAKE_SOURCE_DIR}/fuzz")
endif()
if(LLE_BUILD_BENCH)
  lle_add_subdirs("${CMAKE_SOURCE_DIR}/bench")
endif()

# libFuzzer binaries, one "name=path" per line, for CI.
get_property(_lle_fuzz_targets GLOBAL PROPERTY LLE_FUZZ_TARGETS)
if(_lle_fuzz_targets)
  list(JOIN _lle_fuzz_targets "\n" _lle_fuzz_lines)
  file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/fuzz_targets.txt" CONTENT "${_lle_fuzz_lines}\n")
endif()
