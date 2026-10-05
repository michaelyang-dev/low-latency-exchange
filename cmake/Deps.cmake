# Third-party dependencies, pinned by release tarball + SHA-256 (ADR-002).
# Only infrastructure libraries are allowed here (T01); adding one needs an ADR.
include(FetchContent)
set(FETCHCONTENT_QUIET ON)

FetchContent_Declare(googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
  URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK ON CACHE BOOL "" FORCE)

FetchContent_Declare(benchmark
  URL https://github.com/google/benchmark/archive/refs/tags/v1.9.5.tar.gz
  URL_HASH SHA256=9631341c82bac4a288bef951f8b26b41f69021794184ece969f8473977eaa340
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(hdrhistogram
  URL https://github.com/HdrHistogram/HdrHistogram_c/archive/refs/tags/0.11.9.tar.gz
  URL_HASH SHA256=0eb5fdb9f1f8c4b9c6eb319502f8d9e28991afffb8418672a61741993855650e
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(HDR_HISTOGRAM_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(HDR_HISTOGRAM_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(HDR_LOG_REQUIRED OFF CACHE BOOL "" FORCE)

# HdrHistogram is a production dependency (src/metrics); GoogleTest and Google
# Benchmark are fetched only when tests or benchmarks are built.
set(_lle_deps hdrhistogram)
if(LLE_BUILD_TESTS OR LLE_BUILD_BENCH)
  list(APPEND _lle_deps googletest benchmark)
endif()

# Third-party code is compiled without our warning flags.
set(_lle_saved_werror ${LLE_WERROR})
FetchContent_MakeAvailable(${_lle_deps})
set(LLE_WERROR ${_lle_saved_werror})
