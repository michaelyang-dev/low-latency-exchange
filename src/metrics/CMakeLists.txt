# Metrics shared-memory segment (11-logging-observability §3). HdrHistogram_c comes
# from cmake/Deps.cmake, which the top level includes when tests or benchmarks
# are enabled.
if(NOT TARGET hdr_histogram_static)
  message(STATUS "lle_metrics: HdrHistogram_c not available (cmake/Deps.cmake not included); skipped")
  return()
endif()
lle_library(lle_metrics SOURCES segment.cpp DEPS lle_common hdr_histogram_static)
