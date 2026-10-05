# nlog: NanoLog-style binary logger (11-logging-observability).
#   lle_log_format  file format encoders, offline formatting and the decoder (no
#                   runtime state; used by nlog_decode and the fuzz harness)
#   lle_log         hot-path runtime: thread registry, backend thread, memory sink
find_package(Threads REQUIRED)

lle_library(lle_log_format
  SOURCES file_format.cpp format_text.cpp decoder.cpp
  DEPS lle_common)

lle_library(lle_log
  SOURCES registry.cpp backend.cpp memory_sink.cpp tsc.cpp
  DEPS lle_log_format lle_common lle_env lle_concurrent Threads::Threads)
