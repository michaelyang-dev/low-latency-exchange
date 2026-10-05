# Minimal lle-top (11-logging-observability §3): text view of a metrics segment.
if(TARGET lle_metrics)
  lle_app(lle_top SOURCES main.cpp DEPS lle_metrics)
endif()
