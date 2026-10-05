# Snapshot container: format, streaming writer with atomic publication, and the
# validating loader (06 §9).
lle_library(lle_snapshot
  SOURCES format.cpp writer.cpp reader.cpp
  DEPS lle_common)

# The engine section (engine_section.h): the engine's canonical state in the
# container. Separate so lle_snapshot stays engine-independent; built only when
# the engine is part of the build (LLE_ONLY may leave it out).
if(TARGET lle_engine)
  lle_library(lle_snapshot_engine
    SOURCES engine_section.cpp
    DEPS lle_snapshot lle_engine)
endif()
