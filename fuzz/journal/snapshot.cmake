# Snapshot loader fuzz target (06 §9), included by fuzz/journal/CMakeLists.txt.
lle_fuzz(snapshot_loader_fuzz SOURCES ${CMAKE_CURRENT_LIST_DIR}/snapshot_loader_fuzz.cpp DEPS lle_snapshot)
