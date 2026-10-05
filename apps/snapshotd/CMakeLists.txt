lle_app(snapshotd SOURCES main.cpp DEPS lle_journal lle_snapshot_engine)
target_include_directories(snapshotd PRIVATE "${CMAKE_SOURCE_DIR}/apps")
