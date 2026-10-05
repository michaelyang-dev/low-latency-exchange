lle_test(snapshot_test
  SOURCES snapshot_format_test.cpp snapshot_reader_test.cpp snapshot_writer_test.cpp
  DEPS lle_snapshot)

# T05: snapshot equivalence of the engine section over generated record streams
# (built with the engine only; see src/snapshot/CMakeLists.txt).
if(TARGET lle_snapshot_engine)
  lle_test(snapshot_engine_test SOURCES snapshot_engine_test.cpp DEPS lle_snapshot_engine)
  target_include_directories(snapshot_engine_test PRIVATE ${CMAKE_SOURCE_DIR}/fuzz/engine)
endif()
