lle_test(journal_test
  SOURCES
    journal_writer_test.cpp
    journal_recovery_test.cpp
    crash_point_property_test.cpp
    l2_ring_test.cpp
    posix_journal_test.cpp
    uring_segment_dir_test.cpp
    follow_cursor_test.cpp
  DEPS lle_journal)

# The tools as processes (only when the apps are part of the build).
if(LLE_BUILD_APPS AND (NOT LLE_ONLY OR "apps/journal_inspect" IN_LIST LLE_ONLY))
  lle_test(journal_tools_test SOURCES journal_tools_test.cpp DEPS lle_journal)
  target_compile_definitions(journal_tools_test PRIVATE
    LLE_JOURNAL_INSPECT="$<TARGET_FILE:journal_inspect>"
    LLE_JOURNAL_DIFF="$<TARGET_FILE:journal_diff>"
    LLE_JOURNAL_REPLAY="$<TARGET_FILE:journal_replay>")
  add_dependencies(journal_tools_test journal_inspect journal_diff journal_replay)
endif()

if(LLE_JOURNAL_HAVE_IO_URING)
  lle_test(journal_io_uring_test SOURCES io_uring_device_test.cpp DEPS lle_journal)
endif()

# Recovery steps 4-5 with the engine (journal/engine_recovery.h).
if(TARGET lle_snapshot_engine)  # needs the engine (src/snapshot builds it only with src/engine)
  lle_test(engine_recovery_test SOURCES engine_recovery_test.cpp DEPS lle_journal lle_snapshot_engine)
  target_include_directories(engine_recovery_test PRIVATE ${CMAKE_SOURCE_DIR}/fuzz/engine)
endif()

# journal_replay --emit against a journal of engine records on disk.
if(LLE_BUILD_APPS AND TARGET lle_snapshot_engine AND (NOT LLE_ONLY OR "apps/journal_replay" IN_LIST LLE_ONLY))
  lle_test(journal_emit_test SOURCES journal_emit_test.cpp DEPS lle_journal lle_snapshot_engine)
  target_include_directories(journal_emit_test PRIVATE ${CMAKE_SOURCE_DIR}/fuzz/engine)
  target_compile_definitions(journal_emit_test PRIVATE LLE_JOURNAL_REPLAY="$<TARGET_FILE:journal_replay>")
  add_dependencies(journal_emit_test journal_replay)
endif()
