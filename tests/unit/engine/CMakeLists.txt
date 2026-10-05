lle_test(engine_test
  SOURCES engine_basic_test.cpp engine_misc_test.cpp engine_replay_test.cpp matching_book_test.cpp records_test.cpp
          cross_test.cpp risk/reject_codes_test.cpp risk/risk_property_test.cpp
  DEPS lle_engine)
target_include_directories(engine_test PRIVATE ${CMAKE_SOURCE_DIR}/fuzz/engine)  # swarm generator

# Separate binary: replaces the global allocation functions to count calls.
lle_test(engine_alloc_test SOURCES engine_alloc_test.cpp DEPS lle_engine)
target_include_directories(engine_alloc_test PRIVATE ${CMAKE_SOURCE_DIR}/fuzz/engine)
