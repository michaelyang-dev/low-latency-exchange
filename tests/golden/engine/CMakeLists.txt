lle_test(engine_golden_test SOURCES engine_golden_test.cpp auction_golden_test.cpp extended_golden_test.cpp DEPS lle_engine)
target_include_directories(engine_golden_test PRIVATE ${CMAKE_SOURCE_DIR}/tests/unit/engine)
