lle_test(ouch50_golden_test SOURCES ouch50_golden_test.cpp DEPS lle_ouch50)

# The generated headers must match the CSV (specgen --check). Python is optional
# for the build; when present, staleness is a test failure.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME ouch50_specgen_check
           COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/../../../tools/specgen/specgen.py" --check)
  set_tests_properties(ouch50_specgen_check PROPERTIES LABELS golden)
endif()
