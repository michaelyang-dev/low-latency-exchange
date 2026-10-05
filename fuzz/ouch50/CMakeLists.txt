# OUCH 5.0 fuzz harnesses and the differential-test generator (03-protocols s9).
# lle_fuzz builds <name>_driver (shared seeded mutation driver, ctest smoke run)
# and, with LLE_LIBFUZZER=ON, the libFuzzer binary <name>.
lle_fuzz(ouch50_decode_fuzz SOURCES ouch50_decode_fuzz.cpp DEPS lle_ouch50 SMOKE_ITERS 200000)
lle_fuzz(tagvalue_fuzz SOURCES tagvalue_fuzz.cpp DEPS lle_ouch50 SMOKE_ITERS 200000)

# Differential generator: piped into tools/spec/ouch50_ref_decoder.py by
# tools/spec/ouch50_diff.py.
lle_app(ouch50_diffgen SOURCES ouch50_diffgen.cpp DEPS lle_ouch50)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND AND LLE_BUILD_TESTS)
  add_test(NAME ouch50_ref_decoder_diff
           COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/spec/ouch50_diff.py"
                   --gen $<TARGET_FILE:ouch50_diffgen> --count 200000 --jobs 4 --seed 11)
  set_tests_properties(ouch50_ref_decoder_diff PROPERTIES LABELS fuzz)
endif()
