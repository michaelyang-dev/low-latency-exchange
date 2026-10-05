lle_test(nlog_test
  SOURCES
    format_spec_test.cpp
    site_test.cpp
    site_inline_a.cpp
    site_inline_b.cpp
    site_mixed.cpp
    site_filtered.cpp
    hot_path_test.cpp
    hot_path_alloc_test.cpp
    roundtrip_test.cpp
    decoder_test.cpp
  DEPS lle_log lle_log_format)
# One TU with DEBUG/INFO compiled out (NlogSites.LevelsBelowMinimumAreCompiledOut).
set_source_files_properties(site_filtered.cpp PROPERTIES COMPILE_DEFINITIONS LLE_NLOG_MIN_LEVEL=2)

# ---------------------------------------------------------------------------
# Compile-fail tests (11-logging-observability §1, T30): each source must be
# rejected by the compiler with the expected nlog diagnostic. The test runs the
# project's compiler in -fsyntax-only mode and passes when the output matches;
# a source that compiles produces no output and therefore fails the test.
# ---------------------------------------------------------------------------
get_filename_component(_nlog_src_root "${CMAKE_CURRENT_SOURCE_DIR}/../../../src" ABSOLUTE)
set(_nlog_cf_flags -std=c++23 -fsyntax-only "-I${_nlog_src_root}" -DLLE_FALSE_SHARING_BYTES=${LLE_FALSE_SHARING_BYTES})
if(CMAKE_OSX_SYSROOT)
  list(APPEND _nlog_cf_flags -isysroot "${CMAKE_OSX_SYSROOT}")
endif()

function(nlog_compile_fail name regex)
  add_test(NAME nlog_compile_fail.${name}
           COMMAND ${CMAKE_CXX_COMPILER} ${_nlog_cf_flags} "${CMAKE_CURRENT_SOURCE_DIR}/compile_fail/${name}.cpp")
  set_tests_properties(nlog_compile_fail.${name} PROPERTIES PASS_REGULAR_EXPRESSION "${regex}"
                                                            LABELS "unit;compile-fail")
endfunction()

nlog_compile_fail(count_too_few "placeholders does not match the number of arguments")
nlog_compile_fail(count_too_many "placeholders does not match the number of arguments")
nlog_compile_fail(unsupported_pointer "nlog: unsupported argument type")
nlog_compile_fail(unsupported_class "nlog: unsupported argument type")
nlog_compile_fail(unsupported_wide_char "nlog: unsupported argument type")
nlog_compile_fail(bad_presentation "presentation type does not match the argument kind")
nlog_compile_fail(std_rejects_spec "std_format_accepts")
nlog_compile_fail(positional "positional or named replacement fields are not supported")
nlog_compile_fail(unmatched_brace "unmatched '}' in format string")
nlog_compile_fail(too_many_args "at most 8 arguments per log call")
# clang: "reference to local variable ... declared in enclosing function";
# GCC: "use of parameter from containing function".
nlog_compile_fail(non_literal_format
  "reference to local variable 'pattern' declared in enclosing function;use of parameter from containing function")
nlog_compile_fail(filtered_level_checked "placeholders does not match the number of arguments")

# Positive control: the same flags accept valid uses (guards against a harness
# that "passes" because every source fails for an unrelated reason).
add_test(NAME nlog_compile_ok
         COMMAND ${CMAKE_CXX_COMPILER} ${_nlog_cf_flags} "${CMAKE_CURRENT_SOURCE_DIR}/compile_fail/ok_compiles.cpp")
set_tests_properties(nlog_compile_ok PROPERTIES LABELS "unit;compile-fail")
