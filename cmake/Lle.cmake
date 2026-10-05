# Helper functions shared by every module.

# ctest TIMEOUT of the tests that run exsim at length (determinism double-runs, the ledger
# self-test): a Debug sanitizer build runs them many times slower (GCC's ASan on arm64:
# about 16 minutes for 128 determinism seeds).
if(LLE_SANITIZE)
  set(LLE_SIM_SLOW_TEST_TIMEOUT 3600)
else()
  set(LLE_SIM_SLOW_TEST_TIMEOUT 900)
endif()

# True in OUT if path REL (relative to the source root) passes the LLE_ONLY
# filter: a list of path prefixes (e.g. "src/common;src/proto/itch50"). A
# directory is kept if it lies under a prefix or is an ancestor of one.
function(lle_keep rel out)
  set(_keep TRUE)
  if(LLE_ONLY)
    set(_keep FALSE)
    foreach(prefix IN LISTS LLE_ONLY)
      if(prefix STREQUAL "")
        continue()  # a trailing ';' would otherwise match every path
      endif()
      string(FIND "${rel}" "${prefix}" pos)
      string(FIND "${prefix}" "${rel}/" pos2)
      if(pos EQUAL 0 OR pos2 EQUAL 0 OR prefix STREQUAL rel)
        set(_keep TRUE)
      endif()
    endforeach()
  endif()
  set(${out} ${_keep} PARENT_SCOPE)
endfunction()

# Add DIR itself if it has a CMakeLists.txt and passes LLE_ONLY.
function(lle_add_dir dir)
  if(EXISTS "${dir}/CMakeLists.txt")
    file(RELATIVE_PATH rel "${CMAKE_SOURCE_DIR}" "${dir}")
    lle_keep("${rel}" keep)
    if(keep)
      add_subdirectory("${dir}")
    endif()
  endif()
endfunction()

# Add every immediate subdirectory of DIR that has a CMakeLists.txt and passes LLE_ONLY.
function(lle_add_subdirs dir)
  if(NOT EXISTS "${dir}")
    return()
  endif()
  file(GLOB children LIST_DIRECTORIES true RELATIVE "${dir}" "${dir}/*")
  list(SORT children)
  foreach(child IN LISTS children)
    if(IS_DIRECTORY "${dir}/${child}")
      lle_add_dir("${dir}/${child}")
    endif()
  endforeach()
endfunction()

# lle_library(<name> [HEADER_ONLY] SOURCES ... DEPS ...)
function(lle_library name)
  cmake_parse_arguments(A "HEADER_ONLY" "" "SOURCES;DEPS" ${ARGN})
  if(A_HEADER_ONLY OR NOT A_SOURCES)
    add_library(${name} INTERFACE)
    target_link_libraries(${name} INTERFACE lle_options ${A_DEPS})
  else()
    add_library(${name} STATIC ${A_SOURCES})
    target_link_libraries(${name} PUBLIC lle_options ${A_DEPS})
  endif()
endfunction()

# lle_test(<name> SOURCES ... DEPS ...) -> GoogleTest executable registered with CTest.
function(lle_test name)
  cmake_parse_arguments(A "" "" "SOURCES;DEPS" ${ARGN})
  if("memory" IN_LIST LLE_SANITIZE OR "thread" IN_LIST LLE_SANITIZE)
    # Allocation-counting tests replace the global operator new, which the MSan and TSan
    # runtimes also define. Convention: such tests live in *alloc_test.cpp files.
    set(_all ${A_SOURCES})
    list(FILTER A_SOURCES EXCLUDE REGEX "alloc_test\\.cpp$")
    if(NOT _all STREQUAL A_SOURCES)
      message(STATUS "MSan/TSan: ${name}: allocation-counting sources skipped")
    endif()
    if(NOT A_SOURCES)
      return()
    endif()
  endif()
  add_executable(${name} ${A_SOURCES})
  target_link_libraries(${name} PRIVATE lle_options ${A_DEPS} GTest::gtest_main)
  # GoogleTest's EXPECT_*/ASSERT_* macros expand to if/else, so GCC flags them
  # inside an unbraced `if` (-Wdangling-else). The allocation-counting tests replace the
  # global operator new/delete with malloc/free on purpose, which GCC's
  # -Wmismatched-new-delete reports at every inlined delete. Test code only.
  target_compile_options(${name} PRIVATE $<$<CXX_COMPILER_ID:GNU>:-Wno-dangling-else -Wno-mismatched-new-delete>)
  include(GoogleTest)
  gtest_discover_tests(${name} DISCOVERY_TIMEOUT 60 PROPERTIES LABELS unit)
endfunction()

# lle_app(<name> SOURCES ... DEPS ...)
function(lle_app name)
  cmake_parse_arguments(A "" "" "SOURCES;DEPS" ${ARGN})
  add_executable(${name} ${A_SOURCES})
  target_link_libraries(${name} PRIVATE lle_options ${A_DEPS})
endfunction()

# lle_bench(<name> SOURCES ... DEPS ...) -> Google Benchmark executable.
function(lle_bench name)
  cmake_parse_arguments(A "" "" "SOURCES;DEPS" ${ARGN})
  add_executable(${name} ${A_SOURCES})
  target_link_libraries(${name} PRIVATE lle_options ${A_DEPS} benchmark::benchmark)
endfunction()

# lle_fuzz(<name> SOURCES ... DEPS ...): a fuzz target defining LLVMFuzzerTestOneInput.
# Always builds <name>_driver (seeded random inputs; runs on macOS and in CI) and,
# with LLE_LIBFUZZER=ON, a libFuzzer binary <name>. A ctest smoke run is registered.
function(lle_fuzz name)
  cmake_parse_arguments(A "" "SMOKE_ITERS" "SOURCES;DEPS" ${ARGN})
  if(NOT A_SMOKE_ITERS)
    set(A_SMOKE_ITERS 20000)
  endif()
  add_executable(${name}_driver ${A_SOURCES} "${CMAKE_SOURCE_DIR}/fuzz/common/fuzz_driver_main.cpp")
  target_link_libraries(${name}_driver PRIVATE lle_options ${A_DEPS})
  if(LLE_BUILD_TESTS)
    add_test(NAME ${name}_smoke COMMAND ${name}_driver --iterations ${A_SMOKE_ITERS} --seed 1)
    set_tests_properties(${name}_smoke PROPERTIES LABELS fuzz)
  endif()
  if(LLE_LIBFUZZER)
    add_executable(${name} ${A_SOURCES})
    target_link_libraries(${name} PRIVATE lle_options ${A_DEPS})
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
    # Listed in <build>/fuzz_targets.txt for CI (.github/workflows/ci-fuzz.yml).
    set_property(GLOBAL APPEND PROPERTY LLE_FUZZ_TARGETS "${name}=$<TARGET_FILE:${name}>")
  endif()
endfunction()
