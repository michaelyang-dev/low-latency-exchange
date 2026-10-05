# Interop with nassau, an independent SoupBinTCP and MoldUDP64 implementation in Java
# (plan 03 §5; T08, T09). Opt-in, test-only: needs a JDK (21+) and the pinned jars:
#   tests/integration/nassau/fetch_nassau.sh <dir> && cmake ... -DLLE_NASSAU_DIR=<dir>
# The test has the ctest label "interop".
set(LLE_NASSAU_DIR "" CACHE PATH "Directory with the pinned nassau jars (fetch_nassau.sh)")
if(LLE_NASSAU_DIR AND LLE_BUILD_APPS AND (NOT LLE_ONLY OR "apps/exchanged" IN_LIST LLE_ONLY))
  find_package(Java 21 REQUIRED COMPONENTS Runtime Development)
  set(_jars "${LLE_NASSAU_DIR}/nassau-core-1.0.0.jar" "${LLE_NASSAU_DIR}/foundation-1.0.0.jar"
            "${LLE_NASSAU_DIR}/commons-lang3-3.12.0.jar")
  string(JOIN ":" _cp ${_jars})
  set(_classes "${CMAKE_CURRENT_BINARY_DIR}/classes")
  set(_java_srcs "${CMAKE_CURRENT_SOURCE_DIR}/SoupInterop.java" "${CMAKE_CURRENT_SOURCE_DIR}/MoldInterop.java")
  add_custom_command(
    OUTPUT "${_classes}/SoupInterop.class" "${_classes}/MoldInterop.class"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${_classes}"
    COMMAND "${Java_JAVAC_EXECUTABLE}" -Xlint:all -Werror -d "${_classes}" -cp "${_cp}" ${_java_srcs}
    DEPENDS ${_java_srcs} ${_jars}
    COMMENT "javac nassau interop clients")
  add_custom_target(nassau_interop_classes DEPENDS "${_classes}/SoupInterop.class" "${_classes}/MoldInterop.class")

  add_executable(nassau_interop_test nassau_interop_test.cpp)
  target_link_libraries(nassau_interop_test PRIVATE lle_options lle_journal lle_gateway lle_md lle_admin lle_soupbin
                        lle_moldudp64 lle_ouch50 lle_engine lle_itch50 lle_metrics lle_glimpse GTest::gtest_main)
  target_compile_options(nassau_interop_test PRIVATE $<$<CXX_COMPILER_ID:GNU>:-Wno-dangling-else>)
  target_compile_definitions(nassau_interop_test PRIVATE
    LLE_EXCHANGED="$<TARGET_FILE:exchanged>"
    LLE_WITNESSD="$<TARGET_FILE:witnessd>"
    LLE_JOURNAL_REPLAY="$<TARGET_FILE:journal_replay>"
    LLE_ITCH_VALIDATE="$<TARGET_FILE:itch_validate>"
    LLE_NLOG_DECODE="$<TARGET_FILE:nlog_decode>"
    LLE_JOURNAL_DIFF="$<TARGET_FILE:journal_diff>"
    LLE_SNAPSHOTD="$<TARGET_FILE:snapshotd>"
    LLE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    LLE_JAVA="${Java_JAVA_EXECUTABLE}"
    LLE_NASSAU_CLASSPATH="${_cp}:${_classes}")
  add_dependencies(nassau_interop_test nassau_interop_classes exchanged witnessd journal_replay itch_validate
                   nlog_decode journal_diff snapshotd)
  include(GoogleTest)
  gtest_discover_tests(nassau_interop_test DISCOVERY_TIMEOUT 60 PROPERTIES LABELS interop TIMEOUT 600)
endif()
