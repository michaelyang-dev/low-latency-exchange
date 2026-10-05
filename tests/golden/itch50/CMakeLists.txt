get_filename_component(_lle_repo_root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
lle_test(itch50_golden_test
  SOURCES itch50_golden_test.cpp itch50_real_samples_test.cpp
  DEPS lle_itch50)
target_compile_definitions(itch50_golden_test PRIVATE LLE_SOURCE_DIR="${_lle_repo_root}")
