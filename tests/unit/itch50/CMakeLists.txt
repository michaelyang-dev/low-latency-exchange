get_filename_component(_lle_repo_root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
lle_test(itch50_test
  SOURCES itch50_codec_test.cpp binary_file_test.cpp validator_test.cpp census_test.cpp roundtrip_real_file_test.cpp
  DEPS lle_itch50)
target_compile_definitions(itch50_test PRIVATE LLE_SOURCE_DIR="${_lle_repo_root}")
