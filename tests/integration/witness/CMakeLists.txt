# witnessd as a process (needs the app in the build).
if(LLE_BUILD_APPS AND (NOT LLE_ONLY OR "apps/witnessd" IN_LIST LLE_ONLY))
  lle_test(witnessd_test SOURCES witnessd_test.cpp DEPS lle_witness)
  target_compile_definitions(witnessd_test PRIVATE LLE_WITNESSD="$<TARGET_FILE:witnessd>")
  add_dependencies(witnessd_test witnessd)
endif()
