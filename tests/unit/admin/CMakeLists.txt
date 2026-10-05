lle_test(admin_test SOURCES admin_test.cpp DEPS lle_admin lle_engine)
target_include_directories(admin_test PRIVATE ${CMAKE_SOURCE_DIR}/tests/unit/sequencer)

# The T03 scripted halt and IPO days (apps/scripted_day/days).
lle_test(scripted_day_test SOURCES scripted_day_test.cpp DEPS lle_admin_day)
target_compile_definitions(scripted_day_test PRIVATE LLE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
