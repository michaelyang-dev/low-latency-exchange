# Journal (06 §3, §5-§7): record format, devices, L3 segment writer, recovery, L2 ring.
set(LLE_JOURNAL_SOURCES
  record.cpp
  segment.cpp
  posix_journal_device.cpp
  mem_journal_device.cpp
  posix_segment_dir.cpp
  uring_segment_dir.cpp
  recovery.cpp
  l2_storage.cpp
  describe.cpp
)
set(LLE_JOURNAL_DEPS lle_common lle_env lle_concurrent ${LLE_SIM_HOOKS})

# IoUringJournalDevice (06 §6) is Linux-only and needs liburing; it is kept out of
# the macOS build entirely.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBURING QUIET IMPORTED_TARGET liburing)
  endif()
  if(LIBURING_FOUND)
    list(APPEND LLE_JOURNAL_SOURCES io_uring_journal_device.cpp)
    list(APPEND LLE_JOURNAL_DEPS PkgConfig::LIBURING)
    set(LLE_JOURNAL_HAVE_IO_URING ON CACHE INTERNAL "")
  else()
    message(STATUS "lle_journal: liburing not found; IoUringJournalDevice disabled")
    set(LLE_JOURNAL_HAVE_IO_URING OFF CACHE INTERNAL "")
  endif()
else()
  set(LLE_JOURNAL_HAVE_IO_URING OFF CACHE INTERNAL "")
endif()

lle_library(lle_journal SOURCES ${LLE_JOURNAL_SOURCES} DEPS ${LLE_JOURNAL_DEPS})
if(LLE_JOURNAL_HAVE_IO_URING)
  target_compile_definitions(lle_journal PUBLIC LLE_HAVE_IO_URING=1)
endif()
