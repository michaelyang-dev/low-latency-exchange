# Journal-track fuzz harnesses (06 §3, §7, §9); see lle_fuzz in cmake/Lle.cmake.
lle_fuzz(journal_record_fuzz SOURCES record_fuzz.cpp DEPS lle_journal)
lle_fuzz(journal_recovery_fuzz SOURCES recovery_fuzz.cpp DEPS lle_journal SMOKE_ITERS 3000)
include(${CMAKE_CURRENT_LIST_DIR}/snapshot.cmake)
