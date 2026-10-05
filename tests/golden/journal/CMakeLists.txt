# Golden journal format (06 §2): exact header bytes and CRCs, computed by an
# independent Python CRC32C.
lle_test(journal_golden_test SOURCES journal_format_test.cpp DEPS lle_journal)
