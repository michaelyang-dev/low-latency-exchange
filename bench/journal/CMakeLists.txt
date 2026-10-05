# Journal-track benchmarks (06 §2, §6, §12). Indicative on macOS (R6 R11).
lle_bench(journal_record_bench SOURCES record_bench.cpp DEPS lle_sequencer)
lle_bench(journal_write_bench SOURCES write_bench.cpp DEPS lle_journal)
