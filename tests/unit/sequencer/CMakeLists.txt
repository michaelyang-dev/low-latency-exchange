lle_test(sequencer_test SOURCES sequencer_test.cpp DEPS lle_sequencer)
lle_test(sequencer_no_alloc_test SOURCES no_alloc_test.cpp DEPS lle_sequencer)
lle_test(sequencer_engine_test SOURCES sequencer_engine_test.cpp DEPS lle_sequencer lle_engine)
