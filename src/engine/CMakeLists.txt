# Deterministic matching engine (05-matching-engine). Emitting code is templated
# on the output sink (engine/detail/*.h); the rest is compiled here.
lle_library(lle_engine SOURCES engine.cpp cross.cpp risk/risk_gate.cpp DEPS lle_lob lle_ouch50 lle_itch50 lle_common)
