# Engine microbenchmark for the T20 mix (05-matching-engine §8). Indicative only on the dev Mac.
lle_bench(engine_mix_bench SOURCES engine_mix_bench.cpp DEPS lle_engine)
# RiskGate::check() alone with the T20 risk profile (05-matching-engine §7).
lle_bench(risk_gate_bench SOURCES risk_gate_bench.cpp DEPS lle_engine)
