# The T18 tick-to-trade instrument (07 §3, WP N-12; METHODOLOGY §13): feed with Poisson
# triggers and hardware TX stamps, order desk with RX stamps, reflector calibration and
# the offline analysis.
lle_app(ttt_harness SOURCES main.cpp DEPS lle_client lle_runtime)
