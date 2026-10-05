# Simulator speed (docs/plan/09 §13): target >= 10^6 simulated events per
# core-second. exsim_speed reports events/s for the raw event loop and for
# whole worlds (the `single` world replaces them when it lands).
lle_bench(exsim_speed SOURCES exsim_speed.cpp DEPS lle_sim_worlds)
