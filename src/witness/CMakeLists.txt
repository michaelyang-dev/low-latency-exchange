# The witness (10 §1-§2): control-plane codec and the sans-I/O grant core.
lle_library(lle_witness SOURCES control.cpp witness.cpp DEPS lle_common lle_env ${LLE_SIM_HOOKS})
