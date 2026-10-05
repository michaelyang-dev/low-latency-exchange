# Hot-standby replication (10 §2-§5): data-plane codec, the sans-I/O replica core
# (primary/backup, detectors, promotion, solo, RESUME, rejoin and catch-up, FORWARD,
# determinism safeguards) and the journal truncation used by rejoin.
lle_library(lle_repl
  SOURCES wire.cpp types.cpp
  DEPS lle_common lle_env lle_journal lle_witness ${LLE_SIM_HOOKS})
