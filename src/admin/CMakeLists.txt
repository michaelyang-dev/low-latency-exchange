# The authenticated admin channel and operator tooling cores (05 §10 E-15):
# wire protocol with HMAC-SHA256, the admin port core feeding the sequencer's
# admin queue, the shared command parser, LULD band computation, and a thin
# POSIX TCP layer for the tools.
lle_library(lle_admin
  SOURCES protocol.cpp commands.cpp luld.cpp net.cpp
  DEPS lle_common lle_sequencer)

# Scripted trading days through the sequencer into the engine (apps/scripted_day, tests).
lle_library(lle_admin_day
  SOURCES day_runner.cpp
  DEPS lle_admin lle_engine lle_itch50 lle_sequencer)
