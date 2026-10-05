# Gateway stage gwN (07 §3, WP N-17): session table and credentials, framing-only
# inbound path into the sequencer queue, release-gated OUCH egress with re-login
# replay from the in-memory ring and the output log.
lle_library(lle_gateway
  SOURCES credentials.cpp session_table.cpp
  DEPS lle_common lle_md lle_soupbin lle_sequencer lle_outlog lle_net_common lle_log)
