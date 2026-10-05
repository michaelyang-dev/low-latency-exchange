# Client-side programs' cores (07 §3; WPs N-04, N-05, N-12, N-13, N-16, N-19, P-12):
# the mold_replay publisher (lossy dual lines, snapshot state), refclient's feed
# handler, T18 strategy and HA order entry, loadgen's schedule and accounting, the
# variant wiring (client_io.h: every backend, AF_XDP with utcp where built), the lab
# instruments' timestamp and analysis code (ttt_harness, loadgen v2), and the reports
# of the T10 evidence.
#
# src/net is configured after src/client (directories are added alphabetically), so
# the AF_XDP pieces are attached with generator expressions: LLE_CLIENT_HAVE_XSK is
# defined, and lle_net_xsk / lle_net_utcp_linux linked, only where they exist.
lle_library(lle_client
  SOURCES order_entry.cpp report.cpp loadgen.cpp loadgen_profile.cpp variant.cpp histogram.cpp phc_clock.cpp ttt.cpp
          backlog.cpp
  DEPS lle_common lle_env lle_moldudp64 lle_soupbin lle_glimpse lle_itch50 lle_ouch50 lle_book lle_net_backends
       lle_net_utcp lle_metrics hdr_histogram_static)
target_link_libraries(lle_client PUBLIC $<TARGET_NAME_IF_EXISTS:lle_net_xsk> $<TARGET_NAME_IF_EXISTS:lle_net_utcp_linux>)
target_compile_definitions(lle_client PUBLIC $<$<TARGET_EXISTS:lle_net_xsk>:LLE_CLIENT_HAVE_XSK=1>)

# The real sequencer and engine in-process (engine_driver.h): itch2ouch's divergence
# report and the loopback OUCH server (ouch_server.h). Kept apart so refclient and
# mold_replay do not link the engine.
lle_library(lle_client_exchange
  SOURCES itch2ouch.cpp divergence.cpp
  DEPS lle_client lle_engine lle_sequencer lle_journal lle_concurrent)
