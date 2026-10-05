# utcp fuzz harnesses (07 §2.4 `utcp_segment_fuzz`): the Ethernet/IPv4/TCP/UDP/ARP
# parsers with a build/re-parse round trip, and the connection state machine driven by
# fuzzer-chosen segments, timers and application calls (single endpoint with invariant
# checks; and a two-endpoint mode with fuzzer-controlled loss/duplication/reordering
# that checks byte-stream exactness).
lle_fuzz(utcp_segment_fuzz SOURCES segment_fuzz.cpp DEPS lle_net_utcp SMOKE_ITERS 200000)
lle_fuzz(utcp_conn_fuzz SOURCES conn_fuzz.cpp DEPS lle_net_utcp SMOKE_ITERS 20000)
