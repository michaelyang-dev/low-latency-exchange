# Gateway stage fuzz harness (07 §3, N-17): a client's byte stream into the gateway.
lle_fuzz(gateway_fuzz SOURCES gateway_fuzz.cpp DEPS lle_gateway lle_md lle_soupbin lle_concurrent SMOKE_ITERS 20000)
