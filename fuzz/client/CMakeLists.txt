# Fuzz harness of the client programs' untrusted-input parsers (feed handler,
# HA order entry, loadgen accounting, itch2ouch converter); see lle_fuzz.
lle_fuzz(client_inputs_fuzz SMOKE_ITERS 5000 SOURCES client_inputs_fuzz.cpp DEPS lle_client_exchange)
