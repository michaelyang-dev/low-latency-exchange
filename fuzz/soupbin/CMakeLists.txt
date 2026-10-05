# SoupBinTCP fuzz harness (03-protocols s9): framer, server and client sessions.
lle_fuzz(soupbin_framer_fuzz SOURCES soupbin_framer_fuzz.cpp DEPS lle_soupbin SMOKE_ITERS 100000)
