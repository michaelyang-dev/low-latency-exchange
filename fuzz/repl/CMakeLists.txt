# Replication data-plane decoder and the replica core fed with decoded datagrams (R-02).
lle_fuzz(repl_wire_fuzz SOURCES wire_fuzz.cpp DEPS lle_repl lle_witness lle_journal SMOKE_ITERS 20000)
