# Fuzz harnesses (03-protocols §9); see lle_fuzz in cmake/Lle.cmake.
lle_fuzz(moldudp64_packet_fuzz SOURCES moldudp64_packet_fuzz.cpp DEPS lle_moldudp64)
lle_fuzz(line_arbiter_fuzz SOURCES line_arbiter_fuzz.cpp DEPS lle_moldudp64)
