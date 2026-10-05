# Fuzz harnesses (03-protocols §9); see lle_fuzz in cmake/Lle.cmake.
lle_fuzz(itch50_decode_fuzz SOURCES itch50_decode_fuzz.cpp DEPS lle_itch50)
lle_fuzz(binary_file_fuzz SOURCES binary_file_fuzz.cpp DEPS lle_itch50)
