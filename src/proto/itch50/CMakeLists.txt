# TotalView-ITCH 5.0 codec, BinaryFILE reader, validator and census (03-protocols §3).
find_package(ZLIB REQUIRED)
lle_library(lle_itch50
  SOURCES binary_file.cpp validator.cpp census.cpp
  DEPS lle_common ZLIB::ZLIB)
