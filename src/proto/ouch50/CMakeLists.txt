# OUCH 5.0 rev 1.05 codec (03-protocols s4). The *.gen.h headers are generated
# by tools/specgen/specgen.py from spec/ouch50_fields.csv and checked in, so the
# build does not need Python.
lle_library(lle_ouch50 SOURCES validate.cpp DEPS lle_common)
