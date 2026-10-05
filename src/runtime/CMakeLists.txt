# Stage runtime (08-concurrency-runtime §1): stage.h (StageLike, StageRef,
# InlineRunner), the threaded Launcher and the pinning helpers.
find_package(Threads REQUIRED)
lle_library(lle_runtime SOURCES launcher.cpp pinning.cpp DEPS lle_common lle_concurrent Threads::Threads)
