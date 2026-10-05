# io_uring backend tests (Linux with liburing only). Needs io_uring enabled in the
# kernel (kernel.io_uring_disabled=0) and not blocked by seccomp (no Docker default
# profile), 07 §5.
if(TARGET lle_net_uring)
  lle_test(net_uring_test SOURCES bip_buffer_test.cpp uring_test.cpp DEPS lle_net_uring)
endif()
