# AF_XDP tests (07 §2.3, §5). ring_test runs anywhere on Linux; the veth suite needs root
# (label `vm`; the script exits 77 -> skipped otherwise):
#   sudo ctest --test-dir <build> -L vm -R xsk --output-on-failure
if(NOT TARGET lle_net_xsk)
  return()
endif()
lle_test(net_xsk_ring_test SOURCES ring_test.cpp DEPS lle_net_xsk)
target_link_libraries(net_xsk_ring_test PRIVATE $<TARGET_NAME_IF_EXISTS:lle_client>)
target_compile_definitions(net_xsk_ring_test PRIVATE $<$<TARGET_EXISTS:lle_client>:LLE_XSK_TEST_CLIENT=1>)
# The root-only gtests run inside a namespace from xsk_veth_test.sh, not via discovery.
add_executable(net_xsk_vm_test xsk_vm_test.cpp)
target_link_libraries(net_xsk_vm_test PRIVATE lle_options lle_net_xsk lle_net_utcp_linux GTest::gtest_main)
target_compile_options(net_xsk_vm_test PRIVATE $<$<CXX_COMPILER_ID:GNU>:-Wno-dangling-else>)
# The clients' StampingFramePort (src/client/xsk_io.h) is covered too where lle_client is
# configured (it is absent under narrow LLE_ONLY sets).
target_link_libraries(net_xsk_vm_test PRIVATE $<TARGET_NAME_IF_EXISTS:lle_client>)
target_compile_definitions(net_xsk_vm_test PRIVATE $<$<TARGET_EXISTS:lle_client>:LLE_XSK_TEST_CLIENT=1>)
lle_app(xsk_udp_echo SOURCES udp_echo.cpp)
lle_app(xsk_interop SOURCES xsk_interop.cpp DEPS lle_net_xsk lle_net_utcp_linux)
lle_app(xsk_kernel_peer SOURCES "${CMAKE_SOURCE_DIR}/tests/integration/utcp/interop/kernel_peer.cpp")
target_include_directories(xsk_interop PRIVATE "${CMAKE_SOURCE_DIR}/tests/integration/utcp/interop")
add_test(NAME xsk_veth_netns
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/xsk_veth_test.sh $<TARGET_FILE:net_xsk_vm_test>
                 $<TARGET_FILE:xsk_udp_echo> $<TARGET_FILE:xsk_interop> $<TARGET_FILE:xsk_kernel_peer>)
set_tests_properties(xsk_veth_netns PROPERTIES LABELS vm SKIP_RETURN_CODE 77 TIMEOUT 1800)
