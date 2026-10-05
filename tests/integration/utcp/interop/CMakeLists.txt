# utcp <-> Linux kernel TCP interop (07 §2.4 Utcp.InteropLinuxPeer): veth pair across two
# network namespaces, AF_PACKET frame port, tc netem loss/reorder. Label `vm`: needs root
# on Linux (the script exits 77 -> skipped otherwise).
#   sudo ctest --test-dir <build> -L vm -R utcp --output-on-failure
lle_app(utcp_interop SOURCES utcp_interop.cpp DEPS lle_net_utcp_linux)
lle_app(utcp_kernel_peer SOURCES kernel_peer.cpp)
add_test(NAME utcp_interop_veth
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/utcp_interop_test.sh $<TARGET_FILE:utcp_interop>
                 $<TARGET_FILE:utcp_kernel_peer>)
set_tests_properties(utcp_interop_veth PROPERTIES LABELS vm SKIP_RETURN_CODE 77 TIMEOUT 1800)
