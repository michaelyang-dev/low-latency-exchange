# Cross-namespace functional test of the kernel-socket and io_uring backends (07 §5):
# veth pair + two network namespaces, UDP multicast feed, UDP echo and TCP echo per
# backend. Label `vm`: needs root on Linux (the script exits 77 → skipped otherwise).
# Run in the VM with: sudo ctest --test-dir <build> -L vm --output-on-failure
lle_app(net_peer SOURCES net_peer.cpp DEPS lle_net_backends)

set(_lle_net_vm_args $<TARGET_FILE:net_peer>)
if(TARGET net_busypoll_test)
  list(APPEND _lle_net_vm_args $<TARGET_FILE:net_busypoll_test>)
endif()
add_test(NAME net_veth_netns COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/veth_netns_test.sh ${_lle_net_vm_args})
set_tests_properties(net_veth_netns PROPERTIES LABELS vm SKIP_RETURN_CODE 77 TIMEOUT 600)
