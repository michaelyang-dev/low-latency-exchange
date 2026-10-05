# Shared network vocabulary (07-networking §1, WP N-01): endpoints, interface lookup,
# socket options and multicast joins, the buffer arena, fixed queues, connection table
# and the NetPort facade types (configs, stats, Backend<K>).
lle_library(lle_net_common
  SOURCES endpoint.cpp iface.cpp sockopt.cpp buffer_arena.cpp port.cpp
  DEPS lle_common lle_env)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LLE_NET_URING_PROBE QUIET liburing>=2.5)
  endif()
  if(LLE_NET_URING_PROBE_FOUND)
    # Lets backend_compiled() report the io_uring variants (src/net/uring builds them).
    target_compile_definitions(lle_net_common PRIVATE LLE_HAVE_LIBURING=1)
  endif()
endif()

# stack.h: every backend compiled into this build behind one compile-time selector
# (Stack<K>, with_backend). A separate INTERFACE target keeps lle_net_common below the
# backends; the backend targets are defined later (or filtered out by LLE_ONLY), so they
# are resolved with generator expressions at generate time.
add_library(lle_net_backends INTERFACE)
target_link_libraries(lle_net_backends INTERFACE
  lle_net_sock
  $<TARGET_NAME_IF_EXISTS:lle_net_busypoll>
  $<TARGET_NAME_IF_EXISTS:lle_net_uring>)
target_compile_definitions(lle_net_backends INTERFACE $<$<TARGET_EXISTS:lle_net_uring>:LLE_NET_HAVE_URING=1>)
