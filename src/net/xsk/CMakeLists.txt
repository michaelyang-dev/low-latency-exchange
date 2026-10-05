# AF_XDP datapath (07 §2.3): UMEM, rings, sockets, the md_steer XDP program and its
# libbpf loader, UDP datagram port, utcp frame port, multicast helper, NAPI control.
# Linux only; libbpf via pkg-config (libxdp is not required: the loader uses libbpf's
# bpf_program__set_ifindex + BPF_F_XDP_DEV_BOUND_ONLY directly).
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  return()
endif()
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LLE_LIBBPF QUIET IMPORTED_TARGET libbpf>=1.0)
endif()
if(NOT LLE_LIBBPF_FOUND)
  message(STATUS "net/xsk: libbpf (pkg-config libbpf >= 1.0) not found; AF_XDP backend not built")
  return()
endif()

lle_library(lle_net_xsk SOURCES umem.cpp socket.cpp steer.cpp multicast.cpp napi.cpp
            DEPS lle_net_utcp PkgConfig::LLE_LIBBPF)

# bpf/md_steer.bpf.c -> <build>/bpf/md_steer.bpf.o (clang -target bpf).
find_program(LLE_BPF_CLANG NAMES clang-21 clang-20 clang-19 clang-18 clang)
if(NOT LLE_BPF_CLANG)
  message(FATAL_ERROR "net/xsk: clang is required to compile bpf/md_steer.bpf.c")
endif()
set(_bpf_arch_inc "/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
if(NOT CMAKE_LIBRARY_ARCHITECTURE)
  set(_bpf_arch_inc "/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu")
endif()
set(LLE_XSK_BPF_OBJECT "${CMAKE_BINARY_DIR}/bpf/md_steer.bpf.o" CACHE INTERNAL "md_steer BPF object")
add_custom_command(
  OUTPUT "${LLE_XSK_BPF_OBJECT}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/bpf"
  COMMAND ${LLE_BPF_CLANG} -O2 -g -Wall -Wextra -Werror -target bpf -I${_bpf_arch_inc}
          -c "${CMAKE_SOURCE_DIR}/bpf/md_steer.bpf.c" -o "${LLE_XSK_BPF_OBJECT}"
  DEPENDS "${CMAKE_SOURCE_DIR}/bpf/md_steer.bpf.c"
  COMMENT "Compiling BPF object md_steer.bpf.o"
  VERBATIM)
add_custom_target(lle_md_steer_bpf ALL DEPENDS "${LLE_XSK_BPF_OBJECT}")
add_dependencies(lle_net_xsk lle_md_steer_bpf)
target_compile_definitions(lle_net_xsk PUBLIC LLE_XSK_BPF_OBJECT="${LLE_XSK_BPF_OBJECT}")
