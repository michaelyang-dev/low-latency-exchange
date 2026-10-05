function(lle_apply_warnings target)
  target_compile_options(${target} INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
    -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    # GCC's -Wnull-dereference reports false positives inside libstdc++ at -O1 and above
    # (unique_ptr, fortified string functions); clang's version is precise.
    $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wnull-dereference>
    -Wdouble-promotion -Wimplicit-fallthrough
    $<$<BOOL:${LLE_WERROR}>:-Werror>)
endfunction()
