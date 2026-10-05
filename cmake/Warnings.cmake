function(lle_apply_warnings target)
  target_compile_options(${target} INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
    -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wnull-dereference
    -Wdouble-promotion -Wimplicit-fallthrough
    $<$<BOOL:${LLE_WERROR}>:-Werror>)
endfunction()
