lle_test(book_test SOURCES itch_book_test.cpp DEPS lle_book)
target_include_directories(book_test PRIVATE ${CMAKE_SOURCE_DIR}/fuzz/lob)  # swarm generator, apply_op

# Separate binary: replaces the global allocation functions to count calls.
lle_test(book_alloc_test SOURCES alloc_test.cpp DEPS lle_book)

# ITCH -> book adapter (book/itch_adapter.h), with messages built by the itch50 codec.
lle_test(book_itch_adapter_test SOURCES itch_adapter_test.cpp DEPS lle_book lle_itch50)
