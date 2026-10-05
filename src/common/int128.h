#pragma once
// 128-bit integers for overflow-free intermediate products. GCC rejects the
// bare `__int128` spelling under -Wpedantic; `__extension__` declares them once.
namespace lle {

__extension__ typedef __int128 i128;
__extension__ typedef unsigned __int128 u128;

}  // namespace lle
