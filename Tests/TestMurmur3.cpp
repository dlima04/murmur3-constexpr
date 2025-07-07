#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include "../Murmur3.hpp"
#include <iostream>

namespace murmur32 {
  constexpr uint32_t seed1 = 3318UL;
  constexpr char8_t str1[] = u8"zo20u7Lfodi7";
  constexpr uint32_t expected1 = 2261267491UL;

  constexpr uint32_t seed2 = 99913UL;
  constexpr char8_t str2[] = u8"1923cj32ASF}~";
  constexpr uint32_t expected2 = 2301554477UL;
}

namespace murmur128 {
  constexpr uint32_t seed1 = 8819423UL;
  constexpr char8_t str1[] = u8"ikADFSL12Zd+2c/.?";
  constexpr uint64_t expected1_highorder = 0xdd82ff40ac44de4aULL;
  constexpr uint64_t expected1_loworder = 0xb813bb982088020fULL;

  constexpr uint32_t seed2 = 19042UL;
  constexpr char8_t str2[] = u8")A^&*DEWS23kbc";
  constexpr uint64_t expected2_highorder = 0x9112683629a37ffdULL;
  constexpr uint64_t expected2_loworder = 0x69cef2591c70dc60ULL;
}

TEST_CASE("32-bit hashes") {
  const uint32_t res1 = murmur3_x86_32(::murmur32::str1, ::murmur32::seed1);
#ifdef MURMUR3_TEST_DEBUG_
  std::cout << "res1 hash: " << res1 << "\n";
#endif
  CHECK(res1 == ::murmur32::expected1);

  const uint32_t res2 = murmur3_x86_32(::murmur32::str2, ::murmur32::seed2);
#ifdef MURMUR3_TEST_DEBUG_
  std::cout << "res2 hash: " << res2 << std::endl;
#endif
  CHECK(res2 == ::murmur32::expected2);
}

TEST_CASE("64-bit hashes") {
  const Murmur3_128 res1 = murmur3_x64_128(::murmur128::str1, ::murmur128::seed1);
  const Murmur3_128 res2 = murmur3_x64_128(::murmur128::str2, ::murmur128::seed2);

#ifdef MURMUR3_TEST_DEBUG_
  std::cout << "res1 low order: " << std::hex << res1.first_ << "\n";
  std::cout << "res1 high order: " << std::hex << res1.second_ << "\n";

  std::cout << "res2 low order: " << std::hex << res2.first_ << "\n";
  std::cout << "res2 high order: " << std::hex << res2.second_ << std::endl;
#endif

  CHECK(res1.first_ == ::murmur128::expected1_loworder);
  CHECK(res1.second_ == ::murmur128::expected1_highorder);

  CHECK(res2.first_ == ::murmur128::expected2_loworder);
  CHECK(res2.second_ == ::murmur128::expected2_highorder);
}
