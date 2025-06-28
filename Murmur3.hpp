#ifndef MURMUR3_HPP
#define MURMUR3_HPP
#include <cstdint>
#include <string_view>
#include <bit>

#define U32_CONSTANT(X) X##LU
#define U64_CONSTANT(X) X##LLU
#define AS_U64(CT_EXPR) static_cast<uint64_t>(CT_EXPR)
#define AS_U32(CT_EXPR) static_cast<uint32_t>(CT_EXPR)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct Murmur3_128 {
  uint64_t first_  = 0;
  uint64_t second_ = 0;
};

constexpr auto murmur3_fmix32(uint32_t hash) -> uint32_t {
  hash ^= hash >> 16;
  hash *= U32_CONSTANT(0x85ebca6b);
  hash ^= hash >> 13;
  hash *= U32_CONSTANT(0xc2b2ae35);
  hash ^= hash >> 16;
  return hash;
}

constexpr auto murmur3_fmix64(uint64_t hash) -> uint64_t {
  hash ^= hash >> 33;
  hash *= U64_CONSTANT(0xff51afd7ed558ccd);
  hash ^= hash >> 33;
  hash *= U64_CONSTANT(0xc4ceb9fe1a85ec53);
  hash ^= hash >> 33;
  return hash;
}

constexpr auto murmur3_x86_32(
  const std::u8string_view& key, const uint32_t seed ) -> uint32_t
{
  constexpr uint32_t c1 = U32_CONSTANT(0xcc9e2d51);
  constexpr uint32_t c2 = U32_CONSTANT(0x1b873593);

  if(key.empty()) {     // Key size must be at least 1 byte.
    return 0;           // reject this call.
  }

  const auto len_bytes  = key.size();
  const auto num_blocks = len_bytes / 4;
  const auto p_tail     = key.data() + num_blocks*4;

  uint32_t hash = seed; // the actual hash.
  uint32_t chnk = 0;    // intermediate value for work.

  for(uint32_t i = 0; i < num_blocks; i++) {
    chnk  = AS_U32(key[i * 4 + 0]) << 0;
    chnk |= AS_U32(key[i * 4 + 1]) << 8;
    chnk |= AS_U32(key[i * 4 + 2]) << 16;
    chnk |= AS_U32(key[i * 4 + 3]) << 24;

    chnk *= c1;
    chnk  = std::rotl(chnk,15);
    chnk *= c2;

    hash ^= chnk;
    hash  = std::rotl(hash,13);
    hash  = hash*5+0xe6546b64;
  }

  chnk = 0;
  switch(len_bytes & 3) {
    case 3: chnk ^= p_tail[2] << 16; [[fallthrough]];
    case 2: chnk ^= p_tail[1] << 8;  [[fallthrough]];
    case 1: chnk ^= p_tail[0];
    chnk *= c1;
    chnk = std::rotl(chnk, 15);
    chnk *= c2;
    hash ^= chnk;
    default: break;
  }

  hash ^= len_bytes;
  hash  = murmur3_fmix32(hash);
  return hash;
}

constexpr auto murmur3_x64_128(
  const std::u8string_view& key, const uint32_t seed ) -> Murmur3_128
{
  if(key.empty()) {   // Key size must be at least 1 byte.
    return {};        // reject this call.
  }

  const auto block_ptr  = key.data();
  const auto len_bytes  = key.size();
  const auto num_blocks = key.size() / 16;

  constexpr uint64_t c1 = U64_CONSTANT(0x87c37b91114253d5);
  constexpr uint64_t c2 = U64_CONSTANT(0x4cf5ad432745937f);

  uint64_t hash1 = seed; // the lower 64 bits.
  uint64_t hash2 = seed; // the upper 64 bits.
  uint64_t chnk1 = 0;    // first intermediate value.
  uint64_t chnk2 = 0;    // second intermediate value.

  for(uint32_t i = 0; i < num_blocks; i++) {
    const auto* pchnk1 = &block_ptr[i * 16];
    const auto* pchnk2 = &block_ptr[(i * 16) + 8];

    // Copy lower 64 bits:
    chnk1  = AS_U64(pchnk1[0]) << 0;
    chnk1 |= AS_U64(pchnk1[1]) << 8;
    chnk1 |= AS_U64(pchnk1[2]) << 16;
    chnk1 |= AS_U64(pchnk1[3]) << 24;

    chnk1 |= AS_U64(pchnk1[4]) << 32;
    chnk1 |= AS_U64(pchnk1[5]) << 40;
    chnk1 |= AS_U64(pchnk1[6]) << 48;
    chnk1 |= AS_U64(pchnk1[7]) << 56;

    // Copy upper 64 bits:
    chnk2  = AS_U64(pchnk2[0]) << 0;
    chnk2 |= AS_U64(pchnk2[1]) << 8;
    chnk2 |= AS_U64(pchnk2[2]) << 16;
    chnk2 |= AS_U64(pchnk2[3]) << 24;

    chnk2 |= AS_U64(pchnk2[4]) << 32;
    chnk2 |= AS_U64(pchnk2[5]) << 40;
    chnk2 |= AS_U64(pchnk2[6]) << 48;
    chnk2 |= AS_U64(pchnk2[7]) << 56;

    chnk1 *= c1;
    chnk1  = std::rotl(chnk1, 31);
    chnk1 *= c2;
    hash1 ^= chnk1;

    hash1  = std::rotl(hash1, 27);
    hash1 += hash2;
    hash1  = hash1*5+0x52dce729;

    chnk2 *= c2;
    chnk2  = std::rotl(chnk2,33); chnk2 *= c1; hash2 ^= chnk2;

    hash2  = std::rotl(hash2,31);
    hash2 += hash1;
    hash2  = hash2*5+0x38495ab5;
  }

  // Begin tail portion.
  const auto* tail = (block_ptr + num_blocks*16);
  chnk1 = 0;
  chnk2 = 0;

  switch(len_bytes & 15) {
    case 15: chnk2 ^= AS_U64(tail[14]) << 48;
    case 14: chnk2 ^= AS_U64(tail[13]) << 40;
    case 13: chnk2 ^= AS_U64(tail[12]) << 32;
    case 12: chnk2 ^= AS_U64(tail[11]) << 24;
    case 11: chnk2 ^= AS_U64(tail[10]) << 16;
    case 10: chnk2 ^= AS_U64(tail[ 9]) << 8;
    case  9: chnk2 ^= AS_U64(tail[ 8]) << 0;
    chnk2 *= c2; chnk2 = std::rotl(chnk2, 33);
    chnk2 *= c1; hash2 ^= chnk2;

    case  8: chnk1 ^= AS_U64(tail[ 7]) << 56;
    case  7: chnk1 ^= AS_U64(tail[ 6]) << 48;
    case  6: chnk1 ^= AS_U64(tail[ 5]) << 40;
    case  5: chnk1 ^= AS_U64(tail[ 4]) << 32;
    case  4: chnk1 ^= AS_U64(tail[ 3]) << 24;
    case  3: chnk1 ^= AS_U64(tail[ 2]) << 16;
    case  2: chnk1 ^= AS_U64(tail[ 1]) << 8;
    case  1: chnk1 ^= AS_U64(tail[ 0]) << 0;
    chnk1 *= c1; chnk1 = std::rotl(chnk1, 31);
    chnk1 *= c2; hash1 ^= chnk1;
  }

  // begin finalization.
  hash1 ^= len_bytes;
  hash2 ^= len_bytes;
  hash1 += hash2;
  hash2 += hash1;

  // Avalanche.
  hash1 = murmur3_fmix64(hash1);
  hash2 = murmur3_fmix64(hash2);

  hash1 += hash2;
  hash2 += hash1;
  return { .first_ = hash1, .second_ = hash2 };
}

constexpr auto operator ""_mm32(const char8_t* str, size_t len) -> uint32_t {
  return murmur3_x86_32({str, len}, 0xbeef);
}

constexpr auto operator ""_mm128(const char8_t* str, size_t len) -> Murmur3_128 {
  return murmur3_x64_128({str, len}, 0xbeef);
}

#endif // MURMUR3_HPP
