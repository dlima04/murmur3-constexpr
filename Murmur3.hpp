#ifndef MURMUR3_HPP
#define MURMUR3_HPP

#define U32_CONSTANT(X) X##LU
#define U64_CONSTANT(X) X##LLU

#include <cstdint>
#include <string_view>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct Murmur3_128T {
  uint64_t first_;
  uint64_t second_;
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

constexpr auto rotl32(const uint32_t x, const int8_t r) -> uint32_t {
  return (x << r) | (x >> (32 - r));
}

constexpr auto rotl64(const uint64_t x, const int8_t r) -> uint64_t {
  return (x << r) | (x >> (64 - r));
}

constexpr auto murmur3_x86_32(
  const std::u8string_view& key, const uint32_t seed ) -> uint32_t
{
  if(key.empty()) {     // Key size must be at least 1 byte.
    return 0;           // reject this call.
  }

  constexpr uint32_t c1 = U32_CONSTANT(0xcc9e2d51);
  constexpr uint32_t c2 = U32_CONSTANT(0x1b873593);

  const auto len_bytes  = key.size();
  const auto num_blocks = len_bytes / 4;
  const auto p_tail     = key.data() + num_blocks*4;

  uint32_t hash = seed; // the actual hash.
  uint32_t chnk = 0;    // intermediate value for work.

  for(uint32_t i = 0; i < num_blocks; i++) {
    chnk  = static_cast<uint32_t>(key[i * 4 + 0]) << 0;
    chnk |= static_cast<uint32_t>(key[i * 4 + 1]) << 8;
    chnk |= static_cast<uint32_t>(key[i * 4 + 2]) << 16;
    chnk |= static_cast<uint32_t>(key[i * 4 + 3]) << 24;

    chnk *= c1;
    chnk  = rotl32(chnk,15);
    chnk *= c2;

    hash ^= chnk;
    hash  = rotl32(hash,13);
    hash  = hash*5+0xe6546b64;
  }

  chnk = 0;
  switch(len_bytes & 3) {
    case 3: chnk ^= p_tail[2] << 16; [[fallthrough]];
    case 2: chnk ^= p_tail[1] << 8;  [[fallthrough]];
    case 1: chnk ^= p_tail[0];
      chnk *= c1;
      chnk = rotl32(chnk, 15);
      chnk *= c2;
      hash ^= chnk;
    default: break;
  }

  hash ^= len_bytes;
  hash  = murmur3_fmix32(hash);

  return hash;
}

constexpr auto murmur3_x64_128(
  const std::u8string_view& key, const uint32_t seed ) -> Murmur3_128T
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

    chnk1  = (uint64_t)pchnk1[0] << 0;
    chnk1 |= (uint64_t)pchnk1[1] << 8;
    chnk1 |= (uint64_t)pchnk1[2] << 16;
    chnk1 |= (uint64_t)pchnk1[3] << 24;
    chnk1 |= (uint64_t)pchnk1[4] << 32;
    chnk1 |= (uint64_t)pchnk1[5] << 40;
    chnk1 |= (uint64_t)pchnk1[6] << 48;
    chnk1 |= (uint64_t)pchnk1[7] << 56;

    chnk2  = (uint64_t)pchnk2[0] << 0;
    chnk2 |= (uint64_t)pchnk2[1] << 8;
    chnk2 |= (uint64_t)pchnk2[2] << 16;
    chnk2 |= (uint64_t)pchnk2[3] << 24;
    chnk2 |= (uint64_t)pchnk2[4] << 32;
    chnk2 |= (uint64_t)pchnk2[5] << 40;
    chnk2 |= (uint64_t)pchnk2[6] << 48;
    chnk2 |= (uint64_t)pchnk2[7] << 56;

    chnk1 *= c1;
    chnk1  = rotl64(chnk1, 31);
    chnk1 *= c2;
    hash1 ^= chnk1;

    hash1  = rotl64(hash1, 27);
    hash1 += hash2;
    hash1  = hash1*5+0x52dce729;

    chnk2 *= c2;
    chnk2  = rotl64(chnk2,33); chnk2 *= c1; hash2 ^= chnk2;

    hash2  = rotl64(hash2,31);
    hash2 += hash1;
    hash2  = hash2*5+0x38495ab5;
  }

  const auto* tail = (block_ptr + num_blocks*16);
  chnk1 = 0;
  chnk2 = 0;

  switch(len_bytes & 15) {
    case 15: chnk2 ^= (uint64_t)(tail[14]) << 48;
    case 14: chnk2 ^= (uint64_t)(tail[13]) << 40;
    case 13: chnk2 ^= (uint64_t)(tail[12]) << 32;
    case 12: chnk2 ^= (uint64_t)(tail[11]) << 24;
    case 11: chnk2 ^= (uint64_t)(tail[10]) << 16;
    case 10: chnk2 ^= (uint64_t)(tail[ 9]) << 8;
    case  9: chnk2 ^= (uint64_t)(tail[ 8]) << 0;
      chnk2 *= c2; chnk2 = rotl64(chnk2, 33);
      chnk2 *= c1; hash2 ^= chnk2;

    case  8: chnk1 ^= (uint64_t)(tail[ 7]) << 56;
    case  7: chnk1 ^= (uint64_t)(tail[ 6]) << 48;
    case  6: chnk1 ^= (uint64_t)(tail[ 5]) << 40;
    case  5: chnk1 ^= (uint64_t)(tail[ 4]) << 32;
    case  4: chnk1 ^= (uint64_t)(tail[ 3]) << 24;
    case  3: chnk1 ^= (uint64_t)(tail[ 2]) << 16;
    case  2: chnk1 ^= (uint64_t)(tail[ 1]) << 8;
    case  1: chnk1 ^= (uint64_t)(tail[ 0]) << 0;
      chnk1 *= c1; chnk1 = rotl64(chnk1, 31);
      chnk1 *= c2; hash1 ^= chnk1;
  }

  hash1 ^= len_bytes;
  hash2 ^= len_bytes;

  hash1 += hash2;
  hash2 += hash1;

  hash1 = murmur3_fmix64(hash1);
  hash2 = murmur3_fmix64(hash2);

  hash1 += hash2;
  hash2 += hash1;

  Murmur3_128T out{};
  out.first_ = hash1;
  out.second_ = hash2;

  return out;
}

#endif //MURMUR3_HPP
