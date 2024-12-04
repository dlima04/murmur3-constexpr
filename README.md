My implementation of [MurmurHash3](https://github.com/PeterScott/murmur3/blob/master/murmur3.c) in C++.
All of the code here is *constexpr*, meaning the hashes can be computed at compile-time. There were a few
obstacles that made this a little tricky to pull off, namely the fact that the original implementation used
pointer type punning quite heavily for the extraction of blocks from a given key. In C++, any cast
that reinterprets underlying data cannot be performed in a constexpr context, so I had to get a little bit creative
in order to make things work.
```cpp
chnk  = static_cast<uint32_t>(key[i * 4 + 0]) << 0;
chnk |= static_cast<uint32_t>(key[i * 4 + 1]) << 8;
chnk |= static_cast<uint32_t>(key[i * 4 + 2]) << 16;
chnk |= static_cast<uint32_t>(key[i * 4 + 3]) << 24;
```
As you can see, each chunk from a given key is extracted one byte at a time. This also gets rid of the punning
issues that the original algorithm had in the first place, so that's a nice plus.

Each function found in *murmur3.hpp* accepts two arguments: a key, and a seed. The 32 bit version of the
algorithm returns the hashed value directly, and the 128 bit ones return a struct containing the upper and 
lower 64 bits of the hash.

Lastly: note that I haven't implemented the x86 (32 bit) version of the algorithm that produces a 128 bit hash.
To be honest, I didn't really need this one, and you shouldn't either if you're on a 64 bit platform, as the 
64 bit version of that particular algorithm is much better regardless. 
