def murmur3_32(key, seed=0):
    """MurmurHash3 x86_32, seed 0 -- matches Resources.mpkinfo digest0."""
    if isinstance(key, str):
        key = key.encode()
    l = len(key); h = seed; c1 = 0xcc9e2d51; c2 = 0x1b873593
    for i in range(0, l // 4 * 4, 4):
        k = int.from_bytes(key[i:i+4], 'little')
        k = (k * c1) & 0xffffffff; k = ((k << 15) | (k >> 17)) & 0xffffffff
        k = (k * c2) & 0xffffffff; h ^= k
        h = ((h << 13) | (h >> 19)) & 0xffffffff; h = (h * 5 + 0xe6546b64) & 0xffffffff
    tail = key[l // 4 * 4:]; k = 0
    if len(tail) >= 3: k ^= tail[2] << 16
    if len(tail) >= 2: k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]; k = (k * c1) & 0xffffffff
        k = ((k << 15) | (k >> 17)) & 0xffffffff; k = (k * c2) & 0xffffffff; h ^= k
    h ^= l; h ^= h >> 16; h = (h * 0x85ebca6b) & 0xffffffff
    h ^= h >> 13; h = (h * 0xc2b2ae35) & 0xffffffff; h ^= h >> 16
    return h
