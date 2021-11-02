import struct

from ._xxh3_64 import xxh3_64
from ._xxh3_64 import ifb32, ifb64


# Since many of the methods of xxh3_128 are common with xxh3_64, create this
# as a subclass.
class xxh3_128(xxh3_64):
    r"""An XXH3_128 hash object.

    This pure python implementation of Yann Collet's XXH3_128
    non-cryptographic hash algorithm is significantly slower than the
    `reference implementation`_, but it produces the same outputs
    given the same inputs.

    Parameters
    ----------
    data : bytes-like object, optional
        Data to update the hash object after initialization.
    seed : 64-bit unsigned int, optional, default=0, keyword only
        Used to initialize the hash.
    secret : bytes-like object, optional, keyword only
        Used to initialize the hash.  Minimum length is 136 bytes.
        Either `seed` or `secret` (or neither) may be provided, but not
        both.  If `secret` is provided and is not None, then `seed` will
        be ignored.  The public API of the `reference implementation`_
        provides separate functions that allow 'seed', 'secret', or
        neither to be used.

    Examples
    --------
    Calculate the digest in various forms for the bytes object,
    ``b'This is a bytes object, not a string!'``.  Specify a `secret`
    value.  If this optional value were not provided, the hash object
    would be initialized differently and the various resulting digest
    values would all be different.

    >>> from ppxxh import xxh3_128
    >>> mysecret = b'This would be better if it were much more random'*3
    >>> m = xxh3_128(secret=mysecret)  # secret is optional
    >>> m.name
    'xxh3_128'
    >>> m.digest_size
    16
    >>> m.block_size
    640
    >>> m.update(b'This is a bytes')
    >>> m.hexdigest()  # a digest may be requested at any time
    '09d3d926256b63f8115d70c72d815412'
    >>> m.update(b' object, not a string!')
    >>> m.digest()
    b'\x10\xf6$\xf2\x85\xb1;\xf5<\xdd\x13\xf4F\x8bd\xca'
    >>> m.hexdigest()
    '10f624f285b13bf53cdd13f4468b64ca'
    >>> m.intdigest()
    22545702341095050794955529224387781834
    >>> m.intdigest2()  # (low64, high64)
    (4385683552005219530, 1222204972921338869)

    Or, a more condensed way to get the same result:

    >>> xxh3_128(b'This is a bytes object, not a string!',
    ...           secret=mysecret).hexdigest()
    '10f624f285b13bf53cdd13f4468b64ca'

    (see ``ppxxh.xxh3_64`` for an example using a `seed`)
    """

    # Constant attributes provided for compatibility with hashlib
    block_size = 1024
    """Number of bytes in each block consumed by the hash (`int`)

    This value is dependent on the size of the `secret` used.  It is
    1024 with a default secret size of 192.
    """

    digest_size = 128 // 8  # size of the hash digest (bytes)
    """Size of the hash digest (bytes)"""

    name = "xxh3_128"
    """Name of the hash algorithm for ppxxh.new(name)"""

    # Hash of short data is specific to 128 bit version of xxh3_*
    # so, provide suitable methods to override those provided by
    # xxh3_64

    @staticmethod
    def _mix32B(i0, i1, d0, d1, secret, seed):
        # _mix32B is required by _len_17to128 and _len_129to240
        i0 = (i0 + __class__._mix16B(d1, secret[16:], seed)) & __class__._M64
        i0 ^= (ifb64(d0) + ifb64(d0, 8)) & __class__._M64
        i1 = (i1 + __class__._mix16B(d0, secret, seed)) & __class__._M64
        i1 ^= (ifb64(d1) + ifb64(d1, 8)) & __class__._M64
        return i0, i1

    def _len_0(self):
        # Used by intdigest() if 0 bytes have been added
        lo = ifb64(self._secret, 64) ^ ifb64(self._secret, 72)
        lo = self._avalanche64(self._seed ^ lo)
        hi = ifb64(self._secret, 80) ^ ifb64(self._secret, 88)
        hi = self._avalanche64(self._seed ^ hi)
        return (hi << 64) + lo

    def _len_1to3(self):
        # Used by intdigest() if 1-3 bytes have been added
        lo = (
            (self._buffer[0] << 16)
            | (self._buffer[self._total_length >> 1] << 24)
            | self._buffer[-1]
            | (self._total_length << 8)
        )
        hi = self._swap32(lo)
        hi = ((hi << 13) | (hi >> 19)) & self._M32
        # hi and lo were 32 bit, but now become 64 bit
        lo ^= (
            (ifb32(self._secret) ^ ifb32(self._secret, 4)) + self._seed
        ) & self._M64
        hi ^= self._s64(
            ifb32(self._secret, 8) ^ ifb32(self._secret, 12), self._seed
        )
        lo = self._avalanche64(lo)
        hi = self._avalanche64(hi)
        return (hi << 64) + lo

    def _len_4to8(self):
        # Used by intdigest() if 4-8 bytes have been added
        i0 = ifb64(self._secret, 16) ^ ifb64(self._secret, 24)
        i0 = (
            ((self._swap32(self._seed & 0xFFFFFFFF) << 32) ^ self._seed) + i0
        ) & self._M64
        i0 ^= ifb32(self._buffer) + (
            ifb32(self._buffer, len(self._buffer) - 4) << 32
        )
        i0 *= self._P64_1 + (self._total_length << 2)  # 128 bit
        lo = i0 & self._M64
        hi = ((i0 >> 64) + (lo << 1)) & self._M64
        lo ^= hi >> 3
        lo ^= lo >> 35
        lo = (lo * 0x9FB21C651E98DF25) & self._M64
        lo ^= lo >> 28
        hi = self._avalanche(hi)
        return (hi << 64) + lo

    def _len_9to16(self):
        # Used by intdigest() if 9-16 bytes have been added
        i0 = self._s64(
            ifb64(self._secret, 32) ^ ifb64(self._secret, 40), self._seed
        )
        i1 = ifb64(self._buffer, len(self._buffer) - 8)
        i0 ^= i1 ^ ifb64(self._buffer)
        i1 ^= (
            (ifb64(self._secret, 48) ^ ifb64(self._secret, 56)) + self._seed
        ) & self._M64
        i0 *= self._P64_1  # 128 bit
        i1 = (
            (i1 & 0xFFFFFFFF00000000)
            + ((i1 & self._M32) * self._P32_2)
            + (i0 >> 64)
        ) & self._M64
        i0 = (i0 + ((self._total_length - 1) << 54)) & self._M64
        i0 = (i0 ^ self._swap64(i1)) * self._P64_2  # #128 bit
        hi = ((i0 >> 64) + (i1 * self._P64_2)) & self._M64
        lo = i0 & self._M64
        hi = self._avalanche(hi)
        lo = self._avalanche(lo)
        return (hi << 64) + lo

    def _len_17to128(self):
        # Used by intdigest() if 17-128 bytes have been added
        i0 = (self._total_length * self._P64_1) & self._M64
        i1 = 0
        if self._total_length > 32:
            if self._total_length > 64:
                if self._total_length > 96:
                    i1, i0 = self._mix32B(
                        i1,
                        i0,
                        self._buffer[48:],
                        self._buffer[-64:],
                        self._secret[96:],
                        self._seed,
                    )
                i1, i0 = self._mix32B(
                    i1,
                    i0,
                    self._buffer[32:],
                    self._buffer[-48:],
                    self._secret[64:],
                    self._seed,
                )
            i1, i0 = self._mix32B(
                i1,
                i0,
                self._buffer[16:],
                self._buffer[-32:],
                self._secret[32:],
                self._seed,
            )
        i1, i0 = self._mix32B(
            i1, i0, self._buffer, self._buffer[-16:], self._secret, self._seed
        )
        # Note the similarlity between this and the end of 129to240
        lo = (i0 + i1) & self._M64
        hi = self._s64(self._total_length, self._seed)
        hi = (hi * self._P64_2) & self._M64
        hi = (hi + (i0 * self._P64_1) + (i1 * self._P64_4)) & self._M64
        lo = self._avalanche(lo)
        hi = ((self._avalanche(hi) ^ self._M64) + 1) & self._M64
        return (hi << 64) + lo

    def _len_129to240(self):
        # Used by intdigest() if 129-240 bytes have been added
        nb_rounds = self._total_length // 32
        i0 = (self._total_length * self._P64_1) & self._M64
        i1 = 0
        for i in range(4):
            i1, i0 = self._mix32B(
                i1,
                i0,
                self._buffer[32 * i :],
                self._buffer[32 * i + 16 :],
                self._secret[32 * i :],
                self._seed,
            )
        i0 = self._avalanche(i0)
        i1 = self._avalanche(i1)
        for i in range(4, nb_rounds):
            i1, i0 = self._mix32B(
                i1,
                i0,
                self._buffer[32 * i :],
                self._buffer[32 * i + 16 :],
                self._secret[self._MIDSIZE_STARTOFFSET + (32 * (i - 4)) :],
                self._seed,
            )
        # last bytes
        i1, i0 = self._mix32B(
            i1,
            i0,
            self._buffer[-16:],
            self._buffer[-32:],
            self._secret[
                self._SECRET_SIZE_MIN - self._MIDSIZE_LASTOFFSET - 16 :
            ],
            ((self._seed ^ self._M64) + 1) & self._M64,
        )
        # Note the similarlity between this and the end of 17to128
        lo = (i0 + i1) & self._M64
        hi = self._s64(self._total_length, self._seed)
        hi = (hi * self._P64_2) & self._M64
        hi = (hi + (i0 * self._P64_1) + (i1 * self._P64_4)) & self._M64
        lo = self._avalanche(lo)
        hi = ((self._avalanche(hi) ^ self._M64) + 1) & self._M64
        return (hi << 64) + lo

    def _final_merge(self, tmp_acc):
        # If more than 240 bytes have been added, then xxh3_64
        # provides all of the logic necessary for intdigest() except
        # for the followng.
        lo = self._merge_accs(
            tmp_acc,
            self._secret[self._SECRET_MERGEACCS_START :],
            (self._total_length * self._P64_1) & self._M64,
        )
        hi = self._merge_accs(
            tmp_acc,
            self._secret[-(8 * len(tmp_acc) + self._SECRET_MERGEACCS_START) :],
            (~(self._total_length * self._P64_2)) & self._M64,
        )
        return (hi << 64) + lo

    # Override the inherited public methods to provide appropriate docstrings
    def update(self, data):
        """
        Update the state of the hash object.

        Parameters
        ----------
        data : bytes-like object
            Data to update the hash object

        Notes
        -----
        Data may be passed to the hash object at initialization and/or
        by an arbitrary number of calls to ``update()``.
        """
        super().update(data)

    def intdigest(self):
        """Return the hash digest as a 128-bit unsigned integer."""
        return super().intdigest()

    # New method
    def intdigest2(self):
        """Return the hash digest as a pair of 64-bit unsigned integers.

        This is the typical output format of the
        `reference implementation`_.
        """
        int128 = self.intdigest()
        return int128 & self._M64, int128 >> 64

    # Modified method
    def digest(self):
        """Return the hash digest as a bytes object.

        This is the big-endian representation of the value returned
        by ``intdigest()`` and is equivalent to the output of the
        ``XXH128_canonicalFromHash()`` function in the
        `reference implementation`_ applied to the value returned by
        ``intdigest2()``.
        """
        low64, high64 = self.intdigest2()
        # for a big endian result, pack high64 befor low64
        return struct.pack(">QQ", high64, low64)

    def hexdigest(self):
        """Return the hash digest as a string of hexidecimal digits.

        This is the value returned by ``digest()`` expressed as a
        printable hex string for easy display.
        """
        return super().hexdigest()

    def copy(self):
        """Return a copy (clone) of the hash object."""
        return super().copy()
