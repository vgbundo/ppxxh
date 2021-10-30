import struct

try:
    from struct import iter_unpack
except ImportError:
    # iter_unpack not available in Python < 3.4
    def iter_unpack(format, buffer):
        fsize = struct.calcsize(format)
        for i in range(0, len(buffer) - fsize + 1, fsize):
            yield struct.unpack_from(format, buffer, i)


class xxh64:
    r"""An XXH64 hash object.

    This pure python implementation of Yann Collet's XXH64
    non-cryptographic hash algorithm is significantly slower than the
    `reference implementation`_, but it produces the same outputs
    given the same inputs.

    Parameters
    ----------
    data : bytes-like object, optional
        Data to update the hash object after initialization.
    seed : 64-bit unsigned int, optional, default=0, keyword only
        Used to initialize the hash.

    Examples
    --------
    Calculate the digest in various forms for the bytes object,
    ``b'This is a bytes object, not a string!'``.  Specify a `seed`
    value.  If this optional value were not provided, the hash object
    would be initialized differently and the various resulting digest
    values would all be different.

    >>> from ppxxh import xxh64
    >>> m = xxh64(seed=14414669413082423462)  # seed is optional
    >>> m.name
    'xxh64'
    >>> m.digest_size
    8
    >>> m.block_size
    32
    >>> m.update(b'This is a bytes')
    >>> m.hexdigest()  # a digest may be requested at any time
    '938907256708f46c'
    >>> m.update(b' object, not a string!')
    >>> m.digest()
    b'!^>f7\x84Ii'
    >>> m.hexdigest()
    '215e3e6637844969'
    >>> m.intdigest()
    2404427859801426281

    A more condensed way to get the same result.

    >>> xxh64(b'This is a bytes object, not a string!',
    ...       seed=14414669413082423462).hexdigest()
    '215e3e6637844969'
    """

    # Constant attributes provided for compatibility with hashlib
    # Of these, only block_size is used internally
    block_size = 32
    """Number of bytes in each block consumed by the hash (constant `int`)
    """

    digest_size = 64 // 8
    """Number of bytes in the hash digest (constant `int`)
    """

    name = "xxh64"
    """Name that may be passed to `ppxxh.new()` (constant `str`)
    """

    # Internal constants
    _P1 = 0x9E3779B185EBCA87
    _P2 = 0xC2B2AE3D27D4EB4F
    _P3 = 0x165667B19E3779F9
    _P4 = 0x85EBCA77C2B2AE63
    _P5 = 0x27D4EB2F165667C5
    _M64 = 0xFFFFFFFFFFFFFFFF  # 64-bit mask

    @staticmethod
    def _r(x, bits):
        # bit rotation of a 64-bit unsigned integer
        return ((x << bits) & __class__._M64) | (x >> (64 - bits))

    def __init__(self, data=None, *, seed=0):
        if seed < 0 or seed > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Seed must be a 64-bit unsigned integer.")
        self._s0 = (seed + self._P1 + self._P2) & self._M64
        self._s1 = (seed + self._P2) & self._M64
        self._s2 = seed & self._M64
        self._s3 = (seed - self._P1) & self._M64
        self._total_length = 0  # total amount of data added
        self._buffer = b""
        if data is not None:
            self.update(data)

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
        self._total_length += len(data)
        self._buffer += data
        # Process _buffer as 32-byte blocks of four little endian 64-bit
        # unsigned integers, until there is not enough remaining for
        # another such block.
        n_extra = len(self._buffer) % self.block_size
        for (b0, b1, b2, b3) in iter_unpack(
            "<QQQQ", self._buffer[: -n_extra or None]
        ):
            self._s0 = (
                self._r((self._s0 + b0 * self._P2) & self._M64, 31) * self._P1
            ) & self._M64
            self._s1 = (
                self._r((self._s1 + b1 * self._P2) & self._M64, 31) * self._P1
            ) & self._M64
            self._s2 = (
                self._r((self._s2 + b2 * self._P2) & self._M64, 31) * self._P1
            ) & self._M64
            self._s3 = (
                self._r((self._s3 + b3 * self._P2) & self._M64, 31) * self._P1
            ) & self._M64
        # Leave only unprocessed bytes in _buffer
        self._buffer = self._buffer[-n_extra:] if n_extra else b""

    # intdigest() is provided for compatibility with the reference
    # implementation of XXH64 even though this method is not part of the
    # hashlib interface
    def intdigest(self):
        """Return the hash digest as a 64-bit unsigned integer.

        This is the typical output format of the
        `reference implementation`_.
        """
        if self._total_length >= self.block_size:
            output = (
                self._r(self._s0, 1)
                + self._r(self._s1, 7)
                + self._r(self._s2, 12)
                + self._r(self._s3, 18)
            ) & self._M64
            for s in [self._s0, self._s1, self._s2, self._s3]:
                output ^= (
                    self._r((s * self._P2) & self._M64, 31) * self._P1
                ) & self._M64
                output = (output * self._P1 + self._P4) & self._M64
        else:
            output = self._s2 + self._P5
        output = (output + self._total_length) & self._M64

        # process remaining bytes from self._buffer, 8 bytes at a time
        n_extra = len(self._buffer) % 8
        for (b,) in iter_unpack("<Q", self._buffer[: -n_extra or None]):
            output ^= (
                self._r((b * self._P2) & self._M64, 31) * self._P1
            ) & self._M64
            output = (self._r(output, 27) * self._P1 + self._P4) & self._M64
        tmpbuffer = self._buffer[-n_extra or len(self._buffer) :]

        # process remaining bytes from tmpbuffer, 4 bytes at a time
        n_extra = len(tmpbuffer) % 4
        for (b,) in iter_unpack("<I", tmpbuffer[: -n_extra or None]):
            output ^= (b * self._P1) & self._M64
            output = (self._r(output, 23) * self._P2 + self._P3) & self._M64
        tmpbuffer = tmpbuffer[-n_extra or len(tmpbuffer) :]

        # process remaining bytes from tmpbuffer, 1 byte at a time
        for b in tmpbuffer:
            output ^= (b * self._P5) & self._M64
            output = (self._r(output, 11) * self._P1) & self._M64

        # mix bits and return output
        output = ((output ^ (output >> 33)) * self._P2) & self._M64
        output = ((output ^ (output >> 29)) * self._P3) & self._M64
        output = output ^ (output >> 32)
        return output

    def digest(self):
        """Return the hash digest as a bytes object.

        This is the big-endian representation of the value returned
        by ``intdigest()`` and is equivalent to the output of the
        ``XXH64_canonicalFromHash()`` function in the
        `reference implementation`_ applied to the value returned by
        ``intdigest()``.
        """
        # For discussion of big-endian vs little-endian for the hash
        # digest of XXHASH algorithms, see
        # https://github.com/Cyan4973/xxHash/issues/45
        return struct.pack(">Q", self.intdigest())

    def hexdigest(self):
        """Return the hash digest as a string of hexidecimal digits.

        This is the value returned by ``digest()`` expressed as a
        printable hex string for easy display.
        """
        # bytes.hex() is simpler, but not available For Python <= 3.4
        return "".join("{0:0>2x}".format(b) for b in self.digest())

    def copy(self):
        """Return a copy (clone) of the hash object."""
        cp = __class__()  # create a new instance
        # copy current state to the new instance
        cp._s0 = self._s0
        cp._s1 = self._s1
        cp._s2 = self._s2
        cp._s3 = self._s3
        cp._total_length = self._total_length
        cp._buffer = self._buffer
        return cp
