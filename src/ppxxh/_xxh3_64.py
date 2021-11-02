import struct


def ifb64(b, offset=0):
    # Convert bytes to a 64-bit little-endian unsigned integer.
    return struct.unpack_from("<Q", b, offset)[0]


def ifb32(b, offset=0):
    # Convert bytes to a 32-bit little-endian unsigned integer.
    return struct.unpack_from("<I", b, offset)[0]


class xxh3_64:
    r"""An XXH3_64 hash object.

    This pure python implementation of Yann Collet's XXH3_64
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
        provides separate functions that allow `seed`, `secret`, or
        neither to be used.

    Examples
    --------
    Calculate the digest in various forms for the bytes object,
    ``b'This is a bytes object, not a string!'``.  Specify a `seed`
    value.  If this optional value were not provided, the hash object
    would be initialized differently and the various resulting digest
    values would all be different.

    >>> from ppxxh import xxh3_64
    >>> m = xxh3_64(seed=2523184290)  # seed is an optional argument
    >>> m.name
    'xxh3_64'
    >>> m.digest_size
    8
    >>> m.block_size
    1024
    >>> m.update(b'This is a bytes')
    >>> m.hexdigest()  # a digest may be requested at any time
    'fb862b73c3e55b90'
    >>> m.update(b' object, not a string!')
    >>> m.digest()
    b'\x1f3\xb4\xfa\x10\x02\xab\xab'
    >>> m.hexdigest()
    '1f33b4fa1002abab'
    >>> m.intdigest()
    2248339625091443627

    A more condensed way to get the same result.

    >>> xxh3_64(b'This is a bytes object, not a string!',
    ...         seed=2523184290).hexdigest()
    '1f33b4fa1002abab'

    (see ``ppxxh.xxh3_128`` for an example using a `secret`)
    """

    # XXH3 Constants
    _MIDSIZE_MAX = 240
    _MIDSIZE_STARTOFFSET = 3
    _MIDSIZE_LASTOFFSET = 17
    _SECRET_SIZE_MIN = 136
    _SECRET_DEFAULT_SIZE = 192
    _STRIPE_LEN = 64
    _SECRET_CONSUME_RATE = 8
    _ACC_NB = _STRIPE_LEN // 8
    _SECRET_LASTACC_START = 7
    _SECRET_MERGEACCS_START = 11
    _M32 = 0xFFFFFFFF  # 32-bit mask
    _M64 = 0xFFFFFFFFFFFFFFFF  # 64-bit mask

    _P32_1 = 0x9E3779B1
    _P32_2 = 0x85EBCA77
    _P32_3 = 0xC2B2AE3D
    _P64_1 = 0x9E3779B185EBCA87
    _P64_2 = 0xC2B2AE3D27D4EB4F
    _P64_3 = 0x165667B19E3779F9
    _P64_4 = 0x85EBCA77C2B2AE63
    _P64_5 = 0x27D4EB2F165667C5

    # default secret used when neither seed nor secret is provided
    _ksecret = bytes.fromhex(
        "b8 fe 6c 39 23 a4 4b be  7c 01 81 2c f7 21 ad 1c"  # 0-15
        + "de d4 6d e9 83 90 97 db  72 40 a4 a4 b7 b3 67 1f"  # 16-31
        + "cb 79 e6 4e cc c0 e5 78  82 5a d0 7d cc ff 72 21"  # 32-47
        + "b8 08 46 74 f7 43 24 8e  e0 35 90 e6 81 3a 26 4c"  # 48-63
        + "3c 28 52 bb 91 c3 00 cb  88 d0 65 8b 1b 53 2e a3"  # 64-79
        + "71 64 48 97 a2 0d f9 4e  38 19 ef 46 a9 de ac d8"  # 80-95
        + "a8 fa 76 3f e3 9c 34 3f  f9 dc bb c7 c7 0b 4f 1d"  # 96-111
        + "8a 51 e0 4b cd b4 59 31  c8 9f 7e c9 d9 78 73 64"  # 112-127
        + "ea c5 ac 83 34 d3 eb c3  c5 81 a0 ff fa 13 63 eb"  # 128-143
        + "17 0d dd 51 b7 f0 da 49  d3 16 55 26 29 d4 68 9e"  # 144-159
        + "2b 16 be 58 7d 47 a1 fc  8f f8 b8 d1 7a d0 31 ce"  # 160-175
        + "45 cb 3a 8f 95 16 04 28  af d7 fb ca bb 4b 40 7e"  # 176-191
    )

    # Constant attributes provided for compatibility with hashlib
    block_size = 1024
    """Number of bytes in each block consumed by the hash (`int`)

    This value is dependent on the size of the `secret` used.  It is
    1024 with a default secret size of 192.
    """

    digest_size = 64 // 8
    """Number of bytes in the hash digest (constant `int`)
    """

    name = "xxh3_64"
    """Name that may be passed to `ppxxh.new()` (constant `str`)
    """

    def __init__(self, data=None, *, seed=0, secret=None):
        self._secret = secret
        self._seed = seed
        if self._secret is None:
            self._secret = self._ksecret
        else:
            self._seed = 0
            if len(self._secret) < self._SECRET_SIZE_MIN:
                raise ValueError(
                    "Invalid secret length. Secret must be at least "
                    + str(self._SECRET_SIZE_MIN)
                    + " bytes."
                )
        if seed < 0 or seed > 0xFFFFFFFFFFFFFFFF:
            # Do this test after checking for a user provided secret
            # since the value of seed is ignored when a secret is
            # provided.
            raise ValueError("Seed must be a 64-bit unsigned integer.")

        # self.block_size is dependent on the length of secret.
        self.block_size = (
            self._STRIPE_LEN * (len(self._secret) - self._STRIPE_LEN)
        ) // self._SECRET_CONSUME_RATE
        self._total_length = 0  # total amount of data added
        self._buffer = b""
        # self._acc will be populated and then updated by self.update()
        # once sufficient data is available that one of the special
        # short input hash variants will not be used.
        self._acc = None
        self._last_stripe = b""

        if data is not None:
            # data was provided to the constructor, so pass this to update()
            self.update(data)

    def _len_0(self):
        # Used by intdigest() if 0 bytes have been added
        return self._avalanche64(
            self._seed ^ ifb64(self._secret, 56) ^ ifb64(self._secret, 64)
        )

    def _len_1to3(self):
        # Used by intdigest() if 1-3 bytes have been added
        b1 = self._buffer[0]
        b2 = self._buffer[self._total_length >> 1]
        b3 = self._buffer[-1]
        i0 = (b1 << 16) | (b2 << 24) | b3 | (self._total_length << 8)
        i1 = (
            (ifb32(self._secret) ^ ifb32(self._secret, 4)) + self._seed
        ) & self._M64
        return self._avalanche64(i0 ^ i1)

    def _len_4to8(self):
        # Used by intdigest() if 4-8 bytes have been added
        acc = self._s64(
            (ifb64(self._secret, 8) ^ ifb64(self._secret, 16)),
            self._seed ^ (self._swap32(self._seed & 0xFFFFFFFF) << 32),
        )
        acc ^= ifb32(self._buffer, len(self._buffer) - 4) + (
            ifb32(self._buffer) << 32
        )
        acc ^= (
            ((acc << 49) | (acc >> 15)) ^ ((acc << 24) | (acc >> 40))
        ) & self._M64
        acc = (acc * 0x9FB21C651E98DF25) & self._M64
        acc ^= ((acc >> 35) + self._total_length) & self._M64
        acc = (acc * 0x9FB21C651E98DF25) & self._M64
        return acc ^ (acc >> 28)

    def _len_9to16(self):
        # Used by intdigest() if 9-16 bytes have been added
        i0 = (
            ((ifb64(self._secret, 24) ^ ifb64(self._secret, 32)) + self._seed)
            & self._M64
        ) ^ ifb64(self._buffer)
        i1 = self._s64(
            ifb64(self._secret, 40) ^ ifb64(self._secret, 48), self._seed
        ) ^ ifb64(self._buffer, len(self._buffer) - 8)
        acc = (
            self._total_length
            + self._swap64(i0)
            + i1
            + self._mul128_fold64(i0, i1)
        ) & self._M64
        return self._avalanche(acc)

    def _len_17to128(self):
        # Used by intdigest() if 17-128 bytes have been added
        acc = (self._total_length * self._P64_1) & self._M64
        if self._total_length > 32:
            if self._total_length > 64:
                if self._total_length > 96:
                    acc = (
                        acc
                        + self._mix16B(
                            self._buffer[48:], self._secret[96:], self._seed
                        )
                    ) & self._M64
                    acc = (
                        acc
                        + self._mix16B(
                            self._buffer[-64:], self._secret[112:], self._seed
                        )
                    ) & self._M64
                acc = (
                    acc
                    + self._mix16B(
                        self._buffer[32:], self._secret[64:], self._seed
                    )
                ) & self._M64
                acc = (
                    acc
                    + self._mix16B(
                        self._buffer[-48:], self._secret[80:], self._seed
                    )
                ) & self._M64
            acc = (
                acc
                + self._mix16B(
                    self._buffer[16:], self._secret[32:], self._seed
                )
            ) & self._M64
            acc = (
                acc
                + self._mix16B(
                    self._buffer[-32:], self._secret[48:], self._seed
                )
            ) & self._M64
        acc = (
            acc + self._mix16B(self._buffer, self._secret, self._seed)
        ) & self._M64
        acc = (
            acc
            + self._mix16B(self._buffer[-16:], self._secret[16:], self._seed)
        ) & self._M64
        return self._avalanche(acc)

    def _len_129to240(self):
        # Used by intdigest() if 129-240 bytes have been added
        acc = (self._total_length * self._P64_1) & self._M64
        for i in range(8):
            acc = (
                acc
                + self._mix16B(
                    self._buffer[16 * i :], self._secret[16 * i :], self._seed
                )
            ) & self._M64
        acc = self._avalanche(acc)
        for i in range(8, self._total_length // 16):
            acc = (
                acc
                + self._mix16B(
                    self._buffer[16 * i :],
                    self._secret[(16 * (i - 8)) + self._MIDSIZE_STARTOFFSET :],
                    self._seed,
                )
            ) & self._M64
        # last bytes
        acc = (
            acc
            + self._mix16B(
                self._buffer[-16:],
                self._secret[
                    self._SECRET_SIZE_MIN - self._MIDSIZE_LASTOFFSET :
                ],
                self._seed,
            )
        ) & self._M64
        return self._avalanche(acc)

    def _final_merge(self, tmp_acc):
        return self._merge_accs(
            tmp_acc,
            self._secret[self._SECRET_MERGEACCS_START :],
            (self._total_length * self._P64_1) & self._M64,
        )

    ####################################################################
    # The remaining methods, as well as the XXH3 Constants and the
    # __init__ method above are common to all xxh3_* classes.
    ####################################################################

    @staticmethod
    def _s64(a, b):
        # The XXHASH algorithms are designed to work exclusively with
        # unsigned integers.  Thus in these algorithms, when a larger
        # number is subtracted from a smaller number, the result remains
        # a positive (unsigned) integer.  So, define s64() to duplicate
        # this behavior of subtracting a 64 bit unsigned integer from
        # another 64 bit unsigned integer.
        return (a + (b ^ __class__._M64) + 1) & __class__._M64

    @staticmethod
    def _swap32(x):
        return (
            ((x << 24) & 0xFF000000)
            | ((x << 8) & 0x00FF0000)
            | ((x >> 8) & 0x0000FF00)
            | ((x >> 24) & 0x000000FF)
        )

    @staticmethod
    def _swap64(x):
        return (
            ((x << 56) & 0xFF00000000000000)
            | ((x << 40) & 0x00FF000000000000)
            | ((x << 24) & 0x0000FF0000000000)
            | ((x << 8) & 0x000000FF00000000)
            | ((x >> 8) & 0x00000000FF000000)
            | ((x >> 24) & 0x0000000000FF0000)
            | ((x >> 40) & 0x000000000000FF00)
            | ((x >> 56) & 0x00000000000000FF)
        )

    @staticmethod
    def _mul128_fold64(i0, i1):
        p = i0 * i1
        return (p & __class__._M64) ^ (p >> 64)

    @staticmethod
    def _mix16B(data, secret, seed):
        i0 = ((ifb64(secret) + seed) ^ ifb64(data)) & __class__._M64
        i1 = __class__._s64(ifb64(secret, 8), seed) ^ ifb64(data, 8)
        return __class__._mul128_fold64(i0, i1)

    @staticmethod
    def _avalanche(h):
        h = ((h ^ (h >> 37)) * 0x165667919E3779F9) & __class__._M64
        return h ^ (h >> 32)

    @staticmethod
    def _avalanche64(h):
        h = ((h ^ (h >> 33)) * __class__._P64_2) & __class__._M64
        h = ((h ^ (h >> 29)) * __class__._P64_3) & __class__._M64
        return h ^ (h >> 32)

    @staticmethod
    def _accumulate_512(acc, data, secret):
        # Update acc using the contents of data[:64] and secret[:64]
        # These 64 bytes are 512 bits
        for i in range(__class__._ACC_NB):
            i0 = ifb64(data, 8 * i)
            i1 = i0 ^ ifb64(secret, 8 * i)
            acc[i ^ 1] = (acc[i ^ 1] + i0) & __class__._M64
            acc[i] = (
                acc[i] + (i1 & __class__._M32) * (i1 >> 32)
            ) & __class__._M64

    @staticmethod
    def _scrambleacc(acc, secret):
        # Update acc using the contents of secret[:64]
        for i in range(__class__._ACC_NB):
            acc[i] = acc[i] ^ (acc[i] >> 47) ^ ifb64(secret, 8 * i)
            acc[i] = (acc[i] * __class__._P32_1) & __class__._M64

    @staticmethod
    def _accumulate(acc, data, secret, nb_stripes):
        # Process a block of data
        for n in range(nb_stripes):
            __class__._accumulate_512(
                acc,
                data[n * __class__._STRIPE_LEN :],
                secret[n * __class__._SECRET_CONSUME_RATE :],
            )

    @staticmethod
    def _mix2accs(acc, secret):
        # Combine two accumulators and secret[:16]
        return __class__._mul128_fold64(
            acc[0] ^ ifb64(secret), acc[1] ^ ifb64(secret, 8)
        )

    @staticmethod
    def _merge_accs(acc, secret, start):
        # Combine acc[:8] with secret[:64] into a 64-bit result.
        result = start
        for i in range(4):
            i0 = __class__._mix2accs(acc[2 * i :], secret[16 * i :])
            result = (result + i0) & __class__._M64
        return __class__._avalanche(result)

    def _update_hashlong(self):
        # Use self._secret, but not self._seed.  If a seed was provided,
        # it was used to generate self._secret.
        nb_rounds = (
            len(self._secret) - self._STRIPE_LEN
        ) // self._SECRET_CONSUME_RATE
        block_len = self._STRIPE_LEN * nb_rounds
        # process as many blocks as possible from the buffer
        nb_blocks = (len(self._buffer) - 1) // block_len
        for n in range(nb_blocks):
            self._accumulate(
                self._acc,
                self._buffer[n * block_len :],
                self._secret,
                nb_rounds,
            )
            self._scrambleacc(self._acc, self._secret[-self._STRIPE_LEN :])

        if nb_blocks != 0:
            # At least one block was consumed.
            # Leave only unprocessed bytes in _buffer but keep a copy
            # of the last stripe since part of this last stripe may
            # need to be be reused in _finalize_hashlong()
            self._last_stripe = self._buffer[: nb_blocks * block_len][
                -self._STRIPE_LEN :
            ]
            self._buffer = self._buffer[nb_blocks * block_len :]

    def _finalize_hashlong(self):
        # This method (and the other methods it uses) must not change
        # any of the state variables.  Otherwise, it would change the
        # output of later calls to this method. So, create and use a
        # copy of self._acc
        tmp_acc = self._acc[:]

        # last partial block
        nb_stripes = (len(self._buffer) - 1) // self._STRIPE_LEN
        self._accumulate(tmp_acc, self._buffer, self._secret, nb_stripes)

        # last stripe
        # Use self._last_stripe and the remainder of self._buffer to
        # get buf_end.  This is only needed when nb_stripes is 0, but is
        # harmless when nb_stripes is not 0.
        buf_end = (self._last_stripe + self._buffer)[-self._STRIPE_LEN :]
        self._accumulate_512(
            tmp_acc,
            buf_end,
            self._secret[-(self._STRIPE_LEN + self._SECRET_LASTACC_START) :],
        )
        # _final_merge() is specific to this class.  Any subclasses must
        # provide an appropriate alternative to produce the correct
        # output.
        return self._final_merge(tmp_acc)

    @staticmethod
    def _customsecret(seed):
        # Generate a non-default secret from a non-default seed.
        secret = b""
        for i in range(__class__._SECRET_DEFAULT_SIZE // 16):
            secret += struct.pack(
                "<Q",
                ((ifb64(__class__._ksecret, 16 * i) + seed) & __class__._M64),
            )
            secret += struct.pack(
                "<Q",
                __class__._s64(ifb64(__class__._ksecret, (16 * i) + 8), seed),
            )
        return secret

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
        # A digest calculated for 240 bytes or less of data will use
        # self._seed and self._secret (at least one of which is the
        # default) directly whereas the digest calulated for more than
        # 240 bytes will use only self._secret. However, if a
        # non-default seed was provided (and not discarded because both
        # a seed and a secret were mistakenly provided) then
        # self._secret must be redefined to a secret generated from
        # self._seed (but only for more than 240 bytes of input data).
        #
        # Because of this, update() does nothing but store the data
        # until more than 240 bytes have been added.  Then, it redefines
        # self._secret (if self.seed != 0) before continuing.  So as to
        # do this only during the first call to update() in which there
        # is sufficient data, self._acc is also intialized at that time,
        # and the process is skipped if self._acc is already initialized.
        if self._total_length <= 240:
            return
        if self._acc is None:
            # There is sufficient data that _update_hashlong() will be
            # used and this is the first call to update that ensures
            # this. So, do setup for _update_hashlong().
            self._acc = [
                self._P32_3,
                self._P64_1,
                self._P64_2,
                self._P64_3,
                self._P64_4,
                self._P32_2,
                self._P64_5,
                self._P32_1,
            ]
            self._last_stripe = b""
            if self._seed != 0:
                self._secret = self._customsecret(self._seed)
        # _update_hashlong() will consume as much of self._buffer
        # as possible.
        self._update_hashlong()

    # intdigest() is provided for compatibility with the reference
    # implementation of XXH3_* even though this method is not part of
    # the hashlib interface
    def intdigest(self):
        """Return the hash digest as a 64-bit unsigned integer.

        This is the typical output format of the
        `reference implementation`_.
        """
        if self._total_length <= 240:
            if self._total_length == 0:
                return self._len_0()
            elif self._total_length <= 3:
                return self._len_1to3()
            elif self._total_length <= 8:
                return self._len_4to8()
            elif self._total_length <= 16:
                return self._len_9to16()
            elif self._total_length <= 128:
                return self._len_17to128()
            elif self._total_length <= 240:
                return self._len_129to240()
        # self._update_hashlong() has consumed as much of self._buffer
        # as possible. self._finalize_hashlong() will complete the
        # hash process
        return self._finalize_hashlong()

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
        cp = self.__class__()  # create a new instance of the subclass
        # copy current state to the new instance
        cp._acc = self._acc
        cp._seed = self._seed
        cp._secret = self._secret
        cp._last_stripe = self._last_stripe
        cp._total_length = self._total_length
        cp._buffer = self._buffer
        return cp
