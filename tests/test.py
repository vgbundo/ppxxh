import contextlib
import doctest
import random
import struct
import sys
import unittest

import ppxxh

# These ifb*_big() functions are NOT the same as the ifb*() functions
# defined in ppxxh._xxh3_64.  These assume b is big-endian while
# those assume b is little-endian.
# Convert bytes to a 32-bit big-endian unsigned integer.
def ifb32_big(b, offset=0):
    return struct.unpack_from(">I", b, offset)[0]


# Convert bytes to a 64-bit big-endian unsigned integer.
def ifb64_big(b, offset=0):
    return struct.unpack_from(">Q", b, offset)[0]


# Convert bytes to a 128-bit big-endian unsigned integer.
def ifb128_big(b, offset=0):
    # Because b is big-endian, unpack high64 before low64
    high64, low64 = struct.unpack_from(">QQ", b, offset)
    return low64 + (high64 << 64)


print("Testing ppxxh with Python", sys.version)

# Patch for unittest in Python < 3.4.
# This will not print the subTest data when an error occurs, but it will
# allow the tests to run for earlier versions of Python 3.
if "subTest" not in dir(unittest.TestCase):

    @contextlib.contextmanager
    def _subTest(self, msg=None, **params):
        yield
        return

    unittest.TestCase.subTest = _subTest


# Use the test data from
# https://github.com/Cyan4973/xxHash/xxHash-dev/cli/xsum_sanity_check.c
# with variations to exercise the various python methods available.

# Some of the tests use a random element.  Repeat these tests
# rand_count times to increase the likelihood of encountering
# any bugs that are dependent on the random element.
rand_count = 20

# Use the same algorithm from xsum_sanity_check.c to build sanity_buffer
# which will be used as input data for the tests.
PRIME32 = 2654435761
PRIME64 = 11400714785074694797
SANITY_BUFFER_SIZE = 2367
sanity_buffer = bytearray()
bytegen = PRIME32
for i in range(SANITY_BUFFER_SIZE):
    sanity_buffer.append((bytegen >> 56) & 0xFF)
    bytegen = (bytegen * PRIME64) & 0xFFFFFFFFFFFFFFFF  # 64 bit mask
custom_secret_size = ppxxh.xxh3_64._SECRET_SIZE_MIN + 11
custom_secret = sanity_buffer[7 : 7 + custom_secret_size]

# Formatting of the following data does not conform to PEP8.
# Instead extra whitespace is used to preserve the layout used in
# xsum_sanity_check.c for easier visual comparison with that source.
# fmt: off
testdata_xxh32 = [
   (  0,       0, 0x02CC5D05),
   (  0, PRIME32, 0x36B78AE7),
   (  1,       0, 0xCF65B03E),
   (  1, PRIME32, 0xB4545AA4),
   ( 14,       0, 0x1208E7E2),
   ( 14, PRIME32, 0x6AF1D1FE),
   (222,       0, 0x5BD11DBD),
   (222, PRIME32, 0x58803C5F)
]

testdata_xxh64 = [
    (   0,       0, 0xEF46DB3751D8E999),
    (   0, PRIME32, 0xAC75FDA2929B17EF),
    (   1,       0, 0xE934A84ADB052768),
    (   1, PRIME32, 0x5014607643A9B4C3),
    (   4,       0, 0x9136A0DCA57457EE),
    (  14,       0, 0x8282DCC4994E35C8),
    (  14, PRIME32, 0xC3BD6BF63DEB6DF0),
    ( 222,       0, 0xB641AE8CB691C174),
    ( 222, PRIME32, 0x20CB8AB7AE10C14A)
 ]

testdata_xxh3_64 = [
    (    0,       0, 0x2D06800538D394C2),  # empty string
    (    0, PRIME64, 0xA8A6B918B2F0364A),  # empty string
    (    1,       0, 0xC44BDFF4074EECDB),  # 1 - 3
    (    1, PRIME64, 0x032BE332DD766EF8),  # 1 - 3
    (    6,       0, 0x27B56A84CD2D7325),  # 4 - 8
    (    6, PRIME64, 0x84589C116AB59AB9),  # 4 - 8
    (   12,       0, 0xA713DAF0DFBB77E7),  # 9 - 16
    (   12, PRIME64, 0xE7303E1B2336DE0E),  # 9 - 16
    (   24,       0, 0xA3FE70BF9D3510EB),  # 17 - 32
    (   24, PRIME64, 0x850E80FC35BDD690),  # 17 - 32
    (   48,       0, 0x397DA259ECBA1F11),  # 33 - 64
    (   48, PRIME64, 0xADC2CBAA44ACC616),  # 33 - 64
    (   80,       0, 0xBCDEFBBB2C47C90A),  # 65 - 96
    (   80, PRIME64, 0xC6DD0CB699532E73),  # 65 - 96
    # xsum_sanity_check.c does not include any tests of xxh3_64 with an input
    # length of 97 - 128.  So, Add the following 2 lines to increase code 
    # coverage
    (  101,       0, 0xB7F2A5219A6ADCD6),  # 97 -128
    (  101, PRIME64, 0x3F0B78B11279E491),  # 97 -128

    (  195,       0, 0xCD94217EE362EC3A),  # 129-240
    (  195, PRIME64, 0xBA68003D370CB3D9),  # 129-240
    # one block, last stripe is overlapping
    (  403,       0, 0xCDEB804D65C6DEA4),
    (  403, PRIME64, 0x6259F6ECFD6443FD),
    # one block, finishing at stripe boundary
    (  512,       0, 0x617E49599013CB6B),
    (  512, PRIME64, 0x3CE457DE14C27708),
    # 2 blocks, finishing at block boundary
    ( 2048,       0, 0xDD59E2C3A5F038E0),
    ( 2048, PRIME64, 0x66F81670669ABABC),
    # 3 blocks, finishing at stripe boundary
    ( 2240,       0, 0x6E73A90539CF2948),
    ( 2240, PRIME64, 0x757BA8487D1B5247),
    # 3 blocks, last stripe is overlapping
    ( 2367,       0, 0xCB37AEB9E5D361ED),
    ( 2367, PRIME64, 0xD2DB3415B942B42A)
]

testdata_xxh3_64_withsecret = [
    (       0, 0, 0x3559D64878C5C66C),  # empty string
    (       1, 0, 0x8A52451418B2DA4D),  # 1 - 3
    (       6, 0, 0x82C90AB0519369AD),  # 4 - 8
    (      12, 0, 0x14631E773B78EC57),  # 9 - 16
    (      24, 0, 0xCDD5542E4A9D9FE8),  # 17 - 32
    (      48, 0, 0x33ABD54D094B2534),  # 33 - 64
    (      80, 0, 0xE687BA1684965297),  # 65 - 96
    (     195, 0, 0xA057273F5EECFB20),  # 129-240
    # one block, last stripe is overlapping
    (     403, 0, 0x14546019124D43B8),
    # one block, finishing at stripe boundary
    (     512, 0, 0x7564693DD526E28D),
    # >= 2 blodcks, at least one scrambling
    (    2048, 0, 0xD32E975821D6519F),
    # >= 2 blocks, at least one scrambling, last stripe unaligned
    (    2367, 0, 0x293FA8E5173BB5E7),
    # exactly 3 full blocks, not a multiple of 256
    ( 64*10*3, 0, 0x751D2EC54BC6038B)
]

testdata_xxh3_128 = [
  (   0,       0, ( 0x6001C324468D497F, 0x99AA06D3014798D8)),  # empty string
  (   0, PRIME32, ( 0x5444F7869C671AB0, 0x92220AE55E14AB50)),  # empty string
  (   1,       0, ( 0xC44BDFF4074EECDB, 0xA6CD5E9392000F6A)),  # 1 - 3
  (   1, PRIME32, ( 0xB53D5557E7F76F8D, 0x89B99554BA22467C)),  # 1 - 3
  (   6,       0, ( 0x3E7039BDDA43CFC6, 0x082AFE0B8162D12A)),  # 4 - 8
  (   6, PRIME32, ( 0x269D8F70BE98856E, 0x5A865B5389ABD2B1)),  # 4 - 8
  (  12,       0, ( 0x061A192713F69AD9, 0x6E3EFD8FC7802B18)),  # 9 - 16
  (  12, PRIME32, ( 0x9BE9F9A67F3C7DFB, 0xD7E09D518A3405D3)),  # 9 - 16
  (  24,       0, ( 0x1E7044D28B1B901D, 0x0CE966E4678D3761)),  # 17 - 32
  (  24, PRIME32, ( 0xD7304C54EBAD40A9, 0x3162026714A6A243)),  # 17 - 32
  (  48,       0, ( 0xF942219AED80F67B, 0xA002AC4E5478227E)),  # 33 - 64
  (  48, PRIME32, ( 0x7BA3C3E453A1934E, 0x163ADDE36C072295)),  # 33 - 64
  (  81,       0, ( 0x5E8BAFB9F95FB803, 0x4952F58181AB0042)),  # 65 - 96
  (  81, PRIME32, ( 0x703FBB3D7A5F755C, 0x2724EC7ADC750FB6)),  # 65 - 96
  # xsum_sanity_check.c does not include any tests of xxh3_128 with an input
  # length of 97 - 128.  So, Add the following to increase code coverage
  ( 101,       0, ( 0x5E9E9ED01FC1F1CF, 0xF96034BF00411258)),  # 97 -128
  ( 101, PRIME32, ( 0xD57FC3372CC4EBAB, 0x06A82AFCA3D7397C)),  # 97 -128

  ( 222,       0, ( 0xF1AEBD597CEC6B3A, 0x337E09641B948717)),  # 129-240
  ( 222, PRIME32, ( 0xAE995BB8AF917A8D, 0x91820016621E97F1)),  # 129-240
  # one block, last stripe is overlapping
  ( 403,       0, ( 0xCDEB804D65C6DEA4, 0x1B6DE21E332DD73D)),
  ( 403, PRIME64, ( 0x6259F6ECFD6443FD, 0xBED311971E0BE8F2)),
  # one block, finishing at stripe boundary
  ( 512,       0, ( 0x617E49599013CB6B, 0x18D2D110DCC9BCA1)),
  ( 512, PRIME64, ( 0x3CE457DE14C27708, 0x925D06B8EC5B8040)),
  # 2 blocks, finishing at block boundary
  (2048,       0, ( 0xDD59E2C3A5F038E0, 0xF736557FD47073A5)),
  (2048, PRIME32, ( 0x230D43F30206260B, 0x7FB03F7E7186C3EA)),
  # 3 blocks, finishing at stripe boundary
  (2240,       0, ( 0x6E73A90539CF2948, 0xCCB134FBFA7CE49D)),
  (2240, PRIME32, ( 0xED385111126FBA6F, 0x50A1FE17B338995F)),
  # 3 blocks, last stripe is overlapping
  (2367,       0, ( 0xCB37AEB9E5D361ED, 0xE89C0F6FF369B427)),
  (2367, PRIME32, ( 0x6F5360AE69C2F406, 0xD23AAE4B76C31ECB))
]

testdata_xxh3_128_withsecret = [
    (  0, 0, ( 0x005923CCEECBE8AE, 0x5F70F4EA232F1D38)),  # empty string
    (  1, 0, ( 0x8A52451418B2DA4D, 0x3A66AF5A9819198E)),  # 1 - 3
    (  6, 0, ( 0x0B61C8ACA7D4778F, 0x376BD91B6432F36D)),  # 4 - 8
    ( 12, 0, ( 0xAF82F6EBA263D7D8, 0x90A3C2D839F57D0F))   # 9 - 16
]

testdata_xxh3_generate_secret = [
    (                                        0, [ 0xB8, 0x26, 0x83, 0x7E ]),
    (                                        1, [ 0xA6, 0x16, 0x06, 0x7B ]),
    (       ppxxh.xxh3_64._SECRET_SIZE_MIN - 1, [ 0xDA, 0x2A, 0x12, 0x11 ]),
    ( ppxxh.xxh3_64._SECRET_DEFAULT_SIZE + 500, [ 0x7E, 0x48, 0x0C, 0xA7 ])
]
# fmt: on


# Given hash object xx and data of arbitrary length, update xx with
# the data by applying the data in a series of randomly chosen segments.
# Return the list of random segment lengths used so that if an error
# is found, the same segment lengths can be used to repeat the error.
def random_updates(xx, data):
    bytes_added = 0
    nlist = []
    while bytes_added < len(data):
        # xsum_sanity_check.c uses larger random values
        n = random.randint(0, 3000)
        nlist.append(n)
        xx.update(data[bytes_added : bytes_added + n])
        bytes_added += n
    return nlist


# like random_updates(), but after each update, create a copy of xx to
# also test the copy() method.
# Return the last copy and the list of random segment lengths.
def random_updates_c(xx, data):
    xx = xx.copy()  # all changes are made to copies
    bytes_added = 0
    nlist = []
    if len(data) == 1:
        # Below the segment lengths are chosen to ensure at least 2
        # calls to update() will be made.  Thus, the case of a single
        # byte of data must be handled differently.
        nlist.append(1)
        xx.update(data)
        return xx.copy(), nlist
    while bytes_added < len(data):
        n = random.randint(1, len(data) - 1)
        nlist.append(n)
        xx.update(data[bytes_added : bytes_added + n])
        xx = xx.copy()
        bytes_added += n
    return xx, nlist


# Given hash object xx and data of arbitrary length, update xx with
# a series of updates, each of which consists of a single byte.
def single_byte_updates(xx, data):
    for i in range(len(data)):
        xx.update(data[i : i + 1])


class Test_sanity_checks(unittest.TestCase):
    def test_xxh32_no_updates(self):
        for length, seed, hash in testdata_xxh32:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                self.assertEqual(
                    ppxxh.xxh32(sanity_buffer[:length], seed=seed).intdigest(),
                    hash,
                )
                self.assertEqual(
                    ifb32_big(
                        ppxxh.xxh32(sanity_buffer[:length], seed=seed).digest()
                    ),
                    hash,
                )
                self.assertEqual(
                    ifb32_big(
                        bytes.fromhex(
                            ppxxh.xxh32(
                                sanity_buffer[:length], seed=seed
                            ).hexdigest()
                        )
                    ),
                    hash,
                )

    # streaming oneshot
    def test_xxh32_intdigest_so(self):
        for length, seed, hash in testdata_xxh32:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                xx = ppxxh.xxh32(seed=seed)
                xx.update(sanity_buffer[:length])
                self.assertEqual(xx.intdigest(), hash)
                self.assertEqual(ifb32_big(xx.digest()), hash)
                self.assertEqual(
                    ifb32_big(bytes.fromhex(xx.hexdigest())), hash
                )

    # streaming random update lengths
    def test_xxh32_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh32:
                xx = ppxxh.xxh32(seed=seed)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb32_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb32_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    # streaming random update lengths using copies of xx
    def test_xxh32_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh32:
                xx = ppxxh.xxh32(seed=seed)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xxc.intdigest(), hash)
                    self.assertEqual(ifb32_big(xxc.digest()), hash)
                    self.assertEqual(
                        ifb32_big(bytes.fromhex(xxc.hexdigest())), hash
                    )
                    if length != 0:
                        # confirm that xxc != xx
                        # This uses the "private" property _total_length
                        # to verify that xx and xxc are not the same
                        # object and that changes made to xxc are not
                        # mistakenly also applied to xx.
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh32_intdigest_ss(self):
        for length, seed, hash in testdata_xxh32:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                xx = ppxxh.xxh32(seed=seed)
                single_byte_updates(xx, sanity_buffer[:length])
                self.assertEqual(xx.intdigest(), hash)
                self.assertEqual(ifb32_big(xx.digest()), hash)
                self.assertEqual(
                    ifb32_big(bytes.fromhex(xx.hexdigest())), hash
                )

    def test_xxh64_no_updates(self):
        for length, seed, hash in testdata_xxh64:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                self.assertEqual(
                    ppxxh.xxh64(sanity_buffer[:length], seed=seed).intdigest(),
                    hash,
                )
                self.assertEqual(
                    ifb64_big(
                        ppxxh.xxh64(sanity_buffer[:length], seed=seed).digest()
                    ),
                    hash,
                )
                self.assertEqual(
                    ifb64_big(
                        bytes.fromhex(
                            ppxxh.xxh64(
                                sanity_buffer[:length], seed=seed
                            ).hexdigest()
                        )
                    ),
                    hash,
                )

    # streaming oneshot
    def test_xxh64_intdigest_so(self):
        for length, seed, hash in testdata_xxh64:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                xx = ppxxh.xxh64(seed=seed)
                xx.update(sanity_buffer[:length])
                self.assertEqual(xx.intdigest(), hash)
                self.assertEqual(ifb64_big(xx.digest()), hash)
                self.assertEqual(
                    ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                )

    # streaming random update lengths
    def test_xxh64_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh64:
                xx = ppxxh.xxh64(seed=seed)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb64_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    # streaming random update lengths using copies of xx
    def test_xxh64_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh64:
                xx = ppxxh.xxh64(seed=seed)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xxc.intdigest(), hash)
                    self.assertEqual(ifb64_big(xxc.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xxc.hexdigest())), hash
                    )
                    if length != 0:
                        # confirm that xxc != xx
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh64_intdigest_ss(self):
        for length, seed, hash in testdata_xxh64:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                xx = ppxxh.xxh64(seed=seed)
                single_byte_updates(xx, sanity_buffer[:length])
                self.assertEqual(xx.intdigest(), hash)
                self.assertEqual(ifb64_big(xx.digest()), hash)
                self.assertEqual(
                    ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                )

    def test_xxh3_64_no_updates(self):
        for length, seed, hash in testdata_xxh3_64:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                self.assertEqual(
                    ppxxh.xxh3_64(
                        sanity_buffer[:length], seed=seed
                    ).intdigest(),
                    hash,
                )
                self.assertEqual(
                    ifb64_big(
                        ppxxh.xxh3_64(
                            sanity_buffer[:length], seed=seed
                        ).digest()
                    ),
                    hash,
                )
                self.assertEqual(
                    ifb64_big(
                        bytes.fromhex(
                            ppxxh.xxh3_64(
                                sanity_buffer[:length], seed=seed
                            ).hexdigest()
                        )
                    ),
                    hash,
                )

    # streaming oneshot
    def test_xxh3_64_intdigest_so(self):
        for length, seed, hash in testdata_xxh3_64:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                xx = ppxxh.xxh3_64(seed=seed)
                xx.update(sanity_buffer[:length])
                self.assertEqual(xx.intdigest(), hash)
                self.assertEqual(ifb64_big(xx.digest()), hash)
                self.assertEqual(
                    ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                )

    # streaming random update lengths
    def test_xxh3_64_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64:
                xx = ppxxh.xxh3_64(seed=seed)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb64_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    # streaming random update lengths using copies of xx
    def test_xxh3_64_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64:
                xx = ppxxh.xxh3_64(seed=seed)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xxc.intdigest(), hash)
                    self.assertEqual(ifb64_big(xxc.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xxc.hexdigest())), hash
                    )
                    if length != 0:
                        # confirm that xxc != xx
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh3_64_intdigest_ss(self):
        for length, seed, hash in testdata_xxh3_64:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                xx = ppxxh.xxh3_64(seed=seed)
                single_byte_updates(xx, sanity_buffer[:length])
                self.assertEqual(xx.intdigest(), hash)
                self.assertEqual(ifb64_big(xx.digest()), hash)
                self.assertEqual(
                    ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                )

    def test_xxh3_64_withsecret_no_updates(self):
        for length, seed, hash in testdata_xxh3_64_withsecret:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                self.assertEqual(
                    ppxxh.xxh3_64(
                        sanity_buffer[:length], seed=seed, secret=custom_secret
                    ).intdigest(),
                    hash,
                )
                self.assertEqual(
                    ifb64_big(
                        ppxxh.xxh3_64(
                            sanity_buffer[:length],
                            seed=seed,
                            secret=custom_secret,
                        ).digest()
                    ),
                    hash,
                )
                self.assertEqual(
                    ifb64_big(
                        bytes.fromhex(
                            ppxxh.xxh3_64(
                                sanity_buffer[:length],
                                seed=seed,
                                secret=custom_secret,
                            ).hexdigest()
                        )
                    ),
                    hash,
                )

    # streaming oneshot
    def test_xxh3_64_withsecret_intdigest_so(self):
        for length, seed, hash in testdata_xxh3_64_withsecret:
            with self.subTest(
                length=length, seed_hex=hex(seed), hash_hex=hex(hash)
            ):
                xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                xx.update(sanity_buffer[:length])
                self.assertEqual(xx.intdigest(), hash)
                self.assertEqual(ifb64_big(xx.digest()), hash)
                self.assertEqual(
                    ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                )

    # streaming random update lengths
    def test_xxh3_64_withsecret_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb64_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    # streaming random update lengths using copies of xx
    def test_xxh3_64_withsecret_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xxc.intdigest(), hash)
                    self.assertEqual(ifb64_big(xxc.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xxc.hexdigest())), hash
                    )
                    if length != 0:
                        # confirm that xxc != xx
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh3_64_withsecret_intdigest_ss(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                with self.subTest(
                    length=length, seed_hex=hex(seed), hash_hex=hex(hash)
                ):
                    xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                    single_byte_updates(xx, sanity_buffer[:length])
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb64_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    # identical to test_xxh3_64_withsecret_no_updates, but a non-zero
    # random seed is provided.  This seed should have no effect when
    # a secret is used.
    def test_xxh3_64_withsecret_rs_no_updates(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                with self.subTest(
                    length=length, seed_hex=hex(seed), hash_hex=hex(hash)
                ):
                    self.assertEqual(
                        ppxxh.xxh3_64(
                            sanity_buffer[:length],
                            seed=seed,
                            secret=custom_secret,
                        ).intdigest(),
                        hash,
                    )
                    self.assertEqual(
                        ifb64_big(
                            ppxxh.xxh3_64(
                                sanity_buffer[:length],
                                seed=seed,
                                secret=custom_secret,
                            ).digest()
                        ),
                        hash,
                    )
                    self.assertEqual(
                        ifb64_big(
                            bytes.fromhex(
                                ppxxh.xxh3_64(
                                    sanity_buffer[:length],
                                    seed=seed,
                                    secret=custom_secret,
                                ).hexdigest()
                            )
                        ),
                        hash,
                    )

    # streaming oneshot
    def test_xxh3_64_withsecret_rs_intdigest_so(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                with self.subTest(
                    length=length, seed_hex=hex(seed), hash_hex=hex(hash)
                ):
                    xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                    xx.update(sanity_buffer[:length])
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb64_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    # streaming random update lengths
    def test_xxh3_64_withsecret_rs_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb64_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    # streaming random update lengths using copies of xx
    def test_xxh3_64_withsecret_rs_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=hex(hash),
                    nlist=nlist,
                ):
                    self.assertEqual(xxc.intdigest(), hash)
                    self.assertEqual(ifb64_big(xxc.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xxc.hexdigest())), hash
                    )
                    if length != 0:
                        # confirm that xxc != xx
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh3_64_withsecret_rs_intdigest_ss(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_64_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                with self.subTest(
                    length=length, seed_hex=hex(seed), hash_hex=hex(hash)
                ):
                    xx = ppxxh.xxh3_64(seed=seed, secret=custom_secret)
                    single_byte_updates(xx, sanity_buffer[:length])
                    self.assertEqual(xx.intdigest(), hash)
                    self.assertEqual(ifb64_big(xx.digest()), hash)
                    self.assertEqual(
                        ifb64_big(bytes.fromhex(xx.hexdigest())), hash
                    )

    def test_xxh3_128_no_updates(self):
        for length, seed, hash in testdata_xxh3_128:
            with self.subTest(
                length=length,
                seed_hex=hex(seed),
                hash_hex=(hex(hash[0]), hex(hash[1])),
            ):
                self.assertEqual(
                    ppxxh.xxh3_128(
                        sanity_buffer[:length], seed=seed
                    ).intdigest(),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)
                self.assertEqual(
                    ppxxh.xxh3_128(
                        sanity_buffer[:length], seed=seed
                    ).intdigest2(),
                    hash,
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(
                        ppxxh.xxh3_128(
                            sanity_buffer[:length], seed=seed
                        ).digest()
                    ),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(
                        bytes.fromhex(
                            ppxxh.xxh3_128(
                                sanity_buffer[:length], seed=seed
                            ).hexdigest()
                        )
                    ),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)

    # streaming oneshot
    def test_xxh3_128_intdigest_so(self):
        for length, seed, hash in testdata_xxh3_128:
            with self.subTest(
                length=length,
                seed_hex=hex(seed),
                hash_hex=(hex(hash[0]), hex(hash[1])),
            ):
                xx = ppxxh.xxh3_128(seed=seed)
                xx.update(sanity_buffer[:length])
                self.assertEqual(
                    xx.intdigest(), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    xx.intdigest2(), hash
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(bytes.fromhex(xx.hexdigest())),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)

    # streaming random update lengths
    def test_xxh3_128_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128:
                xx = ppxxh.xxh3_128(seed=seed)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                    nlist=nlist,
                ):
                    self.assertEqual(
                        xx.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xx.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xx.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)

    # streaming random update lengths using copies of xx
    def test_xxh3_128_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128:
                xx = ppxxh.xxh3_128(seed=seed)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                    nlist=nlist,
                ):
                    self.assertEqual(
                        xxc.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xxc.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xxc.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xxc.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)
                    if length != 0:
                        # confirm that xxc != xx
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh3_128_intdigest_ss(self):
        for length, seed, hash in testdata_xxh3_128:
            with self.subTest(
                length=length,
                seed_hex=hex(seed),
                hash_hex=(hex(hash[0]), hex(hash[1])),
            ):
                xx = ppxxh.xxh3_128(seed=seed)
                single_byte_updates(xx, sanity_buffer[:length])
                self.assertEqual(
                    xx.intdigest(), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    xx.intdigest2(), hash
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(bytes.fromhex(xx.hexdigest())),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)

    def test_xxh3_128_withsecret_no_updates(self):
        for length, seed, hash in testdata_xxh3_128_withsecret:
            with self.subTest(
                length=length,
                seed_hex=hex(seed),
                hash_hex=(hex(hash[0]), hex(hash[1])),
            ):
                self.assertEqual(
                    ppxxh.xxh3_128(
                        sanity_buffer[:length], seed=seed, secret=custom_secret
                    ).intdigest(),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)
                self.assertEqual(
                    ppxxh.xxh3_128(
                        sanity_buffer[:length], seed=seed, secret=custom_secret
                    ).intdigest2(),
                    hash,
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(
                        ppxxh.xxh3_128(
                            sanity_buffer[:length],
                            seed=seed,
                            secret=custom_secret,
                        ).digest()
                    ),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(
                        bytes.fromhex(
                            ppxxh.xxh3_128(
                                sanity_buffer[:length],
                                seed=seed,
                                secret=custom_secret,
                            ).hexdigest()
                        )
                    ),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)

    # streaming oneshot
    def test_xxh3_128_withsecret_intdigest_so(self):
        for length, seed, hash in testdata_xxh3_128_withsecret:
            with self.subTest(
                length=length,
                seed_hex=hex(seed),
                hash_hex=(hex(hash[0]), hex(hash[1])),
            ):
                xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                xx.update(sanity_buffer[:length])
                self.assertEqual(
                    xx.intdigest(), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    xx.intdigest2(), hash
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(bytes.fromhex(xx.hexdigest())),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)

    # streaming random update lengths
    def test_xxh3_128_withsecret_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128_withsecret:
                xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                    nlist=nlist,
                ):
                    self.assertEqual(
                        xx.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xx.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xx.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)

    # streaming random update lengths using copies of xx
    def test_xxh3_128_withsecret_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128_withsecret:
                xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                    nlist=nlist,
                ):
                    self.assertEqual(
                        xxc.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xxc.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xxc.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xxc.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)
                    if length != 0:
                        # confirm that xxc != xx
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh3_128_withsecret_intdigest_ss(self):
        for length, seed, hash in testdata_xxh3_128_withsecret:
            with self.subTest(
                length=length,
                seed_hex=hex(seed),
                hash_hex=(hex(hash[0]), hex(hash[1])),
            ):
                xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                single_byte_updates(xx, sanity_buffer[:length])
                self.assertEqual(
                    xx.intdigest(), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    xx.intdigest2(), hash
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                )  # hash is (low64, high64)
                self.assertEqual(
                    ifb128_big(bytes.fromhex(xx.hexdigest())),
                    hash[0] + (hash[1] << 64),
                )  # hash is (low64, high64)

    # identical to test_xxh3_128_withsecret_no_updates, but a non-zero
    # random seed is provided.  This seed should have no effect when
    # a non-None secret is applied.
    def test_xxh3_128_withsecret_rs_no_updates(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                ):
                    self.assertEqual(
                        ppxxh.xxh3_128(
                            sanity_buffer[:length],
                            seed=seed,
                            secret=custom_secret,
                        ).intdigest(),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ppxxh.xxh3_128(
                            sanity_buffer[:length],
                            seed=seed,
                            secret=custom_secret,
                        ).intdigest2(),
                        hash,
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(
                            ppxxh.xxh3_128(
                                sanity_buffer[:length],
                                seed=seed,
                                secret=custom_secret,
                            ).digest()
                        ),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(
                            bytes.fromhex(
                                ppxxh.xxh3_128(
                                    sanity_buffer[:length],
                                    seed=seed,
                                    secret=custom_secret,
                                ).hexdigest()
                            )
                        ),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)

    # streaming oneshot
    def test_xxh3_128_withsecret_rs_intdigest_so(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                ):
                    xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                    xx.update(sanity_buffer[:length])
                    self.assertEqual(
                        xx.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xx.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xx.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)

    # streaming random update lengths
    def test_xxh3_128_withsecret_rs_intdigest_sr(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                nlist = random_updates(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                    nlist=nlist,
                ):
                    self.assertEqual(
                        xx.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xx.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xx.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)

    # streaming random update lengths using copies of xx
    def test_xxh3_128_withsecret_rs_intdigest_src(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                xxc, nlist = random_updates_c(xx, sanity_buffer[:length])
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                    nlist=nlist,
                ):
                    self.assertEqual(
                        xxc.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xxc.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xxc.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xxc.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)
                    if length != 0:
                        # confirm that xxc != xx
                        self.assertNotEqual(
                            xx._total_length, xxc._total_length
                        )

    # streaming single byte updates
    def test_xxh3_128_withsecret_rs_intdigest_ss(self):
        for r in range(rand_count):
            for length, seed, hash in testdata_xxh3_128_withsecret:
                seed = random.randint(1, 0xFFFFFFFF)
                with self.subTest(
                    length=length,
                    seed_hex=hex(seed),
                    hash_hex=(hex(hash[0]), hex(hash[1])),
                ):
                    xx = ppxxh.xxh3_128(seed=seed, secret=custom_secret)
                    single_byte_updates(xx, sanity_buffer[:length])
                    self.assertEqual(
                        xx.intdigest(), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        xx.intdigest2(), hash
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(xx.digest()), hash[0] + (hash[1] << 64)
                    )  # hash is (low64, high64)
                    self.assertEqual(
                        ifb128_big(bytes.fromhex(xx.hexdigest())),
                        hash[0] + (hash[1] << 64),
                    )  # hash is (low64, high64)

    def test_xxh3_generate_secret(self):
        sample_index = (0, 62, 131, 191)
        for length, secret_samples in testdata_xxh3_generate_secret:
            with self.subTest(
                length=length,
                secret_samples=[hex(secret_samples[i]) for i in range(4)],
            ):
                gs = ppxxh.generate_secret(sanity_buffer[:length])
                self.assertEqual([gs[i] for i in sample_index], secret_samples)


# name, digest_size (bytes), block_size (bytes), class
# Note that block_size for xxh3_* is actually variable
# depending on the size of secret.  The values reported
# by xxh3_*.block_size and shown below are for the default
# secret size, which will be correct when the defaul secret is used.
info = (
    ("xxh32", 4, 16, ppxxh.xxh32),
    ("xxh64", 8, 32, ppxxh.xxh64),
    ("xxh3_64", 8, 1024, ppxxh.xxh3_64),
    ("xxh3_128", 16, 1024, ppxxh.xxh3_128),
)


class Test_hashlib_compatibility(unittest.TestCase):
    # hashlib has the following attributes:
    #  algorithms_guaranteed
    #  algorithms_available
    # and the following method:
    #  new(name[, data])
    #
    # hash objects returned by the hashlib constructors have the
    # following attributes:
    #  digest_size (size of object returned by digest())
    #  block_size
    #  name (lowercase, suitable for use as parameter to new())
    # and the following methods, all of which are well used
    # in Test_sanity_checks:
    #  update(data)
    #  digest()
    #  hexdigest()
    #  copy()
    def test_hashlib_compat(self):
        self.assertEqual(len(info), len(ppxxh.algorithms_guaranteed))
        self.assertEqual(len(info), len(ppxxh.algorithms_available))
        for name, digest_size, block_size, cls in info:
            with self.subTest(name=name):
                self.assertTrue(name in ppxxh.algorithms_guaranteed)
                self.assertTrue(name in ppxxh.algorithms_available)
                self.assertEqual(ppxxh.new(name).name, name)
                self.assertEqual(cls().name, name)
                self.assertEqual(cls().digest_size, digest_size)
                self.assertEqual(len(cls().digest()), digest_size)
                self.assertEqual(cls().block_size, block_size)


classes = [ppxxh.xxh32, ppxxh.xxh64, ppxxh.xxh3_64, ppxxh.xxh3_128]


# Verify that errors are raised when expected.
class Test_errortests(unittest.TestCase):
    def test_error_usedforsecurity(self):
        # None of these hash functions should be used for security
        for name, digest_size, block_size, cls in info:
            with self.subTest(name=name):
                self.assertRaises(
                    ValueError, ppxxh.new, name, usedforsecurity=True
                )

    def test_error_negative_seed(self):
        # seed must be a non-negative integer
        for name, __, __, cls in info:
            with self.subTest(name=name):
                self.assertRaises(ValueError, cls, seed=-1)

    def test_error_oversized_seed(self):
        # seed must not be larger than 64 bits (32 bits for xxh32)
        for name, __, __, cls in info:
            if name == "xxh32":
                maxseed = 0xFFFFFFFF
            else:
                maxseed = 0xFFFFFFFFFFFFFFFF
            with self.subTest(name=name, maxseed=hex(maxseed)):
                cls(seed=maxseed)  # should not raise an error
                self.assertRaises(ValueError, cls, seed=maxseed + 1)

    def test_error_invalid_name(self):
        # name must in ppxxh.algorithms_available
        self.assertRaises(ValueError, ppxxh.new, "not_a_hash_name")

    def test_error_64_small_secret(self):
        # len(secret) must be at least ppxxh.xxh3_64._SECRET_SIZE_MIN
        self.assertRaises(
            ValueError,
            ppxxh.xxh3_64,
            sanity_buffer,
            secret=custom_secret[: ppxxh.xxh3_64._SECRET_SIZE_MIN - 1],
        )

    def test_error_128_small_secret(self):
        # len(secret) must be at least ppxxh.xxh3_128._SECRET_SIZE_MIN
        self.assertRaises(
            ValueError,
            ppxxh.xxh3_128,
            sanity_buffer,
            secret=custom_secret[: ppxxh.xxh3_128._SECRET_SIZE_MIN - 1],
        )

    def test_error_classes_seed_not_positional(self):
        # if seed is provided, it must be given as a keyword argument,
        # not as a positional argument
        for cls in classes:
            with self.subTest(name=cls.name):
                self.assertRaises(TypeError, cls, sanity_buffer, 0)


if __name__ == "__main__":
    # test docstring examples in the hash classes
    for c in [ppxxh.xxh32, ppxxh.xxh64, ppxxh.xxh3_64, ppxxh.xxh3_128]:
        doctest.run_docstring_examples(c, globals())
    # perform the unittests
    unittest.main()
