import typing


def problem1(data: bytes) -> bytes:
    """
    Compute SHA1 hash of data

    >>> problem1(b'hello').hex()
    'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    """


def problem2(data: bytes) -> bytes:
    """
    Compute SHA256 hash of data

    >>> problem2(b'hello').hex()
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """


class SHAttered(typing.TypedDict):
    """
    Hashes of proof PDFs from https://SHAttered.io/

    This clearly illustrates SHA1 should no longer be used
    for cryptography-sensesitive applications as SHA1 collissions
    have been found. Both blue and red PDFs have same SHA1 hash.

    Note that SHA256 is still safe. The same PDFs produce
    different SHA256 hashes as expected.
    """

    blue_pdf_sha1: bytes
    blue_pdf_sha256: bytes

    red_pdf_sha1: bytes
    red_pdf_sha256: bytes


def problem3() -> SHAttered:
    """
    Provide SHA1 and SHA256 hashes of https://SHAttered.io/ PDFs

    Note this function accepts no input. You can compute the hashes either:

    * hardcode hash values as PDFs are known hashes
    * compute hash by downloading the pdfs (e.g. with requests library)

    >>> hashes = problem3()
    >>> hashes['blue_pdf_sha1'] == hashes['red_pdf_sha1']
    True
    >>> hashes['blue_pdf_sha256'] == hashes['red_pdf_sha256']
    False
    """


def sha256_padding(length: int) -> bytes:
    """
    Get the padding for SHA256

    SHA256 works on consistent length blocks.
    If the data is not of the same block, it needs to padded
    so that SHA256 can be computed.

    The padding scheme is as follows:

    * add single 1-bit to input
    * add X variable number of 0-bits
    * add 64 bits (8 bytes) big-endian original message length

    The X variable number of bits is adjusted to make the padded
    message be 64 bytes long (SHA256 block size).
    """
    # for the mod its +8, not +9 (0x80 byte and 8 length bytes)
    # since otherwise 64 % 64 = 0 which means we subtract 0
    # and would pad with 64 bytes even though 0 are necessary
    zero_bytes = 64 - 1 - (length + 8) % 64
    return b"\x80" + b"\x00" * zero_bytes + (length * 8).to_bytes(8, "big")


def problem4(length: int, hash: bytes, suffix: bytes) -> bytes:
    """
    Apply length extension attack to SHA256 hash

    After above SHAttered you might think SHA256 is the perfect hash function.
    Lets break it thought with length extension attack!
    Length extension attack is applicable to any hash function
    using Merkle–Damgård construction.
    https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

    Other hash functions which use different construction methods
    are not vulnerable. For example:

    * SHA3 is not vulnerable as it uses Sponge construction
      https://en.wikipedia.org/wiki/Sponge_function
    * BLAKE-family of hash functions is not vulnerable as it uses HAIFA construction
      https://en.wikipedia.org/wiki/HAIFA_construction

    Some background:

    * SHA256 pads messages in order to make them fit SHA256 block size
    * padding scheme is public (see above for implementation)
    * SHA256 has internal state. By "hashing" things, SHA256
      internally "scrambles" its state.
    * To hash longer inputs, SHA256 iterates over input by
      64 byte blocks and for each iteration keeps "scrambling" its state.
    * The resulting SHA256 hash is simply its state serialized to bytes
    * Note that last block does not do anything special

    To visualize that:

       ┌─────────────────────────────────────┬─────────────────┐
       │                input                │     padding     │
       ├───────────────────────────┬─────────┴─────────────────┤
       │           block           │           block           │
                     │                           │
                     ▼                           ▼
     initial   ┌──────────┐                ┌──────────┐
      state    │  SHA256  │                │  SHA256  │
    ──────────▶│  block   │        ┌──────▶│  block   │
               └──────────┘        │       └──────────┘
                     │   updated   │             │
                     │    state    │             ▼
                     └─────────────┘       ┌──────────┐
                                           │  SHA256  │
                                           │ hash of  │
                                           │  input   │
                                           └──────────┘

    Given last block of SHA256 does not do anything special and that the hash
    is simply the last state, we can use that to "extend" the hash.
    Lets say if we wanted now to hash new input consisting of:

    * old input
    * old input padding
    * additinal suffix

    To do that we can simply restore the SHA256 state from the given input hash
    which already contains both the original input and its padding.
    Once the state is restored, we can continue with SHA256 blocks as usual
    to hash rest of the blocks containing the new suffix.

       ┌─────────────────────────────────────┬─────────────────┬────────┬──────────────────┐
       │                input                │     padding     │ suffix │  suffix padding  │
       ├───────────────────────────┬─────────┴─────────────────┼────────┴──────────────────┤
       │           block           │           block           │           block           │
                     │                           │                           │
                     ▼                           ▼                           ▼
     initial   ┌──────────┐                ┌──────────┐                ┌──────────┐
      state    │  SHA256  │                │  SHA256  │                │  SHA256  │
    ──────────▶│  block   │        ┌──────▶│  block   │        ┌──────▶│  block   │
               └──────────┘        │       └──────────┘        │       └──────────┘
                     │   updated   │             │             │             │
                     │    state    │             ▼     restore │             │
                     └─────────────┘       ┌──────────┐ state  │             ▼
                                           │  SHA256  │        │       ┌──────────┐
                                           │ hash of  │ ───────┘       │  SHA256  │
                                           │  input   │                │ hash of  │
                                           └──────────┘                │  input   │
                                                                       │ +padding │
                                                                       │ +suffix  │
                                                                       └──────────┘

    To implement this in Python, the SHA256 implementation needs to allow
    to restore the internal SHA256 state. Python stdlib hashlib does not allow
    to do that. You can use https://pypi.org/project/sha256/ instead.
    It is preinstalled in Gradescope.

    > import sha256
    > h = sha256.sha256()
    > h.state = (b'oldhash', old_length + padding_length)

    This library does not have much documentation or examples in the README,
    however after the state is restored, it is very similar to native hashlib
    in its usage. Also feel free to check out its source code in GitHub.

    The input you will receive will be:

    * old input length (you do not actually need full input value)
    * SHA256 hash of the input
    * new suffix to extend the hash with

    >>> original_data = b'hello'
    >>> original_data_padded = original_data + sha256_padding(len(original_data))
    >>> extended_data = original_data_padded + b'world'

    >>> reference_hash = problem2(extended_data)
    >>> reference_hash.hex()
    '383b468b32a3705237b55d28a5440c77bda8b3b356cf8c6cfeeb69f305712df3'

    >>> extended_hash = problem4(len(original_data), problem2(original_data), b'world')
    >>> extended_hash.hex()
    '383b468b32a3705237b55d28a5440c77bda8b3b356cf8c6cfeeb69f305712df3'

    >>> reference_hash == extended_hash
    True
    """


def problem5(key: bytes, data: bytes) -> bytes:
    """
    HMAC given data with the provided key using SHA256

    >>> problem5(b'secret', b'data').hex()
    '1b2c16b75bd2a870c114153ccda5bcfca63314bc722fa160d690de133ccbb9db'
    """
