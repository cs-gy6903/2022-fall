#!/usr/env/bin python3
# -*- coding: utf-8 -*-

import functools
import simple_bson
import sys


BLOCK_SIZE_BYTES = 16
KEY_SIZE_BYTES = 16


def problem1(data: bytes) -> bytes:
    """
    Implement PKCS#7 padding.

    Parameters
    ----------
    data : bytes

    Returns
    -------
    bytes
        Padded input data

    Notes
    -----
    The basic idea behind PKCS#7 is to pad a plaintext to the closest length divisible
    by the cipher's block size, and to pad using byte values equal to the length of the
    padding material. For instance, 3 bytes of padding would be `\x03\x03\x03`. An
    important case to note is when the plaintext length is divisible by the block size.
    In this case, an entire block of padding is appended, with each byte equal to the
    block size (i.e. `\0x10` in hex for AES with its 16-byte block size).

    Some references:

    https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    https://www.rfc-editor.org/rfc/rfc5652#section-6.3

    You MUST implement this yourself. Submissions using a library to compute the padding
    will receive 0 points.

    Examples
    --------
    NOTE: byte literals' backslashes are escaped in the docstring.

    >>> problem1(b"\\x01").hex()
    '010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f'
    >>> problem1(b"\\x01" * 13).hex()
    '01010101010101010101010101030303'
    >>> problem1(b"\\x01" * 16).hex()
    '0101010101010101010101010101010110101010101010101010101010101010'
    """


def problem2(data: bytes) -> bytes:
    """
    Strip PKCS#7 padding.

    Parameters
    ----------
    data : bytes

    Returns
    -------
    bytes
        Original data stripped of its padding

    Notes
    -----
    The key concept to note here is that the last byte of the input will **always** be
    equal to the length of the padding suffix you need to strip.

    You MUST implement this yourself. Submissions using a library to strip the padding
    will receive 0 points.

    Examples
    --------
    >>> problem2(bytes.fromhex('010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f')).hex()
    '01'
    >>> problem2(bytes.fromhex('01010101010101010101010101030303')).hex()
    '01010101010101010101010101'
    >>> problem2(bytes.fromhex('0101010101010101010101010101010110101010101010101010101010101010')).hex()
    '01010101010101010101010101010101'
    """


def problem3(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt a plaintext using AES ECB.

    Parameters
    ----------
    plaintext : bytes
    key : bytes

    Returns
    -------
    bytes
        ECB-encrypted ciphertext

    Notes
    -----
    ECB mode is essentially just using the raw cipher. It does not require an IV
    ("initialization vector"). A plaintext is broken up into 16-byte blocks, and each
    block is passed into the AES encryption cipher. Note that the same key is used for
    encrypting each block. What if two blocks have identical values? Given that block
    ciphers are PRPs, and are thus _deterministic_, what are the confidentiality
    implications of this scenario? You don't need to submit answers to these questions,
    but pondering them may convince you that using a raw block cipher can lead to some
    fowl surprises:

                     .88888888:.
                    88888888.88888.
                  .8888888888888888.
                  888888888888888888
                  88' _`88'_  `88888
                  88 88 88 88  88888
                  88_88_::_88_:88888
                  88:::,::,:::::8888
                  88`:::::::::'`8888
                 .88  `::::'    8:88.
                8888            `8:888.
              .8888'             `888888.
             .8888:..  .::.  ...:'8888888:.
            .8888.'     :'     `'::`88:88888
           .8888        '         `.888:8888.
          888:8         .           888:88888
        .888:88        .:           888:88888:
        8888888.       ::           88:888888
        `.::.888.      ::          .88888888
       .::::::.888.    ::         :::`8888'.:.
      ::::::::::.888   '         .::::::::::::
      ::::::::::::.8    '      .:8::::::::::::.
     .::::::::::::::.        .:888:::::::::::::
     :::::::::::::::88:.__..:88888:::::::::::'
      `'.:::::::::::88888888888.88:::::::::'
            `':::_:' -- '' -'-' `':_::::'`

    ------------------------------------------------
    source: https://asciiart.website/index.php?art=logos%20and%20insignias/linux
    explanation: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)

    The input `plaintext`'s length may be indivisible by the AES block size (16 bytes),
    so you MUST PKCS#7-pad plaintext before encrypting.

    You MAY use a library's implementation of AES in ECB mode for this problem, but you
    MUST loop over the input plaintext block-by-block to encrypt. Submissions encrypting
    the entire plaintext in one shot will receive 0 points.

    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │  plaintext[0]  │  │  plaintext[1]  │  ...  │  plaintext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘
             │                   │                        │
             │                   │                        │
             ▼                   ▼                        ▼
         ┌───────┐           ┌───────┐                ┌───────┐
         │       │           │       │                │       │
         │  AES  │           │  AES  │                │  AES  │
    K ──▶│Encrypt│      K ──▶│Encrypt│           K ──▶│Encrypt│
         │ Block │           │ Block │                │ Block │
         │       │           │       │                │       │
         └───────┘           └───────┘                └───────┘
             │                   │                        │
             │                   │                        │
             ▼                   ▼                        ▼
    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │ ciphertext[0]  │  │ ciphertext[1]  │  ...  │ ciphertext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘

    Examples
    --------
    NOTE: byte literals' backslashes are escaped in the docstring.

    >>> problem3(b"\\x00" * 32, b"\\x00" * 16).hex()
    '66e94bd4ef8a2c3b884cfa59ca342b2e66e94bd4ef8a2c3b884cfa59ca342b2e0143db63ee66b0cdff9f69917680151e'
    """


def problem4(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt a ciphertext using AES ECB.

    Parameters
    ----------
    ciphertext : bytes
    key : bytes

    Returns
    -------
    bytes
        plaintext

    Notes
    -----
    ECB decryption looks very similar to encryption; it just uses the decrypt PRP of
    the AES cipher.

    You MUST strip PKCS#7 padding before returning the plaintext.

    You MAY use a library's implementation of AES in ECB mode for this problem, but you
    MUST loop over the input ciphertext block-by-block to decrypt. Submissions
    decrypting the entire ciphertext in one shot will receive 0 points.

    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │ ciphertext[0]  │  │ ciphertext[1]  │  ...  │ ciphertext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘
             │                   │                        │
             │                   │                        │
             ▼                   ▼                        ▼
         ┌───────┐           ┌───────┐                ┌───────┐
         │       │           │       │                │       │
         │  AES  │           │  AES  │                │  AES  │
    K ──▶│Decrypt│      K ──▶│Decrypt│           K ──▶│Decrypt│
         │ Block │           │ Block │                │ Block │
         │       │           │       │                │       │
         └───────┘           └───────┘                └───────┘
             │                   │                        │
             │                   │                        │
             ▼                   ▼                        ▼
    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │  plaintext[0]  │  │  plaintext[1]  │  ...  │  plaintext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘

    Examples
    --------
    NOTE: byte literals' backslashes are escaped in the docstring.

    >>> problem4(bytes.fromhex('66e94bd4ef8a2c3b884cfa59ca342b2e66e94bd4ef8a2c3b884cfa59ca342b2e0143db63ee66b0cdff9f69917680151e'), b'\\x00' * 16).hex()
    '0000000000000000000000000000000000000000000000000000000000000000'
    """


def xor(*args: bytes) -> bytes:
    """
    Defined here: https://github.com/cs-gy6903/resources#xor-bytes
    """
    return bytes(functools.reduce(lambda a, b: a ^ b, i) for i in zip(*args))


def problem5(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt a plaintext using AES CBC.

    Parameters
    ----------
    plaintext : bytes
    key : bytes
    iv : bytes

    Returns
    -------
    bytes
        CBC-encrypted ciphertext

    Notes
    -----
    Below is a diagram of CBC mode. To make ciphertexts indistinguishable under common
    plaintexts, CBC XORs the previous block's ciphertext (or, the `iv` in the case of
    the 0th block) with the current block's plaintext before encrypting under AES. This
    makes each block's ciphertext dependent on the prior block's ciphertext (or `iv`),
    providing better confidentiality than ECB, but making parallelization impossible.

    As with raw ECB, you need to PKCS#7-pad the plaintext before encrypting.

    You MUST use ECB mode of the AES cipher to implement this. Solutions using
    library-provided CBC mode will receive 0 points.

    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │  plaintext[0]  │  │  plaintext[1]  │  ...  │  plaintext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘
             │                   │                        │
             ▼                   ▼                        ▼
       IV   .─.                 .─.                      .─.
     ─────▶( X )    ┌─────────▶( X )       ┌───────────▶( X )
            `─'     │           `─'        │             `─'
             │      │            │         │              │
             ▼      │            ▼         │              ▼
         ┌───────┐  │        ┌───────┐     │          ┌───────┐
         │       │  │        │       │     │          │       │
         │  AES  │  │        │  AES  │                │  AES  │
    K ──▶│Encrypt│  │   K ──▶│Encrypt│    ...    K ──▶│Encrypt│
         │ Block │  │        │ Block │                │ Block │
         │       │  │        │       │     │          │       │
         └───────┘  │        └───────┘     │          └───────┘
             │      │            │         │              │
             ├──────┘            ├─────────┘              │
             │                   │                        │
             ▼                   ▼                        ▼
    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │ ciphertext[0]  │  │ ciphertext[1]  │  ...  │ ciphertext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘

    Examples
    --------
    NOTE: byte literals' backslashes are escaped in the docstring.

    >>> problem5(b"\\x00" * 32, b"\\x00" * 16, b"\\x00" * 16).hex()
    '66e94bd4ef8a2c3b884cfa59ca342b2ef795bd4a52e29ed713d313fa20e98dbc5c047616756fdc1c32e0df6e8c59bb2a'
    """


def problem6(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt a ciphertext using AES CBC.

    Parameters
    ----------
    ciphertext : bytes
    key : bytes
    iv : bytes

    Returns
    -------
    bytes
        plaintext

    Notes
    -----
    CBC decryption is similar to encryption, except the IV/last block is XOR'd with the
    current block _after_ the input block has been passed through the cipher.

    As with raw ECB, you MUST strip PKCS#7 padding before returning the plaintext.

    You MUST use ECB mode of the AES cipher to implement this. Solutions using
    library-provided CBC mode will receive 0 points.

    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │ ciphertext[0]  │  │ ciphertext[1]  │  ...  │ ciphertext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘
             │                   │                        │
             ├──────┐            ├─────────┐              │
             │      │            │         │              │
             ▼      │            ▼         │              ▼
         ┌───────┐  │        ┌───────┐     │          ┌───────┐
         │       │  │        │       │     │          │       │
         │  AES  │  │        │  AES  │                │  AES  │
    K ──▶│Decrypt│  │   K ──▶│Decrypt│    ...    K ──▶│Decrypt│
         │ Block │  │        │ Block │                │ Block │
         │       │  │        │       │     │          │       │
         └───────┘  │        └───────┘     │          └───────┘
             │      │            │         │              │
             ▼      │            ▼         │              ▼
       IV   .─.     │           .─.        │             .─.
     ─────▶( X )    └─────────▶( X )       └───────────▶( X )
            `─'                 `─'                      `─'
             │                   │                        │
             ▼                   ▼                        ▼
    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │  plaintext[0]  │  │  plaintext[1]  │  ...  │  plaintext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘

    Examples
    --------
    NOTE: byte literals' backslashes are escaped in the docstring.

    >>> problem6(bytes.fromhex('66e94bd4ef8a2c3b884cfa59ca342b2ef795bd4a52e29ed713d313fa20e98dbc5c047616756fdc1c32e0df6e8c59bb2a'), b"\\x00" * 16, b"\\x00" * 16).hex()
    '0000000000000000000000000000000000000000000000000000000000000000'
    """


def problem7(iv: bytes) -> bytes:
    """
    Increment counter portion of input `iv`.

    Parameters
    ----------
    iv : bytes

    Returns
    -------
    bytes
        Incremented iv

    Notes
    -----
    The input `iv` will be the size of an AES block (16 bytes) with the first 8 bytes
    representing a nonce and the next 8 bytes representing a counter (which may be any
    value that fits into 8 bytes). You'll need to parse the counter's bytes as an
    unsigned integer, increment it, and reconstruct the new IV by appending the
    incremented counter to the nonce before returning.

    The counter portion of the IV is subject to overflow. Your implementation MUST
    account for this. If the counter reaches its maximum value, the next increment needs
    to yield 0.

    You MUST implement this logic yourself. Solutions using a library to increment will
    receive 0 points.

    Examples
    --------
    >>> problem7(bytes([x for x in range(1, 9)]) + b"\\x00" * 8).hex()
    '01020304050607080000000000000001'
    >>> problem7(bytes([x for x in range(1, 9)]) + b"\\xff" * 8).hex()
    '01020304050607080000000000000000'
    """


def problem8(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt a plaintext using AES CTR.

    Parameters
    ----------
    plaintext : bytes
    key : bytes
    iv : bytes

    Returns
    -------
    bytes
        CTR-encrypted ciphertext

    Notes
    -----
    As the diagram below shows, the plaintext is never passed through the AES cipher.
    Instead, the IV and its subsequently incremented values are encrypted under AES to
    generate a "key stream" that is then XOR'd with plaintext blocks to yield a
    ciphertext. In this way, AES CTR can be thought of (and even implemented) as a
    stream cipher.

    As with CBC and raw ECB, you need to PKCS#7-pad plaintext when encrypting and strip
    same before returning when decrypting. Note that while padding is not generally
    required when AES CTR is used as a stream cipher, we do require it here. You're free
    to implement AES CTR as either a stream cipher or block cipher, but the grader will
    expect plaintext inputs to be padded to the AES block size.

    You MUST use ECB mode of the AES cipher to implement this. Solutions using
    library-provided CTR mode will receive 0 points.

                      Nonce     Counter                     Nonce     Counter
                      d9e6...  ...34020                     d9e6...  ...34021
                      ┌────────────────┐                    ┌────────────────┐   ...
                      └───────┼────────┘                    └───────┼────────┘
                              │                                     │
                      ┌───────▼────────┐                    ┌───────▼────────┐
                      │                │                    │                │
                      │   AES Encrypt  │                    │   AES Encrypt  │
               K─────►│                │             K─────►│                │   ...
                      │     Block      │                    │     Block      │
                      │                │                    │                │
                      │                │                    │                │
                      └───────┬────────┘                    └───────┬────────┘
       plaintext[0]           │             plaintext[1]            │
    ┌────────────────┐        │          ┌────────────────┐         │
    └────────────────┴──────►XOR         └────────────────┴───────►XOR
                              │                                     │
                      ┌───────▼────────┐                    ┌───────▼────────┐   ...
                      └────────────────┘                    └────────────────┘
                        ciphertext[0]                          ciphertext[1]

    Examples
    --------
    >>> problem8(b"\\x00" * 32, b"\\x00" * 16, b"\\x00" * 16).hex()
    '66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a1398cade70a6b382e338d2a961a2ee68'
    """


def problem9(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt a ciphertext using AES CTR.

    Parameters
    ----------
    ciphertext : bytes
    key : bytes
    iv : bytes

    Returns
    -------
    bytes
        plaintext

    Notes
    -----
    In the diagram below, note that **AES encryption** is used to generate the
    decryption key stream.

    You MUST use ECB mode of the AES cipher to implement this. Solutions using
    library-provided CTR mode will receive 0 points.

                      Nonce     Counter                     Nonce     Counter
                      d9e6...  ...34020                     d9e6...  ...34021
                      ┌────────────────┐                    ┌────────────────┐   ...
                      └───────┼────────┘                    └───────┼────────┘
                              │                                     │
                      ┌───────▼────────┐                    ┌───────▼────────┐
                      │                │                    │                │
                      │   AES Encrypt  │                    │   AES Encrypt  │
               K─────►│                │             K─────►│                │   ...
                      │     Block      │                    │     Block      │
                      │                │                    │                │
                      │                │                    │                │
                      └───────┬────────┘                    └───────┬────────┘
      ciphertext[0]           │            ciphertext[1]            │
    ┌────────────────┐        │          ┌────────────────┐         │
    └────────────────┴──────►XOR         └────────────────┴───────►XOR
                              │                                     │
                      ┌───────▼────────┐                    ┌───────▼────────┐   ...
                      └────────────────┘                    └────────────────┘
                         plaintext[0]                           plaintext[1]

    Examples
    --------
    >>> problem9(bytes.fromhex('66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a1398cade70a6b382e338d2a961a2ee68'), b"\\x00" * 16, b"\\x00" * 16).hex()
    '0000000000000000000000000000000000000000000000000000000000000000'
    """


if __name__ == "__main__":
    inputs = simple_bson.loads(sys.stdin.buffer.read())
    solutions = {k: globals()[k](**v) for k, v in inputs.items()}
    sys.stdout.buffer.write(simple_bson.dumps(solutions))
