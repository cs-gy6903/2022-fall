#!/usr/bin/env python3
import functools
import secrets
import sys
import typing

import more_itertools
import simple_bson


def xor(*args: typing.Union[bytes, typing.Iterable[bytes]]) -> bytes:
    """
    Copy from https://github.com/cs-gy6903/resources#xor-iterators

    >>> xor(b'hello', b'world').hex()
    '1f0a1e000b'
    >>> xor(b'hello', b'world', b'hello') # note it has >2 parameters
    b'world'
    >>> xor(xor(b'hello', b'world'), b'hello') # equivalent to above but longer :D
    b'world'

    >>> xor(b'hello', [b'world']).hex()
    '1f0a1e000b'

    >>> def g(i: bytes):
    ...     while True:
    ...         yield i

    >>> xor(b'hello', g(b'world')).hex()
    '1f0a1e000b'
    >>> xor(b'hellothere', b'worldthere', g(b'hello'))
    b'worldhello'
    """
    return bytes(
        functools.reduce(lambda a, b: a ^ b, i)
        for i in zip(
            *[more_itertools.flatten(more_itertools.collapse(i)) for i in args]
        )
    )


def example(data: bytes) -> bytes:
    """
    Convert utf-8 encoded bytes to uppercase and return modified utf-8 encoded bytes

    >>> example(b'hello')
    b'HELLO'
    >>> example(b'hello').decode()
    'HELLO'
    >>> example('привіт'.encode())
    b'\xd0\x9f\xd0\xa0\xd0\x98\xd0\x92\xd0\x86\xd0\xa2'
    >>> example('привіт'.encode()).decode()
    'ПРИВІТ'
    """
    return data.decode("utf-8").upper().encode("utf-8")


def problem1(n: int) -> typing.List[int]:
    """
    Generate a list of `n` random numbers in range [0,256)

    Please use cryptographically-secure entropy source
    see secrets module in python

    # not doctest as output is random
    > problem1(5)
    [140, 7, 218, 46, 104]
    """
    return [secrets.randbelow(2**8) for _ in range(n)]


def problem2(n: int) -> bytes:
    """
    Generate random `n` bytes

    Please use cryptographically-secure entropy source
    see secrets module in python

    # not doctest as output is random
    > problem2(5)
    b'\x18s\x0b8B'
    """
    return secrets.token_bytes(n)


def problem3(data: bytes) -> bytes:
    """
    Manipulate given data bytes where each byte is multiplied * 2 % 256

    In other words, input is a collection of bytes
    You should multiply each of those bytes by 2 mod 256
    (not to overflow)
    and then return resulting bytes

    >>> problem3(b'hello')
    b'\xd0\xca\xd8\xd8\xde'
    """
    return bytes((i * 2) % (2**8) for i in data)


def problem4(data: typing.List[bytes]) -> bytes:
    """
    XOR all given bytes and output resulting XORed bytes

    All inputs will be of same length

    >>> problem4([
    ...     b'hello',
    ...     b'world',
    ...     b'hello',
    ... ])
    b'world'
    """
    return xor(*data)


def problem5(data: str) -> bytes:
    """
    Decode given hex-encoded string to bytes

    >>> problem5('d0cad8d8de')
    b'\xd0\xca\xd8\xd8\xde'
    """
    return bytes.fromhex(data)


def problem6(data: bytes) -> str:
    """
    Encode given bytes to hex-encoded string

    >>> problem6(b'hello')
    '68656c6c6f'
    """
    return data.hex()


if __name__ == "__main__":
    inputs = simple_bson.loads(sys.stdin.buffer.read())
    solutions = {k: globals()[k](**v) for k, v in inputs.items()}
    sys.stdout.buffer.write(simple_bson.dumps(solutions))
