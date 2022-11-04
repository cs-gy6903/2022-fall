#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import pathlib
import sys
import typing
import urllib.parse

import certifi
import simple_bson


# hack to allow relative import for all CLI call variants:
# * python -m <module>
# * python <file>.py
sys.path.append(str(pathlib.Path(__file__).parent))


class TLSResponse(typing.TypedDict):
    """
    TLSResponse after making request to a server
    """

    data: bytes
    """
    server response application data including HTTP headers
    """

    error: str
    """
    if request is not successful, this should be the error code from Error enum
    """


def tls13_http_get(
    *,
    path: bytes,
    ip: bytes,
    port: int,
    hostname: bytes,
    ca: bytes,
) -> TLSResponse:
    """
    Make HTTP GET request to given server via TLS13 tunnel

    Parameters
    ----------
    path
        URL path where request should be made to
    ip
        Where socket connection should be made to
        Note it could be hostname
    port
        On which port socket connection should be made to
    hostname
        SNI hostname of the request
    ca
        RAW bytes of root CA cert in PEM format
        To test on public sites, you may use certifi cert bundle
        which comes with all Mozilla trust store certificates
        hence will allow to make connections to public sites

    Examples
    --------
    >>> tls13_http_get(
    ...     path='/'.encode(),
    ...     ip='google.com'.encode(),
    ...     port=443,
    ...     hostname='google.com'.encode(),
    ...     ca=pathlib.Path(certifi.where()).read_bytes(),
    ... )
    {'data': b'HTTP/1.0 301 Moved Permanently...', 'error': ''}
    >>> tls13_http_get(
    ...     path='/'.encode(),
    ...     ip='google.com'.encode(),
    ...     port=443,
    ...     hostname='haha.com'.encode(),
    ...     ca=pathlib.Path(certifi.where()).read_bytes(),
    ... )
    {'data': b'', 'error': '<error:invalid hostname>'}

    """


def scaffolding_uint8(x: int) -> bytes:
    """
    Convert given integer to uint8 bytes

    >>> pretty_hex(scaffolding_uint8(129))
    81
    """


def scaffolding_uint16(x: int) -> bytes:
    """
    Encode given integer to uint16 bytes

    >>> pretty_hex(scaffolding_uint16(129))
    00 81
    """


def scaffolding_uint24(x: int) -> bytes:
    """
    Encode given integer to uint24 bytes

    >>> pretty_hex(scaffolding_uint24(129))
    00 00 81
    """


def scaffolding_uint32(x: int) -> bytes:
    """
    Encode given integer to uint32 bytes

    >>> pretty_hex(scaffolding_uint32(129))
    00 00 00 81
    """


def scaffolding_vector_opaque(data: bytes) -> bytes:
    """
    Encode opaque value as single-dimentional array vector

    https://www.rfc-editor.org/rfc/rfc8446#section-3.4

    You are essentically implementing RFC notation:
    opaque data[n];

    >>> pretty_hex(scaffolding_vector_opaque(b'hello'))
    68 65 6c 6c 6f
    """


def scaffolding_variable_vector_opaque(
    n: int,
    data: bytes,
) -> bytes:
    """
    Encode opaque value as variable-length vector

    https://www.rfc-editor.org/rfc/rfc8446#section-3.4

    You are essentically implementing RFC notation:
    opaque data<0...length>;

    You are given:
    * n is max number of bytes of length in notation above
    * data of the vector

    Practically this simply adds the length prefix of given length to the value

    >>> pretty_hex(scaffolding_variable_vector_opaque(2, b'hello'))
    00 05 68 65 6c 6c 6f
    """


def scaffolding_variable_vector_uint16(
    n: int,
    data: list[int],
) -> bytes:
    """
    Encode uint16 values as variable-length vector

    https://www.rfc-editor.org/rfc/rfc8446#section-3.4

    You are essentically implementing RFC notation:
    uint16 data<0...length>;

    You are given:
    * n is max number of bytes of length in notation above
    * data which is a list of numbers

    >>> pretty_hex(scaffolding_variable_vector_uint16(2, [1, 2, 3]))
    00 06 00 01 00 02 00 03
    """


def scaffolding_variable_vector_opaque_items(
    n: int,
    l: int,
    data: list[bytes],
) -> bytes:
    """
    Encode byte values as variable-length vector

    https://www.rfc-editor.org/rfc/rfc8446#section-3.4

    You are essentically implementing RFC notation:
    opaque item<0..length>;
    item data<0...items>;

    You are given:
    * n is max number of bytes of items in notation above
    * l is max number of bytes of length in notation above
    * data which is a list of numbers

    >>> pretty_hex(scaffolding_variable_vector_opaque_items(2, 2, [b'hello', b'world']))
    00 0e 00 05 68 65 6c 6c 6f 00 05 77 6f 72 6c 64
    """


def scaffolding_generate_client_hello(hostname: bytes) -> bytes:
    """
    Generate full client hello record including all headers

    https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2

    First step in the handshake is to send client hello record.

    Parameters
    ----------
    hostname
        SNI hostname (only single value, not list as supported by SNI)
        for which to generate ClientHello

    # not doctest as it has random bits
    # * client random
    # * session id
    # * keyshare
    >> pretty_hex(scaffolding_client_hello(b'nyu.edu'))
    000: 16 03 01 00 94 01 00 00 90 03 03 8c 8d 89 00 a0
    016: 08 2a c7 81 38 cb bf 5e 22 40 1a b4 cd 2e d6 8e
    032: ac 0c dc 47 6d 10 bc 86 18 73 ef 14 af 83 f6 37
    048: e8 85 c5 a2 00 98 cc 13 35 22 0b 7d ee 9c f6 c1
    064: 00 02 13 01 01 00 00 51 00 2b 00 03 02 03 04 00
    080: 0a 00 04 00 02 00 1d 00 0d 00 04 00 02 04 03 00
    096: 33 00 26 00 24 00 1d 00 20 3e 05 58 95 fe b9 1d
    112: 6e cb 17 f7 dd cf 8a c2 2c 9c 2e 88 18 61 15 af
    128: 82 0f 98 5b 5e 6e b4 85 4c 00 00 00 0c 00 0a 00
    144: 00 07 6e 79 75 2e 65 64 75
    """


def scaffolding_parse_record_type(record: bytes) -> bytes:
    """
    Parse record content to get record content type

    https://www.rfc-editor.org/rfc/rfc8446#section-5.1

    Server can send different records back to client
    which client should handle appropriately:

    * handshake records
    * alert records
    * application data

    Even though this function only asks you to return the content type
    it is strongly adviced for your code to fully parse given record.
    Note TLS can send Alert records at any time to indicate error to the client
    and so that should be handled appropriately.

    Parameters
    ----------
    record
        Full record including headers of some arbitrary record sent to client

    >>> pretty_hex(scaffolding_parse_record_type(bytes_from_pretty('''
    ... 15 03 03 00 02 02 00
    ... ''')))
    15
    >>> pretty_hex(scaffolding_parse_record_type(bytes_from_pretty('''
    ... 17 03 03 00 05 68 65 6c 6c 6f
    ... ''')))
    17
    """


def scaffolding_validate_server_hello(
    client_random: bytes, client_session_id: bytes, server_hello: bytes
) -> bool:
    """
    Validate server_hello is valid for given client_hello parameters.

    You can assume client hello formed using these parameters
    is fully compliant with TLS1.3 RFC.

    Parameters
    ----------
    client_random
        Random data client has sent to server
    client_session_id
        Session id client has sent to server
    server_hello
        Full server hello record including headers

    Returns
    -------
    If the server hello record is valid in the context of client hello.
    This should check for things like:

    * did you even get server hello? see problem above
    * protocol versions
    * selected cipher suite(s) - note this project supports a single suite
    * compression method
    * session id
    * supported versions

    >>> scaffolding_validate_server_hello(
    ...     client_random=bytes(range(32)),
    ...     client_session_id=bytes(range(20)),
    ...     server_hello=bytes_from_pretty('''
    ...         000: 16 03 03 00 6e 02 00 00 6a 03 03 26 a9 ec 5d 13
    ...         016: 7a 6d 8e 1d 09 25 ac 3a cd 07 53 4c ad 99 2a eb
    ...         032: fb a5 d1 9e c9 c4 0f de af 94 8d 14 00 01 02 03
    ...         048: 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13
    ...         064: 13 01 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00
    ...         080: 1d 00 20 ee 1a 56 83 6c 84 d7 0c ad ba e0 62 c4
    ...         096: 7f 1b 51 3a 81 e3 3d 7b 4e 6d a5 af 3b 13 84 0d
    ...         112: dd 1c 3f
    ...     '''),
    ... )
    True
    >>> scaffolding_validate_server_hello(
    ...     client_random=b'random',
    ...     client_session_id=b'session_id',
    ...     server_hello=bytes_from_pretty('''
    ...         15 03 03 00 02 02 00
    ...     '''),
    ... )
    False
    """


def scaffolding_transcript_hash_hellos(
    client_hello: bytes, server_hello: bytes
) -> bytes:
    """
    Compute transcript hash of both client and server hellos

    Note transcript hash needs to be calculated multiple times
    along the TLS handshake however this only tests client+server hellos.
    Check TRANSCRIPT_HANDSHAKES from public.py.

    https://www.rfc-editor.org/rfc/rfc8446#section-4.4.1

    Parameters
    ----------
    client_hello
        Client hello record including headers
    server_hello
        Server hello record including headers

    >>> pretty_hex(scaffolding_transcript_hash_hellos(
    ...     client_hello=bytes_from_pretty('''
    ...         000: 16 03 01 00 94 01 00 00 90 03 03 8c 8d 89 00 a0
    ...         016: 08 2a c7 81 38 cb bf 5e 22 40 1a b4 cd 2e d6 8e
    ...         032: ac 0c dc 47 6d 10 bc 86 18 73 ef 14 00 01 02 03
    ...         048: 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13
    ...         064: 00 02 13 01 01 00 00 51 00 2b 00 03 02 03 04 00
    ...         080: 0a 00 04 00 02 00 1d 00 0d 00 04 00 02 04 03 00
    ...         096: 33 00 26 00 24 00 1d 00 20 3e 05 58 95 fe b9 1d
    ...         112: 6e cb 17 f7 dd cf 8a c2 2c 9c 2e 88 18 61 15 af
    ...         128: 82 0f 98 5b 5e 6e b4 85 4c 00 00 00 0c 00 0a 00
    ...         144: 00 07 6e 79 75 2e 65 64 75
    ...     '''),
    ...     server_hello=bytes_from_pretty('''
    ...         000: 16 03 03 00 6e 02 00 00 6a 03 03 26 a9 ec 5d 13
    ...         016: 7a 6d 8e 1d 09 25 ac 3a cd 07 53 4c ad 99 2a eb
    ...         032: fb a5 d1 9e c9 c4 0f de af 94 8d 14 00 01 02 03
    ...         048: 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13
    ...         064: 13 01 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00
    ...         080: 1d 00 20 ee 1a 56 83 6c 84 d7 0c ad ba e0 62 c4
    ...         096: 7f 1b 51 3a 81 e3 3d 7b 4e 6d a5 af 3b 13 84 0d
    ...         112: dd 1c 3f
    ...     '''),
    ... ))
    00: 16 e2 7f 02 a5 d6 d5 63 99 a1 2b bf 88 8f 8f 44
    16: 34 29 31 e1 62 89 39 b9 dc 2d 9d 41 db 7f 6b ce
    """


def scaffolding_hkdf_extract(key: bytes, salt: bytes) -> bytes:
    """
    HKDF extract secret given key and salt

    This implements HKDF-Extract() as defined in RFC

    https://www.rfc-editor.org/rfc/rfc8446#section-7.1
    https://www.rfc-editor.org/rfc/rfc5869#section-2.2

    >>> pretty_hex(scaffolding_hkdf_extract(key=b'\\xff' * 32, salt=b''))
    00: ce 9c a0 61 30 1c 49 71 75 e5 bf 60 26 99 dd e2
    16: 97 86 96 7f 3c 1d 57 40 e2 bd ee d3 9e a6 26 17
    """


def scaffolding_hkdf_expand_label(
    secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """
    HKDF expand label secret from given parameters

    This implements Derive-Secret() utility which under the hood uses
    HKDF-Expand-Label() as defined in RFC

    https://www.rfc-editor.org/rfc/rfc8446#section-7.1
    https://www.rfc-editor.org/rfc/rfc5869#section-2.2

    Parameters
    ----------
    secret
        Secret to expand with the label
    label
        TLS label suffix for the expansion.
        Note this does not include "tls13 " prefix.
        It is just just the "Label" as defined in HkdfLabel in RFC.
        For example this will be "c hs traffic".
    context
        Expansion context. In some cases can be:
        * transcript hash up until that point in the handshake
        * fixed empty hash
        * empty (for iv+key calculation)
    length
        Different key schedule parameters will be of different length.
        This parameter specifies for how long to expand secret
        from the given parameters.
        Note we always use sha256 for this project.

    >>> pretty_hex(scaffolding_hkdf_expand_label(
    ...     secret=b'\\xff' * 32,
    ...     label=b'derived',
    ...     context=b'\\x00' * 32,
    ...     length=32,
    ... ))
    00: 64 ec 99 70 1d 0f 7c 52 da 3c 15 02 82 9c 38 8f
    16: 49 d4 74 6c 00 c0 a0 01 e7 ff 88 c0 f9 37 6f 07
    >>> pretty_hex(scaffolding_hkdf_expand_label(
    ...     secret=b'\\xff' * 32,
    ...     label=b'iv',
    ...     context=b'',
    ...     length=12,
    ... ))
    a3 d2 3d 8f 90 6f 64 c0 ac b9 71 3f
    >>> pretty_hex(scaffolding_hkdf_expand_label(
    ...     secret=b'\\xff' * 32,
    ...     label=b'key',
    ...     context=b'',
    ...     length=16,
    ... ))
    e7 de 02 5c 10 2b cf 71 08 c0 7f dd b2 05 0a 41
    """


class IncrementalKey(typing.TypedDict):
    """
    Individual TLS key used for encrypting messaging

    https://www.rfc-editor.org/rfc/rfc8446#section-7.3

    Note that in TLS all encryption keys are incremental
    and as such this data-structure includes a counter
    of the key.
    """

    iv: bytes
    key: bytes
    counter: int


class KeyScheduleValues(typing.TypedDict):
    """
    Complete TLS key schedule

    Note all fields are optional here.
    In autograder we will only check whatever fields you actually
    return here. You can use this as a sanity check for the specific keys
    you are having issues with.
    """

    dh_key: typing.Optional[bytes]

    empty_hash: typing.Optional[bytes]
    early_secret: typing.Optional[bytes]

    handshake_derived: typing.Optional[bytes]
    handshake_secret: typing.Optional[bytes]

    client_handshake_secret: typing.Optional[bytes]
    server_handshake_secret: typing.Optional[bytes]

    client_handshake_key: typing.Optional[IncrementalKey]
    server_handshake_key: typing.Optional[IncrementalKey]

    master_derived: typing.Optional[bytes]
    master_secret: typing.Optional[bytes]

    client_app_secret: typing.Optional[bytes]
    server_app_secret: typing.Optional[bytes]

    client_app_key: typing.Optional[IncrementalKey]
    server_app_key: typing.Optional[IncrementalKey]

    exporter_secret: typing.Optional[bytes]
    resumption_secret: typing.Optional[bytes]


def scaffolding_key_schedule(
    dh_key: bytes,
    client_server_hello_transcript: bytes,
    server_finished_transcript: bytes,
    client_finished_transcript: bytes,
) -> KeyScheduleValues:
    """
    Generate full key schedule given all the transcripts and DH exchanged secret.

    https://www.rfc-editor.org/rfc/rfc8446#section-7.1

    Parameters
    ----------
    dh_key
        Common key as derived via ECDH exchange
    *_transcript
        Transcripts of handshake at different stages of handshake

    Returns
    -------
    Reference implementation will return all fields of KeyScheduleValues
    however you can may return only fields you are interested in testing.
    Also all encryption keys here are expected to be at counter 0.

    Doctest test vectors same as in
    https://datatracker.ietf.org/doc/rfc8448/

    >>> pretty_hex_dict(scaffolding_key_schedule(
    ...     dh_key=bytes_from_pretty('''
    ...         8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
    ...         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d
    ...     '''),
    ...     client_server_hello_transcript=bytes_from_pretty('''
    ...         86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
    ...         d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
    ...     '''),
    ...     server_finished_transcript=bytes_from_pretty('''
    ...         96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
    ...         00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
    ...     '''),
    ...     client_finished_transcript=bytes_from_pretty('''
    ...         20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26
    ...         84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d
    ...     '''),
    ... ))
    dh_key:
    00: 8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
    16: 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d
    empty_hash:
    00: e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
    16: 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55
    early_secret:
    00: 33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
    16: 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a
    handshake_derived:
    00: 6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
    16: 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
    handshake_secret:
    00: 1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01
    16: 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac
    client_handshake_secret:
    00: b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f
    16: 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21
    server_handshake_secret:
    00: b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
    16: e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38
    client_handshake_key.iv:
    5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f
    client_handshake_key.key:
    db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01
    client_handshake_key.counter:
    0
    server_handshake_key.iv:
    5d 31 3e b2 67 12 76 ee 13 00 0b 30
    server_handshake_key.key:
    3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc
    server_handshake_key.counter:
    0
    master_derived:
    00: 43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5
    16: 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4
    master_secret:
    00: 18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47
    16: 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
    client_app_secret:
    00: 9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52
    16: 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5
    server_app_secret:
    00: a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32
    16: 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43
    client_app_key.iv:
    5b 78 92 3d ee 08 57 90 33 e5 23 d9
    client_app_key.key:
    17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51
    client_app_key.counter:
    0
    server_app_key.iv:
    cf 78 2b 88 dd 83 54 9a ad f1 e9 84
    server_app_key.key:
    9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56
    server_app_key.counter:
    0
    exporter_secret:
    00: fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5
    16: 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50
    resumption_secret:
    00: 7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf
    16: da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
    """


def scaffolding_incrementing_key(iv: bytes, counter: int) -> bytes:
    """
    Compute encryption nonce given iv, and key counter of encryption key

    https://www.rfc-editor.org/rfc/rfc8446#section-5.3

    >>> pretty_hex(scaffolding_incrementing_key(
    ...     iv=bytes(range(12)),
    ...     counter=5,
    ... ))
    00 01 02 03 04 05 06 07 08 09 0a 0e
    """


def scaffolding_decrypt_record(
    data: bytes, iv: bytes, key: bytes, counter: int
) -> list[bytes]:
    """
    Decrypt given data stream using given key parameters

    Parameters
    ----------
    data
        Encrypted record(s) including all headers.
        Note it could be multiple records together.
    iv
    key
    counter
        Key parameters of first decryption key

    Returns
    -------
    All decrypted records in the data stream.

    >>> scaffolding_decrypt_record(
    ...     iv=b'\\x00' * 12,
    ...     key=b'\\xff' * 16,
    ...     counter=5,
    ...     data=bytes_from_pretty('''
    ...         00: 17 03 03 00 16 03 78 70 fc 2b a0 f3 9f 9b 4c 24
    ...         16: fa bd 42 58 db 35 5e d5 96 3a d2
    ...         00: 17 03 03 00 16 e5 93 bb 9d 23 81 46 53 43 4e 36
    ...         16: 44 93 7d 38 fd 46 74 7b ec eb a9
    ...     '''),
    ... )
    [b'\\x17\\x03\\x03\\x00\\x05hello', b'\\x17\\x03\\x03\\x00\\x05hello']
    """


def scaffolding_decrypt_coalesce(
    records: list[bytes], iv: bytes, key: bytes, counter: int
) -> bytes:
    """
    Decrypt and coalesce given data stream using given key parameters

    GradeScope test suite will not use this tecnique so this is optional.
    Some real servers use this technique so you may implement this
    if you would like to interact with real online servers.

    This is very similar to previous decrypt but you could have:

    * long application data record is split into multiple smaller
      application data records which need to be coalesced together

    Per RFC:

    > Application Data messages contain data that is opaque to TLS.
    > Application Data messages are always protected.  Zero-length
    > fragments of Application Data MAY be sent, as they are potentially
    > useful as a traffic analysis countermeasure.  Application Data
    > fragments MAY be split across multiple records or coalesced into a
    > single record.

    Parameters
    ----------
    records
        Encrypted records including all headers.
    iv
    key
    counter
        Key parameters of first decryption key

    Returns
    -------
    All decrypted records coalesced together

    # 2 encrypted records of "hello" and "world" are merged
    >> scaffolding_decrypt_coalesce(
    ...     iv=b'\\x00' * 12,
    ...     key=b'\\xff' * 16,
    ...     counter=5,
    ...     records=[
    ...         bytes_from_pretty('''
    ...             00: 17 03 03 00 16 03 78 70 fc 2b a0 f3 9f 9b 4c 24
    ...             16: fa bd 42 58 db 35 5e d5 96 3a d2
    ...         '''),
    ...         bytes_from_pretty('''
    ...             00: 17 03 03 00 16 fa 99 a5 9d 28 81 16 49 77 08 b1
    ...             16: 07 4b 01 53 ff 94 2a de 71 93 63
    ...         '''),
    ...     ],
    ... )
    [b'\\x17\\x03\\x03\\x00\\nhelloworld']
    """


def scaffolding_decrypt_split(
    record: bytes, iv: bytes, key: bytes, counter: int
) -> list[bytes]:
    """
    Decrypt and split given data stream using given key parameters

    GradeScope test suite will not use this tecnique so this is optional.
    Some real servers use this technique so you may implement this
    if you would like to interact with real online servers.

    This is very similar to previous decrypt but you could have:

    * multiple decrypted records are all coalesced/merged into a single
      encrypted application data record and those records need to be split
      after decryption for processing

    Per RFC:

    > Application Data messages contain data that is opaque to TLS.
    > Application Data messages are always protected.  Zero-length
    > fragments of Application Data MAY be sent, as they are potentially
    > useful as a traffic analysis countermeasure.  Application Data
    > fragments MAY be split across multiple records or coalesced into a
    > single record.

    Parameters
    ----------
    record
        Encrypted record including all headers
        which internally contains multiple coalesced records
    iv
    key
    counter
        Key parameters of first decryption key

    Returns
    -------
    All decrypted split records from the encrypted record

    # encrypted extensions and dummy finished handshake records
    # are merged into single encrypted record
    # note this is just an example. real server will never send
    # finished right after encrypted extensions
    # (those records are small so make for smaller doctest :D)
    >>> for i in scaffolding_decrypt_split(
    ...     iv=b'\\x00' * 12,
    ...     key=b'\\xff' * 16,
    ...     counter=5,
    ...     record=bytes_from_pretty('''
    ...         00: 17 03 03 00 3b 63 1d 1c 92 44 b7 c1 f6 20 be 26
    ...         16: 9e b9 6e 66 4f de 9c 7f 2e 59 0c 6d 8d 4a ce 3b
    ...         32: bd 21 ef 30 af 13 a2 6c f2 ab 4c 5d ac 06 ef 9b
    ...         48: 5f ab 49 8a a0 33 6f 00 06 4f 1a b7 72 d0 2b 5b
    ...     '''),
    ... ):
    ...     pretty_hex(i)
    16 03 03 00 06 08 00 00 02 00 00
    00: 16 03 03 00 24 14 00 00 20 00 01 02 03 04 05 06
    16: 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16
    32: 17 18 19 1a 1b 1c 1d 1e 1f
    """


def scaffolding_encrypt(data: bytes, iv: bytes, key: bytes, counter: int) -> bytes:
    """
    Encrypt given data stream using given key parameters

    Parameters
    ----------
    data
        Plaintext application data to be encrypted
    iv
    key
    counter
        Key parameters of encryption key

    Returns
    -------
    Encrypted record including headers

    >>> pretty_hex(scaffolding_encrypt(
    ...     iv=b'\\x00' * 12,
    ...     key=b'\\xff' * 16,
    ...     counter=5,
    ...     data=b'hello',
    ... ))
    00: 17 03 03 00 16 03 78 70 fc 2b a0 f3 9f 9b 4c 24
    16: fa bd 42 58 db 35 5e d5 96 3a d2
    """


def main() -> int:
    """
    Simple implementation which converts tls13_http_get() from above to CLI client
    """
    parser = argparse.ArgumentParser("TLS1.3 basic client")

    def path_type(value: str) -> pathlib.Path:
        path = pathlib.Path(value).resolve()
        if not path.exists() or not path.is_file():
            return parser.error(f"{value!r} does not exist or is not a file")
        return path

    def url_type(value: str) -> urllib.parse.SplitResult:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != "https":
            return parser.error(f"{value!r} does not use https scheme")
        if not parsed.hostname:
            return parser.error(f"{value!r} does not have hostname")
        return parsed

    parser.add_argument("url", type=url_type, help="URL to send request to")
    parser.add_argument(
        "--cafile",
        type=path_type,
        default=certifi.where(),
        help="Path to CA cert file in PEM format",
    )
    parser.add_argument(
        "--ip", help="Do not resolve hostname but instead connect to this ip"
    )
    parser.add_argument(
        "-i", "--include", action="store_true", help="Include response http headers"
    )
    args = parser.parse_args()

    ca = args.cafile.read_bytes()

    url: urllib.parse.SplitResult = args.url
    assert url.hostname
    hostname: bytes = url.hostname.encode()
    ip: bytes = (args.ip or url.hostname).encode()
    port: int = url.port or 443
    path: bytes = (url.path or "/").encode()

    response = tls13_http_get(path=path, ip=ip, port=port, hostname=hostname, ca=ca)

    if response["error"]:
        print(response["error"])
        return 1

    data = response["data"].decode()

    if not args.include:
        data = data.split("\r\n\r\n", 1)[-1]

    print(data)
    return 0


if __name__ == "__main__":
    if sys.stdin.isatty():
        sys.exit(main())
    else:
        inputs = simple_bson.loads(sys.stdin.buffer.read())
        solutions = {
            k: globals()[k.split("__")[0]](**v)
            for k, v in inputs.items()
            if k in globals()
        }
        sys.stdout.buffer.write(simple_bson.dumps(solutions))
