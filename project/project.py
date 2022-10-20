#!/usr/bin/env python3
import argparse
import dataclasses
import sys
import typing
import urllib.parse

import certifi


def hkdf_extract(*, key: bytes, salt: bytes) -> bytes:
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-7.1
    https://www.rfc-editor.org/rfc/rfc5869#section-2.2

    >>> pretty_hex(hkdf_extract(key=b'\\xff' * 32, salt=b''))
    00: ce 9c a0 61 30 1c 49 71 75 e5 bf 60 26 99 dd e2
    16: 97 86 96 7f 3c 1d 57 40 e2 bd ee d3 9e a6 26 17
    """


def hkdf_expand_label(
    *, secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-7.1
    https://www.rfc-editor.org/rfc/rfc5869#section-2.3

    >>> pretty_hex(hkdf_expand_label(
    ...     secret=b'\\xff' * 32,
    ...     label=b'label',
    ...     context=b'',
    ...     length=32,
    ... ))
    00: 34 93 b6 2c a2 40 76 98 7a 49 17 66 b5 a4 06 07
    16: d4 0f 51 88 a0 37 ca d9 db cd 3e 0d b2 ce 05 21
    """


@dataclasses.dataclass
class KeyShareX25519:
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2

    >>> client = KeyShareX25519(
    ...     private_key=x25519.X25519PrivateKey.from_private_bytes(
    ...         bytes_from_pretty('''
    ...             49 af 42 ba 7f 79 94 85 2d 71 3e f2 78
    ...             4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05
    ...         ''')
    ...     ),
    ...  )
    >>> server = KeyShareX25519(
    ...     public_key=x25519.X25519PublicKey.from_public_bytes(
    ...         bytes_from_pretty('''
    ...             c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
    ...             72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f
    ...         ''')
    ...     ),
    ... )

    >>> pretty_hex(client.exchange(server))
    00: 8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
    16: 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d
    """


@dataclasses.dataclass
class KeySchedule:
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-7

    Test vectors from:
    https://datatracker.ietf.org/doc/rfc8448/

    >>> s = KeySchedule()

    >>> pretty_hex(s.early_secret)
    00: 33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
    16: 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a

    >>> s.exchange(
    ...     dh_key=bytes_from_pretty('''
    ...         8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
    ...         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d
    ...     '''),
    ...     transcript_hash=bytes_from_pretty('''
    ...         86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
    ...         d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
    ...     '''),
    ... )

    >>> pretty_hex(s.empty_hash)
    00: e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
    16: 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55

    >>> pretty_hex(s.handshake_derived)
    00: 6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
    16: 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba

    >>> pretty_hex(s.handshake_secret)
    00: 1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01
    16: 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac

    >>> pretty_hex(s.client_handshake_secret)
    00: b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f
    16: 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21

    >>> pretty_hex(s.client_handshake_key.iv)
    5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f
    >>> pretty_hex(s.client_handshake_key.key)
    db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01

    >>> pretty_hex(s.server_handshake_secret)
    00: b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
    16: e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38

    >>> pretty_hex(s.server_handshake_key.iv)
    5d 31 3e b2 67 12 76 ee 13 00 0b 30
    >>> pretty_hex(s.server_handshake_key.key)
    3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc

    >>> pretty_hex(s.master_derived)
    00: 43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5
    16: 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4

    >>> pretty_hex(s.master_secret)
    00: 18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47
    16: 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19

    >>> s.server_finished(transcript_hash=bytes_from_pretty('''
    ...     96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
    ...     00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
    ... '''))

    >>> pretty_hex(s.client_app_secret)
    00: 9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52
    16: 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5

    >>> pretty_hex(s.client_app_key.iv)
    5b 78 92 3d ee 08 57 90 33 e5 23 d9
    >>> pretty_hex(s.client_app_key.key)
    17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51

    >>> pretty_hex(s.server_app_secret)
    00: a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32
    16: 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43

    >>> pretty_hex(s.server_app_key.iv)
    cf 78 2b 88 dd 83 54 9a ad f1 e9 84
    >>> pretty_hex(s.server_app_key.key)
    9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56

    >>> pretty_hex(s.exporter_secret)
    00: fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5
    16: 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50

    >>> s.client_finished(transcript_hash=bytes_from_pretty('''
    ...     20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26
    ...     84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d
    ... '''))

    >>> pretty_hex(s.resumption_secret)
    00: 7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf
    16: da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
    """


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
    verbose: bool = True,
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
        hence will allow to make connections to publis sites
    verbose
        Optional flag when True can print additional verbose information to stderr

    Examples
    --------
    >>> tls13_http_get(
    ...     path='/'.encode(),
    ...     ip='google.com'.encode(),
    ...     port=443,
    ...     hostname='google.com'.encode(),
    ...     ca=pathlib.Path(certifi.where()).read_bytes(),
    ...     verbose=False,
    ... )
    {'data': b'HTTP/1.0 301 Moved Permanently...', 'error': ''}
    >>> tls13_http_get(
    ...     path='/'.encode(),
    ...     ip='google.com'.encode(),
    ...     port=443,
    ...     hostname='haha.com'.encode(),
    ...     ca=pathlib.Path(certifi.where()).read_bytes(),
    ...     verbose=False,
    ... )
    {'data': b'', 'error': '<error:invalid hostname>'}
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
    sys.exit(main())
