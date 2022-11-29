# -*- coding: utf-8 -*-
import enum
import functools
import re
import sys
import typing

import more_itertools
import typing_extensions


BYTE_ORDER = "big"
"""
https://www.rfc-editor.org/rfc/rfc8446#section-3.3
"""


T = typing.TypeVar("T")


class ValueProtocol(typing.Protocol):
    """
    Protocol of objects with value property

    This is compatible with built-in Enums which makes it conventient
    to serialize either enums or custom objects to bytes.

    All these examples satisfy this protocol:

    >>> class FooEnum(enum.Enum):
    ...     FOO = b'foo'

    >>> FooEnum.FOO.value
    b'foo'

    >>> class FooCustom:
    ...     @property
    ...     def value(self) -> bytes:
    ...         return b'foo'

    >>> FooCustom().value
    b'foo'
    """

    @property
    def name(self) -> str:
        ...

    @property
    def value(self) -> bytes:
        ...


T_ValueProtocol = typing.TypeVar("T_ValueProtocol", bound=ValueProtocol)


class TypedValueProtocol(typing.Protocol[T_ValueProtocol]):
    """
    Similar to ValueProtocol but it also allows to [de]serialize itself to bytes

    This is convenient to for example describe various extensions which all
    must define a type and must both serialize and deserialize to/from bytes

    For example this example satisfies this protocol:

    >>> class FooEnum(enum.Enum):
    ...     FOO = b'foo'

    >>> import dataclasses

    >>> @dataclasses.dataclass
    ... class Example:
    ...     type = FooEnum
    ...     data: bytes # lets assume data is 5 bytes
    ...
    ...     @property
    ...     def value(self) -> bytes:
    ...         return self.data
    ...
    ...     @classmethod
    ...     def from_value(
    ...         cls,
    ...         data: typing.Iterator[int],
    ...         parent: typing.Optional[typing.Type[typing_extensions.Self]] = None,
    ...     ) -> typing_extensions.Self:
    ...         return cls(data=take(5, data))

    >>> all_data = iter(b'helloworld')
    >>> take_all(all_data, lambda data: Example.from_value(data))
    [Example(data=b'hello'), Example(data=b'world')]
    """

    type: T_ValueProtocol

    @property
    def value(self) -> bytes:
        ...

    @property
    def annotated(self) -> list[ValueProtocol]:
        ...

    @classmethod
    def from_value(
        cls,
        data: typing.Iterator[int],
        parent: typing.Optional[typing.Type[typing_extensions.Self]] = None,
    ) -> typing_extensions.Self:
        """
        parent argument is useful to trace the deserialization path

        e.g. whether deserialization is being done for client or server records
        as sometimes they take different shape
        """
        ...


T_TypedValueProtocol = typing.TypeVar("T_TypedValueProtocol", bound=TypedValueProtocol)
T_ValueProtocols = typing.TypeVar(
    "T_ValueProtocols", bound=ValueProtocol | TypedValueProtocol
)


class AnnotatedMixin:
    @property
    def value(self) -> bytes:
        return b"".join(i.value for i in self.annotated)

    @property
    def annotated(self) -> list[ValueProtocol]:
        ...

    def annotate(self, file: typing.Optional[typing.IO] = None) -> None:
        if not self.annotated:
            return
        longest_name = max(len(str(i.name)) for i in self.annotated)
        longest_value = max(len(i.value) for i in self.annotated)
        longest_value = len(str(longest_value)) if longest_value > 16 else 0
        indent = " " * (longest_name + 3)
        for i in self.annotated:
            value = _pretty_hex(i.value, indent, longest_value).strip()
            print(f"{i.name: <{longest_name}}   {value}".strip(), file=file)


T_AnnotatedMixin = typing.TypeVar("T_AnnotatedMixin", bound=AnnotatedMixin)


def annotate(data: T_AnnotatedMixin) -> T_AnnotatedMixin:
    if "pytest" in "".join(sys.argv):
        if "--doctest-modules" not in sys.argv:
            data.annotate(sys.stdout)
    elif sys.stdin.isatty():
        data.annotate(sys.stderr)
    return data


def _pretty_hex(data: bytes, indent: str = "", prefix_length: int = 0) -> str:
    segment = 16
    return "\n".join(
        indent
        + (
            f"{str(i * segment).zfill(prefix_length or len(str(len(data))))}: "
            if len(data) > segment or prefix_length
            else "" * prefix_length
        )
        + " ".join(f"{x:02x}" for x in chunk)
        for i, chunk in enumerate(more_itertools.chunked(data, segment))
    )


def pretty_hex(data: bytes, file: typing.Optional[typing.IO] = None) -> None:
    """
    Print pretty bytes

    If data is >16 bytes prints byte length prefixes

    https://docs.python.org/3.10/library/string.html#format-specification-mini-language

    >>> pretty_hex(b'\\x00\\x01')
    00 01

    >>> pretty_hex(bytes(range(20)))
    00: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    16: 10 11 12 13
    """
    print(_pretty_hex(data), file=file)


def pretty_hex_dict(data: dict[str, typing.Any | dict], prefix: str = "") -> None:
    """
    Print pretty bytes of a dict

    >>> pretty_hex_dict({'foo': b'\\x00' * 5, 'bar': {'baz': b'\\x01' * 5}})
    foo:
    00 00 00 00 00
    bar.baz:
    01 01 01 01 01
    """
    for k, v in data.items():
        if isinstance(v, dict):
            pretty_hex_dict(v, f"{k}.")
        else:
            print(f"{prefix}{k}:")
            pretty_hex(v) if isinstance(v, bytes) else print(v)


def bytes_from_pretty(data: str) -> bytes:
    """
    Get bytes from pretty hex

    This is useful to parse test vectors provided in the RFCs
    (or to make doctests more pretty :D)

    >>> bytes_from_pretty('00 01 02 03').hex()
    '00010203'

    >>> bytes_from_pretty('''
    ... 00 01
    ... 02 03
    ... ''').hex()
    '00010203'

    >>> bytes_from_pretty('00: 00 01 02 03').hex()
    '00010203'

    >>> bytes_from_pretty('''
    ... 00: 00 01
    ... 02: 02 03
    ... ''').hex()
    '00010203'
    """
    return bytes.fromhex(re.sub(r"\s+|\w+:", "", data))


def xor(*args: typing.Union[bytes, typing.Iterable[bytes]]) -> bytes:
    """
    XOR any number of bytes iterable inputs

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


def take(length: int, data: typing.Iterator[int]) -> bytes:
    """
    Take length number of bytes from bytes iterable

    This is especially useful to take specified number of bytes
    such as in the TLSPlaintext record but leave rest of the data
    to be processed by future records.

    >>> value = iter(b'helloworld')
    >>> take(5, value)
    b'hello'
    >>> take(5, value)
    b'world'
    >>> take(5, value)
    Traceback (most recent call last):
    StopIteration: no data but expected 5 bytes
    """
    assert not isinstance(data, bytes), "data should be iter()"
    value = more_itertools.take(length, data)
    if length and not value:
        raise StopIteration(f"no data but expected {length} bytes")
    if len(value) != length:
        raise ValueError(f"Did not take {length} bytes but only {len(value)}")
    return bytes(value)


def take_all(
    data: typing.Iterator[int], factory: typing.Callable[[typing.Iterator[int]], T]
) -> list[T]:
    """
    >>> take_all(iter(b'helloworld'), lambda value: take(5, value))
    [b'hello', b'world']
    """
    values: list[T] = []
    while True:
        try:
            values.append(factory(data))
        except StopIteration:
            return values


class BytesEnum(enum.Enum):
    """
    Enum utility which allows to deserialize enum from bytes iterator

    >>> class Foo(BytesEnum):
    ...     FOO = b'foo'
    ...     BAR = b'bar'

    >>> Foo.get_length()
    3

    >>> data = iter(b'foobar')
    >>> Foo.from_value(data)
    <Foo.FOO: b'foo'>
    >>> Foo.from_value(data)
    <Foo.BAR: b'bar'>
    """

    @classmethod
    def get_length(cls) -> int:
        return len(next(iter(cls.__members__.values())).value)

    @classmethod
    def from_value(
        cls: typing.Type[typing_extensions.Self],
        data: typing.Iterator[int],
        parent: typing.Optional[typing.Type[TypedValueProtocol]] = None,
    ) -> typing_extensions.Self:
        return cls(take(cls.get_length(), data))


@enum.unique
class ProtocolVersion(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-5.1
    """

    SSL30 = b"\x03\x00"
    TLS10 = b"\x03\x01"
    TLS11 = b"\x03\x02"
    TLS12 = b"\x03\x03"
    TLS13 = b"\x03\x04"


@enum.unique
class ContentType(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-5.1
    """

    INVALID = b"\x00"
    CHANGE_CIPHER_SPEC = b"\x14"
    ALERT = b"\x15"
    HANDSHAKE = b"\x16"
    APPLICATION_DATA = b"\x17"
    HEARTBEAT = b"\x18"


@enum.unique
class HandshakeType(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-4
    """

    CLIENT_HELLO = b"\x01"
    SERVER_HELLO = b"\x02"
    NEW_SESSION_TICKET = b"\x04"
    END_OF_EARLY_DATA = b"\x05"
    ENCRYPTED_EXTENSIONS = b"\x08"
    CERTIFICATE = b"\x0b"
    CERTIFICATE_REQUEST = b"\x0d"
    CERTIFICATE_VERIFY = b"\x0f"
    FINISHED = b"\x14"
    KEY_UPDATE = b"\x18"
    MESSAGE_HASH = b"\xfe"


@enum.unique
class CipherSuite(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
    """

    TLS_AES_128_GCM_SHA256 = b"\x13\x01"
    TLS_AES_256_GCM_SHA384 = b"\x13\x02"
    TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03"
    TLS_AES_128_CCM_SHA256 = b"\x13\x04"
    TLS_AES_128_CCM_8_SHA256 = b"\x13\x05"


@enum.unique
class CompressionMethod(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
    """

    NULL = b"\x00"


@enum.unique
class ExtensionType(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-4.2
    """

    SERVER_NAME = b"\x00\x00"  # RFC 6066
    MAX_FRAGMENT_LENGTH = b"\x00\x01"  # RFC 6066
    STATUS_REQUEST = b"\x00\x05"  # RFC 6066
    SUPPORTED_GROUPS = b"\x00\x0a"  # RFC 8422, 7919
    SIGNATURE_ALGORITHMS = b"\x00\x0d"  # RFC 8446
    USE_SRTP = b"\x00\x0e"  # RFC 5764
    HEARTBEAT = b"\x00\x0f"  # RFC 6520
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = b"\x00\x10"  # RFC 7301
    SIGNED_CERTIFICATE_TIMESTAMP = b"\x00\x12"  # RFC 6962
    CLIENT_CERTIFICATE_TYPE = b"\x00\x13"  # RFC 7250
    SERVER_CERTIFICATE_TYPE = b"\x00\x14"  # RFC 7250
    PADDING = b"\x00\x15"  # RFC 7685
    PRE_SHARED_KEY = b"\x00\x29"  # RFC 8446
    EARLY_DATA = b"\x00\x2a"  # RFC 8446
    SUPPORTED_VERSIONS = b"\x00\x2b"  # RFC 8446
    COOKIE = b"\x00\x2c"  # RFC 8446
    PSK_KEY_EXCHANGE_MODES = b"\x00\x2d"  # RFC 8446
    CERTIFICATE_AUTHORITIES = b"\x00\x2f"  # RFC 8446
    OID_FILTERS = b"\x00\x30"  # RFC 8446
    POST_HANDSHAKE_AUTH = b"\x00\x31"  # RFC 8446
    SIGNATURE_ALGORITHMS_CERT = b"\x00\x32"  # RFC 8446
    KEY_SHARE = b"\x00\x33"  # RFC 8446


@enum.unique
class NameType(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc6066#section-3
    """

    HOST_NAME = b"\x00"


@enum.unique
class NamedGroup(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7
    """

    # Elliptic Curve Groups (ECDHE)
    SECP256R1 = b"\x00\x17"
    SECP384R1 = b"\x00\x18"
    SECP521R1 = b"\x00\x19"
    X25519 = b"\x00\x1D"
    X448 = b"\x00\x1E"
    # Finite Field Groups (DHE)
    FFDHE2048 = b"\x01\x00"
    FFDHE3072 = b"\x01\x01"
    FFDHE4096 = b"\x01\x02"
    FFDHE6144 = b"\x01\x03"
    FFDHE8192 = b"\x01\x04"


@enum.unique
class SignatureScheme(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
    """

    # RSASSA-PKCS1-v1_5 algorithms
    RSA_PKCS1_SHA256 = b"\x04\x01"
    RSA_PKCS1_SHA384 = b"\x05\x01"
    RSA_PKCS1_SHA512 = b"\x06\x01"

    # ECDSA algorithms
    ECDSA_SECP256R1_SHA256 = b"\x04\x03"
    ECDSA_SECP384R1_SHA384 = b"\x05\x03"
    ECDSA_SECP521R1_SHA512 = b"\x06\x03"

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    RSA_PSS_RSAE_SHA256 = b"\x08\x04"
    RSA_PSS_RSAE_SHA384 = b"\x08\x05"
    RSA_PSS_RSAE_SHA512 = b"\x08\x06"

    # EdDSA algorithms */
    ED25519 = b"\x08\x07"
    ED448 = b"\x08\x08"

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RSA_PSS_PSS_SHA256 = b"\x08\x09"
    RSA_PSS_PSS_SHA384 = b"\x08\x0a"
    RSA_PSS_PSS_SHA512 = b"\x08\x0b"

    # Legacy algorithms
    RSA_PKCS1_SHA1 = b"\x02\x01"
    ECDSA_SHA1 = b"\x02\x03"


@enum.unique
class CertificateType(BytesEnum):
    """
    https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2
    """

    X509 = b"\x00"
    RAWPUBLICKEY = b"\x02"


@enum.unique
class AlertLevel(BytesEnum):
    WARNING = b"\x01"
    FATAL = b"\x02"


@enum.unique
class AlertDescription(BytesEnum):
    CLOSE_NOTIFY = b"\x00"
    UNEXPECTED_MESSAGE = b"\x0a"
    BAD_RECORD_MAC = b"\x14"
    DECRYPTION_FAILED_RESERVED = b"\x15"
    RECORD_OVERFLOW = b"\x16"
    DECOMPRESSION_FAILURE_RESERVED = b"\x1e"
    HANDSHAKE_FAILURE = b"\x28"
    NO_CERTIFICATE_RESERVED = b"\x29"
    BAD_CERTIFICATE = b"\x2a"
    UNSUPPORTED_CERTIFICATE = b"\x2b"
    CERTIFICATE_REVOKED = b"\x2c"
    CERTIFICATE_EXPIRED = b"\x2d"
    CERTIFICATE_UNKNOWN = b"\x2e"
    ILLEGAL_PARAMETER = b"\x2f"
    UNKNOWN_CA = b"\x30"
    ACCESS_DENIED = b"\x31"
    DECODE_ERROR = b"\x32"
    DECRYPT_ERROR = b"\x33"
    EXPORT_RESTRICTION_RESERVED = b"\x3c"
    PROTOCOL_VERSION = b"\x46"
    INSUFFICIENT_SECURITY = b"\x47"
    INTERNAL_ERROR = b"\x50"
    INAPPROPRIATE_FALLBACK = b"\x56"
    USER_CANCELED = b"\x5a"
    NO_RENEGOTIATION_RESERVED = b"\x64"
    MISSING_EXTENSION = b"\x6d"
    UNSUPPORTED_EXTENSION = b"\x6e"
    CERTIFICATE_UNOBTAINABLE_RESERVED = b"\x6f"
    UNRECOGNIZED_NAME = b"\x70"
    BAD_CERTIFICATE_STATUS_RESPONSE = b"\x71"
    BAD_CERTIFICATE_HASH_VALUE_RESERVED = b"\x72"
    UNKNOWN_PSK_IDENTITY = b"\x73"
    CERTIFICATE_REQUIRED = b"\x74"
    NO_APPLICATION_PROTOCOL = b"\x78"


TRANSCRIPT_HANDSHAKES = (
    HandshakeType.CLIENT_HELLO,
    # HelloRetryRequest is the same as ServerHello,
    HandshakeType.SERVER_HELLO,
    HandshakeType.ENCRYPTED_EXTENSIONS,
    HandshakeType.CERTIFICATE_REQUEST,
    HandshakeType.CERTIFICATE,
    HandshakeType.CERTIFICATE_VERIFY,
    HandshakeType.FINISHED,
    HandshakeType.END_OF_EARLY_DATA,
)


@enum.unique
class Error(enum.Enum):
    BAD_TLS_VERSION = "<error:bad tls version>"
    """
    Used when bad TLS version (non 1.3) is encountered
    """

    BAD_SIGNATURE = "<error:bad signature>"
    """
    Used when any of the server certificate signatures are invalid
    For example when Certificate signature is "corrupted" signed by the
    intermediate cert
    """

    BAD_CERTIFICATE = "<error:bad certificate>"
    """
    Used when client receives certificate which cannot be validated
    For example it is issued by unkown issuer
    """

    BAD_CERTIFICATE_VALIDITY = "<error:bad certificate validity>"
    """
    Used when server sertificate has bad validity period.
    It applies to both cert is not valid yet or already expired.
    """

    MISSING_RECORDS = "<error:missing records>"
    """
    Used when server did not send some required TLS records.
    """

    INVALID_HOSTNAME = "<error:invalid hostname>"
    """
    Used when hostname could not be validated.
    Host validate should use SNI and if missing the certificate
    fallback to CN of the cert subject.
    """

    OTHER = "<error:other>"
    """
    Used for any other TLS errors
    """


def rfc_enum(length: int, data: str):
    """
    Helper for converting RFC enums to python code

    this was used to create some of the enums above
    """
    pattern = re.compile(r"(?P<name>[\w_]+)\((?P<value>\d+)\)")
    for line in data.splitlines():
        search = pattern.search(line)
        if not search:
            continue
        name = search.group("name").upper()
        value = "".join(
            f"\\x{i:02x}"
            for i in int(search.group("value")).to_bytes(length, BYTE_ORDER)
        )
        print(f'    {name} = b"{value}"')
