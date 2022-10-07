# Desription

Standardized [a few years ago][1], TLS 1.3 marks a drastic reform of prior TLS
versions. The principle themes of 1.3 are simplification, RTT reduction, and
rescricting ciphersuite support in accordance with contemporary cryptographic
best practices. TLS 1.3 simultaneously simplifies the protocol and improves
performance by reducing round trips at the TLS layer from 3 to 2 during the
handshake. This is accomplished by the client sending a "guess" of supported
ciphersuites in the client Hello, along with KeyShare iformation. If the the
client has guessed correctly, the server can utilize the client's KeyShare and
immediately send its own KeyShare and certificate in its server Hello. At this
point, we've only burned one round trip, and the client is ready to send its
Finished message along with its first segment of application data over the
symmetrically encrypted TLS channel!

In this project, we will implement the client side of a restricted TLS 1.3
handshake and a (basic) symmetric session. Students will incrementally build a
client along "checkpoints" in the autograder at each step of the TLS handshake,
ending with a TLS client capable of interacting with real-world endpoints. To
simplify the assignment's implementation, we will restrict the supported
ciphersuite to `TLS_AES_128_GCM_SHA256` using ECDHE with x25519 for key
exchange, 128-bit AES in GCM mode for symmetric encryption, and ed25519 for
signatures. We will not implement session resumption/stores, pre-shared keys,
downgrade prevention, or other real-world concerns that would be required for a
practical TLS implementation.

The client will, however, need to validate the server certificate, checking for
things like expiration, signature validity, etc. The client will also implement
some TLS extensions such as Supported Versions (required in TLS 1.3), Key Share
(also rquired), and Server Name Indication ("SNI"). SNI is used to specify
which domain a client is attempting to connect to on a server that hosts
multiple domains (such as a load balancer in a cloud environment). SNI is very
simple to implement, as it only requires adding an additional field to the
client Hello message.

# Resources

- [TLS 1.3 RFC][1]
- [The Illustrated TLS 1.3 Connection][2]
- [A Detailed Look at RFC 8446 (a.k.a. TLS 1.3)][3]
- [online ASN.1 encoder/decoder][6]

Diagrams illustrating the format of client Hello message, Supported Versions
Extension, and Key Share Extension:

![](./img/client_hello.png)
![](./img/supported_versions.png)
![](./img/key_share.png)

# Specification

## Phases

### Phase 0: Record Encoding

This section will give an overview of how TLS records are encoded at the byte
level. Some types described in the RFC will be fixed-size (e.g. [32-bit
integers][8]), and some will be variable length (e.g. [vectors][9]). For
example:

- a 32-bit integer with a value decimal 19 is encoded as `0x00000013`
- a 8-bit integer with a value decimal 1 is encoded as `0x01`
- a 0-byte vector is encoded as `0x00`
- a 1-byte vector with max byte as the value is encoded as `0x01ff`
- a 4-byte vector where each byte is a subsequent power of 2 is encoded as
  `0x0400010204`

The scaffolding code will ask you to encode some of these types with given byte
array values.

Another important concept in record encoding is headers. Headers allow parsers
to modify their behavior based on the type, size, and protocol version of
records. Here are the header formats we'll cover:

1. record header
    1. record type (1 byte)
    1. protocol version (constant value of `0x0301`, 2 bytes)
    1. record size (2 bytes)
1. handshake message header
    1. message type (one byte)
    1. message size (3 bytes)

The record type of all (unencrypted) handshake records is `0x16`. While
encrypted handshake messages are still messages _on the message level_, they
have a different record type of "application data", `0x17`. This is because at
the record level, encrypted message contents are opaque and must be decrypted
before the message type can be determined.

### Phase 1: Present client Hello

In the first phase of the handshake, the client presents a client Hello message
to the server. The format of the client Hello is described [in the RFC][4].
Note that a number of the mandatory fields are unused in the protocol, but are
required for backwards compatibility of the protocol. The client Hello for this
project wil consist of the following required fields (not including record and
message headers), in order:

1. client version (constant `0x0303`, 2 bytes)
1. client random (32 bytes)
1. unused legacy session ID (constant empty vector `0x00`, 1 bytes total)
1. supported cipher suites (constant vector [`0x021301`][7], 3 bytes total)
    - NOTE: that for simplicity, the project will only support a single cipher
      suite, `TLS_AES_128_GCM_SHA256` (`0x1301`).
1. unused legacy compression methods (constant vector `0x0100`, 2 bytes)
1. extensions length (2 bytes)
1. extensions (variable length, see below)

Each extension is encoded as follows:

1. extension type (2 bytes)
1. extension data length (2 bytes)
1. extension data (given by ibid.)

The client Hello must also include the following extensions in the format
described [in the RFC][5]:

1. [supported versions][10] (constant value of `0x002b0003020304`, 7 bytes total)
    - type `0x002b` (2 bytes)
    - extension len `0x0003` (2 bytes)
    - versions len `0x02` (1 byte)
    - version `0x0304` (2 bytes)
1. [server name][14] (variable length, < (2^8)^2 == 65536)
    - type `0x0000` (2 bytes)
    - extension len `0x..` (2 bytes)
    - names len `0x..` (2 bytes, there will only be one entry, this is the len
      of all proceeding bytes)
    - entry type `0x00`, indicates hostname (1 byte)
    - hostname len, `0x..` (2 bytes)
    - hostname `0x..` (variable length)
1. [supported groups][11] (constant vector `0x02001d`, 3 bytes)
    - NOTE: for simplicity, the project will only support a single curve
      [x25519][12].
1. [key share][13] (42 bytes)
    - type `0x0033` (2 bytes)
    - extension len `0x..` (2 bytes)
    - key share len `0x..` (2 bytes)
    - kex group ID `0x001d` i.e. x25519 (2 bytes)
        - NOTE: for simplicity, the project will only support one curve
    - public key len `0x0020` i.e. 32 bytes (2 bytes)
    - public key `0x..` (32 bytes)

The scaffolding code will validate your Phase 1 output for size and content
as applicable. Note that the scaffolding will **not expect** these values to be
Record-encoded.

### Phase 2: Validate server Hello

In the next step of the handshake, the server sends its server Hello to the
client, followed by (or perhaps concurrently to) its server Finished message
and encrypted server Certificate record.

The [server Hello message][15] is given in the following format (not including
record and message headers):

1. unused legacy server version (constant value of `0x0303`, 2 bytes)
1. server random (32 bytes)
1. unused legacy session ID echo (echoes whatever client sent, i.e. `0x00`, 1
   byte)
1. cipher suite selection (constant value [`0x1301`][7], 3 bytes total)
    - NOTE: this is the server's _selection_, so it's a singular value rather
      than a list as in the client Hello.
1. unused legacy compression method selection (constant value `0x00`, 1 bytes)
1. extensions length (2 bytes)
1. extensions (49 bytes, see below)

While the RFC requires special treatment by the client if it [encounters the
following value of Server Random][15], but to keep things simple, we will not
require this behavior:

>   For reasons of backward compatibility with middleboxes (see
>   Appendix D.4), the HelloRetryRequest message uses the same structure
>   as the server Hello, but with Random set to the special value of the
>   SHA-256 of "HelloRetryRequest":
>
>     CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
>     C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
>
>   Upon receiving a message with type server_hello, implementations MUST
>   first examine the Random value and, if it matches this value, process
>   it as described in Section 4.1.4).

The server Hello must include the following extensions in the format described
[in the RFC][15]:

1. [supported versions][10] (constant value of `0x002b0003020304`, 7 bytes total)
    - type `0x002b` (2 bytes)
    - extension len `0x0003` (2 bytes)
    - versions len `0x02` (1 byte)
    - version `0x0304` (2 bytes)
1. [key share][13] (42 bytes)
    - type `0x0033` (2 bytes)
    - extension len `0x..` (2 bytes)
    - key share len `0x..` (2 bytes)
    - kex group ID `0x001d` i.e. x25519 (2 bytes)
        - NOTE: for simplicity, the project will only support one curve
    - public key len `0x0020` i.e. 32 bytes (2 bytes)
    - public key `0x..` (32 bytes)

### Phase 3: Calculate Session Secrets

Now that the client has generated its own keypair and has recieved that of the
server, it's ready to calculate the session secrets. Section 4.2.8.2 of the RFC
[describes][16] how to interpret the keyshare's public key field for ECDHE
under X25519:

>   For X25519 and X448, the contents of the public value are the byte
>   string inputs and outputs of the corresponding functions defined in
>   [RFC7748]: 32 bytes for X25519 and 56 bytes for X448.

And RFC-7748 [described][17] how we can use this public key value:

>   Using their generated values and the received input, Alice computes
>   X25519(a, K_B) and Bob computes X25519(b, K_A).
>
>   Both now share K = X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9))
>   as a shared secret.  Both MAY check, without leaking extra
>   information about the value of K, whether K is the all-zero value and
>   abort if so (see below).  Alice and Bob can then use a key-derivation
>   function that includes K, K_A, and K_B to derive a symmetric key.

While it would be important to check for the zero-value in real-world
implementations, we won't require that here.

Using the shared secret (referred to as `K` above) and HKDF (as described [in
RFC 5869][19] and [on wikipedia][20] (with sample python implementation)) to
compute the Master Secret using the [following scheme][18]:

```
01             0
02             |
03             v
04   PSK ->  HKDF-Extract = Early Secret
05             |
06             +-----> Derive-Secret(., "ext binder" | "res binder", "")
07             |                     = binder_key
08             |
09             +-----> Derive-Secret(., "c e traffic", client Hello)
10             |                     = client_early_traffic_secret
11             |
12             +-----> Derive-Secret(., "e exp master", client Hello)
13             |                     = early_exporter_master_secret
14             v
15       Derive-Secret(., "derived", "")
16             |
17             v
18   (EC)DHE -> HKDF-Extract = Handshake Secret
19             |
20             +-----> Derive-Secret(., "c hs traffic",
21             |                     client Hello...server Hello)
22             |                     = client_handshake_traffic_secret
23             |
24             +-----> Derive-Secret(., "s hs traffic",
25             |                     client Hello...server Hello)
26             |                     = server_handshake_traffic_secret
27             v
28       Derive-Secret(., "derived", "")
29             |
30             v
31   0 -> HKDF-Extract = Master Secret
32             |
33             +-----> Derive-Secret(., "c ap traffic",
34             |                     client Hello...server Finished)
35             |                     = client_application_traffic_secret_0
36             |
37             +-----> Derive-Secret(., "s ap traffic",
38             |                     client Hello...server Finished)
39             |                     = server_application_traffic_secret_0
40             |
41             +-----> Derive-Secret(., "exp master",
42             |                     client Hello...server Finished)
43             |                     = exporter_master_secret
44             |
45             +-----> Derive-Secret(., "res master",
46                                   client Hello...client Finished)
47                                   = resumption_master_secret
```

Note that since we're not implementing the Pre-Shared Key (PSK) extension,
we'll need to follow the guidance around using the 0 PSK as described
[here][17]:

>   if PSK is not in use, Early Secret will still be HKDF-Extract(0, 0) ... if
>   no PSK is selected, it will then need to compute the Early Secret
>   corresponding to the zero PSK.

This ends up working in our favor, however, because it means that we can
precompute the value on line 15 that's fed into HKDF as a seed on line 18. It
is safe to precompute this, as it is invariant over all handshakes that do not
use a PSK. This means that computing the master secret becomes as simple as:

```
salt = Derive-Secret(HKDF-Extract(0, 0), "derived", "")
MasterSecret = Derive-Secret(HKDF-Extract(K, salt), "derived", "")
```

Where `K` is the handshake secret and `HKDF-Extract` and `HKDF-Expand` are
defined [like so][19]:

```
   HKDF-Extract(salt, IKM) -> PRK

   Options:
      Hash     a hash function; HashLen denotes the length of the
               hash function output in octets

   Inputs:
      salt     optional salt value (a non-secret random value);
               if not provided, it is set to a string of HashLen zeros.
      IKM      input keying material
```

and `Derive-Secret` is defined (indirectly) [like so][18]:

```
       Derive-Secret(Secret, Label, Messages) =
            HKDF-Expand-Label(Secret, Label,
                              Transcript-Hash(Messages), Hash.length)

       HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

       Where HkdfLabel is specified as:

       struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
       } HkdfLabel;
```

In particular, note how the HkdfLabel is constructed from the Label, Context,
and Length inputs to `HKDF-Expand-Label`. This will be needed later.

Transcript-Hash is defined [like so][21]:

```
Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
```

Note that, in general, when we're taking Message hashes, we're _excluding_ the
Record headers but _including_ the Message headers (as well as the Message
contents):

>   This value is computed by hashing the concatenation of each included
>   handshake message, including the handshake message header carrying the
>   handshake message type and length fields, but not including record layer
>   headers.
>   ...
>   For concreteness, the transcript hash is always taken from the
>   following sequence of handshake messages, starting at the first
>   client Hello and including only those messages that were sent:
>   client Hello, HelloRetryRequest, client Hello, server Hello,
>   EncryptedExtensions, server CertificateRequest, server Certificate,
>   server CertificateVerify, server Finished, EndOfEarlyData, client
>   Certificate, client CertificateVerify, client Finished.

Additionally, note that for the purposes of this project we will not be
sending/recieving any of:

- HelloRetryRequest
- second client Hello
- EncryptedExtensions
- server CertificateRequest
- client Certificate
- client CertificateVerify

and that at this point in the handshake, only the client Hello and server Hello
will be available for the transcript.

### Phase 4: Validate server: Certificate, CertificateVerify, and Finished

Now that both sides have exchanged their respective Hello messages and key
shares, the rest of the handshake can be encrypted under each party's public
key. So, subsequent records sent by the server will be encrypted using the
client's public key (i.e. the key sent in the intial client Hello message).

Unlike preceding plaintext handshake records, ecrypted handshake messages have
a record type of "application data" (`0x17`).

Encrypted application data records, described in [section 5.2 of RFC-8446][22],
have the following format (this includes the record header):

- record type (`0x17`, 1 byte)
- unused legacy protocol version (`0x0303`, 2 bytes)
- record data length (2 bytes)
- encrypted application data ciphertext (variable length)
- authentication tag (length depends on cipher, 16 bytes for AES GCM)

So, for each of this phase's messages, we'll need to decrypt the records in
order to parse the messages and validate their contents. Per our negotiated
ciphersuite, these records are encrypted using AES 128 GCM, so we know that
we'll need a master key and an IV. The calculation of these inputs is described
in [section 7.3 of RFC-8446][23]; you may recognize our old friend
`HKDF-Expand-Label` from Phase 3:

```
   [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
   [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
```

Because this is 128-bit AES, the key and IV lengths are 128 bits (i.e. 16
bytes). So, what do we use for the `Secret` passed into `HKDF-Expand-Label`?
Recall this excerpt from the graph in [section 7.1 of RFC-8446][18]:

```
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic",
             |                     client Hello...server Hello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s hs traffic",
             |                     client Hello...server Hello)
             |                     = server_handshake_traffic_secret
```

For decrypting encrypted records on the client side during the handshake, we
will use the server's derived secret labeled with "s hs traffic". Note that the
handshake keys and IVs are different for client and server. In order to
encrypt/decrypt both sides of the conversation, both client and server will
need to compute each others' symmetric cipher inputs. This is possible because
they both derive these secrets using the initial shared secret courtesy of
Diffie-Hellman, from which the common handshake secret is derived, from which
the client/server secrets are derived. The server uses the server secret to
encrypt records and the client uses the client secret to encrypt records, so
for decryption each party needs to use the other's secret to derive the
symmetric cipher inputs for decryption.

Once the client has established the server's handshake key and IV, they can
pass them, the ciphertext, and the authentication tag to a cryptography library
to perform decryption (and validation of the auth tag against the ciphertext,
ensuring integrity).

Now it's time to parse and validate the server's messages! As with prior
sections detailing message format, we will elide record and message headers
below.

The server Certificate message is given in the following format:

- request context (constant empty vector `0x00`, 1 bytes total)
- certificate list length, `n` certificates (3 bytes)
- certificate `0` length (3 bytes)
- certificate `0` data (variable length)
- certificate `1` length (3 bytes)
- certificate `1` data (variable length)
- ...
- certificate `n` length (3 bytes)
- certificate `n` data (variable length)

NOTE: the bytes representing each certificate are presented in a format we
haven't seen yet on this assignment: x509 encoded in ASN.1 DER. This steaming
bowl of alphabet soup is actually surprisingly simple (well, DER is relatively
simple type-length-value similar to TLS record encoding, but x509 is a bit more
intricate); feel free to use a library to parse it.

After parsing the certificate, we will need to check the following attributes
of the cert to determine whether the cert is valid:

1. Issuer Name matches provided CA
1. cert is temporally valid (i.e. current time is after Not Before and before
   Not After)
1. Subject Name matches client Hello's SNI
1. the Certificate trust chain is valid per the trusted CA pulic key cert
   inputted at the top-level of the project. we'll cover walking this trust
   chain in greater detail below.

The CertificateVerify message is used to tie the identity attested in the
certificate to the holder of the key exchange's (ephemeral!) private key. The
signature contained in CertificateVerify is computed using the server's ECDHE
private key over a `Transcript-Hash` (per requirements, using SHA-256) of all
preceeding handshake messages (including the server Certificate message). This
means that it (the signature in CertificateVerify) can be verified using the
server's ECDHE public key and independently computing a `Transcript-Hash` of
all previous handshake messages.

TODO: high-level description of walking trust chain from root to leaf.

The CertificateVerify message is given in the following format:

- signature type (constant `0x0807` for ed25519, 2 bytes)
- signature length (`0x40`, 2 bytes)
- signature data (64 bytes)

The server Finished message is used by the server to tell the client that it
has sent all of its handshake messages, and that if the client agrees on an
offered `Transcript-Hash` of handshake messages, the symmetric session has been
established and application data can be transmitted bilaterally.

The Finished messge has a single field, `verify_data`. [Section 4.4.4 of
RFC-8446][23] describes how this value is calculated:

```
   finished_key =
      HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
...
      verify_data =
          HMAC(finished_key,
               Transcript-Hash(Handshake Context,
                               Certificate*, CertificateVerify*))
```

And [section 4.4 of RFC-8446][25] describes how `BaseKey` for server Finished
is determined:

```
   The following table defines the Handshake Context and MAC Base Key
   for each scenario:

   +-----------+-------------------------+-----------------------------+
   | Mode      | Handshake Context       | Base Key                    |
   +-----------+-------------------------+-----------------------------+
   | Server    | ClientHello ... later   | server_handshake_traffic_   |
   |           | of EncryptedExtensions/ | secret                      |
   |           | CertificateRequest      |                             |
```

So, we are to use the server handshake secret as the `BaseKey`. Recall that we
derived this secret in Phase 3. Upon recieving the server Finished message, the
client needs to determine whether it is valid. It can do this by independently
computing what it believes to be the correct server Finished transcript hash,
computing HMAC over that transcript using the server's handshake secret (as
above), and comparing its expected server Finished against the actual server
Finished. If the two don't match, the server Finished is considered invalid and
the connection is aborted.

To guide implementation of this running-hash-over-context (which comes up many
times during the handshake), recall this excerpt from [section 4.4.1 of
RFC-8446][21]:

>   In general, implementations can implement the transcript by keeping a
>   running transcript hash value based on the negotiated hash.  Note,
>   however, that subsequent post-handshake authentications do not
>   include each other, just the messages through the end of the main
>   handshake.

The server Finished message is given in the following format:

- verify data (size of HMAC-SHA256 output, 32 bytes)

### Phase 5: Present client Finished

The client Finished message performs a similar function as server Finished --
it gives the server an authentic digest of the client's view of the handshake,
and allows the server to decide whether that digest matches expectation. The
server will compute an expected client Finished, and abort the handshake if the
actual client Finished differs from its expectations.

The client's `verify_data` is computed in the same way as the server's,
described in [Section 4.4.4 of RFC-8446][23]:

```
   finished_key =
      HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
...
      verify_data =
          HMAC(finished_key,
               Transcript-Hash(Handshake Context,
                               Certificate*, CertificateVerify*))
```

The only differences between client and server Finished messages are the
handshake context and which `BaseKey` is used to derive the HMAC's
`finished_key`. As before, the context and `BaseKey` are defined in the table
from [section 4.4 of RFC-8446][25]:

```
   The following table defines the Handshake Context and MAC Base Key
   for each scenario:

   +-----------+-------------------------+-----------------------------+
   | Mode      | Handshake Context       | Base Key                    |
   +-----------+-------------------------+-----------------------------+
   ...
   | Client    | ClientHello ... later   | client_handshake_traffic_   |
   |           | of server               | secret                      |
   |           | Finished/EndOfEarlyData |                             |
```

The client Finished message should be given in the following format:

- verify data (size of HMAC-SHA256 output, 32 bytes)


### Phase 6: Application Data

Coming Soon!


### Phase 7: Putting It All Together

Coming Soon!


# Scaffolding Problems

Byte arrays (referred to as `bytes` below) are given hex-encoded JSON strings
below, but the actual assignment will use BSON for stdin/stdout IO and `bytes`
objects for python auto-import grading. Likewise with the output bytes in the
example outputs.

TODO: add additional problems for testing record-encoded variants, perhaps in
Phase 7?

**DISCLAIMER:** At the time of this writing (10/7/2022), the scaffolding
problems below are still being implemented in the autograder, and are subject
to change pending finalization. We will notify the class and remove this
disclaimer when they're finalized (although, as always, Gradescope is the
ultimate "source of truth"). Until then, please update your local copy of this
specification regularly and keep an eye on #general for GitHub notifications
about updates to this repo.

## Phase 0: Record Encoding

1. `encoding` sub-problems:
    1. `uint32(x: int) -> bytes`: record-encode `x` as a 32-bit unsigned
       integer
    1. `uint8(x: int) -> bytes`: record-encode `x` as a 8-bit unsigned integer
    1. `uint16(x: int) -> bytes`: record-encode `x` as a 16-bit unsigned
       integer
    1. `byte_vectors(vecs: List[bytes]) -> List[bytes]`: record-encode vector
       in `vecs` as a variable-length vector
1. `record_header(record_type: bytes, version: bytes, size: int) -> bytes`:
   given `record_type` and `version` produce a record header for a record of
   size `size`.
1. `handshake_message_header(message_type: bytes, size: int) -> bytes`: for a
   given `message_type`, produce a handshake message header for a message of
   size `size`.

## Phase 1: Present client Hello

1. `client_version() -> bytes`: return the encoded client version
1. `client_random(size: int) -> bytes`: return `size` encodeded random bytes
1. `legacy_session_id() -> bytes`: return the encoded legacy session id
1. `supported_cipher_suites() -> bytes`: return the encoded supported cipher
   suite
1. `legacy_compression_methods() -> bytes`: return the encoded legacy
   compression methods
1. `extensions_length() -> bytes`: return the encoded length of extensions
    - NOTE: this must correspond to the sum of the responses to the
      `extensions` subproblems below
1. `extensions` sub-problems:
    1. `supported_versions() -> bytes`: retrun the encoded supported version
    1. `server_name(name: str) -> bytes`: convert string `name` into encoded
       and padded-out server name extension value
        - NOTE: the `name` input is a normal string, and is not hex-encoded
    1. `supported_groups() -> bytes`:  return the encoded supported kex group
    1. `key_share() -> bytes`: generate a client key share, encode it, and
       return it

## Phase 2: Validate server Hello

1. `legacy_version(candidate: bytes) -> bool`: return true if `candidate` is
   valid, else false
1. `server_random(candidate: bytes) -> bool`: return true if `candidate` is
   valid (i.e. the correct size), else false
1. `legacy_session_id_echo(candidate: bytes) -> bool`: return true if
   `candidate` is valid, else false
1. `legacy_compression_method(candidate: bytes) -> bool`: return true if
   `candidate` is valid, else false
1. `extensions_length(candidate: bytes) -> bool`: return true if `candidate` is
   valid, else false
    - NOTE: this must correspond to the sum of the lengths of the provided
      extensions candidates detailed below
1. `extensions` sub-problems:
    1. `supported_versions(candidate: bytes) -> bool`: return true if
       `candidate` is valid, else false
    1. `key_share(candidate: bytes) -> bool`: return true if `candidate` is
       valid, else false

## Phase 3: Calculate Session Secrets

1. `hkdf_extract(salt: bytes, keying_material: bytes) -> bytes`: return the
   output of calling `HKDF-Extract` on `salt` and `keying_material`.
1. `hkdf_expand(key: bytes, context: bytes, out_len: bytes) -> bytes`: return
   the output of calling `HKDF-Expand` on `key` and `context` truncated at
   `out_len` bytes
1. `transcript_hash(hash_algorithm: str, messages: List[bytes])`: return a
   transcript hash over `messages` using `hash_algorithm`.
    - NOTE: `hash_algorithm` will only ever be `SHA256` in this assignment
    - NOTE: each `bytes` object in `messages` **will contain Record headers**
      that you'll need to strip out before digesting.
1. `hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int)
   -> bytes` return the output of `HKDF-Expand-Label` called on the given input.
1. `derive_secret(secret: bytes, label: bytes, messages: List[bytes]) -> bytes`
   return the output of `Derive-Secret` called on the given inputs.
    - NOTE: each `bytes` object in `messages` **will contain Record headers**
      that you'll need to strip out before digesting.
    - NOTE: you'll need to construct the HkdfLabel struct from the `label`
      input yourself as described in section [7.1 of RFC-8446][18].
1. `compute_secrets(client_hello: bytes, server_hello: bytes) -> ...`:
    1. `shared_secret`: shared secret computed with ECDHE given client and
       server keyshares
    1. `early_secret`: pre-computable (i.e. invariant) Early Secret
    1. `handshake_secret`: output of `HKDF-Extract` salted by `early_secret`
       and keyed with `shared_secret`
    1. `client_handshake_secret`: output of `Derive-Secret` keyed by
       `handshake_secret` with label `c hs traffic` and a `Transcript-Hash`
       over all prior messages.
    1. `server_handshake_secret`: output of `Derive-Secret` keyed by
       `handshake_secret` with label `s hs traffic` and a `Transcript-Hash`
       over all prior messages.
    1. `master_secret`: output of `HKDF-Extract` salted by
       `Derive-Secret(handshake_secret, ...)` and keyed with `0`

## Phase 4: Validate server Finished, server Certificate, and CertificateVerify

Coming Soon!

## Phase 5: Present client Finished

Coming Soon!

## Phase 6: Application Data

Coming Soon!

## Phase 7: Putting It All Together

Coming Soon!

## Example Input

```json
{
    "phase0": {
        "encoding": {
            "uint32": 7,
            "uint8": 0,
            "uint16": 11,
            "byte_vectors": [
                "ffffff",
                "010101"
            ]
        },
        "record_header": {
            "record_type": "16",
            "version": "0304",
            "size": 200
        },
        "handshake_message_header": {
            "message_type": "01",
            "size": 200
        }
    },
    "phase1": {
        "client_version": null,
        "client_random": 32,
        "legacy_session_id": null,
        "supported_cipher_suites": null,
        "legacy_compression_methods": null,
        "extensions_length": null,
        "extensions": {
            "supported_versions": null,
            "server_name": "localhost",
            "supported_groups": null,
            "key_share": null,
        }
    },
    "phase2": {
        "legacy_version": "0303",
        "server_random": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "legacy_session_id_echo": "00",
        "cipher_suite": "021301",
        "legacy_compression_method": "00",
        "extensions_length": "TODO",
        "extensions": {
            "supported_versions": "002b0003020304",
            "key_share": "TODO",
        }
    },
    "phase3": {
        "hkdf_extract": {
            "salt": "TODO",
            "keying_material": "TODO",
        },
        "hkdf_expand": {
            "key": "TODO",
            "context": "TODO",
            "out_len": 0
        },
        "transcript_hash": {
            "hash_algorithm": "SHA256",
            "messages": [
                "TODO client Hello",
                "TODO server Hello"
            ]
        }
        "hkdf_expand_label": {
            "secret": "TODO",
            "label": "TODO",
            "context": "TODO",
            "length": 0,
        },
        "derive_secret": {
            "secret": "TODO",
            "label": "TODO",
            "messages": ["TODO"]
        },
        "compute_secrets": {
            "client_hello": "TODO",
            "server_hello": "TODO"
        }
    },
    "phase4": {"TODO": true},
    "phase5": {"TODO": true},
    "phase6": {"TODO": true},
    "phase7": {"TODO": true}
}
```

## Example Output

**DISCLAIMER:** At the time of this writing (10/7/2022), some of the sample
output below is hand-written and thus subject to minor, potential inaccuracies.
This disclaimer will be removed once sample outputs are populated with
programmatically generated values, providing higher degrees of assurance.i We
will notify the class and remove this disclaimer when they're finalized
(although, as always, Gradescope is the ultimate "source of truth"). Until
then, please update your local copy of this specificaiton regularly and keep an
eye on #general for GitHub notifications about updates to this repo.

```json
{
    "phase0": {
        "encoding": {
            "uint32": "000007",
            "uint8": "00",
            "uint16": "00xb",
            "byte_vectors": [
                "03ffffff",
                "03010101"
            ]
        },
        "record_header": "16030400c8",
        "handshake_message_header": "010000c8"
    },
    "phase1": {
        "client_version": "0303",
        "client_random": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "legacy_session_id": "00",
        "supported_cipher_suites": "021301",
        "legacy_compression_methods": "1000",
        "extensions_length": "TODO",
        "extensions": {
            "supported_versions": "002b0003020304",
            "server_name": "0000001a00180000096c6f63616c686f7374",
            "supported_groups": "02001d",
            "key_share": "TODO"
        }
    },
    "phase2": {
        "legacy_version": true,
        "server_random": true,
        "legacy_session_id_echo": true,
        "cipher_suite": true,
        "legacy_compression_method": true,
        "extensions_length": true,
        "extensions": {
            "supported_versions": true,
            "key_share": true
        }
    },
    "phase3": {
        "hkdf_extract": "TODO",
        "hkdf_expand": "TODO",
        "transcript_hash": "TODO",
        "hkdf_expand_label": "TODO",
        "derive_secret": "TODO",
        "compute_secrets": {
            "shared_secret": "TODO",
            "early_secret": "TODO",
            "handshake_secret": "TODO",
            "client_handshake_secret": "TODO",
            "server_handshake_secret": "TODO",
            "master_secret": "TODO"
        }
    },
    "phase4": {"TODO": true},
    "phase5": {"TODO": true},
    "phase6": {"TODO": true},
    "phase7": {"TODO": true}
}
```

## CLI


```
$ ./project -h
usage: ./project [-h] [-v] [-c <trust_store_path> <server_hostname> <port>]

If no options are specified, operate in scaffolding mode, and recieve
communicate scaffolding input/output over stdin/stdout (bson-encoded) or, if
you're using python, expect your various `phase` functions to be auto-imported
and evaluated by the autograder.


In client mode, you and initiate a TLS 1.3
connection to <server_hostname> on <port>. Challenge input should be read as
raw bytes from stdin and the challenge response's signature should be written
to stdout.

-c  operate in client mode, the required parameters are:

    <trust_store_path>  path to the DER-encoded (`.crt` in OpenSSL-land) trust
                        store
    <server_hostname>   hostname to connect to
    <server_port>       port to connect to


-h  show this help message and exit

-v  verbose logging of handshake steps, optional to implement but will help
    with debugging.
```



[1]: https://www.rfc-editor.org/rfc/rfc8446
[2]: https://tls13.xargs.org/
[3]: https://blog.cloudflare.com/rfc-8446-aka-tls-1-3/
[4]: https://www.rfc-editor.org/rfc/rfc8446#page-27
[5]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2
[6]: https://lapo.it/asn1js/
[7]: https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
[8]: https://www.rfc-editor.org/rfc/rfc8446#section-3.3
[9]: https://www.rfc-editor.org/rfc/rfc8446#section-3.4
[10]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
[11]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7
[12]: https://en.wikipedia.org/wiki/Curve25519
[13]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8
[14]: https://www.rfc-editor.org/rfc/rfc6066#section-3
[15]: https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
[16]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2
[17]: https://www.rfc-editor.org/rfc/rfc7748#section-6.1
[18]: https://www.rfc-editor.org/rfc/rfc8446#section-7.1
[19]: https://www.rfc-editor.org/rfc/rfc5869
[20]: https://en.wikipedia.org/wiki/HKDF
[21]: https://www.rfc-editor.org/rfc/rfc8446#section-4.4.1
[22]: https://www.rfc-editor.org/rfc/rfc8446#section-5.2
[23]: https://www.rfc-editor.org/rfc/rfc8446#section-7.3
[24]: https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4
[25]: https://www.rfc-editor.org/rfc/rfc8446#section-4.4
