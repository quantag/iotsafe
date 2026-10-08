# IoT SAFE Applet — APDU reference

Complete command set of the applet, as implemented in `IoTSafeApplet.process()`
and defined in `IoTSafeDeclarations`. All values are hexadecimal.

- [Class byte and command chaining](#class-byte-and-command-chaining)
- [Command summary](#command-summary)
- [PIN and PUK management](#pin-and-puk-management)
- [Object management](#object-management)
- [Key generation and import](#key-generation-and-import)
- [Cryptographic operations](#cryptographic-operations)
- [Random numbers and applet info](#random-numbers-and-applet-info)
- [Parameter encodings](#parameter-encodings)
- [Status words](#status-words)
- [Limits](#limits)

---

## Class byte and command chaining

| CLA | Meaning |
| --- | --- |
| `80` | Last or only command of a chain |
| `B0` | Non-last command of a chain |

Any other CLA is rejected with `6E00`.

**Incoming chaining.** Send the leading blocks with CLA `B0` and the final block
with CLA `80`. The INS of every block must match the one that opened the chain,
or the applet answers `6992`; P1 and P2 are read only from the opening block and
are ignored thereafter. Only `4A` (store certificate), `42` (store
private key), `44` (store public key), `50` (sign) and `52` (decrypt) accept
chaining; anything else answers `6991`. For store-certificate the total length
is carried in P1||P2 of each block, and the applet allocates a buffer of exactly
that size; for the other four, blocks accumulate in a 768-byte transient buffer.

**Outgoing chaining.** When a response exceeds 256 bytes the applet returns the
first block with `61 xx`, where `xx` is the number of bytes still pending (`00`
meaning 256 or more). Retrieve the remainder with GET RESPONSE — INS `C0` or the
applet-specific `A0`, both with P1 = P2 = `00`.

> Issue a GET RESPONSE only when a preceding command reported bytes remaining.
> With no pending response the command dereferences a null buffer and the
> platform answers `6F00`.

## Command summary

| INS | Command | PIN required | Chaining |
| --- | --- | --- | --- |
| `20` | VERIFY PIN | — | — |
| `22` | ACTIVATE PIN / PUK | PUK, for PIN activation | — |
| `24` | CHANGE PIN / PUK | proves PIN or PUK in-command | — |
| `26` | CANCEL AUTHENTICATION | — | — |
| `28` | GET PIN STATUS | — | — |
| `30` | LIST OBJECTS | partial — see below | — |
| `32` | DELETE OBJECT | yes | — |
| `34` | SET OBJECT INFO DATA | yes | — |
| `36` | GET OBJECT INFO DATA | — | — |
| `38` | GET PUBLIC KEY DATA | — | — |
| `3A` | GET PRIVATE KEY DATA | yes | — |
| `3C` | GET CERTIFICATE DATA | — | — |
| `40` | GENERATE KEY PAIR | yes | — |
| `42` | STORE PRIVATE KEY | yes | yes |
| `44` | STORE PUBLIC KEY | yes | yes |
| `46` | GENERATE SECRET KEY | yes | — |
| `48` | STORE SECRET KEY | yes | — |
| `4A` | STORE CERTIFICATE | yes | yes |
| `50` | SIGN | yes | yes |
| `52` | DECRYPT | yes | yes |
| `54` | WRAP / UNWRAP | yes | — |
| `58` | SET SEED | **no** | — |
| `70` | GET APPLET VERSION | — | — |
| `84` | GET RANDOM | — | — |
| `A0`, `C0` | GET RESPONSE | — | — |

---

## PIN and PUK management

Both the user PIN and the PUK are `OwnerPIN` objects, 4 to 8 bytes, with a
retry counter fixed at activation. Verification state is cleared on deselect and
on card reset.

### VERIFY PIN — `80 20 P1 00 Lc <value>`

| P1 | Target |
| --- | --- |
| `00` | User PIN |
| `01` | PUK |

On failure the applet returns `63 Cx`, where `x` is the number of attempts left
(capped at `F`). At zero attempts remaining it returns `63 C0` without
comparing. If the target is not yet activated, `6985`.

### ACTIVATE PIN / PUK — `80 22 P1 00 Lc <size> <retries> <value>`

| P1 | Action | Precondition |
| --- | --- | --- |
| `00` | Activate the user PIN | PUK must be activated **and** verified |
| `01` | Activate the PUK | none |

`Lc` must equal `2 + size`, and `size` must be 4 to 8. An already-activated
target returns `6985`; neither PIN can be re-activated, only changed.

> Activating the PUK requires no authentication, by design, so that a virgin
> card can be taken over during personalisation. Perform this step in a
> controlled environment, or behind a GlobalPlatform secure channel, before the
> card reaches the field.

### CHANGE PIN / PUK — `80 24 P1 00 Lc <current> <newSize> <new>`

| P1 | Action | Credential proved in `<current>` |
| --- | --- | --- |
| `00` | Change the user PIN | current user PIN |
| `01` | Change the PUK | current PUK |
| `02` | Reset the user PIN | current PUK |

`<current>` is a bare value with no length prefix — the applet reads exactly as
many bytes as the stored credential currently occupies, then takes the next byte
as `newSize`. A wrong-length failure therefore surfaces as `63 Cx`, not `6700`.

### CANCEL AUTHENTICATION — `80 26 P1 00 00`

Drops verification state: P1 `00` user PIN, `01` PUK, `02` both.

> Against a card whose PIN or PUK has never been activated this command
> dereferences a null object and returns `6999`.

### GET PIN STATUS — `80 28 P1 00 Lc`

| P1 | Response |
| --- | --- |
| `00` | 4 bytes, user PIN |
| `01` | 4 bytes, PUK |
| `02` | 8 bytes, user PIN then PUK |

Each 4-byte group is: activated (`00`/`01`), initial retry counter, remaining
tries, verified (`00`/`01`). An inactive credential reports four zero bytes.

---

## Object management

### LIST OBJECTS — `80 30 00 00 00`

Returns the concatenated 8-byte identifiers of the objects on the card:
certificates and public keys always; private and secret keys **only** when the
user PIN is verified. Response length is a multiple of 8.

### DELETE OBJECT — `80 32 00 00 08 <objectID>`

The class byte of the identifier selects the store to delete from. Deleting one
half of a key pair leaves the other in place.

### SET OBJECT INFO DATA — `80 34 00 00 Lc <objectID> <info>`

Attaches up to 240 bytes of free-form data — a label, a URI — to an existing
object. `Lc` covers identifier and data together.

### GET OBJECT INFO DATA — `80 36 00 00 08 <objectID>`

Returns the data set above.

> This command performs no PIN check, so the info data of a private or secret
> key can be read without authentication by a caller that knows the identifier.
> LIST OBJECTS deliberately withholds those identifiers when unauthenticated.

### GET CERTIFICATE DATA — `80 3C 00 00 08 <objectID>`

Returns the stored certificate, with outgoing chaining for anything over 256
bytes.

### GET PUBLIC KEY DATA — `80 38 P1 00 08 <objectID>`

| P1 | Returns | Valid for |
| --- | --- | --- |
| `01` | Modulus | RSA public key |
| `02` | Public exponent | RSA public key |
| `03` | Public point W, uncompressed | EC public key |

### GET PRIVATE KEY DATA — `80 3A 01 00 08 <objectID>`

P1 `01` returns the modulus of an RSA private key; this is the only supported
parameter, and no private exponent or EC scalar can be read out.

---

## Key generation and import

### GENERATE KEY PAIR — `80 40 <keyType> <curve> 00`

Generates on-card and returns 16 bytes: the private key identifier followed by
the public key identifier. See [parameter encodings](#parameter-encodings) for
the key type and curve bytes; `<curve>` must be `00` for RSA.

### STORE PRIVATE KEY — `80 42 <keyType> <curve> Lc <TLV…>`

| Key | Expected TLV sequence |
| --- | --- |
| RSA | `10` modulus, then `12` private exponent |
| EC | `14` private scalar S |

Returns the 8-byte identifier. Curve parameters are set from `<curve>` before
the imported material is applied.

### STORE PUBLIC KEY — `80 44 <keyType> <curve> Lc <TLV…>`

| Key | Expected TLV sequence |
| --- | --- |
| RSA | `10` modulus, then `11` public exponent |
| EC | `13` public point W, uncompressed |

Returns the 8-byte identifier.

### GENERATE SECRET KEY — `80 46 <keyType> 00 00`

`<keyType>` is `06` (AES-128) or `07` (AES-256). Returns the 8-byte identifier.

### STORE SECRET KEY — `80 48 <keyType> 00 Lc 15 <len> <key>`

Imports an AES key under tag `15`. The applet zeroes the command data after
reading it. Returns the 8-byte identifier.

### STORE CERTIFICATE — `80 4A <lenHi> <lenLo> Lc <certificate>`

P1||P2 carries the **total** certificate length, which must match `Lc` for a
single-APDU store, or the sum of the chained blocks. Returns the 8-byte
identifier. Rejected with `6A84` if storing the certificate would leave less
than 10 240 bytes of persistent memory free.

Certificates larger than 255 bytes — which is to say all realistic ones —
require incoming chaining:

```
B0 4A 02 10 FF <first 255 bytes>      # total length 0x0210 = 528
B0 4A 02 10 FF <next 255 bytes>
80 4A 02 10 12 <final 18 bytes>       # CLA 80 closes the chain
```

---

## Cryptographic operations

### SIGN — `80 50 <algorithm> 00 Lc <objectID> <data>`

| `<algorithm>` | Scheme | Input |
| --- | --- | --- |
| `01` | RSA-2048 raw | Exactly 256 bytes, pre-padded by the host |
| `02` | ECDSA with SHA-224 | Message, hashed on card |
| `03` | ECDSA with SHA-256 | Message, hashed on card |
| `04` | ECDSA with SHA-384 | Message, hashed on card |
| `05` | ECDSA with SHA-512 | Message, hashed on card |
| `06` | ECDSA over a supplied hash | Pre-computed digest |

Algorithm `06` uses the proprietary `ALG_ECDSA_NONE` (`0x66`) and is available
only on platforms that implement it. A key that cannot support the requested
scheme answers `6A83`.

> Raw RSA signing needs a 256-byte input plus the 8-byte identifier, which
> exceeds the 255-byte limit of a single command: algorithm `01` is reachable
> **only** through incoming chaining.

### DECRYPT — `80 52 01 00 Lc <objectID> <ciphertext>`

P1 `01` selects RSA-2048 without padding; the ciphertext must be exactly 256
bytes, so this command is likewise reachable only through chaining. The host is
responsible for removing padding from the result.

### WRAP / UNWRAP — `80 54 <algorithm> <mode> Lc <data>`

| `<algorithm>` | Cipher |
| --- | --- |
| `02` | AES-128 CBC, no padding |
| `03` | AES-128 ECB, no padding |

| `<mode>` | Data | Effect |
| --- | --- | --- |
| `01` | 8-byte object ID | Initialise for wrapping |
| `02` | 8-byte object ID | Initialise for unwrapping |
| `03` | Block-aligned payload | Process a block, return output |
| `04` | Block-aligned payload | Process the final block, return output |

Payloads for modes `03` and `04` must be a multiple of 16 bytes. The cipher
holds its state between commands, so an init must precede the first update, and
the whole sequence must run within one card session.

> CBC mode takes no initialisation vector, so it operates with an all-zero IV.
> Wrapping the same plaintext under the same key always yields the same
> ciphertext. Treat the output accordingly, or derive a per-operation key.

---

## Random numbers and applet info

### GET RANDOM — `80 84 00 00 Le`

Returns `Le` random bytes, 1 to 256 (`Le = 00` meaning 256).

### SET SEED — `80 58 00 00 Lc <seed>`

Mixes the supplied bytes into the on-card generator.

> This command requires no authentication. Anyone with APDU access can
> influence the generator that produces AES keys and object identifiers.
> Treat it as a provisioning-time command and block it in the field.

### GET APPLET VERSION — `80 70 00 00 00`

Returns two bytes: major, then minor. The current applet reports `01 15`.

---

## Parameter encodings

### Key types

| Value | Key |
| --- | --- |
| `01` | RSA-2048 |
| `02` | EC over F<sub>p</sub>, 224 bit |
| `03` | EC over F<sub>p</sub>, 256 bit |
| `04` | EC over F<sub>p</sub>, 384 bit |
| `05` | EC over F<sub>p</sub>, 521 bit (built as 528 bit for Infineon products) |
| `06` | AES-128 |
| `07` | AES-256 |

### Curves

| Value | Curve | Valid with key type |
| --- | --- | --- |
| `00` | none | `01` (RSA) |
| `01` | secp224k1 | `02` |
| `02` | secp224r1 | `02` |
| `03` | secp256k1 | `03` |
| `04` | secp256r1 | `03` |
| `05` | secp384r1 | `04` |
| `06` | secp521r1 | `05` |

A mismatched key type and curve is rejected with `6A86`.

### Object classes

The first byte of every object identifier.

| Value | Class |
| --- | --- |
| `01` | RSA private key |
| `02` | RSA public key |
| `03` | EC private key |
| `04` | EC public key |
| `05` | AES secret key |
| `06` | X.509 certificate |

### TLV tags

| Tag | Content |
| --- | --- |
| `10` | RSA modulus |
| `11` | RSA public exponent |
| `12` | RSA private exponent |
| `13` | EC public point W, uncompressed |
| `14` | EC private scalar S |
| `15` | AES key value |

Lengths use DER definite-length encoding, short or long form, with at most two
length octets.

> A long-form single length octet of `80`–`FF` is read as a signed value and
> comes out negative. Keep imported values below 128 bytes, or use the two-octet
> long form (`82 xx xx`). See [known-issues.md](known-issues.md).

---

## Status words

| SW | Meaning |
| --- | --- |
| `9000` | Success |
| `61xx` | Success, `xx` bytes pending — issue GET RESPONSE |
| `63Cx` | PIN or PUK verification failed, `x` attempts remaining |
| `6700` | Wrong length |
| `6982` | Security status not satisfied — PIN or PUK not verified |
| `6985` | Credential already activated, or not yet activated |
| `6991` | Command does not support chaining |
| `6992` | INS does not match the chain in progress |
| `6999` | Unexpected internal state |
| `6A80` | Wrong data, object not found, or invalid PIN size |
| `6A81` | An object with the same identifier already exists |
| `6A82` | Data cannot be unwrapped |
| `6A83` | Signature scheme unavailable for the selected key |
| `6A84` | Not enough memory |
| `6A86` | P1 or P2 not supported |
| `6D00` | INS not supported |
| `6E00` | CLA not supported |

Note that `6A80` and `6985` are each reused for several distinct conditions, so
a host cannot always tell them apart from the status word alone.

## Limits

| Property | Value |
| --- | --- |
| Objects per class | 20 |
| Object identifier length | 8 bytes |
| PIN and PUK length | 4 to 8 bytes |
| User info data per object | 240 bytes |
| Certificate size | bounded by free memory, 10 240 bytes held in reserve |
| Transient working buffer | 768 bytes |
| Maximum response per APDU | 256 bytes, then outgoing chaining |
