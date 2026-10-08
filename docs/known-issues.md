# Known issues

Defects and design limitations found by review of the published source. Line
references are against the current `main`. Nothing here is a report of
exploitation in the field; these are code-reading findings, published so that
anyone building on the applet can judge the risk themselves.

Severity reflects impact on a deployed device, assuming the applet sits behind a
GlobalPlatform secure channel as intended.

| # | Severity | Issue | Location |
| --- | --- | --- | --- |
| 1 | High | Input and output buffers alias during chained sign and decrypt | `IoTSafeApplet.java:1063,1072,1150` |
| 2 | High | Reseeding the random generator needs no authentication | `IoTSafeApplet.java:956` |
| 3 | Medium | TLV length octets `80`–`FF` are sign-extended | `PKIUtil.java:59` |
| 4 | Medium | All applet state is static | `IoTSafeApplet.java:49-101` |
| 5 | Medium | Object identifiers are 7 bytes of a chained-CBC digest | `PKIObject.java:100-118` |
| 6 | Low | Raw RSA sign and decrypt unreachable without chaining | `IoTSafeApplet.java:1004,1109` |
| 7 | Low | `encodeLength` mis-encodes a length of exactly 256 | `PKIUtil.java:121` |
| 8 | Low | GET RESPONSE with no pending data throws through an unguarded path | `IoTSafeApplet.java:201` |
| 9 | Low | CANCEL AUTHENTICATION on an inactive credential returns `6999` | `IoTSafeApplet.java:1778,1785` |
| 10 | Low | Object info data readable without authentication | `IoTSafeApplet.java:888` |
| 11 | Low | AES-CBC key wrapping uses an all-zero IV | `IoTSafeApplet.java:1203` |
| 12 | Info | Duplicate status words make failures ambiguous | `IoTSafeDeclarations.java:229-245` |
| 13 | Info | Package AID sits under Oracle's RID | `configurations/IoTSafeApplet.conf` |

---

## 1. Input and output buffers alias during chained sign and decrypt

`chainingIncomingDataBuffer` is assigned `workingBuffer`
(`IoTSafeApplet.java:131`), so the two names refer to one array. On the chained
path, `signData` and `decryptData` read their input from
`chainingIncomingDataBuffer` while writing their output to `workingBuffer` at
offset 0 — the same array, with overlapping regions:

```java
sigLength = tmpSignature.sign(tmpBuf, tmpOffset, tmpDataLength,
                              workingBuffer, (short) 0);
```

Java Card does not define behaviour when a `Signature` or `Cipher` input range
overlaps its output range. Implementations may throw, silently truncate, or
produce a corrupt result. Because raw RSA operations are reachable *only* via
chaining (issue 6), every raw RSA signature and decryption on this applet takes
this path.

**Fix direction:** give the chained path its own output buffer, or copy the
input out of `workingBuffer` before the call.

## 2. Reseeding the random generator needs no authentication

`setSeed` (INS `58`) calls `checkPinAuthentication` nowhere, so any caller with
APDU access can mix chosen bytes into the generator that subsequently produces
AES keys (`ObjectManager.generateSecretKey`) and the per-card object identifier
key (`ObjectManager` constructor).

A conformant `ALG_SECURE_RANDOM` implementation mixes a seed into existing
entropy rather than replacing it, which limits this considerably, but the
guarantee is platform-specific and should not be relied on.

**Fix direction:** require PIN or PUK authentication, or remove the command and
rely on the platform's own entropy.

## 3. TLV length octets `80`–`FF` are sign-extended

In the long form with one length octet:

```java
length = (short)(tlvBuffer[(short)(offset + 2)]);
```

A Java `byte` is signed, so `0x80`–`0xFF` yield −128 to −1 rather than 128 to
255. The negative length reaches `setModulus`, `setW` or `setS` and surfaces as
`6A80`. In practice this breaks import of any value of 128 to 255 bytes encoded
with `81 xx` — which includes a 2048-bit RSA modulus, if the host chooses that
encoding. The two-octet form `82 xx xx` goes through `Util.makeShort` and is
unaffected.

**Fix direction:** mask with `& 0xFF`.

`getLength` also performs no bounds check that tag, length and value lie within
the supplied buffer. Out-of-range values currently land in the broad
`catch (Exception)` in the store paths and become `6A80`, so this is contained,
but it relies on the catch rather than on validation.

## 4. All applet state is static

PINs, key stores, cipher and signature instances, chaining buffers and the
object manager singleton are all `static` fields of `IoTSafeApplet` and
`ObjectManager`. In Java Card, statics belong to the package, not the applet
instance, so two instances installed from this CAP would share one PIN, one PUK
and one set of keys — authenticating to either would unlock the other's objects.

**Mitigation today:** install exactly one instance per card.
**Fix direction:** move state to instance fields and keep only genuinely
immutable data static.

## 5. Object identifiers are 7 bytes of a chained-CBC digest

`generateObjectID` hashes the key or certificate material with SHA-256,
encrypts the digest with a card-unique 2-key 3DES key, and keeps the class byte
plus the first 7 bytes. Two consequences:

- Seven bytes is a 56-bit space. Collisions are unlikely by accident but are not
  prevented by construction; the duplicate check (`6A81`) rejects a colliding
  object outright, so a collision presents as an object that cannot be stored.
- The cipher is used via `update` on a CBC instance that is re-initialised per
  call but never finalised. Behaviour is deterministic per card, which is what
  the design needs, but using `doFinal` and an explicit IV would make that
  intent explicit rather than incidental.

Identifiers are derived from key material and are therefore not secret-bearing
in any useful way, but they are also not host-selectable, which some
provisioning stacks expect.

## 6. Raw RSA sign and decrypt unreachable without chaining

Both paths require the input to be exactly 256 bytes
(`CIPHER_RSA_2048_NOPAD_BLOCK_LENGTH`), and both compute the payload length as
`Lc − 8` to account for the object identifier. A single APDU caps `Lc` at 255,
giving at most 247 payload bytes, so the unchained branch always answers `6700`.
Only the chained path can satisfy the check — and that path hits issue 1.

**Fix direction:** no behaviour change needed if chaining is the intended
interface; document it, and consider rejecting the unchained form with a clearer
status word.

## 7. `encodeLength` mis-encodes a length of exactly 256

```java
if (lengthToEncode > 0x100) {   // two length octets
```

For `lengthToEncode == 0x100` the comparison is false, so the one-octet branch
runs and writes `(byte) 0x100`, which is `0x00` — a declared length of zero. The
boundary should be `>= 0x100`, or equivalently `> 0xFF`.

`encodeLength` is not called from any current code path, so this is latent.

## 8. GET RESPONSE with no pending data throws through an unguarded path

The GET RESPONSE branch runs before the CLA check and before the `try` block
that converts exceptions into status words. With no response pending,
`chainingOutgoingBuffer` is null and `sendData` dereferences it; the exception
escapes `process()` and the platform answers `6F00` rather than a meaningful
status word.

**Fix direction:** return `6985` or `6700` when nothing is pending.

## 9. CANCEL AUTHENTICATION on an inactive credential returns `6999`

`cancelAuthentication` calls `userPin.isValidated()` and `puk.isValidated()`
without the null checks every other command performs. On a card where the
credential was never activated this throws, is caught by the general handler,
and becomes `6999` instead of `6985`.

## 10. Object info data readable without authentication

`LIST OBJECTS` deliberately withholds private and secret key identifiers from
an unauthenticated caller, but `GET OBJECT INFO DATA` (INS `36`) performs no PIN
check. A caller who learns an identifier by other means can read the label
attached to a private or secret key. The key material itself stays protected.

**Fix direction:** require authentication when the identifier's class byte
denotes a private or secret key, matching `LIST OBJECTS`.

## 11. AES-CBC key wrapping uses an all-zero IV

`CIPHER_MODE_WRAP_INIT` initialises the CBC cipher with no initialisation
vector, so Java Card uses an all-zero IV. Wrapping identical plaintext under
one key always yields identical ciphertext, which leaks equality of wrapped
values. ECB mode (`03`) has the same property by definition and additionally
leaks block-level structure.

**Fix direction:** accept an IV in the init command, or derive a fresh wrapping
key per operation.

## 12. Duplicate status words make failures ambiguous

`SW_WRONG_DATA`, `SW_OBJECT_NOT_AVAILABLE` and `SW_PIN_PUK_WRONG_SIZE` are all
`6A80`; `SW_PIN_ALREADY_ACTIVATED` and `SW_PIN_NOT_ACTIVATED` are both `6985`.
A host cannot distinguish "no such object" from "malformed data", or "already
activated" from "not activated", which complicates provisioning diagnostics.

## 13. Package AID sits under Oracle's RID

The package and applet AIDs begin `A0 00 00 00 62`, Oracle's registered
identifier for Java Card samples. This is fine for development and will collide
with nothing in a lab, but a deployed applet should use an AID under a RID its
owner controls.

---

## Reporting something not listed here

For a defect with security impact, follow [SECURITY.md](../SECURITY.md) instead
of opening a public issue. For everything else, an issue with the APDU trace
that reproduces it is the most useful thing you can send.
