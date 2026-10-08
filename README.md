# IoT SAFE Applet

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform: Java Card 3.1](https://img.shields.io/badge/Java%20Card-3.1-orange.svg)](https://www.oracle.com/java/java-card/)
[![Status: reference implementation](https://img.shields.io/badge/status-reference%20implementation-yellow.svg)](#project-status)

A Java Card applet that turns a SIM, eSIM or embedded secure element into a
hardware root of trust for IoT devices, in the spirit of the GSMA **IoT SAFE**
(IoT SIM Applet For Secure End-to-End Communication) model: keys are generated
and used inside the tamper-resistant element, and private keys never leave it.

Developed by [Quantag IT Solutions GmbH](https://quantag-it.com) and released
under the Apache License 2.0.

---

## What it does

The applet exposes a PKCS#11-like object store and a set of cryptographic
operations over ISO 7816-4 APDUs:

| Capability | Detail |
| --- | --- |
| Key generation | RSA-2048, EC over F<sub>p</sub> (224/256/384/521 bit), AES-128/256 |
| Key import | RSA and EC public and private keys, AES secret keys, as TLV |
| Signing | ECDSA with SHA-224/256/384/512, ECDSA over a pre-computed hash, raw RSA-2048 |
| Decryption | RSA-2048 (no padding — the host applies and strips padding) |
| Key wrapping | AES-128 in CBC or ECB, no padding, as a multi-step init/update/final flow |
| Certificates | Store, retrieve and delete X.509 certificates, with APDU chaining for large files |
| Object model | Up to 20 objects per class, each addressed by an 8-byte object identifier |
| Access control | User PIN and PUK via `OwnerPIN`, with retry counters and lifecycle commands |
| Randomness | On-card secure random number generation and reseeding |

Supported curves: `secp224k1`, `secp224r1`, `secp256k1`, `secp256r1`,
`secp384r1`, `secp521r1`.

The complete command set — every INS, P1/P2 combination, data format and status
word — is documented in **[docs/apdu-reference.md](docs/apdu-reference.md)**.

## Repository layout

```
iot-safe-applet/          Java Card applet (the product)
  src/com/consec/iotsafe/
    IoTSafeApplet.java      APDU dispatch, PIN lifecycle, crypto operations, chaining
    IoTSafeDeclarations.java Protocol constants: CLA/INS/P1/P2, status words, tags, limits
    ObjectManager.java       Object store: create, look up, list, delete
    PKIObject.java           Base object: object ID derivation, user info data
    CertObject.java          X.509 certificate object
    PrivKeyObject.java       Private key object
    PubKeyObject.java        Public key object
    SecretKeyObject.java     AES secret key object
    KeyParams.java           SEC curve parameters and key type mapping
    PKIUtil.java             ASN.1 DER TLV helpers
  configurations/           Oracle scriptgen/converter configuration (AID, target)
  build.xml                 Command-line build: compile, convert, verify

ApduMe/                   Windows host tool: replays an APDU script over PC/SC
docs/                     Protocol reference and operational guides
```

### Object identifiers

Objects are addressed by an 8-byte identifier the card derives itself, rather
than one the host chooses. The first byte encodes the object class (`01` RSA
private … `06` X.509 certificate); the remaining seven bytes are derived from
the object's own key or certificate material. A generated key pair returns the
private key ID followed by the public key ID, and both share the same value
apart from the class byte.

## Building the applet

**Prerequisites**

- Oracle [Java Card Development Kit](https://www.oracle.com/java/technologies/javacard-sdk-downloads.html) 3.1.0 (tools + simulator)
- JDK 11 or later
- Apache Ant 1.10+ (for the command-line build)

**From the command line**

```bash
export JC_HOME=/path/to/java_card_devkit-3_1_0
cd iot-safe-applet
ant                 # compile, convert to CAP, verify
```

The CAP lands in `deliverables/IoTSafeApplet/`. Targets: `cap` (the default),
`clean`, `distclean`, and `bootstrap`, which downloads the
[ant-javacard](https://github.com/martinpaljak/ant-javacard) task used to drive
the Oracle toolchain. `ant -p` lists them.

> The Java Card Development Kit is not redistributable, so this build cannot
> run in public CI and is not covered by the workflow in `.github/`. Please
> report anything that does not work against your SDK version.

**From Eclipse**

The repository carries an Eclipse project with the Oracle Java Card plug-in
nature. Import it, then point the `Sample_Platform_HOME` classpath variable at
your Java Card Development Kit installation.

### Application identifiers

| | AID |
| --- | --- |
| Package | `A0 00 00 00 62 03 01 0C 01` |
| Applet | `A0 00 00 00 62 03 01 0C 01 01` |

> **Before any production deployment, change these.** The RID
> `A0 00 00 00 62` belongs to Oracle and is reserved for Java Card samples.
> Allocate an AID under your own registered RID, or use a `D2 76 …`-style
> self-assigned identifier, and update `configurations/IoTSafeApplet.conf`.

## Loading and exercising the applet

Install the CAP with any GlobalPlatform tool — [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)
is the usual choice:

```bash
gp --install IoTSafeApplet.cap
```

Then drive it with `ApduMe`, which replays a C-style APDU script against a
PC/SC reader and logs both directions:

```
ApduMe.exe iotsafe.apdu
```

Reader selection, connect/transmit protocol and share mode are configured in
`apdume.ini` next to the executable.

**Building ApduMe:** Windows only — it uses MFC and the WinSCard API. Open
`ApduMe/ApduMe.sln` in Visual Studio 2022 (toolset v143, "Desktop development
with C++" plus "C++ MFC"), or build from a Developer Command Prompt:

```
msbuild ApduMe\ApduMe.sln /p:Configuration=Release /p:Platform=x64
```

A first session looks like this — activate the PUK, activate the PIN under PUK
authentication, verify the PIN, then generate a key pair:

```
80 22 01 00 08 06 05 31 32 33 34 35 36     # activate PUK   "123456", 5 retries
80 20 01 00 06 31 32 33 34 35 36           # verify PUK
80 22 00 00 06 04 03 31 32 33 34           # activate PIN   "1234", 3 retries
80 20 00 00 04 31 32 33 34                 # verify PIN
80 40 03 04 00                             # generate EC P-256 key pair
```

## Project status

This is a **reference implementation**, published so that others building IoT
SAFE provisioning stacks have a working applet to read, test against and learn
from.

It targets Java Card 3.1 and carries platform-specific accommodations: a 528-bit
key length for `secp521r1` to suit Infineon products, and the proprietary
`ALG_ECDSA_NONE` signature algorithm (`0x66`) found on jTOP platforms. Expect to
adjust both for other cards — the `0x66` instance is created unconditionally at
install time, so on a platform that does not provide it the applet will fail to
install until that line is removed or guarded.

Please read these limitations before building anything on it:

- **No secure channel.** PINs and imported key material travel in the clear in
  the APDU data field. The applet is written to sit behind GlobalPlatform
  SCP02/SCP03, or inside a SIM where the ISD provides channel security — it
  does not establish one itself. Do not expose it over an unprotected
  contactless or remote interface.
- **No independent security evaluation.** The applet has not been through a
  Common Criteria or third-party audit, and carries no certification.
- **Padding is the host's job.** RSA signing and decryption are raw
  (`ALG_RSA_NOPAD`) primitives. A host that does not implement PKCS#1 correctly
  will produce signatures that are not secure.
- **Known defects.** Open issues of substance — including buffer aliasing in
  the chained sign/decrypt path, sign-extension in TLV length parsing, and an
  unauthenticated reseed command — are tracked in the issue list and summarised
  in [docs/known-issues.md](docs/known-issues.md). Review them before you ship.
- **Applet state is static.** All applet state lives in `static` fields, so a
  second instance of this package would share PINs and keys with the first.
  Install exactly one instance per card.

## Contributing

Bug reports, protocol clarifications and patches are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the
Apache 2.0 licence with a Developer Certificate of Origin sign-off.

To report a security issue, please follow [SECURITY.md](SECURITY.md) rather
than opening a public issue.

## Licence

Copyright 2023-2026 Quantag IT Solutions GmbH.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
terms and [NOTICE](NOTICE) for the attribution requirement — if you redistribute
this software or a derivative of it, in source or binary form, you must
reproduce the contents of `NOTICE` in your accompanying documentation or
materials.

Commercial licensing, integration support and provisioning-stack work are
available from Quantag IT Solutions GmbH: <https://quantag-it.com>.
