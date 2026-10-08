# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The applet reports its own version over the air via `80 70 00 00 00`, which is
independent of repository releases; the applet version is noted against each
entry where it changes.

## [Unreleased]

### Added

- Apache License 2.0, with a `NOTICE` file carrying the attribution requirement
  under section 4(d), and SPDX headers on every source file.
- `README.md` with capability overview, repository layout, build and loading
  instructions, and a first-session APDU example.
- `docs/apdu-reference.md` — complete protocol reference: every command, P1/P2
  encoding, TLV tag, status word and limit, derived from the implementation.
- `docs/known-issues.md` — thirteen defects and design limitations found by
  source review, with file and line references and suggested fixes.
- `CONTRIBUTING.md`, including the Java Card house style and the note that the
  duplicated PIN checks are deliberate fault-injection countermeasures.
- `SECURITY.md` with a private disclosure process and stated deployment
  assumptions.
- `iot-safe-applet/build.xml` — command-line build of the CAP driven by
  `JC_HOME`, so Eclipse and the Oracle plug-in are no longer required.
- Continuous integration: licence header check, markdown link check, and an
  `ApduMe` build on Windows.
- `.gitignore` covering Java Card, Eclipse, Visual Studio and CMake output.

### Changed

- Copyright attributed to Quantag IT Solutions GmbH across all source files;
  per-file `@author` tags replaced with class-level documentation describing
  what each class does.
- `iot-safe-applet/.classpath` no longer hard-codes a local
  `C:\Program Files (x86)\...` javadoc path.

### Removed

- `ApduMe/ApduMe.vcxproj.user`, which held one developer's local debugger
  settings and should never have been tracked.

### Known at time of publication

No functional change has been made to the applet in this release — it behaves
exactly as the version that was in internal use. The defects in
`docs/known-issues.md` are documented, not yet fixed. Issues 1 (buffer aliasing
in chained sign and decrypt), 2 (unauthenticated reseed) and 3 (TLV length
sign-extension) are the ones to address first.

## [1.15] — 2023-04-06

Applet version `01 15`. Final state of the internal development effort, and the
code as first published.

### Added

- IoT SAFE applet for Java Card 3.1: PIN and PUK lifecycle via `OwnerPIN`;
  object store for certificates, public keys, private keys and secret keys, with
  card-derived 8-byte identifiers; RSA-2048, EC F<sub>p</sub> 224/256/384/521
  and AES-128/256 key generation and import; ECDSA signing with SHA-224 through
  SHA-512; raw RSA signing and decryption; AES key wrapping; on-card random
  number generation; APDU command chaining in both directions.
- Support for `secp224k1`, `secp224r1`, `secp256k1`, `secp256r1`, `secp384r1`
  and `secp521r1`, with a 528-bit key length for `secp521r1` to accommodate
  Infineon products.
- `ApduMe` — Windows PC/SC tool that replays a C-style APDU script against a
  reader and logs both directions, serving the role `apdutool` plays in the
  Java Card Development Kit, but against physical cards.

[Unreleased]: https://github.com/quantag/iotsafe/compare/v1.15...HEAD
[1.15]: https://github.com/quantag/iotsafe/releases/tag/v1.15
