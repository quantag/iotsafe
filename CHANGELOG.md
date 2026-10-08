# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The applet reports its own version over the air via `80 70 00 00 00`, which is
independent of repository releases; the applet version is noted against each
entry where it changes.

## [Unreleased]

### Security

- **Fixed cryptographic buffer aliasing on the chained sign and decrypt paths**
  (known issue 1). `chainingIncomingDataBuffer` is the working buffer, and both
  operations wrote their output to offset 0 of that same array while reading
  input from it, which Java Card leaves undefined for an overlapping
  `Signature` or `Cipher` range. The 768-byte working buffer is now partitioned
  into a 512-byte input region and a 256-byte output region
  (`CHAINING_INPUT_BUFFER_SIZE`, `CRYPTO_OUTPUT_OFFSET`, `CRYPTO_OUTPUT_SIZE`),
  `handleChaining` bounds accumulated input to the input region, and both
  operations reject chained input that would reach into the output region. No
  additional RAM is used. Raw RSA operations are reachable only through
  chaining, so every raw RSA signature and decryption previously took the
  aliased path.
- **Removed the SET SEED command, INS `58`** (known issue 2). It required no
  authentication, letting any caller with APDU access mix chosen bytes into the
  generator that produces AES keys and object identifiers. INS `58` now answers
  `6D00` and is retired; it must not be reused. **This is a breaking change for
  any host that called it.**
- **Fixed sign-extension in TLV length parsing** (known issue 3).
  `PKIUtil.getLength` read a single long-form length octet without masking, so
  `0x80`–`0xFF` became negative and import of any 128-to-255-byte value encoded
  as `81 xx` failed with `6A80`. Now masked with `0x00FF`, which keeps the
  expression within `short` as Java Card Classic requires.

### Fixed

- **ApduMe no longer depends on MFC**, which is what broke the first CI run:
  the GitHub Windows runners do not carry the Visual Studio MFC component, so
  the build failed on `afxwin.h`. The tool is a console program and used MFC
  only for a string class. `CString` is now `std::wstring`, `stdafx.h` includes
  the Win32 headers instead of `afxwin.h`/`afxext.h`/`afxdtctl.h`/`afxcmn.h`,
  `UseOfMfc` is `false` in every configuration, and the `AfxMessageBox` call —
  a modal dialog in a console tool — is now a log line. ApduMe builds with the
  C++ workload alone, and CI guards against MFC being reintroduced.
- `findReader` returned `nullptr` as a `CString`, which trips an ATL assertion
  rather than signalling "not found". It now returns an empty `std::wstring`
  and callers test with `empty()`.
- **`build.xml` referenced an ant-javacard release that does not exist.**
  Version `21.03.13` was never tagged, so `ant bootstrap` would fail with a
  404. Pinned to `26.05.15`, the current release.

### Added

- **The build tool is verified by checksum before use.** `bootstrap` checks the
  downloaded `ant-javacard.jar` against a pinned SHA-256
  (`14f5e25c…d000589`) and refuses to run a jar that does not match, so a
  corrupted or substituted download cannot take part in building the CAP. A new
  `print-tool-checksum` target prints the hash when moving to another version.
- `docs/known-issues.md` gained a
  [testing-gap section](docs/known-issues.md#what-is-not-covered-by-tests)
  setting out what a test suite should cover, including the boundary cases that
  would act as regression tests for issues 1 and 3.
- CI step asserting ApduMe stays free of MFC.

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

Issues 1, 2 and 3 of `docs/known-issues.md` are fixed, as recorded above. Both
High-severity findings are closed. Eleven items remain open; the most
substantial are issue 4 (all applet state is `static`, so two instances of the
package would share one PIN and one key store) and issue 11 (AES-CBC key
wrapping with an all-zero IV). Both change observable behaviour and want an
agreed approach before a patch.

**Behaviour changed in this release**, unlike the initial publication: SET SEED
is gone, chained sign and decrypt accept at most 512 bytes of input rather than
768, and TLV values of 128 to 255 bytes encoded as `81 xx` now import correctly
instead of failing. The fixes were verified by code review and by a parse check;
none has been executed on a card from this working copy.

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
