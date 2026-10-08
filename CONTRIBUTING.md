# Contributing

Thanks for looking at this. The applet is published as a working reference for
people building IoT SAFE provisioning stacks, and contributions that make it
more correct or more portable are welcome.

## Licence and sign-off

This project is licensed under the Apache License 2.0. Contributions are
accepted under the same licence, with a Developer Certificate of Origin
sign-off — no separate CLA.

Add a `Signed-off-by` line to each commit, which `git commit -s` does for you:

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off you certify that you wrote the contribution or otherwise have the
right to submit it under Apache 2.0, as set out in the
[Developer Certificate of Origin](https://developercertificate.org/).

New files need the standard header; copy it from any existing source file. The
copyright line stays as it is — please do not add your own, and do not remove
the `SPDX-License-Identifier` line.

## Before you open a pull request

- **Describe the card you tested on.** Platform, Java Card version and whether
  you used a physical card or the simulator. Applet behaviour varies
  considerably between products, and a change that fixes one platform can break
  another.
- **Include the APDU trace.** For anything touching the protocol, a before/after
  trace from `ApduMe` or your own tool is the fastest way to review a change.
  `ApduMe` writes one automatically next to its input script.
- **Keep protocol changes separate from refactoring.** A commit that both moves
  code and changes a status word is hard to review and harder to bisect.
- **Update `docs/apdu-reference.md`** in the same pull request if you change any
  command, parameter encoding or status word. The reference is meant to be
  authoritative; a change that leaves it stale will be asked to come back.
- **Note any change in CAP size or memory footprint.** The applet targets cards
  where both are tight.

## Working on the known issues

[docs/known-issues.md](docs/known-issues.md) lists the defects found by review,
with file and line references and a suggested direction for each. Issues 1
through 3 are the ones worth attention first. If you take one on, say so in the
issue thread so two people don't write the same patch.

Two of those entries are structural rather than local — static applet state
(issue 4) and object identifier derivation (issue 5). Both change observable
behaviour, so please open an issue to agree the approach before writing the
patch.

## Java Card house style

The existing code follows conventions that are deliberate on this platform, and
patches should match them:

- No object allocation outside `install()` and the object-creation paths, which
  already wrap allocation in `JCSystem.beginTransaction()` and request garbage
  collection explicitly.
- `short` for every length, offset and counter; cast arithmetic back to `short`.
- Compare constants on the left, as the existing code does
  (`if (TRUE != getChainingStatus())`).
- Fault-injection countermeasures stay. The duplicated PIN checks and the
  security counters in `checkPinAuthentication` look redundant and are not —
  they make a single skipped instruction insufficient to bypass a check. Keep
  them, and follow the pattern in new security-relevant code.
- Throw `ISOException` with a status word from `IoTSafeDeclarations`; do not
  invent new values without adding them there.
- Zero any buffer that held key material or PIN values before returning.

## Style

Existing files use tabs, which is what the Eclipse project is configured for.
Please keep to that in files you touch rather than reformatting them; a
whitespace-only diff across a file makes the real change invisible.

## Reporting bugs

Open an issue with the APDU trace, the card and SDK version, and what you
expected to happen. For anything with security impact, follow
[SECURITY.md](SECURITY.md) instead of filing publicly.
