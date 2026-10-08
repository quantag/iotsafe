<!--
Copyright 2023-2026 Quantag IT Solutions GmbH
SPDX-License-Identifier: Apache-2.0
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Tested on

<!--
Which card and SDK. Say "not tested on hardware" if that is the case — it is
useful to know, and not a reason to withhold a patch.
-->

- Card platform / simulator:
- Java Card version:
- SDK used to build:

## APDU trace

<!-- Before and after, for anything that touches the protocol. -->

```text

```

## Checklist

- [ ] Commits are signed off (`git commit -s`) — see [CONTRIBUTING.md](https://github.com/quantag/iotsafe/blob/main/CONTRIBUTING.md)
- [ ] New files carry the licence header, existing copyright lines untouched
- [ ] `docs/apdu-reference.md` updated if any command, encoding or status word changed
- [ ] `docs/known-issues.md` updated if this fixes or affects a listed issue
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Fault-injection countermeasures preserved (duplicated checks, security counters)
- [ ] No allocation added outside `install()` or the existing transactional object-creation paths
- [ ] Buffers holding key or PIN material are zeroed before return

## Effect on footprint

<!-- CAP size and persistent/transient memory, if this moves either. -->
