# Security policy

## Scope and expectations

This applet is a **reference implementation**. It has not been through a Common
Criteria evaluation or any third-party security audit, and it carries no
certification. Known defects — including ones with security relevance — are
published openly in [docs/known-issues.md](docs/known-issues.md) rather than
held back.

Please read that document before reporting: if your finding is already listed,
an issue adding detail or a patch is more useful than a private report.

The applet also assumes a deployment model that is worth stating plainly,
because findings that depend on breaking it are not defects in the applet:

- **It does not implement a secure channel.** PINs and imported key material
  travel in the clear in the APDU data field. The applet is designed to sit
  behind GlobalPlatform SCP02/SCP03, or inside a SIM where the issuer security
  domain provides channel security.
- **Padding is the host's responsibility.** RSA signing and decryption are raw
  primitives, by design.
- **PUK activation is unauthenticated on a virgin card**, so that the card can
  be taken over during personalisation. This step belongs in a controlled
  environment.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that is not already listed
in `docs/known-issues.md`.

**Preferred:** use GitHub's private vulnerability reporting — the *Security* tab
of this repository, then *Report a vulnerability*. This keeps the report, the
discussion and the eventual advisory in one place.

**Alternative:** email <security@quantag-it.com>. If you want to encrypt the
report, say so in a first message without details and we will exchange keys.

Useful contents of a report:

- The command sequence that triggers it, ideally as an APDU trace
- The card platform and Java Card version, or the simulator version
- What an attacker gains, and what access they need to get there
- Whether the behaviour persists across card reset and applet deselect

## What to expect

| | |
| --- | --- |
| Acknowledgement | within 5 working days |
| Initial assessment | within 15 working days |
| Fix or published advisory | depends on severity and on the platforms affected |

We will tell you which of the two we are doing and why. Where a finding cannot
be fixed without breaking the protocol, we will document it in
`docs/known-issues.md` instead and say so.

Reporters are credited in the advisory and in `CHANGELOG.md` unless they prefer
otherwise. There is no bug bounty.

## Supported versions

The applet reports its own version via `80 70 00 00 00`. Only the current
`main` branch receives fixes; there are no maintained release branches.

| Applet version | Supported |
| --- | --- |
| 1.15 (`01 15`) | Yes — current |
| Earlier | No |

## Downstream deployments

If you have put this applet, or a derivative, on cards in the field, consider
watching this repository so that advisories reach you. We have no way to
identify downstream users and cannot notify you directly.
