# IdentiKey Core — Commercial License

IdentiKey Core is **dual-licensed**. You may use it under either the
[GNU Affero General Public License v3.0 or later](LICENSE-AGPL) — free of charge, forever —
or under a commercial license from **Identikey Inc.**

You only need a commercial license if the AGPL's obligations don't work for your product.
If you're happy to comply with the AGPL, you owe nothing and can stop reading.

The protocol crates (`identikey-auth`, the specs, and recrypt's core crates) are
permissively licensed and **never** need a commercial license. See [LICENSE](LICENSE).

---

## When you need a commercial license

The AGPL is a strong copyleft license. Section 5 requires that anyone you convey a modified
version to receives the complete corresponding source under the AGPL, and **section 13**
extends that to *network use*: if you let users interact with a modified IdentiKey Core over
a network, you must offer them its complete corresponding source.

For most operators — individuals, researchers, nonprofits, community deployments, and any
organization willing to share source — the AGPL is a perfect fit and is free, **including
running IdentiKey Core in production commercially**.

You will likely want a commercial license if any of the following apply and you do **not**
wish to release your corresponding source under the AGPL:

- You offer a **hosted identity service** built on IdentiKey Core to third parties, and
  cannot or will not disclose its source under AGPL §13.
- You have written **proprietary extensions** — claims mappers, custom grant handlers,
  provisioning connectors, policy plugins — that link the server and would become derivative
  works.
- You **embed** IdentiKey Core in a proprietary product that you sell, lease, or distribute.
- Your legal or procurement policy **prohibits AGPL** software.

A commercial license grants you the same code under terms that **remove the AGPL's copyleft
and network-source-disclosure obligations**, so you can ship a closed product.

## When you almost certainly do *not*

We would rather you deployed this than paid us for permission you didn't need:

- **Running it unmodified**, at any scale, commercially or otherwise.
- **Re-branding the login and account pages.** Explicitly excepted — see
  [LICENSE-EXCEPTIONS.md](LICENSE-EXCEPTIONS.md) §2. Changing a logo does not make you a
  publisher of modified source.
- **Building a client**, an SDK, a mobile app, or an independent implementation of the wire
  protocols. That is the permissive tier; it creates no derivative work of this repository.
- **Self-hosting for your own organization** and complying with §13 by making your source
  available to your users.

## How to obtain one

Email **sales@identikey.io** with:

- your company and product,
- roughly how IdentiKey Core will be used (hosted service, embedded, internal deployment),
- expected scale (deployments / monthly active identities).

We'll follow up with a quote and a license agreement.

---

## Third-party components

IdentiKey Core depends on third-party libraries distributed under their own licenses, which
are unaffected by this licensing and continue to apply to that code. A commercial license
does not relicense them.

*This document is a summary of the commercial-licensing offer, not the commercial license
agreement itself. The binding terms are in the signed agreement provided at purchase.
Nothing here modifies your rights under the AGPL or the permissive licenses, which remain
available to everyone.*
