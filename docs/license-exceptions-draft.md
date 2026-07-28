# Draft: AGPL Additional Permissions for identikey-core

**Status:** Draft. Lands with the licence declaration (bead `identikey-core-ydd.5`).
**Applies to:** `identikey-core` — the hosted OIDC provider and its web UI, once
declared AGPL-3.0-or-later + commercial.

Two additional permissions under AGPL section 7. The first mirrors what recrypt now
carries. The second is specific to this repo and is a **product decision**, not
housekeeping — read §2's rationale before adopting it.

---

## 1. Cryptographic library linking exception

Identical in effect to [`recrypt/LICENSE-EXCEPTIONS.md`](../../recrypt/LICENSE-EXCEPTIONS.md) §1.
Adopt the same wording. `identikey-core` will link the same AWS/rustls/crypto stack,
so it inherits the same exposure.

---

## 2. Branding and theming exception

> As an additional permission under section 7 of the GNU Affero General Public
> License version 3, modifications limited **solely** to the visual presentation of
> the user-facing pages served by this software — templates, stylesheets, images,
> fonts, colours, logos, wordmarks, and user-visible text strings — do not by
> themselves cause the modified version to be a "modified version" for the purposes
> of AGPL section 13, and you are not required to offer Corresponding Source to
> users on the basis of such modifications alone.
>
> This permission does **not** extend to any change in behaviour, including but not
> limited to: authentication or authorization logic; token issuance, validation, or
> claims; key handling or custody; session or consent handling; data collection,
> retention, or transmission; network endpoints; or any server-side code. If your
> modifications go beyond presentation, AGPL section 13 applies in full to the whole
> of your modified version.

### Why this is worth granting

AGPL §13 triggers on *modified* versions served over a network. **Every serious
deployment of an identity provider rebrands the login page** — that is not an edge
case, it is the first thing anyone does. Without this exception, essentially every
honest self-hoster trips §13 by changing a logo, and owes a source offer to every
end user who ever sees a login screen.

That outcome is bad on three counts:

1. **It punishes the wrong people.** Community deployments, nonprofits and
   individuals get caught; the SaaS competitor reselling us — the actual target of
   network copyleft — is caught by the behavioural clause regardless.
2. **It earns the "AGPL is a trap" reputation**, which is the single biggest reason
   an identity product gets filtered out of enterprise evaluation before a human
   sees it. Every competitor (Keycloak, Ory Hydra, ZITADEL — all Apache-2.0;
   Authentik — MIT core) is already permissive. We are choosing a harder road; we
   should not also make it needlessly hostile.
3. **It is inconsistent with the exit test.** Self-hosting is supposed to be
   first-class. A licence that makes ordinary self-hosting legally fraught is a
   soft form of lock-in, just enforced by lawyers instead of by architecture.

### What it deliberately does not give away

The commercial-licence triggers that actually matter are untouched:

- Proprietary plugins, claims mappers, or extensions that link the server
- Offering the software as a hosted service to third parties
- Any behavioural modification at all
- Embedding in a proprietary product

The exception is scoped to pixels. Anything that changes what the software *does*
falls back to full §13.

### The argument against

It gives up a real, if grubby, revenue trigger: enterprises that would have bought a
commercial licence purely to avoid a source-offer obligation created by their own
logo. Some fraction of dual-licence revenue in this market genuinely comes from that
kind of accidental trip.

**Recommendation: grant it anyway.** Revenue that depends on a customer not noticing
a technicality is not durable, and it is precisely the shape of thing the exit test
exists to rule out. Charge for hosting, support, proprietary extension rights, and
resale — things people knowingly choose to buy.

---

## Open question

Does the exception cover **user-visible text strings**? The draft says yes, which
allows translation and re-wording. The risk is a deployment that rewrites consent or
security-warning copy to be misleading while claiming presentation-only status.

Options: (a) keep strings in scope and accept the risk; (b) exclude strings, which
blocks translation and is worse; (c) keep strings in scope but carve out consent and
security-notice copy specifically. **(c) is probably right** — draft it with counsel
when the licence lands.
