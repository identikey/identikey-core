# Additional Permissions to the AGPL

These are **additional permissions** under section 7 of the GNU Affero General Public
License v3.0, granted by Identikey Inc. for the AGPL-licensed contents of this repository.

They apply only when you are exercising rights under the AGPL. If you hold a commercial
license (see [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)) they are unnecessary — the
commercial license has no copyleft obligations to be excepted from.

Additional permissions may be removed by any recipient, per AGPL section 7. If you convey a
modified version you may drop these permissions from your copy; you may not add restrictions
beyond what the AGPL allows.

---

## 1. Cryptographic library linking exception

> As an additional permission under section 7 of the GNU Affero General Public License
> version 3, you may link this software with, and distribute the resulting executable
> together with, general-purpose cryptographic libraries whose licenses are incompatible
> with the AGPL — including but not limited to OpenSSL, LibreSSL, BoringSSL, AWS-LC, and
> libraries derived from any of them — and you may convey the resulting work under the terms
> of the AGPL notwithstanding that incompatibility.
>
> This permission applies to the cryptographic library and to any code it requires, and
> extends to modified versions of this software that carry it forward. It does not extend to
> any other AGPL-incompatible code.

Identical in effect to the exception carried by `recrypt`. It exists because a transitive
dependency can introduce an AGPL-incompatible crypto license without anyone noticing — which
has already happened once in this project (`aws-lc-sys` 0.36.0 declared an `OpenSSL`
component and reached both AGPL binaries through the AWS SDK). CI now enforces a license
allowlist; this permission ensures the next occurrence is a routine dependency bump rather
than a licensing incident, and that self-hosters are never the ones left holding an
undistributable binary.

---

## 2. Branding and theming exception

> As an additional permission under section 7 of the GNU Affero General Public License
> version 3, modifications limited **solely** to the visual presentation of the user-facing
> pages served by this software — templates, stylesheets, images, fonts, colours, logos,
> wordmarks, and user-visible text strings — do not by themselves cause the modified version
> to be a "modified version" for the purposes of AGPL section 13, and you are not required to
> offer Corresponding Source to users on the basis of such modifications alone.
>
> **This permission does not extend to any change in behaviour**, including but not limited
> to: authentication or authorization logic; token issuance, validation, or claims; key
> handling or custody; session or consent handling; data collection, retention, or
> transmission; network endpoints; or any server-side code.
>
> **Nor does it extend to the wording of consent prompts, permission descriptions, custody
> disclosures, or security warnings.** Those may be *translated* faithfully, but altering
> what they tell the user is a change in behaviour for the purposes of this exception, not a
> change in presentation.
>
> If your modifications go beyond presentation as scoped above, AGPL section 13 applies in
> full to the whole of your modified version.

### Why this is granted

AGPL §13 triggers on *modified* versions served over a network, and **every serious
deployment of an identity provider rebrands the login page** — it is the first thing anyone
does. Without this exception, essentially every honest self-hoster would trip §13 by changing
a logo, and owe a source offer to every end user who ever sees a login screen.

That outcome punishes the wrong people. Community deployments, nonprofits and individuals get
caught; the SaaS competitor reselling us — the actual target of network copyleft — is caught
by the behavioural clause regardless. Self-hosting is meant to be first-class here, and a
license that makes ordinary self-hosting legally fraught is a soft form of lock-in enforced by
lawyers instead of architecture.

It gives up a real revenue trigger: enterprises that would have bought a commercial license
purely to avoid an obligation created by their own logo. We think revenue that depends on a
customer not noticing a technicality is not durable. Charge for hosting, support, proprietary
extension rights, and resale — things people knowingly choose to buy.

### Why consent and security copy is carved out

The exception covers user-visible text so that deployments can translate and localise freely.
But consent prompts and security warnings are not decoration — they are how the software tells
a user what is about to happen to their identity and their keys. A deployment that rewrote
"this application will be able to sign on your behalf" into something reassuring and false
would be changing what the software *does* to the user while claiming presentation-only
status. Faithful translation: fine. Altering the meaning: §13 applies.

---

## 3. Interoperability note (not an exception)

For the avoidance of doubt, and consistent with how the AGPL already works:

Speaking the IdentiKey wire protocols — implementing the specs, exchanging messages with a
server, or writing an independent client, SDK, or mobile app — creates no derivative work of
this software and imposes no obligation whatsoever.

**The copyleft boundary is the server, never the protocol.**
