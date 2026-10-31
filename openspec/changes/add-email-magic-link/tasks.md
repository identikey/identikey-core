# Tasks

- [x] Send a single-use magic link for an email address on a known XID.
- [x] Redeem that link once and store the address on `accounts.email` for that same XID.
- [x] Refuse a second redeem, a redeem that would attach the address to a different account, and an address already stored for another account under `lower(email)`.
- [x] Show that redeeming the link inserts no credentials row and does not read `managed_key_blob`.
