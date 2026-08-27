# Tasks

Owed at ACTIVE BUILD.

- [x] `/authorize/passkey` HTML is a product page, not a `<pre>` of
      JSON; it runs usernameless `credentials.get`
- [x] GET `/signup` + POST that `create_managed` then
      `begin_register`; finish enrolls a passkey
- [x] Assertion of an unknown credential still inserts no account
- [x] Tests: passkey page is `text/html`; signup then register
      stores a credentials row; unknown assert does not insert
- [x] `cargo test -p identikey-server` (or the existing sqlx test
      set for these routes)

Handoffs (not checkboxes):

- Elect-key export at signup (exit / C3)
- `ccf.11` account UI
- Taskmaster `add-oidc-rp`
