# Tasks

- [ ] Decide the instrument: Config OP only, or Basic OP after a
      confidential-client change (`client_secret_basic` +
      `client_secret_post`, two extra clients). Do not require
      Basic OP in CI until the OP can pass it.
- [ ] Name exact `run-test-plan.py` plan ids and a sample config
- [ ] Specify how the suite completes login (`/authorize/dev` is a
      form; the suite will not paste a XID by itself)
- [ ] Pin the suite image (or git sha) by digest; document the
      local Docker command
- [ ] Seed a C2 user in CI without implicit signup
- [ ] Docker network + redirect URIs the suite actually uses
- [ ] How a red plan relates to the required GitHub job now that
      the code flow has landed (property-red vs failing `main`)
- [ ] Documented Docker / `run-test-plan.py` command in-repo
- [ ] CI runs the chosen plan(s) against local identikey-server
- [ ] Suite is not a Cargo dependency
- [ ] Job fails the build when a chosen, in-scope plan is red

Not owed here (bullets, not boxes):

- Paying for certification
- FAPI plans
- Licence research (done 2026-08-18, MIT)
