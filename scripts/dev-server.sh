#!/usr/bin/env bash
# Run the local OP with .env.server. Exporting before `cargo run` also gives
# the sqlx query macros the right DATABASE_URL (the root .env has the old one).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env.server ]; then
  sed -e "s/YOUR_USER/${USER}/" \
      -e "s/^IDENTIKEY_MANAGED_WRAP_KEY=$/IDENTIKEY_MANAGED_WRAP_KEY=$(openssl rand -hex 32)/" \
      .env.server.example > .env.server
  echo "created .env.server" >&2
fi

# Shell env wins: only export keys that are not already set.
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  [[ -n "${!key+x}" ]] || export "$key=$value"
done < .env.server

exec cargo run -p identikey-server "$@"
