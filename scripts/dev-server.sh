#!/usr/bin/env bash
# Run the local OP with .env. Exporting before `cargo run` also gives
# cargo the same DATABASE_URL the sqlx macros read.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  sed -e "s/YOUR_USER/${USER}/" \
      -e "s/^IDENTIKEY_MANAGED_WRAP_KEY=$/IDENTIKEY_MANAGED_WRAP_KEY=$(openssl rand -hex 32)/" \
      .env.example > .env
  echo "created .env" >&2
fi

# Shell env wins: only export keys that are not already set.
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  [[ -n "${!key+x}" ]] || export "$key=$value"
done < .env

exec cargo run -p identikey-server "$@"
