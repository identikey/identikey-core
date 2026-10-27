#!/usr/bin/env bash
# Install the loopback IdentiKey OP as a Homebrew service.
#
#   brew services start identikey-local
#
# Listens on 127.0.0.1:8070, separate from scripts/dev-server.sh (:8080)
# and from https://auth.identikey.me. Local apps POST /register.
# The database is identikey-local. The dev database is left alone.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required (brew services runs the provider)" >&2
  exit 1
fi
if ! command -v createdb >/dev/null 2>&1 || ! command -v psql >/dev/null 2>&1; then
  echo "PostgreSQL client tools (createdb, psql) must be on PATH" >&2
  exit 1
fi
if ! pg_isready -q; then
  echo "PostgreSQL is not accepting connections. Start it, then re-run." >&2
  exit 1
fi

prefix="$(brew --prefix)"
data_dir="${prefix}/var/identikey-local"
env_file="${prefix}/etc/identikey-local.env"
log_dir="${prefix}/var/log"
db_name="identikey-local"

mkdir -p "$data_dir" "$log_dir" "${prefix}/etc"
chmod 700 "$data_dir"

if [[ ! -f "$env_file" ]]; then
  wrap="$(openssl rand -hex 32)"
  umask 077
  cat >"$env_file" <<EOF
IDENTIKEY_LOCAL_REGISTER=1
IDENTIKEY_DEV_LOGIN=1
IDENTIKEY_BIND=127.0.0.1:8070
IDENTIKEY_ISSUER=http://127.0.0.1:8070
IDENTIKEY_DATA_DIR=$(printf '%q' "$data_dir")
IDENTIKEY_MANAGED_WRAP_KEY=${wrap}
WEBAUTHN_RP_ID=localhost
WEBAUTHN_EXPECTED_ORIGIN=http://127.0.0.1:8070,http://localhost:8070
DATABASE_URL=$(printf '%q' "postgres://${USER}@localhost:5432/${db_name}")
EOF
  chmod 600 "$env_file"
  echo "wrote ${env_file} (mode 0600). The wrap key stays in that file."
else
  echo "left existing ${env_file} in place"
fi

if ! psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${db_name}'" | grep -q 1; then
  createdb "$db_name"
  echo "created database ${db_name}"
fi

echo "building identikey-server (release)"
# The workspace release profile sets strip = "debuginfo". On this Mac that
# mis-aligns the sqlx proc-macro dylib (dyld: mis-aligned LINKEDIT string
# pool) and the build dies. Linux deploys keep the profile as written.
export CARGO_PROFILE_RELEASE_STRIP=none
cargo build --release -p identikey-server

stage="$(mktemp -d)"
payload="$(mktemp -d)"
tarball="${payload}/identikey-local.tar.gz"
cleanup() { rm -rf "$stage" "$payload"; }
trap cleanup EXIT

cp target/release/identikey-server "$stage/identikey-server"
cp packaging/homebrew/identikey-local-launch "$stage/identikey-local-launch"
chmod 755 "$stage/identikey-server" "$stage/identikey-local-launch"
tar -C "$stage" -czf "$tarball" identikey-server identikey-local-launch
sha="$(shasum -a 256 "$tarball" | awk '{print $1}')"
url="file://${tarball}"

tap="$(brew --repository)/Library/Taps/identikey/homebrew-local"
if [[ ! -d "$tap/.git" ]]; then
  brew tap-new identikey/local
fi
mkdir -p "$tap/Formula"
formula="$tap/Formula/identikey-local.rb"
sed -e "s|IDENTIKEY_LOCAL_URL|${url}|" -e "s|IDENTIKEY_LOCAL_SHA256|${sha}|" \
  packaging/homebrew/identikey-local.rb.in >"$formula"
if [[ -n "$(git -C "$tap" status --porcelain)" ]]; then
  git -C "$tap" add Formula/identikey-local.rb
  git -C "$tap" commit -m "Rebuild identikey-local from the local checkout" >/dev/null
fi

if brew list --formula identikey-local >/dev/null 2>&1; then
  brew reinstall --formula identikey/local/identikey-local
else
  brew install --formula identikey/local/identikey-local
fi

# The tarball is deleted by the trap. Reinstall already copied the binaries
# into the keg, so the file:// URL does not need to survive.
brew services restart identikey-local

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl -fsS "http://127.0.0.1:8070/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo "identikey-local did not answer on 127.0.0.1:8070" >&2
  echo "log: ${log_dir}/identikey-local.log" >&2
  exit 1
fi

echo "identikey-local is up at http://127.0.0.1:8070"
echo "register a client with POST /register (loopback redirects only)"
