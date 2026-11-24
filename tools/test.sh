#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
zap=${ZAP:-zap}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
export ZAP_CACHE="$scratch/cache"
unset ZAP_ZENV

"$zap" fmt --check "$root/src" "$root/tests"

# Exercise the public API from a consumer with oauth installed as a dependency.
cd "$scratch"
ln -s "$root" oauth
cat > zap.toml <<'MANIFEST'
[package]
name = "oauth_tests"
version = "0.0.0"

[dependencies]
oauth = { path = "oauth" }
MANIFEST
"$zap" zenv create --no-venv
mkdir tests
cp "$root"/tests/*_test.zap tests/
# Exercise private URL derivation while the HTTP discovery API is pending.
{
    cat "$root/src/oauth.zap"
    printf '\n'
    cat "$root/tests/internal/provider_urls_test.zap"
} > tests/provider_urls_test.zap
ZAP_ZENV="$scratch/zenv" "$zap" test tests/
