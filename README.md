# oauth

OAuth 1/2 client for [Zap](https://github.com/zaplang-io/zap) — an official **non-core** package.

- Tracking issue: [zaplang-io/zap#319](https://github.com/zaplang-io/zap/issues/319)
- Contributor & agent conventions: [AGENTS.md](AGENTS.md)
- Design decisions: [DECISIONS.md](DECISIONS.md)

> **Status: docs-first.** No implementation yet — the planned surface is tracked in the [issues](https://github.com/zaplang-io/oauth/issues) (see the Tier-1 scope epic).

The token model in [#2](https://github.com/zaplang-io/oauth/issues/2) depends on
[Zap support for `scope` as a field and keyword](https://github.com/zaplang-io/zap/issues/1405).

## Goals

A typed Zap OAuth 2 client whose public API mirrors Python's [**authlib**](https://docs.authlib.org/) and [**requests-oauthlib**](https://requests-oauthlib.readthedocs.io/) as closely as Zap's static typing allows, with Go's [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) as a secondary design reference. API-parity with the popular Python library is a project rule — see [AGENTS.md](AGENTS.md).

Planned scope (first cut — OAuth 2):

- **Token model + refresh** — access/refresh tokens, expiry, automatic refresh.
- **Authorization Code flow + PKCE** — build the authorize URL, exchange the code, verify `state`.
- **Client Credentials flow** — machine-to-machine token acquisition.
- **Token endpoint client** — the `/token` request/response plumbing shared by the flows.
- **Provider discovery** — OpenID Connect / OAuth `.well-known` metadata.
- **Device Code flow** (optional) — for input-constrained devices.

## Usage (planned — illustrative only)

```zap
import oauth

# Authorization Code + PKCE
client = oauth.Client(
    client_id="abc",
    redirect_uri="https://app.example/callback",
    token_endpoint="https://issuer.example/token",
    authorization_endpoint="https://issuer.example/authorize",
)
url, state, verifier = client.authorization_url(scope=["openid", "profile"])
# ... user authorizes, provider redirects back with code ...
token = client.fetch_token(code=code, state=state, code_verifier=verifier)

# Client Credentials
svc = oauth.Client(client_id="svc", client_secret="s3cret",
                   token_endpoint="https://issuer.example/token")
token = svc.fetch_token(grant_type="client_credentials", scope=["api"])
```

The exact signatures (keyword vs positional, defaults, return shapes) are not final. Any ambiguity is escalated to the maintainer with Python/Go examples and recorded in [DECISIONS.md](DECISIONS.md) rather than decided unilaterally.

## Build and test

Test cases live under `tests/` and run with the `zap test` methodology:

```
zap test tests/
```

GitHub Actions runs the suite on pull requests and pushes inside the
`ghcr.io/zaplang-io/zap:latest` container. CI stays pinned to `zap:latest`
until this module reaches a 1.0 release.

## Development

Read **[AGENTS.md](AGENTS.md)** before contributing — it covers the authlib/requests-oauthlib-parity rule, the one-issue-one-PR flow, how design decisions are recorded in **[DECISIONS.md](DECISIONS.md)**, and the rule for reporting core Zap language/stdlib defects upstream in `zaplang-io/zap` (rather than working around them here).
