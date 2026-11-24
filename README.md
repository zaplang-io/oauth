# oauth

OAuth 1/2 client for [Zap](https://github.com/zaplang-io/zap) — an official **non-core** package.

- Tracking issue: [zaplang-io/zap#319](https://github.com/zaplang-io/zap/issues/319)
- Contributor & agent conventions: [AGENTS.md](AGENTS.md)
- Design decisions: [DECISIONS.md](DECISIONS.md)

The OAuth 2 bearer token model is available. The [Tier-1 epic](https://github.com/zaplang-io/oauth/issues/1) tracks the endpoint and grant flows.

## Goals

A typed Zap OAuth 2 client whose public API mirrors Python's [**authlib**](https://docs.authlib.org/) and [**requests-oauthlib**](https://requests-oauthlib.readthedocs.io/) as closely as Zap's static typing allows, with Go's [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) as a secondary design reference. API-parity with the popular Python library is a project rule — see [AGENTS.md](AGENTS.md).

Planned scope (first cut — OAuth 2):

- **Token model + refresh** — access/refresh tokens, expiry, automatic refresh.
- **Authorization Code flow + PKCE** — build the authorize URL, exchange the code, verify `state`.
- **Client Credentials flow** — machine-to-machine token acquisition.
- **Token endpoint client** — the `/token` request/response plumbing shared by the flows.
- **Provider discovery** — OpenID Connect / OAuth `.well-known` metadata.
- **Device Code flow** (optional) — for input-constrained devices.

## Bearer tokens

```zap
import oauth

token = oauth.Token.from_json("{\"access_token\":\"example\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"read\"}")
print(token.scope.unwrap())
print(token.is_expired())
saved = token.to_json()
restored = oauth.Token.from_json(saved)
```

`from_json` requires a non-empty access token and a bearer token type, matched
case-insensitively. `expires_in` and `expires_at` use non-negative integer seconds.
When both are present, `expires_at` retains the original Unix deadline across
reloads. `is_expired()` uses a 60-second leeway. Supply `leeway=0` to check the
actual expiry, or another non-negative number of seconds for an earlier refresh.

`token.ensure_active_token(fetch)` returns the current token while active. For
an expired token it passes the refresh credential to `fetch`, a `fn(str) -> Token`,
and returns the replacement. Keep the returned token for subsequent requests.
The replacement inherits the old refresh credential if the response omits it.
Live token endpoint integration is tracked in [#3](https://github.com/zaplang-io/oauth/issues/3).
Its typed provider errors depend on [Zap #1432](https://github.com/zaplang-io/zap/issues/1432).

`InvalidTokenError` identifies malformed token JSON or invalid fields.
`MissingRefreshTokenError` identifies an expired token with no refresh credential.
Serialized tokens contain credentials and should be stored accordingly.

## Planned client usage

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

Run the native `zap test` suite against a temporary consumer that installs this
checkout as a package:

```
sh tools/test.sh
```

GitHub Actions runs the suite on pull requests and pushes inside the
`ghcr.io/zaplang-io/zap:latest` container. CI stays pinned to `zap:latest`
until this module reaches a 1.0 release.

## Development

Read **[AGENTS.md](AGENTS.md)** before contributing — it covers the authlib/requests-oauthlib-parity rule, the one-issue-one-PR flow, how design decisions are recorded in **[DECISIONS.md](DECISIONS.md)**, and the rule for reporting core Zap language/stdlib defects upstream in `zaplang-io/zap` (rather than working around them here).
