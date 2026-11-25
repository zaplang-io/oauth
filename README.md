# oauth

OAuth 1/2 client for [Zap](https://github.com/zaplang-io/zap) — an official **non-core** package.

- Tracking issue: [zaplang-io/zap#319](https://github.com/zaplang-io/zap/issues/319)
- Contributor & agent conventions: [AGENTS.md](AGENTS.md)
- Design decisions: [DECISIONS.md](DECISIONS.md)

The package supports OAuth 2 bearer tokens, token endpoint exchange,
Authorization Code with PKCE, Client Credentials, provider discovery, and Device
Authorization. See the [Tier-1 epic](https://github.com/zaplang-io/oauth/issues/1).

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

`InvalidTokenError` identifies malformed token JSON or invalid fields.
`MissingRefreshTokenError` identifies an expired token with no refresh credential.
Serialized tokens contain credentials and should be stored accordingly.

## Token endpoint

```zap
import oauth

client = oauth.Client(
    client_id="service",
    client_secret="example-secret",
    token_endpoint="https://issuer.example/token",
    timeout=5000,
)
try:
    token = client.fetch_token({"grant_type": "client_credentials", "scope": "read"})
except oauth.TokenEndpointError as failure:
    print(failure.status, failure.error)
```

The client defaults to `client_secret_basic`. Set
`token_endpoint_auth_method="client_secret_post"` to send credentials in the
form. The endpoint requires HTTPS, with HTTP available on numeric loopback
addresses. The client returns the original response from redirecting endpoints
as an error. The total `timeout` is in milliseconds and defaults to `0` for no
deadline.

`Client.refresh_token(refresh_token)` performs a refresh grant directly.
`Client.ensure_active_token(token, leeway=60)` checks expiry first and keeps the
old refresh credential when the replacement omits one.

Standard OAuth provider codes raise named exceptions such as `InvalidClientError`
and `InvalidGrantError`. A `TokenEndpointError` catch also handles those errors
and exposes `status`, `error`, `error_description`, and `error_uri`. The last
two fields are optional. `TokenEndpointHTTPError` covers failed HTTP responses
without usable OAuth error fields. A malformed successful token response raises
`InvalidTokenError`. A transport deadline raises `TimeoutError`.

## Authorization Code with PKCE

```zap
import oauth

client = oauth.Client(
    client_id="abc",
    client_secret="example-secret",
    redirect_uri="https://app.example/callback",
    token_endpoint="https://issuer.example/token",
    authorization_endpoint="https://issuer.example/authorize",
)
request = client.authorization_url(scope=["openid", "profile"])
url, state, verifier = request
# Save request in the user's session and redirect the browser to url.
# Retrieve the request from that same session when the provider redirects back.
token = client.exchange_code(callback_url, request)
```

Each authorization generates a fresh S256 verifier and a random `state` unless
you supply a session-bound state. Treat the verifier as a secret. Store the
request tuple in your session and consume it once when processing the callback.
The provider rejects reuse of an authorization code with `InvalidGrantError`.

`exchange_code` requires the callback URL to match the registered redirect URI
and validates its state before any token request. A mismatch raises
`MismatchingStateError`, a malformed callback raises
`InvalidAuthorizationResponseError`, and an authorization denial raises
`AuthorizationResponseError` with the provider's error fields.

For a public client, set `client_secret=""` and
`token_endpoint_auth_method="none"`.

## Client Credentials

```zap
import oauth

client = oauth.Client("service", "example-secret", "https://issuer.example/token", timeout=5000)
token = client.fetch_client_credentials(scope=["api:read"])

source = client.client_credentials_token_source(scope=["api:read"], leeway=30)
token = source.token()
```

Use `fetch_client_credentials` for a single exchange. Reuse a token source to
cache the token and reacquire it when it reaches the expiry threshold.
Concurrent callers share the acquisition, and each receives its own token
value. The source defaults to a 60-second leeway. An empty scope list omits
the scope field. This grant requires client authentication and discards any
refresh token returned by the provider.

## Provider metadata

Fetch a provider's discovery document and apply its endpoints to a client:

```zap
import oauth

metadata = oauth.discover("https://issuer.example/tenant")
client = oauth.Client.from_metadata(metadata, "service", "example-secret", timeout=5000)
```

Discovery tries OpenID Connect first and falls back to RFC 8414 on HTTP 404.
The issuer claim must match exactly. The HTTP client caps the response body at
65,536 bytes, disables redirects, and uses a five-second deadline per request
by default. Supply `timeout` in milliseconds to change the deadline.

Metadata exposes the validated endpoints and advertised capabilities, including
scopes, grant types, and PKCE methods. An RFC 8414 document can omit the
authorization endpoint if it advertises only grants that do not use it, such as
Client Credentials. Use `ProviderMetadata.from_json(issuer, document)` when you
already have a document from a trusted source.

HTTP status failures raise `ProviderDiscoveryHTTPError`, which exposes `status`.
Invalid documents raise `InvalidProviderMetadataError`, with specific subtypes
`IssuerMismatchError` and `ProviderMetadataTooLargeError`.

## Device Authorization

```zap
import oauth

client = oauth.Client(
    "device-client", "", "https://issuer.example/token",
    token_endpoint_auth_method="none",
    device_authorization_endpoint="https://issuer.example/device",
    timeout=5000,
)
authorization = client.device_authorization(scope=["read"])
print(authorization.verification_uri, authorization.user_code)
token = client.device_access_token(authorization)
```

Start device authorization in response to a user action. Display the user code
and verification URI, and keep the device code private. If discovery advertises
the device authorization endpoint, `Client.from_metadata` configures it.

For caller-driven polling, wait `authorization.poll_after_ms()` milliseconds
before calling `client.poll_device_access_token(authorization)`. It returns
`None` while authorization is pending or backing off. An early call raises
`DevicePollingTooSoonError` and exposes `retry_after_ms`. The default interval
is five seconds when the provider omits it. `slow_down` adds five seconds, and
a timed-out request doubles the interval. Both styles stop at completion,
denial, or expiry. `DeviceAccessDeniedError` and `DeviceCodeExpiredError` are
typed token endpoint errors. Local expiry uses status `0`.

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
