# oauth package decisions

Design decisions for the Zap `oauth` library, keyed to issues. Each records a
choice that could not be read straight off Python's [authlib](https://docs.authlib.org/) /
[requests-oauthlib](https://requests-oauthlib.readthedocs.io/) or Go's
[`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2), with the
reference it follows or departs from. Signature ambiguities are resolved with the
maintainer (with Python/Go examples) before being recorded here.

## Parity target: authlib / requests-oauthlib

The package tracks [**authlib**](https://docs.authlib.org/) and
[**requests-oauthlib**](https://requests-oauthlib.readthedocs.io/) as its primary
API references, with Go's `golang.org/x/oauth2` as a secondary reference. The
OAuth 2 RFCs ([6749](https://www.rfc-editor.org/rfc/rfc6749),
[7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636),
[8628 Device Code](https://www.rfc-editor.org/rfc/rfc8628)) are the tie-breaker
when the libraries differ. Deviations are recorded below, keyed to the issue that
introduces them.

## Token expiry and refresh ownership ([#2](https://github.com/zaplang-io/oauth/issues/2))

- Follow Authlib’s expiry model. `expires_in` represents the response lifetime
  in seconds. `expires_at` represents the absolute expiry in Unix seconds. A
  relative lifetime establishes an absolute expiry when the response is received.
  Persistence retains the absolute expiry so loading a token preserves its
  original deadline.
- `Token.is_expired(leeway)` uses a 60-second default, matching Authlib. Callers
  can supply a leeway in seconds.
- Issue #2 owns the token model and refresh behavior. Issue #3 connects that
  behavior to the live token endpoint.

The token field and JSON key use `scope`. Zap supports the identifier through
the soft keyword change in [zaplang-io/zap#1405](https://github.com/zaplang-io/zap/issues/1405).

## Token endpoint transport ([#3](https://github.com/zaplang-io/oauth/issues/3))

- Expose `Client.fetch_token(form)` with an explicit `dict[str, str]` of grant
  parameters. The client owns credential placement. `Client.refresh_token`
  submits a refresh grant, and `Client.ensure_active_token` connects the token
  model’s existing refresh behavior to that exchange.
- Default to `client_secret_basic`, matching Authlib. Callers can select
  `client_secret_post` with `token_endpoint_auth_method`.
- Encode form parameters and HTTP Basic credentials as UTF-8 form components
  per RFC 6749 §2.3.1 and Appendix B.
- Send credential-bearing POST requests with redirects disabled. Handle the
  original response at the configured token endpoint.
- Map standard provider codes to named exceptions under `TokenEndpointError`.
  Every subtype preserves the base field layout for typed catches. Exceptions
  expose the HTTP status and provider code, description, and URI through
  [Zap’s structured exception fields](https://github.com/zaplang-io/zap/issues/1432).
  Unknown provider codes use the base type. Failed HTTP responses without a
  usable provider error use `TokenEndpointHTTPError`.

## Authorization Code and PKCE ([#4](https://github.com/zaplang-io/oauth/issues/4))

- `Client.authorization_url()` returns `(url, state, verifier)` for the caller
  to keep in the initiating session. It always generates a fresh verifier and
  uses S256. The caller can supply `state`, which otherwise uses secure random
  bytes like the verifier.
- `Client.exchange_code(callback_url, request)` accepts that tuple and validates
  the registered callback URI, state, and PKCE binding before posting the code.
  `Client.fetch_token(form)` remains the shared token endpoint method.
- Public clients select `token_endpoint_auth_method="none"` with an empty
  client secret. The exchange sends their `client_id` and verifier in the form.
- The provider enforces single use of authorization codes. Callers should take
  the saved tuple out of their session as part of callback processing.
