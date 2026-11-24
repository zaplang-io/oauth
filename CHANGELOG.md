# Changelog

## Unreleased

- Add the OAuth 2 bearer token model with JSON persistence, expiry checks, and
  a refresh callback that preserves the existing refresh credential when omitted
  by the provider. [#2](https://github.com/zaplang-io/oauth/issues/2)
- Add `Client.fetch_token` and live refresh with form-encoded client
  authentication, request deadlines, and typed provider errors.
  [#3](https://github.com/zaplang-io/oauth/issues/3)
- Add Authorization Code exchange with S256 PKCE, generated state, callback
  validation, and support for public clients.
  [#4](https://github.com/zaplang-io/oauth/issues/4)
- Add Client Credentials token acquisition and a coroutine-safe token source
  that reacquires tokens based on expiry. [#5](https://github.com/zaplang-io/oauth/issues/5)
- Add typed provider metadata parsing, exact issuer validation, and client
  configuration from metadata. [#6](https://github.com/zaplang-io/oauth/issues/6)
