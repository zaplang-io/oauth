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

## Decisions (2026-11-21)

_No decisions recorded yet. Add one section per decision as issues are implemented._
