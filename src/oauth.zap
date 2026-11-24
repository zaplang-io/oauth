import datetime

# A JSON token document is malformed or contains an unsupported field value.
@exception
struct InvalidTokenError:
    str message

# An expired token has no refresh credential.
@exception
struct MissingRefreshTokenError:
    str message

# An OAuth 2 bearer token. Expiry fields use whole seconds.
struct Token:
    str access_token
    str token_type
    Optional[int64] expires_at = None
    Optional[int64] expires_in = None
    Optional[str] refresh_token = None
    Optional[str] scope = None

    # Decode an endpoint response or a saved token. A stored absolute expiry
    # takes precedence so reloads do not extend the token's lifetime.
    def from_json(str document) -> Token:
        match _load_json(document):
            case JsonValue.Object(fields):
                return _decode_token(fields)
            case _:
                raise InvalidTokenError("token JSON must be an object")

    # Encode the token for persistence, including its original expiry.
    # The returned document contains credentials.
    def to_json(self) -> str:
        dict[str, JsonValue] fields = {
            "access_token": JsonValue.Str(self.access_token),
            "token_type": JsonValue.Str(self.token_type),
        }
        if self.expires_at.is_some():
            fields["expires_at"] = JsonValue.Int(self.expires_at.unwrap())
        if self.expires_in.is_some():
            fields["expires_in"] = JsonValue.Int(self.expires_in.unwrap())
        if self.refresh_token.is_some():
            fields["refresh_token"] = JsonValue.Str(self.refresh_token.unwrap())
        if self.scope.is_some():
            fields["scope"] = JsonValue.Str(self.scope.unwrap())
        return json.dumps(JsonValue.Object(fields))

    # True at expiry or within leeway seconds of expiry. A token without an
    # expiry has no known expiry. Leeway must be non-negative.
    def is_expired(self, int64 leeway = 60) -> bool:
        if leeway < 0:
            raise ValueError("token expiry leeway must be non-negative")
        if self.expires_at.is_none():
            return False
        auto now = datetime.to_timestamp(datetime.now())
        auto expiry = self.expires_at.unwrap()
        return expiry <= now or expiry - now <= leeway

    # Return this token if active, otherwise use fetch to obtain a replacement.
    # The refresh credential persists when the server omits it.
    def ensure_active_token(self, fn(str) -> Token fetch, int64 leeway = 60) -> Token:
        if not self.is_expired(leeway):
            return self
        auto credential = self.refresh_token.unwrap_or("")
        if credential == "":
            raise MissingRefreshTokenError("expired token has no refresh token")
        auto replacement = fetch(credential)
        if replacement.refresh_token.is_some():
            return replacement
        return Token(
            replacement.access_token,
            replacement.token_type,
            replacement.expires_at,
            replacement.expires_in,
            self.refresh_token,
            replacement.scope,
        )

def _load_json(str document) -> JsonValue:
    try:
        return json.loads(document)
    except Exception:
        raise InvalidTokenError("invalid token JSON")

def _decode_token(dict[str, JsonValue] fields) -> Token:
    auto access_token = _read_string(fields, "access_token").unwrap_or("")
    if access_token == "":
        raise InvalidTokenError("access_token must be present and non-empty")
    auto token_type = _read_string(fields, "token_type").unwrap_or("")
    if token_type.lower() != "bearer":
        raise InvalidTokenError("token_type must be Bearer")
    auto expires_in = _read_seconds(fields, "expires_in")
    auto expires_at = _read_seconds(fields, "expires_at")
    if expires_at.is_none() and expires_in.is_some():
        auto now = datetime.to_timestamp(datetime.now())
        auto lifetime = expires_in.unwrap()
        if lifetime > 9223372036854775807 - now:
            raise InvalidTokenError("computed expires_at exceeds int64")
        expires_at = Optional.Some(now + lifetime)
    auto refresh_token = _read_string(fields, "refresh_token")
    if refresh_token.is_some() and refresh_token.unwrap() == "":
        raise InvalidTokenError("refresh_token must be non-empty when supplied")
    return Token(
        access_token,
        token_type,
        expires_at,
        expires_in,
        refresh_token,
        _read_string(fields, "scope"),
    )

def _read_string(dict[str, JsonValue] fields, str key) -> Optional[str]:
    if key not in fields:
        return None
    match fields[key]:
        case JsonValue.Str(value):
            return Optional.Some(value)
        case _:
            raise InvalidTokenError(key + " must be a string")

def _read_seconds(dict[str, JsonValue] fields, str key) -> Optional[int64]:
    if key not in fields:
        return None
    match fields[key]:
        case JsonValue.Int(value):
            if value >= 0:
                return Optional.Some(value)
        case _:
            pass
    raise InvalidTokenError(key + " must be a non-negative integer")

# OAuth form parameters and Basic credentials use UTF-8 percent encoding
# with spaces represented by '+' (RFC 6749 Appendix B).
def _form_component(str value) -> str:
    return url.quote(value).replace("%20", "+")

def _encode_token_form(dict[str, str] form) -> str:
    list[str] encoded = []
    for key, value in form.items():
        encoded.append(_form_component(key) + "=" + _form_component(value))
    return "&".join(encoded)

def _basic_authorization(str client_id, str client_secret) -> str:
    auto credentials = _form_component(client_id) + ":" + _form_component(client_secret)
    return "Basic " + base64.encode(bytes(credentials))

def _post_token_form(
    str token_endpoint,
    dict[str, str] form,
    str client_id,
    str client_secret,
    str auth_method,
    int64 timeout,
) -> bytes:
    if "client_id" in form or "client_secret" in form:
        raise ValueError("client credentials must come from the endpoint configuration")
    auto headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    auto fields = form
    match auth_method:
        case "client_secret_basic":
            headers["Authorization"] = _basic_authorization(client_id, client_secret)
        case "client_secret_post":
            fields = form.copy()
            fields["client_id"] = client_id
            fields["client_secret"] = client_secret
        case _:
            raise ValueError("unsupported token endpoint authentication method")
    auto body = _encode_token_form(fields)
    # A redirect can resend the credentials to a different destination.
    auto client = http.Client(follow=False, timeout=timeout)
    try:
        return client.post(token_endpoint, body, headers)
    finally:
        client.shutdown()

# Keep the base payload layout as a prefix so fields also work in base catches.
# OAuth token endpoint failures.
@exception
struct TokenEndpointError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# The provider rejected a malformed token request.
@exception(TokenEndpointError)
struct InvalidRequestError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# The provider rejected the client credentials.
@exception(TokenEndpointError)
struct InvalidClientError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# The provider rejected the authorization grant or refresh token.
@exception(TokenEndpointError)
struct InvalidGrantError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# The client is unauthorized to use the grant.
@exception(TokenEndpointError)
struct UnauthorizedClientError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# The provider does not support the requested grant.
@exception(TokenEndpointError)
struct UnsupportedGrantTypeError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# The provider rejected the requested scope.
@exception(TokenEndpointError)
struct InvalidScopeError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# The endpoint returned a failed HTTP status without a usable OAuth error.
@exception(TokenEndpointError)
struct TokenEndpointHTTPError:
    str message
    int64 status
    str error = ""
    Optional[str] error_description = None
    Optional[str] error_uri = None

# An OAuth 2 client configured for a token endpoint.
struct Client:
    str client_id
    str client_secret
    str token_endpoint
    str token_endpoint_auth_method = "client_secret_basic"
    int64 timeout = 0

    # Exchange a grant form for a bearer token. The client adds authentication.
    # Timeout is a total deadline in milliseconds, with zero for no deadline.
    def fetch_token(self, dict[str, str] form) -> Token:
        if self.client_id == "":
            raise ValueError("client_id must be non-empty")
        if self.timeout < 0:
            raise ValueError("token endpoint timeout must be non-negative")
        if form.get("grant_type").unwrap_or("") == "":
            raise ValueError("grant_type must be non-empty")
        auto endpoint = _validate_token_endpoint(self.token_endpoint)
        auto response = _post_token_form(
            endpoint,
            form,
            self.client_id,
            self.client_secret,
            self.token_endpoint_auth_method,
            self.timeout,
        )
        return _decode_token_response(http.status(response), http.body(response))

    # Exchange a refresh credential for a replacement bearer token.
    def refresh_token(self, str refresh_token) -> Token:
        if refresh_token == "":
            raise ValueError("refresh_token must be non-empty")
        return self.fetch_token(
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
        )

    # Refresh through the configured endpoint only if the current token needs it.
    def ensure_active_token(self, Token token, int64 leeway = 60) -> Token:
        return token.ensure_active_token(
            lambda credential: self.refresh_token(credential),
            leeway,
        )

def _validate_token_endpoint(str endpoint) -> str:
    for octet in bytes(endpoint):
        if octet < 33 or octet >= 127:
            raise ValueError("token endpoint must be an ASCII URI without whitespace")
    auto parts = url.split(endpoint)
    if not parts.has_authority or parts.host == "" or parts.userinfo != "" or "#" in endpoint:
        raise ValueError(
            "token endpoint must be an absolute URI without user information or a fragment",
        )
    if parts.scheme != "https":
        if parts.scheme != "http" or parts.host != "127.0.0.1" and parts.host != "::1":
            raise ValueError("token endpoint requires HTTPS outside numeric loopback")
    return url.build(parts)

def _decode_token_response(int64 status, str document) -> Token:
    auto success = status >= 200 and status < 300
    try:
        match _load_json(document):
            case JsonValue.Object(fields):
                if "error" in fields:
                    _raise_provider_error(status, fields)
                if success:
                    return _decode_token(fields)
            case _:
                if success:
                    raise InvalidTokenError("token JSON must be an object")
    except InvalidTokenError:
        if success:
            raise
    raise TokenEndpointHTTPError("token endpoint HTTP status " + str(status), status)

def _raise_provider_error(int64 status, dict[str, JsonValue] fields):
    auto error = _read_string(fields, "error").unwrap_or("")
    if error == "":
        raise InvalidTokenError("OAuth error code must be non-empty")
    auto description = _read_string(fields, "error_description")
    auto uri = _read_string(fields, "error_uri")
    auto message = "token endpoint rejected the request"
    match error:
        case "invalid_request":
            raise InvalidRequestError(message, status, error, description, uri)
        case "invalid_client":
            raise InvalidClientError(message, status, error, description, uri)
        case "invalid_grant":
            raise InvalidGrantError(message, status, error, description, uri)
        case "unauthorized_client":
            raise UnauthorizedClientError(message, status, error, description, uri)
        case "unsupported_grant_type":
            raise UnsupportedGrantTypeError(message, status, error, description, uri)
        case "invalid_scope":
            raise InvalidScopeError(message, status, error, description, uri)
        case _:
            raise TokenEndpointError(message, status, error, description, uri)
